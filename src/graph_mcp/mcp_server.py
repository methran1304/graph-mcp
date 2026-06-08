"""FastMCP server. Nine thin Graph passthrough tools.

The server holds no business logic. The model constructs every Graph URL, body and
query; each tool simply forwards the request through GraphClient, which injects a
per-user On-Behalf-Of token. Responses (including Graph errors) are returned
verbatim so the model can drive multi-step workflows itself.
"""

from __future__ import annotations

import base64
import hmac
import json
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp

from graph_mcp.graph_client import GraphClient
from graph_mcp.request_context import OboAuthRewriteMiddleware, UserContextMiddleware
from graph_mcp.telemetry import get_logger

log = get_logger(__name__)

_NOT_CONFIGURED = (
    "Graph not configured: set GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET"
)
# Inline-base64 download guard. Anything bigger has to use return_url.
_MAX_INLINE_DOWNLOAD_BYTES = 4 * 1024 * 1024

# Surfaced to the model by the MCP client so it follows the reliable file flows
# without per-user prompting. Files never travel through the model as base64.
_SERVER_INSTRUCTIONS = """\
Microsoft Graph passthrough. Construct Graph paths/bodies yourself; tools inject a \
per-user token and return the Graph response under `json` (check `status_code`).

FILE UPLOADS: never put a file in a tool argument as base64.
- Use graph_create_upload_session(path) to get a pre-authenticated upload_url, then \
in your code/bash tool stream the file's bytes straight to it (320 KiB-multiple \
fragments, Content-Range, no Authorization header, URL used verbatim). Works for any size.

EMAIL ATTACHMENTS (send): do NOT inline-base64 the file. Attach as a link:
1) upload the file to OneDrive (graph_create_upload_session); 2) grant the recipients \
access. For INTERNAL recipients create an organization-scoped link \
(POST /me/drive/items/{id}/createLink {"type":"view","scope":"organization"}); for \
EXTERNAL recipients prefer POST /me/drive/items/{id}/invite (recipients=[their emails], \
roles=["read"], requireSignIn=true, sendInvitation=false) so access is identity-bound and \
audited (use an anonymous link only if the user explicitly asks; org policy may block it); \
3) attach the resulting link to the draft as a referenceAttachment (sourceUrl = the link); \
4) send. Works for any size; the recipient opens the file via the link. If sharing is \
refused by org policy, tell the user instead of sending a dead link.

EMAIL ATTACHMENTS (read/process): NEVER request contentBytes, never read as base64.
- Call graph_get_attachment_url(message_id, attachment_id) to get a download_url, then \
fetch that URL in your code tool. It works for links and embedded files of any size.
- For metadata only, graph_get the attachment with $select=id,name,size,contentType \
(omit contentBytes).
"""


def _ok(data: dict[str, Any]) -> str:
    return json.dumps({"ok": True, **data})


def _err(msg: str) -> str:
    return json.dumps({"ok": False, "error": msg})


class _SharedKeyAuthMiddleware(BaseHTTPMiddleware):
    """Backend hop-auth: only the APIM gateway (which holds the shared key) may
    reach this container. APIM validates the user's Entra token, then calls the
    backend with X-API-Key + the forwarded user token."""

    def __init__(self, app: ASGIApp, key: str) -> None:
        super().__init__(app)
        self._key = key.encode()

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        raw = request.headers.get("X-API-Key", "")
        try:
            candidate = raw.encode("ascii")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return PlainTextResponse("Unauthorized", status_code=401)
        if not hmac.compare_digest(candidate, self._key):
            return PlainTextResponse("Unauthorized", status_code=401)
        return await call_next(request)


def _create_mcp(client: GraphClient | None) -> FastMCP:
    """Create the FastMCP instance and register the 8 Graph tools (closing over
    `client`). Split out from build_mcp_app so tests can introspect the tool set."""
    mcp = FastMCP(
        "graph-mcp",
        instructions=_SERVER_INSTRUCTIONS,
        transport_security=TransportSecuritySettings(
            # DNS rebinding protection (Host header validation) is disabled because
            # the ACA ingress rewrites the Host header before it reaches the app.
            # The hop-auth key enforces access control regardless, and HTTPS ingress
            # blocks the classic (HTTP-only) DNS rebinding vector.
            enable_dns_rebinding_protection=False,
        ),
    )

    # ------------------------------------------------------------------
    # graph_get: GET
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_get(
        path: str,
        params: dict[str, Any] | None = None,
        api_version: str = "v1.0",
    ) -> str:
        """Read any Microsoft Graph resource (GET).

        `path` is a Graph path you construct, e.g. "/me/drive",
        "/sites/{site_id}/drives", "/drives/{id}/root:/Reports:/children", or a
        full https URL (e.g. an @odata.nextLink). Use api_version="beta" for beta
        endpoints. Pass OData query options ($select, $filter, $top, $expand, …)
        via `params`.

        CAN: list files/folders/drives/sites; read Excel ranges/tables; read file
        metadata, versions, permissions; read SharePoint list items; read Teams,
        calendar and mail metadata; run delta queries.
        CANNOT: write (use graph_post/patch/delete); download binary file content
        (use graph_download); search across services (use graph_search); paginate
        automatically. Follow the returned next_link with another graph_get.
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            return _ok(await client.request("GET", path, params=params, api_version=api_version))
        except Exception as exc:
            log.warning("graph_get failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_post: POST
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_post(
        path: str,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        api_version: str = "v1.0",
    ) -> str:
        """Create resources and trigger actions (POST).

        CAN: create files/folders, create Excel sessions, copy files, create
        sharing links, send mail, create calendar events, post Teams messages,
        create SharePoint sites/lists, restore recycle-bin items, invoke Graph
        actions.
        CANNOT: update existing resources (use graph_patch); upload binary file
        content (use graph_create_upload_session); search across services (use graph_search).
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            return _ok(await client.request("POST", path, body=body, params=params, api_version=api_version))
        except Exception as exc:
            log.warning("graph_post failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_patch: PATCH
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_patch(
        path: str,
        body: dict[str, Any],
        params: dict[str, Any] | None = None,
        api_version: str = "v1.0",
    ) -> str:
        """Update existing resources in place (PATCH).

        CAN: update Excel cell values/formatting/tables in SharePoint without
        download; rename/move files; update SharePoint list-item metadata; update
        calendar events.
        CANNOT: create new resources (use graph_post); edit Word/PowerPoint content
        in place (Graph has no API for that, replace the whole file via
        graph_create_upload_session); upload binary content (use graph_create_upload_session).
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            return _ok(await client.request("PATCH", path, body=body, params=params, api_version=api_version))
        except Exception as exc:
            log.warning("graph_patch failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_delete: DELETE
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_delete(
        path: str,
        api_version: str = "v1.0",
    ) -> str:
        """Remove resources (DELETE).

        CAN: delete files/folders (soft-deleted to recycle bin), SharePoint list
        items, calendar events; remove sharing permissions; delete Excel worksheets
        and table rows.
        CANNOT: permanently delete (Graph soft-deletes); restore deleted items (use
        graph_post against the recycle bin).
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            return _ok(await client.request("DELETE", path, api_version=api_version))
        except Exception as exc:
            log.warning("graph_delete failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_download: GET (binary content)
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_download(
        path: str,
        return_url: bool = True,
        api_version: str = "v1.0",
    ) -> str:
        """Retrieve binary file content (GET).

        `path` is the content endpoint, e.g.
        "/drives/{id}/items/{item-id}/content" or
        "/drives/{id}/root:/file.pdf:/content". By default (return_url=true) this
        returns a short-lived pre-authenticated download URL. Preferred, and
        required for large files. Set return_url=false to get the bytes inline as
        base64 (only for small files; larger ones are refused).

        For PDF conversion, append "?format=pdf" semantics via the content path the
        Graph way (e.g. ".../content?format=pdf" through graph_get is also fine).
        CANNOT: let the model edit Word/PowerPoint binary; be included in graph_batch.
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            if return_url:
                return _ok(await client.download_url(path, api_version=api_version))
            data = await client.download(path, api_version=api_version)
            if len(data) > _MAX_INLINE_DOWNLOAD_BYTES:
                return _err(
                    f"File is {len(data) / 1024 / 1024:.1f} MB, too large to inline as "
                    "base64. Call again with return_url=true for a pre-authenticated URL."
                )
            return _ok({
                "content_base64": base64.b64encode(data).decode("ascii"),
                "size_bytes": len(data),
            })
        except Exception as exc:
            log.warning("graph_download failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_search: POST /search/query
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_search(
        query_string: str = "",
        entity_types: list[str] | None = None,
        from_index: int = 0,
        size: int = 25,
        fields: list[str] | None = None,
        region: str = "",
        body: dict[str, Any] | None = None,
    ) -> str:
        """Search across Microsoft 365 via the Microsoft Search API (POST /search/query).

        Provide a KQL `query_string` and `entity_types` (e.g. ["driveItem"],
        ["message"], ["event"], ["site"], ["chatMessage"], ["listItem"]). Or pass a
        fully-formed `body` to use the raw Search request shape.

        CAN: search SharePoint, OneDrive, Teams and Outlook at once; filter by
        entity type, file type, date, author; relevance-ranked results.
        CANNOT: search Excel cell values (use graph_get on the Excel REST API);
        guarantee real-time indexing of brand-new files; reach other users' OneDrive
        beyond the signed-in user's permissions.
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            if body is None:
                req: dict[str, Any] = {
                    "entityTypes": entity_types or ["driveItem"],
                    "query": {"queryString": query_string},
                    "from": from_index,
                    "size": size,
                }
                if fields:
                    req["fields"] = fields
                if region:
                    req["region"] = region
                body = {"requests": [req]}
            return _ok(await client.search(body))
        except Exception as exc:
            log.warning("graph_search failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_batch: POST /$batch
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_batch(requests: list[dict[str, Any]]) -> str:
        """Execute up to 20 Graph operations in a single request (POST /$batch).

        Each item is a Graph batch sub-request: {"id": "1", "method": "GET",
        "url": "/me/drive", ...}. Mix GET/POST/PATCH/DELETE; use "dependsOn" to
        sequence. URLs are relative to the Graph version root.

        CAN: run up to 20 ops in parallel; sequence with dependsOn; cut latency for
        bulk workflows.
        CANNOT: exceed 20 (split into multiple calls); include file upload/download
        (/content) operations; guarantee atomicity (partial failures possible).
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            for r in requests:
                url = str(r.get("url", ""))
                if url.endswith("/content") or "/content?" in url:
                    return _err(
                        "graph_batch cannot include file upload/download (/content) "
                        "operations. Use graph_create_upload_session / graph_download instead."
                    )
            return _ok(await client.batch(requests))
        except Exception as exc:
            log.warning("graph_batch failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_create_upload_session: large/binary file upload. Requires the caller's
    # code environment to reach the storage host, which for a sandboxed client
    # means allow-listing *.sharepoint.com in its egress rules. The server
    # creates the session (per-user OBO); the caller streams the bytes straight to
    # the returned pre-authenticated URL. No base64 through the model, no
    # credentials in the sandbox, any size.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_create_upload_session(
        path: str,
        conflict_behavior: str = "replace",
        api_version: str = "v1.0",
    ) -> str:
        """Open a resumable upload session and return its pre-authenticated upload URL.

        Best for large/binary files when your code/bash tool has network access to
        the file's storage host. The returned `upload_url` is PRE-AUTHENTICATED:
        stream the file's raw bytes to it yourself; nothing large goes through the model.

        `path` is the destination content endpoint, e.g.
        "/me/drive/root:/Reports/big.xlsx:/content".

        HOW TO UPLOAD (in your code/bash tool):
          - Use the returned `upload_url` verbatim. Do NOT truncate, re-encode,
            or split it. The tempauth token is ~1 KB; a corrupted URL → 401
            invalidSignature. (Store it in a variable in the same process; don't
            echo it through the shell.)
          - PUT the file in fragments that are a multiple of 320 KiB (e.g. 5–10 MiB);
            the last fragment is the remainder.
          - Per PUT headers: `Content-Range: bytes {start}-{end}/{total}` and
            `Content-Length`. Do NOT send an Authorization header.
          - 202 = send the next fragment; 200/201 on the final fragment = done.

        For small text content you can instead create the file directly with
        graph_post (e.g. PUT-style create), but this session path is the reliable
        way to land binary/large files.
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            upload_url = await client.create_upload_session(
                path, conflict_behavior=conflict_behavior, api_version=api_version
            )
            return _ok({
                "upload_url": upload_url,
                "fragment_multiple_bytes": 320 * 1024,
                "instructions": (
                    "PUT raw file bytes to upload_url in 320 KiB-multiple fragments with a "
                    "Content-Range header; no Authorization header; use the URL verbatim."
                ),
            })
        except Exception as exc:
            log.warning("graph_create_upload_session failed", error=str(exc))
            return _err(str(exc))

    # ------------------------------------------------------------------
    # graph_get_attachment_url: read a mail attachment as a download URL, never
    # base64. referenceAttachment → resolve the link; fileAttachment → stage the
    # bytes to a OneDrive temp folder (swept after the TTL) and return its URL.
    # ------------------------------------------------------------------
    @mcp.tool()
    async def graph_get_attachment_url(
        message_id: str,
        attachment_id: str,
        api_version: str = "v1.0",
    ) -> str:
        """Get a download URL for a mail attachment, any size.

        Use this instead of reading an attachment's `contentBytes` (base64), which
        truncates for large files. Returns a `download_url` you fetch in your code
        tool (needs egress to the storage host, already available for SharePoint/
        OneDrive). Handles both kinds:
          - link attachments (referenceAttachment) → the file's existing URL (no copy);
          - embedded files (fileAttachment, up to 150 MB) → streamed server-side into a
            OneDrive temp folder, returned as a download URL. No bytes through the model.

        Staged temp files are auto-swept once older than the configured TTL (default 1 day).
        """
        if client is None:
            return _err(_NOT_CONFIGURED)
        try:
            return _ok(await client.attachment_download_url(
                message_id, attachment_id, api_version=api_version,
            ))
        except Exception as exc:
            log.warning("graph_get_attachment_url failed", error=str(exc))
            return _err(str(exc))

    return mcp


def build_mcp_app(
    *,
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    scopes: list[str] | None = None,
    mcp_key: str | None = None,
    max_concurrent: int = 4,
    default_site_id: str = "",
    default_drive_id: str = "",
    default_base_path: str = "",
    reject_expired_token: bool = True,
    token_expiry_skew_seconds: int = 60,
    attachment_temp_folder: str = "_mcp-attachments",
    attachment_ttl_seconds: int = 86400,
) -> ASGIApp:
    """Build the Graph MCP ASGI app.

    Auth model (identical to the Excel MCP): the APIM gateway validates the user's
    Entra token and forwards it under X-Forwarded-Authorization. This backend
    trusts APIM via the X-API-Key hop-auth and exchanges the forwarded token for a
    per-user Graph token via On-Behalf-Of.
    """
    client: GraphClient | None = None
    if tenant_id and client_id and client_secret:
        client = GraphClient(
            tenant_id,
            client_id,
            client_secret,
            scopes=scopes or ["https://graph.microsoft.com/.default"],
            max_concurrent=max_concurrent,
            default_site_id=default_site_id,
            default_drive_id=default_drive_id,
            default_base_path=default_base_path,
            attachment_temp_folder=attachment_temp_folder,
            attachment_ttl_seconds=attachment_ttl_seconds,
        )

    mcp = _create_mcp(client)

    # Inner-most: capture the gateway-forwarded user token into a contextvar
    # (pure-ASGI so it propagates to the tool handlers). Then rewrite a swallowed
    # OBO auth failure (200 {ok:false}) into a real 401 so the client refreshes.
    # Outer: hop-auth so only APIM can reach the container.
    app: ASGIApp = UserContextMiddleware(
        mcp.streamable_http_app(),
        reject_expired_token=reject_expired_token,
        expiry_skew_seconds=token_expiry_skew_seconds,
    )
    app = OboAuthRewriteMiddleware(app)
    if mcp_key:
        app = _SharedKeyAuthMiddleware(app, mcp_key)
    return app
