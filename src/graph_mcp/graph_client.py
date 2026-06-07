"""Graph client. The only real logic in here.

Holds no business logic: it injects a per-user On-Behalf-Of token into the Graph
calls that the model constructs, applies throttling-retry, and shapes the
response. URL, body and params are all built by the caller; this class just
authenticates and
forwards the HTTP request.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import msal

from graph_mcp.request_context import (
    get_apim_user,
    get_req_seq,
    get_user_token,
    token_exp,
    user_token_source,
)
from graph_mcp.telemetry import get_logger

_log = get_logger(__name__)

_GRAPH_HOST = "https://graph.microsoft.com"
_MAX_BATCH_REQUESTS = 20  # Graph $batch hard limit
_MAX_RETRIES = 4
_FILE_ATTACHMENT = "#microsoft.graph.fileAttachment"
_REFERENCE_ATTACHMENT = "#microsoft.graph.referenceAttachment"


class AuthError(RuntimeError):
    """Raised when a Graph token cannot be obtained for the current request.

    Behind the gateway this should not occur for a normal request; it signals a
    misconfiguration (e.g. the resource app lacks the delegated Graph permissions
    needed for On-Behalf-Of, or no user token was forwarded).
    """


class GraphClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        scopes: list[str],
        max_concurrent: int = 4,
        default_site_id: str = "",
        default_drive_id: str = "",
        default_base_path: str = "",
        attachment_temp_folder: str = "_mcp-attachments",
        attachment_ttl_seconds: int = 86400,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._att_folder = attachment_temp_folder.strip("/")
        self._att_ttl = attachment_ttl_seconds
        # Built lazily on the first OBO exchange, so construction does no network I/O
        # (MSAL validates the authority eagerly otherwise).
        self._app: msal.ConfidentialClientApplication | None = None
        self._scopes = list(scopes)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        # Non-secret placeholder values, substituted into request paths.
        self._defaults = {
            "site_id": default_site_id,
            "drive_id": default_drive_id,
            "base_path": default_base_path,
        }

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _msal_app(self) -> msal.ConfidentialClientApplication:
        # Confidential client. Exchanges the inbound user token for a per-user
        # Graph token via On-Behalf-Of (needs the client secret).
        if self._app is None:
            self._app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=f"https://login.microsoftonline.com/{self._tenant_id}",
                client_credential=self._client_secret,
            )
        return self._app

    def _graph_token_obo(self) -> str:
        """Exchange the current request's user token for a delegated Graph token.

        The user token is the Entra Bearer that APIM validated and forwarded
        under X-Forwarded-Authorization (see request_context.py). The
        On-Behalf-Of binds the Graph token to *that* user. There's no
        shared/process-wide identity, so concurrent requests from different users
        never see each other's data.
        """
        assertion = get_user_token()
        # TEMPORARY diagnostic: log the token actually used by the OBO, tagged with
        # the request seq. If this seq/exp is OLDER than the in-flight request's
        # (per the middleware's obo_token_diag), the tool is reading a stale/frozen
        # context, ie. the OBO is using a previous request's assertion.
        _log.info(
            "obo_assertion_used",
            req_seq=get_req_seq(),
            token_source=user_token_source(),
            assertion_exp=token_exp(assertion) if assertion else None,
            apim_user=get_apim_user(),
            assertion_present=bool(assertion),
        )
        if not assertion:
            raise AuthError(
                "No user token on this request. Per-user Graph access requires a "
                "delegated Microsoft sign-in forwarded by the gateway."
            )
        result = self._msal_app().acquire_token_on_behalf_of(
            user_assertion=assertion,
            scopes=self._scopes,
        )
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            raise AuthError(f"On-Behalf-Of token exchange failed: {error}")
        return str(result["access_token"])

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._graph_token_obo()}",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    # ------------------------------------------------------------------
    # Path resolution + placeholder substitution
    # ------------------------------------------------------------------

    def resolve_path(self, path: str, *, api_version: str = "v1.0") -> str:
        """Turn a caller-supplied path into an absolute Graph URL.

        1. Substitute {site_id} / {drive_id} / {base_path} from config.
        2. Pass absolute URLs through unchanged.
        3. Otherwise prefix with the Graph host + api_version (v1.0 | beta).
        """
        for token, value in self._defaults.items():
            placeholder = "{" + token + "}"
            if placeholder in path:
                if not value:
                    raise ValueError(
                        f"Path uses {{{token}}} but GRAPH_DEFAULT_{token.upper()} is not "
                        f"configured. Pass the real value, or resolve it via graph_get."
                    )
                path = path.replace(placeholder, value)

        if path.startswith(("http://", "https://")):
            return path
        return f"{_GRAPH_HOST}/{api_version}/{path.lstrip('/')}"

    @staticmethod
    def _format_response(resp: httpx.Response) -> dict[str, Any]:
        """Shape a Graph response for the caller. Never raises on 4xx/5xx: the
        Graph error body is returned verbatim so the model can react (e.g. a 403 for a
        not-yet-consented scope)."""
        out: dict[str, Any] = {"status_code": resp.status_code}
        next_link = None
        if resp.content:
            ctype = resp.headers.get("content-type", "")
            if "application/json" in ctype:
                try:
                    body = resp.json()
                    out["json"] = body
                    if isinstance(body, dict):
                        next_link = body.get("@odata.nextLink")
                except ValueError:
                    out["text"] = resp.text
            else:
                out["text"] = resp.text
        if next_link:
            # Surfaced explicitly so the model knows to paginate via graph_get.
            out["next_link"] = next_link
        return out

    # ------------------------------------------------------------------
    # Core verb passthrough (GET / POST / PATCH / DELETE)
    # ------------------------------------------------------------------

    async def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        params: dict[str, Any] | None = None,
        api_version: str = "v1.0",
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = self.resolve_path(path, api_version=api_version)
        resp: httpx.Response | None = None
        for attempt in range(_MAX_RETRIES):
            async with self._semaphore:
                async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
                    resp = await client.request(
                        method.upper(),
                        url,
                        headers=self._headers(extra_headers),
                        json=body,
                        params=params,
                    )
            if resp.status_code == 429 and attempt < _MAX_RETRIES - 1:
                retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
                await asyncio.sleep(retry_after)
                continue
            break
        assert resp is not None
        return self._format_response(resp)

    # ------------------------------------------------------------------
    # Download
    # ------------------------------------------------------------------

    @staticmethod
    def _item_path(path: str) -> str:
        """Strip a trailing /content (and the path-addressing ':') to get the item URL."""
        p = path
        p = p.removesuffix("/content")
        p = p.removesuffix(":")
        return p

    async def download(self, path: str, *, api_version: str = "v1.0") -> bytes:
        """Download raw bytes. `path` is the content endpoint."""
        url = self.resolve_path(path, api_version=api_version)
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(url, headers=self._headers())
            resp.raise_for_status()
            return resp.content

    async def download_url(self, path: str, *, api_version: str = "v1.0") -> dict[str, Any]:
        """Return the item's pre-authenticated download URL (no bytes over MCP)."""
        item = self._item_path(path)
        url = self.resolve_path(item, api_version=api_version)
        params = {"$select": "id,name,size,@microsoft.graph.downloadUrl"}
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
        return self._format_response(resp)

    # ------------------------------------------------------------------
    # Batch + Search
    # ------------------------------------------------------------------

    async def batch(self, requests: list[dict[str, Any]]) -> dict[str, Any]:
        if len(requests) > _MAX_BATCH_REQUESTS:
            raise ValueError(
                f"$batch accepts at most {_MAX_BATCH_REQUESTS} requests; got "
                f"{len(requests)}. Split into multiple graph_batch calls."
            )
        url = f"{_GRAPH_HOST}/v1.0/$batch"
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                url,
                headers=self._headers({"Content-Type": "application/json"}),
                json={"requests": requests},
            )
        return self._format_response(resp)

    async def search(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{_GRAPH_HOST}/v1.0/search/query"
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                url,
                headers=self._headers({"Content-Type": "application/json"}),
                json=body,
            )
        return self._format_response(resp)

    # ------------------------------------------------------------------
    # Resumable upload session
    # ------------------------------------------------------------------

    async def create_upload_session(
        self,
        path: str,
        *,
        conflict_behavior: str = "replace",
        api_version: str = "v1.0",
    ) -> str:
        """Open a Graph resumable upload session; return its pre-authenticated uploadUrl.

        The caller's own code environment, which has egress, streams the file's bytes
        straight to the returned URL, so file content never crosses the model.
        `path` is the content endpoint, e.g.
        "/me/drive/root:/Reports/big.xlsx:/content" or
        "/drives/{id}/items/{item-id}/content".
        """
        content_url = self.resolve_path(path, api_version=api_version)
        if content_url.endswith("/content"):
            session_url = content_url[: -len("/content")] + "/createUploadSession"
        else:
            session_url = content_url.rstrip("/") + "/createUploadSession"
        body = {"item": {"@microsoft.graph.conflictBehavior": conflict_behavior}}
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                session_url,
                headers=self._headers({"Content-Type": "application/json"}),
                json=body,
            )
            resp.raise_for_status()
            return str(resp.json()["uploadUrl"])

    # ------------------------------------------------------------------
    # Mail attachments → always return a download URL (never base64)
    # ------------------------------------------------------------------

    async def attachment_download_url(
        self,
        message_id: str,
        attachment_id: str,
        *,
        api_version: str = "v1.0",
    ) -> dict[str, Any]:
        """Return a fetchable download URL for a mail attachment, never its bytes.

        - referenceAttachment (OneDrive/SharePoint link): resolve its sourceUrl to
          the drive item's downloadUrl. No copy.
        - fileAttachment (embedded bytes): stream the raw content into a OneDrive
          temp folder and return that item's downloadUrl. Sweeps stale staged files
          (older than the TTL) first.
        The caller fetches download_url directly, no base64 through the model.
        """
        base = f"/me/messages/{message_id}/attachments/{attachment_id}"
        # Probe type + metadata WITHOUT pulling contentBytes.
        meta = await self.request(
            "GET", base,
            params={"$select": "id,name,size,contentType,isInline"},
            api_version=api_version,
        )
        if meta.get("status_code") != 200:
            return meta  # surface the Graph error verbatim
        body = meta.get("json", {})
        atype = body.get("@odata.type", "")
        name = body.get("name", attachment_id)
        size = body.get("size")
        ctype = body.get("contentType")

        if atype == _REFERENCE_ATTACHMENT:
            full = await self.request("GET", base, params={"$select": "sourceUrl"}, api_version=api_version)
            source_url = (full.get("json") or {}).get("sourceUrl", "")
            url = await self._resolve_share_download_url(source_url, api_version=api_version)
            return {"type": "reference", "name": name, "size": size,
                    "content_type": ctype, "staged": False, "download_url": url}

        if atype == _FILE_ATTACHMENT:
            await self._sweep_temp_folder(api_version=api_version)
            url, item_id = await self._stage_file_attachment(
                base, name, api_version=api_version
            )
            return {"type": "file", "name": name, "size": size, "content_type": ctype,
                    "staged": True, "drive_item_id": item_id, "download_url": url}

        return {"ok_note": f"Unsupported attachment type {atype!r} (only file/reference).",
                "type": atype, "name": name}

    async def _resolve_share_download_url(self, source_url: str, *, api_version: str) -> str:
        # Encode a sharing URL to a share id per Graph: base64url, strip '=', prepend 'u!'.
        enc = base64.urlsafe_b64encode(source_url.encode("utf-8")).decode("ascii").rstrip("=")
        share_id = "u!" + enc
        resp = await self.request(
            "GET", f"/shares/{share_id}/driveItem",
            params={"$select": "id,name,size,@microsoft.graph.downloadUrl"},
            api_version=api_version,
        )
        return str((resp.get("json") or {}).get("@microsoft.graph.downloadUrl", ""))

    async def _stage_file_attachment(
        self, attachment_base: str, name: str, *, api_version: str
    ) -> tuple[str, str]:
        """Stream the attachment's raw $value into the OneDrive temp folder; return
        (downloadUrl, driveItemId). Buffers the bytes (attachments are ≤150 MB)."""
        await self._ensure_temp_folder(api_version=api_version)
        value_url = self.resolve_path(f"{attachment_base}/$value", api_version=api_version)
        async with httpx.AsyncClient(timeout=300, follow_redirects=True) as client:
            r = await client.get(value_url, headers=self._headers())
            r.raise_for_status()
            data = r.content
        safe = name.replace("/", "_").replace("\\", "_")
        put_url = self.resolve_path(
            f"/me/drive/root:/{self._att_folder}/{safe}:/content", api_version=api_version
        )
        async with httpx.AsyncClient(timeout=300) as client:
            up = await client.put(
                put_url,
                headers=self._headers({"Content-Type": "application/octet-stream"}),
                params={"@microsoft.graph.conflictBehavior": "rename"},
                content=data,
            )
            up.raise_for_status()
            item_id = up.json()["id"]
        got = await self.request(
            "GET", f"/me/drive/items/{item_id}",
            params={"$select": "@microsoft.graph.downloadUrl"},
            api_version=api_version,
        )
        return str((got.get("json") or {}).get("@microsoft.graph.downloadUrl", "")), str(item_id)

    async def _ensure_temp_folder(self, *, api_version: str) -> None:
        # Idempotent: create the temp folder, ignoring "already exists".
        await self.request(
            "POST", "/me/drive/root/children",
            body={"name": self._att_folder, "folder": {},
                  "@microsoft.graph.conflictBehavior": "fail"},
            api_version=api_version,
        )

    async def _sweep_temp_folder(self, *, api_version: str) -> None:
        """Delete staged files older than the TTL. Best-effort; never raises."""
        try:
            listing = await self.request(
                "GET", f"/me/drive/root:/{self._att_folder}:/children",
                params={"$select": "id,name,createdDateTime", "$top": 200},
                api_version=api_version,
            )
            if listing.get("status_code") != 200:
                return
            cutoff = datetime.now(UTC) - timedelta(seconds=self._att_ttl)
            for item in (listing.get("json") or {}).get("value", []):
                created = item.get("createdDateTime")
                if not created:
                    continue
                when = datetime.fromisoformat(created)
                if when < cutoff:
                    await self.request("DELETE", f"/me/drive/items/{item['id']}", api_version=api_version)
        except Exception:
            return
