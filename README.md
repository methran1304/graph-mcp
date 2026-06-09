# graph-mcp

Thin authenticated Microsoft Graph passthrough over MCP. Nine verb-shaped
tools and no business logic: the model builds every Graph URL, body and query
itself, and all the server does is inject a per-user On-Behalf-Of token.

## Install

```bash
uv sync --extra dev
uv run uvicorn graph_mcp.main:app --port 8080
```

Python ≥ 3.13. `GET /health` verifies configuration.

## Configuration

All settings take the `GRAPH_` prefix.

| Variable | Purpose |
| --- | --- |
| `GRAPH_TENANT_ID` | Entra tenant |
| `GRAPH_CLIENT_ID` / `GRAPH_CLIENT_SECRET` | The OBO confidential client. Must be the resource app the user token's audience targets |
| `GRAPH_API_KEY` | Shared key for the hop from your gateway to this server |
| `GRAPH_SCOPES` | Defaults to `.default`, so it picks up whatever delegated permissions are consented |
| `GRAPH_MAX_CONCURRENT` | In-flight Graph calls, default 4 |
| `GRAPH_REJECT_EXPIRED_TOKEN` | Refuse an expired forwarded assertion with a real 401. On by default |
| `GRAPH_DEFAULT_SITE_ID` / `_DRIVE_ID` / `_BASE_PATH` | Optional `{site_id}` / `{drive_id}` / `{base_path}` placeholders |
| `GRAPH_ATTACHMENT_TEMP_FOLDER` / `_TTL_SECONDS` | Staging area for embedded attachments, swept once the TTL passes |

## Tools

| Tool | Verb | Purpose |
| --- | --- | --- |
| `graph_get` | GET | Read any resource; paginate via the returned `next_link` |
| `graph_post` | POST | Create resources, trigger actions |
| `graph_patch` | PATCH | Update in place |
| `graph_delete` | DELETE | Remove (soft-delete to the recycle bin) |
| `graph_batch` | POST | Up to 20 operations in one request |
| `graph_search` | POST | Microsoft Search across SharePoint, OneDrive, Teams, Outlook |
| `graph_create_upload_session` | POST | Returns a pre-authenticated upload URL |
| `graph_download` | GET | Returns a pre-authenticated download URL, or inline base64 |
| `graph_get_attachment_url` | POST | Resolves a mail attachment to a download URL |

## Design

**No business logic.** Adding a Graph capability usually means adding a tool.
Here it means nothing at all: the model already knows the Graph API, so
exposing the verbs exposes all of it. New delegated permissions work with no
code change once admin consents them.

**File bytes never pass through the model.** Uploads return a pre-authenticated
`upload_url` the caller streams to directly, in 320 KiB-multiple fragments with
a `Content-Range` and no `Authorization` header. Downloads and mail attachments
work the same way. Nothing gets base64'd into a tool argument or result, so file
size is bounded by the network and not by a context window.

**Permissions are Microsoft's to enforce, not this server's.** The gateway
validates the user's Entra token and forwards it under
`X-Forwarded-Authorization`, and the server exchanges that for a delegated
Graph token via On-Behalf-Of. A user sees exactly what their own account can
see. No allow-list here to drift out of date, and no service principal quietly
holding more access than the person using it.

**The forwarded assertion is checked for expiry before use.** An expired one
gets a real 401 with a `WWW-Authenticate` challenge instead of a confusing
downstream Graph error, so the client knows to refresh rather than retry.

**Request identity lives in contextvars, set by pure-ASGI middleware.** Not
Starlette's `BaseHTTPMiddleware`, whose task boundary loses the contextvar
before the handler ever reads it. Same reason the MCP SDK's own auth
middleware is pure-ASGI.

## Development

```bash
uv run pytest
uv run ruff check .
uv run mypy src
```

## License

MIT
