"""Standalone entrypoint. Run with: python -m graph_mcp.main

Runs the MCP ASGI app directly under uvicorn (no FastAPI wrapper). Mounting a
Starlette sub-app inside FastAPI silently skips the sub-app's lifespan, which
prevents FastMCP's session-manager task group from starting. Running the app at
the top level lets uvicorn deliver lifespan events through the full middleware
chain as intended.
"""

from __future__ import annotations

import uvicorn
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from graph_mcp.config import get_settings
from graph_mcp.mcp_server import build_mcp_app
from graph_mcp.telemetry import configure_logging, get_logger

log = get_logger(__name__)


def create_app() -> ASGIApp:
    cfg = get_settings()
    configure_logging(cfg.log_level)
    log.info("graph-mcp starting", tenant=cfg.tenant_id, client=cfg.client_id)

    inner = build_mcp_app(
        tenant_id=cfg.tenant_id,
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        scopes=cfg.scope_list(),
        mcp_key=cfg.api_key or None,
        max_concurrent=cfg.max_concurrent,
        default_site_id=cfg.default_site_id,
        default_drive_id=cfg.default_drive_id,
        default_base_path=cfg.default_base_path,
        reject_expired_token=cfg.reject_expired_token,
        token_expiry_skew_seconds=cfg.token_expiry_skew_seconds,
        attachment_temp_folder=cfg.attachment_temp_folder,
        attachment_ttl_seconds=cfg.attachment_ttl_seconds,
    )

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        # Health check bypasses auth and MCP routing.
        # Lifespan / websocket scopes fall straight through to `inner`.
        if scope["type"] == "http" and scope.get("path") == "/health":
            await JSONResponse({"status": "ok", "service": "graph-mcp"})(scope, receive, send)
            return
        await inner(scope, receive, send)

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run("graph_mcp.main:app", host="0.0.0.0", port=8000)
