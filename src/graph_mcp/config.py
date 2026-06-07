from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolve .env relative to this file: src/graph_mcp/ → platform/graph/.env
_ENV_FILE = Path(__file__).parent.parent.parent / ".env"

_DEFAULT_SCOPES = "https://graph.microsoft.com/.default"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GRAPH_",
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        # env vars always take precedence over .env values
        case_sensitive=False,
    )

    log_level: str = "INFO"
    api_key: str = ""

    # The On-Behalf-Of confidential client. This MUST be the Entra resource app
    # that the user token's audience targets, because OBO can only be performed
    # by the audience app itself. The API gateway validates
    # the token and forwards it under X-Forwarded-Authorization; the server
    # exchanges it for a per-user Graph token via OBO. See graph_client.py.
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""

    # Space-separated Graph scopes for the OBO exchange. Default ".default" pulls
    # whatever delegated permissions admin has consented for the app. New
    # permissions (Mail, Calendars, …) work with zero code change.
    scopes: str = _DEFAULT_SCOPES

    # Reject an expired/imminently-expiring forwarded assertion with a real 401 +
    # WWW-Authenticate (so the client refreshes) instead of letting it reach the
    # OBO exchange, where Entra rejects it (AADSTS500133) and the error gets
    # swallowed into a 200. expiry_skew refuses tokens this many seconds early to
    # avoid the assertion dying mid-request.
    reject_expired_token: bool = True
    token_expiry_skew_seconds: int = 60

    # Max parallel Graph API calls (1–2 for sandbox, 4–8 for production).
    max_concurrent: int = 4

    # Optional, NON-SECRET org defaults (the doc's MCP_SITE_ID / MCP_DRIVE_ID /
    # MCP_BASE_PATH). When set, tools substitute {site_id} / {drive_id} /
    # {base_path} placeholders in a path so the model can skip discovery
    # round-trips. Leave empty and it resolves IDs at runtime via graph_get.
    default_site_id: str = ""
    default_drive_id: str = ""
    default_base_path: str = ""

    # graph_get_attachment_url stages embedded mail attachments into this OneDrive
    # folder so the caller can fetch them via a download URL (never base64). Stale
    # staged files are swept lazily on each call once older than the TTL.
    attachment_temp_folder: str = "_mcp-attachments"
    attachment_ttl_seconds: int = 86400  # 1 day

    def scope_list(self) -> list[str]:
        return [s for s in self.scopes.split() if s]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
