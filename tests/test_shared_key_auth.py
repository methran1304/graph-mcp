from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from graph_mcp.mcp_server import build_mcp_app


@pytest.fixture
def authed_app():
    return build_mcp_app(mcp_key="supersecret")


@pytest.fixture
def open_app():
    return build_mcp_app(mcp_key=None)


def test_correct_key_passes(authed_app) -> None:
    client = TestClient(authed_app, raise_server_exceptions=False)
    resp = client.get("/", headers={"X-API-Key": "supersecret"})
    assert resp.status_code != 401


def test_wrong_key_rejected(authed_app) -> None:
    client = TestClient(authed_app, raise_server_exceptions=False)
    resp = client.get("/", headers={"X-API-Key": "wrongkey"})
    assert resp.status_code == 401


def test_missing_key_rejected(authed_app) -> None:
    client = TestClient(authed_app, raise_server_exceptions=False)
    resp = client.get("/")
    assert resp.status_code == 401


async def test_non_ascii_key_rejected_at_middleware() -> None:
    # httpx blocks non-ASCII header values before they reach the network, so
    # test the middleware dispatch directly with a raw latin-1 header value.
    from unittest.mock import AsyncMock, MagicMock

    from starlette.requests import Request

    from graph_mcp.mcp_server import _SharedKeyAuthMiddleware

    middleware = _SharedKeyAuthMiddleware(MagicMock(), "supersecret")

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-api-key", "café".encode("latin-1"))],
        "query_string": b"",
    }
    request = Request(scope)
    call_next = AsyncMock()

    response = await middleware.dispatch(request, call_next)
    assert response.status_code == 401
    call_next.assert_not_called()


def test_no_auth_middleware_when_key_is_none(open_app) -> None:
    client = TestClient(open_app, raise_server_exceptions=False)
    resp = client.get("/")
    assert resp.status_code != 401
