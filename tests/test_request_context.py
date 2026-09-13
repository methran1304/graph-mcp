"""UserContextMiddleware extracts the APIM-forwarded token into a contextvar
and rejects expired assertions with a 401 before they reach the MCP handler."""

from __future__ import annotations

import base64
import json
import time

from graph_mcp.request_context import (
    OboAuthRewriteMiddleware,
    UserContextMiddleware,
    _user_token,
    get_apim_user,
    get_user_token,
    user_token_source,
)


def _scope(headers: list[tuple[bytes, bytes]], method: str = "POST") -> dict:
    return {"type": "http", "method": method, "path": "/mcp", "headers": headers, "query_string": b""}


def _json_rpc_app(body: bytes):
    """A fake inner ASGI app that returns `body` as a 200 (mimics a tool result)."""

    async def app(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    return app


async def _drain(receive) -> None:  # minimal ASGI receive/send stubs
    return None


def _jwt(exp: int) -> str:
    """Build an unsigned JWT carrying only an `exp` claim (signature ignored)."""
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).rstrip(b"=").decode()
    return f"header.{payload}.sig"


def _capture_send() -> tuple[list[dict], object]:
    messages: list[dict] = []

    async def send(message: dict) -> None:
        messages.append(message)

    return messages, send


async def test_forwarded_token_and_user_are_captured() -> None:
    captured: dict[str, str] = {}

    async def inner(scope, receive, send) -> None:
        captured["token"] = get_user_token()
        captured["user"] = get_apim_user()

    mw = UserContextMiddleware(inner)
    scope = _scope([
        (b"x-forwarded-authorization", b"Bearer the-user-jwt"),
        (b"x-apim-user", b"alex"),
    ])
    await mw(scope, _drain, None)

    assert captured["token"] == "the-user-jwt"  # "Bearer " stripped
    assert captured["user"] == "alex"


async def test_missing_headers_yield_empty() -> None:
    captured: dict[str, str] = {}

    async def inner(scope, receive, send) -> None:
        captured["token"] = get_user_token()

    await UserContextMiddleware(inner)(_scope([]), _drain, None)
    assert captured["token"] == ""


async def test_contextvar_reset_after_request() -> None:
    async def inner(scope, receive, send) -> None:
        assert get_user_token() == "abc"

    await UserContextMiddleware(inner)(
        _scope([(b"x-forwarded-authorization", b"abc")]), _drain, None
    )
    # After the request completes the contextvar is reset to its default.
    assert get_user_token() == ""


async def test_expired_token_returns_401_without_calling_app() -> None:
    called = False

    async def inner(scope, receive, send) -> None:
        nonlocal called
        called = True

    messages, send = _capture_send()
    expired = _jwt(int(time.time()) - 100)
    await UserContextMiddleware(inner)(
        _scope([(b"x-forwarded-authorization", f"Bearer {expired}".encode())]), _drain, send
    )

    assert called is False  # short-circuited before the MCP handler
    start = next(m for m in messages if m["type"] == "http.response.start")
    assert start["status"] == 401
    headers = dict(start["headers"])
    assert headers[b"www-authenticate"].startswith(b"Bearer")


async def test_near_expiry_token_refused_by_skew() -> None:
    called = False

    async def inner(scope, receive, send) -> None:
        nonlocal called
        called = True

    messages, send = _capture_send()
    # Valid for another 30s, but the 60s skew refuses it early.
    soon = _jwt(int(time.time()) + 30)
    await UserContextMiddleware(inner, expiry_skew_seconds=60)(
        _scope([(b"x-forwarded-authorization", f"Bearer {soon}".encode())]), _drain, send
    )

    assert called is False
    assert next(m for m in messages if m["type"] == "http.response.start")["status"] == 401


async def test_valid_token_passes_through() -> None:
    captured: dict[str, str] = {}

    async def inner(scope, receive, send) -> None:
        captured["token"] = get_user_token()

    valid = _jwt(int(time.time()) + 3600)
    messages, send = _capture_send()
    await UserContextMiddleware(inner)(
        _scope([(b"x-forwarded-authorization", f"Bearer {valid}".encode())]), _drain, send
    )

    assert captured["token"] == valid
    assert messages == []  # nothing sent by the middleware itself


async def test_unparseable_token_passes_through() -> None:
    captured: dict[str, str] = {}

    async def inner(scope, receive, send) -> None:
        captured["token"] = get_user_token()

    messages, send = _capture_send()
    # Not a JWT / no readable exp → let it through (APIM already validated it).
    await UserContextMiddleware(inner)(
        _scope([(b"x-forwarded-authorization", b"Bearer not-a-jwt")]), _drain, send
    )

    assert captured["token"] == "not-a-jwt"
    assert messages == []


async def test_disabled_guard_lets_expired_token_through() -> None:
    captured: dict[str, str] = {}

    async def inner(scope, receive, send) -> None:
        captured["token"] = get_user_token()

    expired = _jwt(int(time.time()) - 100)
    messages, send = _capture_send()
    await UserContextMiddleware(inner, reject_expired_token=False)(
        _scope([(b"x-forwarded-authorization", f"Bearer {expired}".encode())]), _drain, send
    )

    assert captured["token"] == expired
    assert messages == []


# --- OboAuthRewriteMiddleware: swallowed OBO auth error -> real 401 ---

async def test_rewrite_swallowed_obo_error_to_401() -> None:
    # A tool swallowed an expired-assertion OBO failure into HTTP 200 {ok:false}.
    body = b'{"ok": false, "error": "On-Behalf-Of token exchange failed: AADSTS500133: ..."}'
    messages, send = _capture_send()
    await OboAuthRewriteMiddleware(_json_rpc_app(body))(_scope([]), _drain, send)

    start = next(m for m in messages if m["type"] == "http.response.start")
    assert start["status"] == 401
    assert dict(start["headers"])[b"www-authenticate"].startswith(b"Bearer")
    # original 200 body must not leak through
    sent_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    assert b"AADSTS500133" not in sent_body
    assert b"invalid_token" in sent_body


async def test_rewrite_passes_through_ok_response() -> None:
    body = b'{"ok": true, "json": {"value": []}}'
    messages, send = _capture_send()
    await OboAuthRewriteMiddleware(_json_rpc_app(body))(_scope([]), _drain, send)

    assert next(m for m in messages if m["type"] == "http.response.start")["status"] == 200
    sent_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    assert sent_body == body


async def test_rewrite_ignores_non_post() -> None:
    # The GET event-stream must never be buffered/rewritten.
    body = b'{"ok": false, "error": "AADSTS500133"}'
    messages, send = _capture_send()
    await OboAuthRewriteMiddleware(_json_rpc_app(body))(_scope([], method="GET"), _drain, send)

    assert next(m for m in messages if m["type"] == "http.response.start")["status"] == 200
    sent_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    assert sent_body == body


# --- get_user_token sources from the live MCP request (fix for the frozen ASGI ctx) ---

async def test_get_user_token_prefers_live_mcp_request_header() -> None:
    import types

    from mcp.server.lowlevel.server import request_ctx

    fake_rc = types.SimpleNamespace(
        request=types.SimpleNamespace(
            headers={"x-forwarded-authorization": "Bearer per-call-token"},
        ),
    )
    # ASGI contextvar holds a STALE token; the live MCP request must win.
    stale = _user_token.set("stale-frozen-token")
    rc = request_ctx.set(fake_rc)  # type: ignore[arg-type]
    try:
        assert get_user_token() == "per-call-token"
        assert user_token_source() == "mcp_request"
    finally:
        request_ctx.reset(rc)
        _user_token.reset(stale)


async def test_get_user_token_falls_back_to_asgi_ctx_when_no_mcp_request() -> None:
    reset = _user_token.set("asgi-token")
    try:
        assert get_user_token() == "asgi-token"   # no MCP request in scope
        assert user_token_source() == "asgi_fallback"
    finally:
        _user_token.reset(reset)


async def test_get_user_token_falls_back_when_mcp_request_lacks_the_header() -> None:
    """An MCP request whose headers don't carry the forwarded auth must still
    fall back to the ASGI contextvar.

    This used to return "" instead: _mcp_request_header handed back "" for a
    missing key, and get_user_token only fell through on None, so the fallback
    was unreachable whenever any MCP request was in scope. The OBO exchange then
    failed with "no user token" while the middleware one layer up had it.
    """
    import types

    from mcp.server.lowlevel.server import request_ctx

    fake_rc = types.SimpleNamespace(
        request=types.SimpleNamespace(headers={"x-apim-user": "alex"}),
    )
    captured = _user_token.set("token-from-asgi-middleware")
    rc = request_ctx.set(fake_rc)  # type: ignore[arg-type]
    try:
        assert get_user_token() == "token-from-asgi-middleware"
        assert user_token_source() == "asgi_fallback"
    finally:
        request_ctx.reset(rc)
        _user_token.reset(captured)


async def test_get_user_token_falls_back_on_an_empty_header_value() -> None:
    """An explicitly empty header is as useless as a missing one."""
    import types

    from mcp.server.lowlevel.server import request_ctx

    fake_rc = types.SimpleNamespace(
        request=types.SimpleNamespace(headers={"x-forwarded-authorization": ""}),
    )
    captured = _user_token.set("token-from-asgi-middleware")
    rc = request_ctx.set(fake_rc)  # type: ignore[arg-type]
    try:
        assert get_user_token() == "token-from-asgi-middleware"
    finally:
        request_ctx.reset(rc)
        _user_token.reset(captured)
