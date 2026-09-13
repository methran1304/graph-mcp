"""Per-request user identity, sourced from APIM-forwarded headers.

The server runs behind an API gateway (Azure API Management in the reference
deployment), which validates the Entra
Bearer token and forwards it to this backend under ``X-Forwarded-Authorization``
(the raw ``Authorization`` header is stripped by APIM). For On-Behalf-Of the
Graph client needs that raw token; we stash it in a request-scoped contextvar so
it can be read deep in the call stack without threading it through every tool
signature.

Implemented as a pure-ASGI middleware (not Starlette ``BaseHTTPMiddleware``) so
the contextvar set here survives to the request handler. Same reason the
MCP SDK's own ``AuthContextMiddleware`` is pure-ASGI.
"""

from __future__ import annotations

import base64
import contextvars
import itertools
import json
import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from graph_mcp.telemetry import get_logger

_log = get_logger(__name__)

# Raw user JWT forwarded by APIM (no "Bearer " prefix), or "" if absent.
_user_token: contextvars.ContextVar[str] = contextvars.ContextVar("user_token", default="")
# The APIM-resolved user slug (X-APIM-User), for audit/logging. "" if absent.
_apim_user: contextvars.ContextVar[str] = contextvars.ContextVar("apim_user", default="")
# TEMPORARY: monotonic per-request sequence, set by the middleware and read again
# at the OBO call. If the OBO reads an OLDER seq than the request in flight, the
# tool is running in a stale/frozen context (not the current request's), which is
# where a stale assertion would come from.
_req_seq: contextvars.ContextVar[int] = contextvars.ContextVar("req_seq", default=0)
_req_counter = itertools.count(1)


def get_req_seq() -> int:
    """Current request's sequence number (0 if unset). TEMPORARY diagnostic."""
    return _req_seq.get()


def token_exp(token: str) -> int | None:
    """Public alias of the JWT-exp decoder (used by graph_client diagnostics)."""
    return _token_exp(token)

_FORWARDED_AUTH_HEADER = b"x-forwarded-authorization"
_APIM_USER_HEADER = b"x-apim-user"

# Returned when the forwarded assertion is expired (or about to expire). A real
# HTTP 401 + WWW-Authenticate is what tells an MCP client to silently refresh
# and retry; a swallowed 200 leaves it sending the dead token forever.
# A gateway's outbound policy may upgrade this bare header to the full
# `resource_metadata="…"` form, since the gateway owns the PRM URL.
_EXPIRED_BODY = (
    b'{"error":"invalid_token",'
    b'"error_description":"Access token expired or about to expire; refresh required."}'
)


def _mcp_request_header(name: str) -> str | None:
    """Read a header from the *live* MCP request context.

    The MCP low-level server sets ``request_ctx`` per JSON-RPC message in the task
    that runs the tool, and (for streamable HTTP) attaches the Starlette request.
    Reading the header here gives THIS tool call's value, unlike the ASGI
    contextvars below, which the session-manager task captures once and freezes,
    so a long-lived session would otherwise keep using the first call's token.
    Returns None when no MCP request is in scope (non-HTTP / non-tool path).
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
    except ImportError:
        return None
    try:
        rc = request_ctx.get()
    except LookupError:
        return None
    headers = getattr(getattr(rc, "request", None), "headers", None)
    if headers is None:
        return None
    # Absent (or empty) header means "this request carries nothing", which has to
    # read as None so callers fall through to the ASGI contextvar. Returning ""
    # here made the fallback in get_user_token unreachable whenever any MCP
    # request was in scope, so a request whose forwarded-auth header didn't land
    # on the request object got "" instead of the token the middleware captured.
    value = headers.get(name)
    if value is None or str(value) == "":
        return None
    return str(value)


def get_user_token() -> str:
    """Return the current request's forwarded user token, or "" if none.

    Prefers the per-call MCP request context (correct across the FastMCP
    session-task boundary); falls back to the ASGI contextvar set by
    UserContextMiddleware when no MCP request is in scope.
    """
    raw = _mcp_request_header("x-forwarded-authorization")
    if raw is not None:
        return _strip_bearer(raw)
    return _user_token.get()


def get_apim_user() -> str:
    """Return the current request's APIM user slug, or "" if none (per-call)."""
    val = _mcp_request_header("x-apim-user")
    if val is not None:
        return val
    return _apim_user.get()


def user_token_source() -> str:
    """TEMPORARY diagnostic: where get_user_token() sourced this call's token."""
    return "mcp_request" if _mcp_request_header("x-forwarded-authorization") is not None else "asgi_fallback"


def _strip_bearer(value: str) -> str:
    return value[7:].strip() if value[:7].lower() == "bearer " else value.strip()


def _token_exp(token: str) -> int | None:
    """Read a JWT's ``exp`` (epoch seconds) WITHOUT verifying the signature.

    APIM has already validated the token's signature, audience and scope before
    forwarding it; here we only need ``exp`` to decide whether the assertion is
    still within range for the downstream On-Behalf-Of exchange (which Entra
    enforces with zero skew). Returns ``None`` if the token can't be parsed or
    carries no ``exp``, in which case the caller lets it through unchanged.
    """
    try:
        payload_b64 = token.split(".")[1]
        padding = "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        exp = claims.get("exp")
    except (IndexError, ValueError, TypeError):
        return None
    return int(exp) if isinstance(exp, (int, float)) else None


def _jose_header(token: str) -> object:
    """Decode the JOSE header (segment 0). 3 segments + {alg,typ} = signed JWS
    (readable payload); 5 segments + {alg,enc} = encrypted JWE (payload is a
    binary key, so ``exp`` can't be read). Non-sensitive (no PII)."""
    try:
        h = token.split(".", 1)[0]
        h += "=" * (-len(h) % 4)
        return json.loads(base64.urlsafe_b64decode(h))
    except (IndexError, ValueError, TypeError):
        return "<undecodable>"


_DBG_APIM_NOW = b"x-dbg-apim-now"
_DBG_TOKEN_EXP = b"x-dbg-token-exp"
_DBG_EXP_GATE = b"x-dbg-expgate"


def _log_token_diag(
    token: str,
    headers: dict[bytes, bytes],
    *,
    reject_enabled: bool,
    skew_seconds: int,
    is_expired: bool,
) -> None:
    """TEMPORARY decision-level diagnostic (testing phase): record every clock
    and decision so we can prove, without assumption, where an expired token
    slips through. Logs token shape and timings only, never the raw token.

    APIM stamps its own view (X-Dbg-*) so one line correlates APIM-eval-time,
    token exp, and the backend's own clock + guard decision."""
    exp = _token_exp(token)
    now = int(time.time())
    _log.info(
        "obo_token_diag",
        req_seq=_req_seq.get(),
        seg_count=len(token.split(".")),
        jose_header=_jose_header(token),
        exp=exp,
        exp_readable=exp is not None,
        backend_now=now,
        secs_to_exp=(exp - now) if exp is not None else None,
        is_expired=is_expired,
        reject_enabled=reject_enabled,
        skew_seconds=skew_seconds,
        will_reject=reject_enabled and is_expired,
        apim_now=headers.get(_DBG_APIM_NOW, b"").decode("latin-1"),
        apim_token_exp=headers.get(_DBG_TOKEN_EXP, b"").decode("latin-1"),
        apim_expgate=headers.get(_DBG_EXP_GATE, b"").decode("latin-1"),
        token_len=len(token),
    )


def _is_expired(token: str, skew_seconds: int) -> bool:
    """True if the token is expired or within ``skew_seconds`` of expiry.

    A positive skew refuses imminently-expiring tokens early so the assertion
    can't die mid-request (between this check and the OBO call). Unparseable
    tokens and tokens without ``exp`` are treated as not-expired (let through,
    APIM already validated them)."""
    exp = _token_exp(token)
    if exp is None:
        return False
    return exp <= time.time() + skew_seconds


async def _send_401_expired(send: Send) -> None:
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"www-authenticate", b'Bearer error="invalid_token"'),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_EXPIRED_BODY)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": _EXPIRED_BODY})


class UserContextMiddleware:
    """Read APIM-forwarded identity headers into request-scoped contextvars.

    Also rejects an expired (or imminently-expiring) forwarded assertion with a
    real HTTP 401 + WWW-Authenticate before the request reaches the MCP handler,
    so the client refreshes instead of receiving a swallowed 200. Set
    ``reject_expired_token=False`` to disable.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        reject_expired_token: bool = True,
        expiry_skew_seconds: int = 60,
    ) -> None:
        self.app = app
        self._reject_expired_token = reject_expired_token
        self._expiry_skew_seconds = expiry_skew_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_auth = headers.get(_FORWARDED_AUTH_HEADER, b"").decode("latin-1")
        apim_user = headers.get(_APIM_USER_HEADER, b"").decode("latin-1")
        token = _strip_bearer(raw_auth)

        # Set the per-request context up front so the diag and the downstream
        # OBO call read THIS request's seq/token, not the last one's.
        tok_reset = _user_token.set(token)
        usr_reset = _apim_user.set(apim_user)
        seq_reset = _req_seq.set(next(_req_counter))  # TEMPORARY diagnostic
        try:
            expired = bool(token) and _is_expired(token, self._expiry_skew_seconds)
            if token:
                _log_token_diag(  # TODO: drop once the stale-token thing is settled
                    token,
                    headers,
                    reject_enabled=self._reject_expired_token,
                    skew_seconds=self._expiry_skew_seconds,
                    is_expired=expired,
                )

            if self._reject_expired_token and expired:
                await _send_401_expired(send)
                return

            await self.app(scope, receive, send)
        finally:
            _user_token.reset(tok_reset)
            _apim_user.reset(usr_reset)
            _req_seq.reset(seq_reset)


# Substrings of the AuthError messages graph_client raises when the On-Behalf-Of
# exchange fails for an auth reason (see graph_client.py). A tool swallows these
# into an HTTP 200 {ok:false}; the rewrite middleware turns that into a 401.
_OBO_AUTH_MARKERS = (
    b"AADSTS500133",                        # assertion not within valid time range
    b"On-Behalf-Of token exchange failed",  # generic OBO failure
    b"No user token on this request",       # assertion missing entirely
)
_REWRITE_401_BODY = (
    b'{"error":"invalid_token",'
    b'"error_description":"On-Behalf-Of exchange rejected the forwarded assertion; refresh required."}'
)
# OBO error envelopes are tiny; stop buffering past this so large/streamed tool
# responses (e.g. inline downloads) are never held in memory.
_REWRITE_SCAN_LIMIT = 64 * 1024


class OboAuthRewriteMiddleware:
    """Convert a *swallowed* On-Behalf-Of auth failure into a real 401.

    The expiry pre-check in :class:`UserContextMiddleware` catches tokens that are
    already expired at request time, but it cannot catch a token that is valid at
    check time yet rejected by Entra when the OBO call actually runs (the tool
    returns the AADSTS error as HTTP 200 ``{ok:false}``). This middleware buffers a
    POST response, and if the body carries an OBO auth-error marker on a 200, it
    rewrites the response to ``401 + WWW-Authenticate`` so the MCP client refreshes
    and retries instead of surfacing a dead-token error to the user.

    Pure-ASGI; only POSTs are inspected (the GET event stream is never buffered),
    and buffering stops after a small cap so large tool payloads pass straight
    through.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        start: Message | None = None
        buffered: list[Message] = []
        body = bytearray()
        state = {"buffering": True, "rewritten": False}

        async def wrapped_send(message: Message) -> None:
            if state["rewritten"]:
                return  # already replaced with a 401, drop the original tail
            if not state["buffering"]:
                await send(message)
                return

            mtype = message["type"]
            if mtype == "http.response.start":
                # Only candidate for rewrite is a 200; otherwise stop buffering.
                if message["status"] != 200:
                    state["buffering"] = False
                    await send(message)
                    return
                nonlocal start
                start = message
                return

            if mtype == "http.response.body":
                body.extend(message.get("body", b""))
                buffered.append(message)
                more = message.get("more_body", False)
                if more and len(body) <= _REWRITE_SCAN_LIMIT:
                    return  # keep buffering until complete (or cap)

                if any(m in bytes(body) for m in _OBO_AUTH_MARKERS):
                    _log.info("obo_auth_rewrite_401", body_len=len(body))
                    await _send_401_rewrite(send)
                    state["rewritten"] = True
                    state["buffering"] = False
                    return

                # Not an OBO error, or over the cap. Flush what we held, verbatim.
                state["buffering"] = False
                if start is not None:
                    await send(start)
                for m in buffered:
                    await send(m)
                return

            await send(message)

        await self.app(scope, receive, wrapped_send)


async def _send_401_rewrite(send: Send) -> None:
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"www-authenticate", b'Bearer error="invalid_token"'),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_REWRITE_401_BODY)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": _REWRITE_401_BODY})
