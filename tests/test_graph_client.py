from __future__ import annotations

import httpx
import pytest
import respx

from graph_mcp.graph_client import AuthError, GraphClient


def _client(monkeypatch, **kwargs) -> GraphClient:
    c = GraphClient(
        "tenant", "client", "secret",
        scopes=["https://graph.microsoft.com/.default"],
        **kwargs,
    )
    # Bypass MSAL/OBO, covered separately in test_obo_no_token_raises.
    monkeypatch.setattr(c, "_graph_token_obo", lambda: "test-token")
    return c


# ---- path resolution -------------------------------------------------------

def test_resolve_path_relative(monkeypatch) -> None:
    c = _client(monkeypatch)
    assert c.resolve_path("/me/drive") == "https://graph.microsoft.com/v1.0/me/drive"
    assert c.resolve_path("me/drive") == "https://graph.microsoft.com/v1.0/me/drive"
    assert c.resolve_path("/me", api_version="beta") == "https://graph.microsoft.com/beta/me"


def test_resolve_path_absolute_passthrough(monkeypatch) -> None:
    c = _client(monkeypatch)
    url = "https://graph.microsoft.com/v1.0/sites?$top=1"
    assert c.resolve_path(url) == url


def test_placeholder_substitution(monkeypatch) -> None:
    c = _client(monkeypatch, default_site_id="SID", default_drive_id="DID", default_base_path="/Docs")
    out = c.resolve_path("/sites/{site_id}/drives/{drive_id}/root:{base_path}/x")
    assert out == "https://graph.microsoft.com/v1.0/sites/SID/drives/DID/root:/Docs/x"


def test_placeholder_unset_raises(monkeypatch) -> None:
    c = _client(monkeypatch)
    with pytest.raises(ValueError, match="GRAPH_DEFAULT_SITE_ID"):
        c.resolve_path("/sites/{site_id}/drives")


# ---- verb passthrough ------------------------------------------------------

@respx.mock
async def test_request_get(monkeypatch) -> None:
    c = _client(monkeypatch)
    route = respx.get("https://graph.microsoft.com/v1.0/me").mock(
        return_value=httpx.Response(200, json={"id": "u1"})
    )
    out = await c.request("GET", "/me")
    assert out["status_code"] == 200
    assert out["json"]["id"] == "u1"
    # OBO token is injected into the Authorization header.
    assert route.calls.last.request.headers["authorization"] == "Bearer test-token"


@respx.mock
async def test_request_surfaces_error_body(monkeypatch) -> None:
    c = _client(monkeypatch)
    respx.get("https://graph.microsoft.com/v1.0/me/messages").mock(
        return_value=httpx.Response(403, json={"error": {"code": "AccessDenied"}})
    )
    out = await c.request("GET", "/me/messages")
    assert out["status_code"] == 403
    assert out["json"]["error"]["code"] == "AccessDenied"


@respx.mock
async def test_request_retries_on_429(monkeypatch) -> None:
    c = _client(monkeypatch)
    route = respx.get("https://graph.microsoft.com/v1.0/me").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"ok": 1}),
        ]
    )
    out = await c.request("GET", "/me")
    assert out["status_code"] == 200
    assert route.call_count == 2


@respx.mock
async def test_next_link_surfaced(monkeypatch) -> None:
    c = _client(monkeypatch)
    respx.get("https://graph.microsoft.com/v1.0/me/messages").mock(
        return_value=httpx.Response(200, json={"value": [], "@odata.nextLink": "https://next"})
    )
    out = await c.request("GET", "/me/messages")
    assert out["next_link"] == "https://next"


# ---- download --------------------------------------------------------------

@respx.mock
async def test_download_url(monkeypatch) -> None:
    c = _client(monkeypatch)
    route = respx.get("https://graph.microsoft.com/v1.0/drives/d/items/x").mock(
        return_value=httpx.Response(200, json={"@microsoft.graph.downloadUrl": "https://dl"})
    )
    out = await c.download_url("/drives/d/items/x/content")  # /content stripped
    assert out["json"]["@microsoft.graph.downloadUrl"] == "https://dl"
    assert route.calls.last.request.url.params["$select"].endswith("downloadUrl")


# ---- batch + auth ----------------------------------------------------------

async def test_batch_limit(monkeypatch) -> None:
    c = _client(monkeypatch)
    with pytest.raises(ValueError, match="at most 20"):
        await c.batch([{"id": str(i), "method": "GET", "url": "/me"} for i in range(21)])


def test_obo_no_token_raises() -> None:
    # No user token in the request context → AuthError before any MSAL call.
    c = GraphClient("t", "c", "s", scopes=["x"])
    with pytest.raises(AuthError):
        c._graph_token_obo()


# ---- upload session --------------------------------------------------------

@respx.mock
async def test_create_upload_session(monkeypatch) -> None:
    c = _client(monkeypatch)
    respx.post(
        "https://graph.microsoft.com/v1.0/drives/d/items/x/createUploadSession"
    ).mock(return_value=httpx.Response(200, json={"uploadUrl": "https://up.example/sess"}))
    url = await c.create_upload_session("/drives/d/items/x/content")
    assert url == "https://up.example/sess"


# ---- mail attachments → download url ---------------------------------------

@respx.mock
async def test_attachment_reference_resolves_link(monkeypatch) -> None:
    c = _client(monkeypatch)
    att = "https://graph.microsoft.com/v1.0/me/messages/M1/attachments/A1"
    respx.get(att, params={"$select": "id,name,size,contentType,isInline"}).mock(
        return_value=httpx.Response(200, json={
            "@odata.type": "#microsoft.graph.referenceAttachment",
            "name": "doc.docx", "size": 1234, "contentType": "application/vnd…",
        })
    )
    respx.get(att, params={"$select": "sourceUrl"}).mock(
        return_value=httpx.Response(200, json={"sourceUrl": "https://x.sharepoint.com/y"})
    )
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/shares/").mock(
        return_value=httpx.Response(200, json={"@microsoft.graph.downloadUrl": "https://dl/ref"})
    )
    out = await c.attachment_download_url("M1", "A1")
    assert out["type"] == "reference"
    assert out["staged"] is False
    assert out["download_url"] == "https://dl/ref"


@respx.mock
async def test_attachment_file_stages_to_onedrive(monkeypatch) -> None:
    c = _client(monkeypatch)
    att = "https://graph.microsoft.com/v1.0/me/messages/M1/attachments/A2"
    respx.get(att, params={"$select": "id,name,size,contentType,isInline"}).mock(
        return_value=httpx.Response(200, json={
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "big.pdf", "size": 9_000_000, "contentType": "application/pdf",
        })
    )
    # sweep: temp folder listing (empty)
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/me/drive/root:/_mcp-attachments:/children").mock(
        return_value=httpx.Response(200, json={"value": []})
    )
    # ensure folder (already exists → 409, tolerated)
    respx.post("https://graph.microsoft.com/v1.0/me/drive/root/children").mock(
        return_value=httpx.Response(409, json={"error": {"code": "nameAlreadyExists"}})
    )
    # $value raw bytes
    respx.get(f"{att}/$value").mock(return_value=httpx.Response(200, content=b"PDFBYTES"))
    # PUT to OneDrive temp folder
    respx.put(url__startswith="https://graph.microsoft.com/v1.0/me/drive/root:/_mcp-attachments/big.pdf:/content").mock(
        return_value=httpx.Response(201, json={"id": "drv99"})
    )
    # downloadUrl lookup
    respx.get("https://graph.microsoft.com/v1.0/me/drive/items/drv99").mock(
        return_value=httpx.Response(200, json={"@microsoft.graph.downloadUrl": "https://dl/staged"})
    )
    out = await c.attachment_download_url("M1", "A2")
    assert out["type"] == "file"
    assert out["staged"] is True
    assert out["download_url"] == "https://dl/staged"
    assert out["drive_item_id"] == "drv99"


@respx.mock
async def test_attachment_sweep_deletes_stale(monkeypatch) -> None:
    c = _client(monkeypatch, attachment_ttl_seconds=3600)
    old = "2000-01-01T00:00:00Z"  # well past TTL
    new = "2999-01-01T00:00:00Z"  # future → keep
    respx.get(url__startswith="https://graph.microsoft.com/v1.0/me/drive/root:/_mcp-attachments:/children").mock(
        return_value=httpx.Response(200, json={"value": [
            {"id": "old1", "name": "a", "createdDateTime": old},
            {"id": "new1", "name": "b", "createdDateTime": new},
        ]})
    )
    deleted = respx.delete("https://graph.microsoft.com/v1.0/me/drive/items/old1").mock(
        return_value=httpx.Response(204)
    )
    await c._sweep_temp_folder(api_version="v1.0")
    assert deleted.called
