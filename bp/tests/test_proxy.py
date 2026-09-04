"""bp proxy: the server's NESTED ProxyEntry is flattened to a clean display row.

Contract reconciliation — the Python model now mirrors the Kotlin nested shape
(request/response), and the list view projects id/method/url/status for the table.
"""

from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from bp.cli import _proxy_rows, app
from bp.client import BurpClient
from bp.commands.proxynav import _proxy_entry_display, _websocket_rows
from bp.models import HttpRequestData, ProxyEntry, ProxyHistory, WebSocketEntry


def test_proxy_entry_model_is_nested() -> None:
    pe = ProxyEntry.model_validate(
        {
            "id": 5,
            "request": {"method": "GET", "url": "http://h/p"},
            "response": {"statusCode": 404},
        }
    )
    assert pe.request is not None and pe.request.method == "GET"
    assert pe.response is not None and pe.response.statusCode == 404


def test_http_request_model_preserves_all_three_body_states() -> None:
    absent = HttpRequestData.model_validate({"method": "GET", "url": "https://t"})
    explicit_empty = HttpRequestData.model_validate(
        {"method": "POST", "url": "https://t", "bodyBase64": ""}
    )
    binary = HttpRequestData.model_validate(
        {"method": "POST", "url": "https://t", "body": "fallback", "bodyBase64": "/w=="}
    )

    assert absent.body is None and absent.bodyBase64 is None
    assert explicit_empty.bodyBase64 == ""
    assert explicit_empty.model_dump()["bodyBase64"] == ""
    assert binary.body == "fallback" and binary.bodyBase64 == "/w=="


def test_websocket_nullable_server_fields_validate() -> None:
    entry = WebSocketEntry.model_validate(
        {
            "id": 1,
            "webSocketId": 1,
            "url": None,
            "direction": None,
            "payload": None,
            "payloadBase64": None,
            "editedPayloadBase64": None,
        }
    )
    assert entry.url is None
    assert entry.direction is None
    assert entry.payload is None
    assert entry.payloadBase64 is None
    assert entry.editedPayloadBase64 is None


def test_websocket_rows_preserve_null_projections() -> None:
    rows = _websocket_rows(
        {
            "total": 1,
            "entries": [
                {
                    "id": 1,
                    "webSocketId": 9,
                    "url": None,
                    "direction": None,
                    "payload": None,
                    "payloadBase64": None,
                    "editedPayloadBase64": None,
                }
            ],
        }
    )
    assert len(rows) == 1
    assert rows[0]["webSocketId"] == 9
    assert rows[0]["url"] is None
    assert rows[0]["payloadBase64"] is None


def test_req_raw_cli_writes_http_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    data = {
        "id": 1,
        "request": {"method": "GET", "url": "https://example.test/a", "headers": []},
        "response": {"statusCode": 200, "headers": [], "body": "ok"},
    }

    monkeypatch.setenv("BP_NO_LEDGER", "1")
    monkeypatch.setattr(BurpClient, "get", lambda _self, _path, **_params: data)
    result = CliRunner().invoke(app, ["--format", "raw", "req", "1"])

    assert result.exit_code == 0, result.stderr
    assert result.stdout_bytes.startswith(b"GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n")
    assert result.stdout_bytes.endswith(b"HTTP/1.1 200 OK\r\n\r\nok")


def test_proxy_rows_flattens_nested_entry() -> None:
    entries = [
        {
            "id": 1,
            "request": {"method": "GET", "url": "http://x/a"},
            "response": {"statusCode": 200},
        }
    ]
    assert _proxy_rows(entries) == [{"id": 1, "method": "GET", "url": "http://x/a", "status": 200}]


def test_proxy_rows_handles_missing_response() -> None:
    rows = _proxy_rows([{"id": 2, "request": {"method": "POST", "url": "http://x/b"}}])
    assert rows == [{"id": 2, "method": "POST", "url": "http://x/b", "status": None}]


def test_proxy_rows_empty() -> None:
    assert _proxy_rows([]) == []


# --- RED contract-drift tests (Kotlin ProxyModels.kt: id=Int, request=HttpRequestData both non-null) ---


def test_proxy_entry_id_is_required() -> None:
    """Kotlin: val id: Int  (non-nullable, no default) — omitting must raise ValidationError."""
    with pytest.raises(ValidationError):
        ProxyEntry.model_validate({"request": {"method": "GET", "url": "http://h/p"}})


def test_proxy_entry_request_is_required() -> None:
    """Kotlin: val request: HttpRequestData  (non-nullable, no default) — omitting must raise ValidationError."""
    with pytest.raises(ValidationError):
        ProxyEntry.model_validate({"id": 1})


def test_proxy_entry_response_is_optional() -> None:
    """Kotlin: val response: HttpResponseData? = null  (nullable with default) — must validate without it."""
    pe = ProxyEntry.model_validate({"id": 3, "request": {"method": "DELETE", "url": "http://h/r"}})
    assert pe.id == 3
    assert pe.response is None


# ---------------------------------------------------------------------------
# RED — AX-CAP-BODY: bp req <id> must NOT leak response body/headers/secrets
# ---------------------------------------------------------------------------

_FAKE_ENTRY_WITH_SECRET: dict[str, Any] = {
    "id": 42,
    "request": {
        "method": "POST",
        "url": "https://api.example.com/login",
        "headers": [{"name": "Authorization", "value": "Bearer JWT_SECRET_TOKEN"}],
        "body": "username=admin&password=hunter2",
    },
    "response": {
        "statusCode": 200,
        "headers": [{"name": "Set-Cookie", "value": "session=TOP_SECRET_COOKIE; HttpOnly"}],
        "body": '{"token":"SUPER_SECRET_JWT","ssn":"123-45-6789"}',
    },
    "timestamp": "2026-06-19T00:00:00Z",
    "listenerInterface": "8080",
    "clientIp": "127.0.0.1",
}


def test_req_display_contains_core_fields() -> None:
    """bp req default output MUST include id, method, url, status (AX-CAP-BODY safe fields)."""
    result = _proxy_entry_display(_FAKE_ENTRY_WITH_SECRET)
    assert result["id"] == 42
    assert result["method"] == "POST"
    assert result["url"] == "https://api.example.com/login"
    assert result["status"] == 200


def test_req_display_suppresses_response_body() -> None:
    """bp req default output MUST NOT contain the response body (PII/secret leak prevention)."""
    result = _proxy_entry_display(_FAKE_ENTRY_WITH_SECRET)
    result_str = str(result)
    assert "SUPER_SECRET_JWT" not in result_str
    assert "123-45-6789" not in result_str
    # No response body key at all
    assert "body" not in result


def test_req_display_suppresses_response_headers() -> None:
    """bp req default output MUST NOT contain response header blobs (cookie/JWT leak prevention)."""
    result = _proxy_entry_display(_FAKE_ENTRY_WITH_SECRET)
    result_str = str(result)
    assert "TOP_SECRET_COOKIE" not in result_str
    assert "Set-Cookie" not in result_str
    # No nested headers key
    assert "headers" not in result


def test_req_display_suppresses_request_body() -> None:
    """bp req default output MUST NOT contain the request body (credential leak prevention)."""
    result = _proxy_entry_display(_FAKE_ENTRY_WITH_SECRET)
    result_str = str(result)
    assert "hunter2" not in result_str
    assert "password" not in result_str


def test_req_display_suppresses_request_headers() -> None:
    """bp req default output MUST NOT contain request header blobs (Bearer token leak prevention)."""
    result = _proxy_entry_display(_FAKE_ENTRY_WITH_SECRET)
    result_str = str(result)
    assert "JWT_SECRET_TOKEN" not in result_str
    assert "Authorization" not in result_str


def test_req_display_consistent_with_proxy_rows() -> None:
    """_proxy_entry_display and _proxy_rows must produce the same id/method/url/status values."""
    list_rows = _proxy_rows([_FAKE_ENTRY_WITH_SECRET])
    single = _proxy_entry_display(_FAKE_ENTRY_WITH_SECRET)
    assert single["id"] == list_rows[0]["id"]
    assert single["method"] == list_rows[0]["method"]
    assert single["url"] == list_rows[0]["url"]
    assert single["status"] == list_rows[0]["status"]


def test_req_display_no_response_entry() -> None:
    """_proxy_entry_display handles missing response gracefully (status=None)."""
    entry: dict[str, Any] = {"id": 7, "request": {"method": "GET", "url": "http://h/p"}}
    result = _proxy_entry_display(entry)
    assert result["status"] is None
    assert result["id"] == 7


# ---------------------------------------------------------------------------
# [12] ProxyHistory.entries required — no spurious [] default
# Kotlin ProxyHistoryResponse.entries: List<ProxyEntry>  (non-nullable, no default)
# ---------------------------------------------------------------------------


def test_proxy_history_missing_entries_raises_validation_error() -> None:
    """[12] entries is non-nullable/no-default in Kotlin ProxyHistoryResponse —
    a payload missing 'entries' must raise pydantic.ValidationError, not silently
    yield an empty list.
    """
    with pytest.raises(ValidationError):
        ProxyHistory.model_validate({"total": 0})


def test_proxy_history_complete_payload_validates() -> None:
    """[12] A complete ProxyHistory payload including entries must still validate."""
    ph = ProxyHistory.model_validate(
        {
            "total": 1,
            "entries": [{"id": 1, "request": {"method": "GET", "url": "http://h/p"}}],
        }
    )
    assert ph.total == 1
    assert len(ph.entries) == 1
    assert ph.entries[0].id == 1


def test_proxy_history_empty_entries_list_is_valid() -> None:
    """[12] entries=[] (empty list) is a valid non-nullable value and must parse fine."""
    ph = ProxyHistory.model_validate({"total": 0, "entries": []})
    assert ph.entries == []
