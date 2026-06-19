"""Tests for the BurpClient envelope unwrapping + error handling (httpx MockTransport, no Burp)."""

from collections.abc import Callable

import httpx
import pytest

from bp.client import BurpClient, BurpError, BurpUnreachable
from bp.models import HealthData

Handler = Callable[[httpx.Request], httpx.Response]


def _client(handler: Handler) -> BurpClient:
    transport = httpx.MockTransport(handler)
    return BurpClient(client=httpx.Client(transport=transport, base_url="http://test"))


def test_health_unwraps_envelope() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {"status": "ok", "version": "0.1.0", "uptime": 42, "burpVersion": None},
                "error": None,
            },
        )

    h = _client(handler).health()
    assert isinstance(h, HealthData)
    assert h.status == "ok"
    assert h.uptime == 42
    assert h.burpVersion is None


def test_error_envelope_raises_burp_error() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"success": False, "data": None, "error": {"code": "INVALID_REQUEST", "message": "bad"}},
        )

    with pytest.raises(BurpError) as ei:
        _client(handler).get("/anything")
    assert ei.value.code == "INVALID_REQUEST"


def test_connection_refused_raises_unreachable() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(BurpUnreachable) as ei:
        _client(handler).health()
    assert ei.value.code == "CONNECTION_REFUSED"


# --- discovery UltraQA: non-ConnectError transport + non-JSON responses ---


def test_read_timeout_maps_to_unreachable() -> None:
    """HIGH: a timeout (not a ConnectError) must surface as a clean error, not a raw traceback."""

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=req)

    with pytest.raises(BurpUnreachable):
        _client(handler).health()


def test_empty_body_response_raises_burp_error_not_valueerror() -> None:
    """HIGH: a 404/empty-body (unwired route) is a server error (exit 1), not a usage error (exit 2)."""

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, content=b"")

    with pytest.raises(BurpError) as ei:
        _client(handler).get("/nonexistent")
    assert ei.value.code == "INVALID_RESPONSE"
    assert not isinstance(ei.value, ValueError)  # must NOT be a pydantic ValueError (→ exit 2)


def test_non_json_body_raises_burp_error() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not json</html>")

    with pytest.raises(BurpError) as ei:
        _client(handler).get("/x")
    assert ei.value.code == "INVALID_RESPONSE"


# --- [07] HIGH: URL credentials must not be stored in ledger target column ---


def _client_with_ledger(handler: Handler, base_url: str) -> tuple[BurpClient, "list[str]"]:
    """Return a BurpClient backed by MockTransport and an in-memory Ledger stub.

    The stub captures the ``target`` value passed to ``record()`` so tests can
    assert on it without touching SQLite.
    """
    from bp.ledger import Ledger, OpRecord

    recorded_targets: list[str] = []

    class _StubLedger(Ledger):
        def record(self, op: OpRecord) -> str:  # type: ignore[override]
            recorded_targets.append(op.target or "")
            return "stub-id"

    transport = httpx.MockTransport(handler)
    ledger = _StubLedger.__new__(_StubLedger)  # bypass __init__ (no SQLite path needed)
    bc = BurpClient(
        client=httpx.Client(transport=transport, base_url=base_url),
        ledger=ledger,  # type: ignore[arg-type]
    )
    return bc, recorded_targets


def _ok_handler(_req: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "success": True,
            "data": {"status": "ok", "version": "0.1.0", "uptime": 1, "burpVersion": None},
            "error": None,
        },
    )


def test_ledger_target_strips_userinfo_with_port() -> None:
    """[07] HIGH: user:password@ in base_url must NOT appear in ledger target."""
    bc, targets = _client_with_ledger(_ok_handler, "http://admin:s3cr3t@127.0.0.1:8089")
    bc.health()
    assert targets, "ledger record() was never called"
    assert targets[0] == "127.0.0.1:8089", f"got {targets[0]!r} — credentials leaked"
    assert "admin" not in targets[0]
    assert "s3cr3t" not in targets[0]


def test_ledger_target_plain_url_unchanged() -> None:
    """[07] HIGH: a plain URL without credentials must produce the same host:port target."""
    bc, targets = _client_with_ledger(_ok_handler, "http://127.0.0.1:8089")
    bc.health()
    assert targets, "ledger record() was never called"
    assert targets[0] == "127.0.0.1:8089", f"got {targets[0]!r}"


def test_ledger_target_hostname_only_no_port() -> None:
    """[07] HIGH: URL with no port should store just the hostname."""
    bc, targets = _client_with_ledger(_ok_handler, "http://user:pass@burphost")
    bc.health()
    assert targets, "ledger record() was never called"
    assert targets[0] == "burphost", f"got {targets[0]!r} — credentials or port leaked"
    assert "user" not in targets[0]
    assert "pass" not in targets[0]
