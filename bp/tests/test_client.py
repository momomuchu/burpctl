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
