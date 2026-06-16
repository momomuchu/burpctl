"""Tests for the bp fuzz orchestration (run_fuzz) — mocked :8089, no Burp."""

import json

import httpx

from bp.client import BurpClient
from bp.runner import run_fuzz


def _mock_client() -> BurpClient:
    base_url = "https://t.example.com/s?u=_&p=_"

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "id": 5,
                        "request": {
                            "method": "GET",
                            "url": base_url,
                            "headers": [{"name": "Host", "value": "t.example.com"}],
                            "body": None,
                        },
                    },
                    "error": None,
                },
            )
        if path == "/repeater/send":
            sent_url = json.loads(req.content)["request"]["url"]
            anomalous = "u=admin" in sent_url
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": {"method": "GET", "url": sent_url, "headers": [], "body": None},
                        "response": {
                            "statusCode": 500 if anomalous else 200,
                            "headers": [],
                            "body": "x" * (999 if anomalous else 100),
                        },
                        "durationMs": 12,
                    },
                    "error": None,
                },
            )
        return httpx.Response(404, json={"success": False, "data": None, "error": {"code": "X", "message": "no"}})

    return BurpClient(client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test"))


def test_run_fuzz_sniper_flags_anomaly() -> None:
    results = run_fuzz(_mock_client(), 5, ["query:u"], {"u": [b"guest", b"admin"]}, "sniper")
    assert len(results) == 2  # 1 position * 2 payloads
    guest = next(r for r in results if r.payloads == ("guest",))
    admin = next(r for r in results if r.payloads == ("admin",))
    assert guest.status == 200 and not guest.anomalous
    assert admin.status == 500 and admin.anomalous  # status differs from baseline


def test_run_fuzz_cluster_bomb_matrix() -> None:
    results = run_fuzz(
        _mock_client(),
        5,
        ["query:u", "query:p"],
        {"u": [b"a", b"b"], "p": [b"1", b"2"]},
        "cluster-bomb",
    )
    assert len(results) == 4  # 2 * 2
    assert {r.payloads for r in results} == {("a", "1"), ("a", "2"), ("b", "1"), ("b", "2")}
