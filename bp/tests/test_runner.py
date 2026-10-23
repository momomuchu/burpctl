"""Tests for the bp fuzz orchestration (run_fuzz) — mocked :8089, no Burp."""

import json

import httpx
import pytest

from bp.cli import _fuzz_exit, _fuzz_rows
from bp.client import BurpClient, BurpError
from bp.pos import Position, PosError
from bp.runner import _payload_lists, run_fuzz


def _mock_client(sends: list[str] | None = None, calls: list[str] | None = None) -> BurpClient:
    base_url = "https://t.example.com/s?u=_&p=_"

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if calls is not None:
            calls.append(path)
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
            if sends is not None:
                sends.append(sent_url)
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
        return httpx.Response(
            404, json={"success": False, "data": None, "error": {"code": "X", "message": "no"}}
        )

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )


def test_run_fuzz_sniper_flags_anomaly() -> None:
    results = run_fuzz(_mock_client(), 5, ["query:u"], {"u": [b"guest", b"admin"]}, "sniper")
    baseline = next(r for r in results if r.baseline)
    payload_results = [r for r in results if not r.baseline]
    assert baseline.index == -1
    assert baseline.payloads == ()
    assert baseline.status == 200
    assert not baseline.anomalous
    assert len(payload_results) == 2  # 1 position * 2 payloads
    guest = next(r for r in payload_results if r.payloads == ("guest",))
    admin = next(r for r in payload_results if r.payloads == ("admin",))
    assert guest.status == 200 and not guest.anomalous
    assert admin.status == 500 and admin.anomalous  # status differs from baseline


def test_empty_selector_is_rejected_before_api_call() -> None:
    calls: list[str] = []

    with pytest.raises(ValueError, match="at least one --pos"):
        run_fuzz(_mock_client(calls=calls), 5, [], {"u": [b"one"]}, "sniper")

    assert calls == []


def test_invalid_or_empty_fuzz_plan_sends_nothing() -> None:
    for selectors, payloads, message in (
        ([], {"u": [b"one"]}, "at least one --pos"),
        (["query:u"], {"u": []}, "at least one concrete request"),
    ):
        sends: list[str] = []
        with pytest.raises(ValueError, match=message):
            run_fuzz(_mock_client(sends), 5, selectors, payloads, "sniper")
        assert sends == []


def test_non_utf8_request_target_is_rejected_before_send() -> None:
    sends: list[str] = []

    with pytest.raises(ValueError, match="structured REST bridge"):
        run_fuzz(_mock_client(sends), 5, ["query:u"], {"u": [b"\xff"]}, "sniper")

    assert sends == []


def test_anomalous_only_retains_fresh_baseline() -> None:
    results = run_fuzz(_mock_client(), 5, ["query:u"], {"u": [b"guest", b"admin"]}, "sniper")

    visible = _fuzz_rows(results, anomalous_only=True)

    assert [row["baseline"] for row in visible] == [True, False]
    assert visible[0]["index"] == -1
    assert visible[1]["payloads"] == ("admin",)


def test_response_lengths_are_utf8_bytes() -> None:
    sends = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal sends
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": {
                            "method": "GET",
                            "url": "https://t.example.com/s?u=base",
                            "headers": [],
                            "body": None,
                        }
                    },
                    "error": None,
                },
            )
        sends += 1
        body = "🙂" * 10 if sends == 1 else "x" * 10
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {"response": {"statusCode": 200, "body": body}, "durationMs": 1},
                "error": None,
            },
        )

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )
    results = run_fuzz(client, 5, ["query:u"], {"u": [b"one"]}, "sniper")

    assert [result.length for result in results] == [40, 10]
    assert results[1].anomalous is True


def test_later_send_error_returns_one_row_per_attempt() -> None:
    sends = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal sends
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": {
                            "method": "GET",
                            "url": "https://t.example.com/s?u=base",
                            "headers": [],
                            "body": None,
                        }
                    },
                    "error": None,
                },
            )
        sends += 1
        if sends == 3:
            return httpx.Response(
                500,
                json={
                    "success": False,
                    "data": None,
                    "error": {"code": "SEND_FAILED", "message": "payload failed"},
                },
            )
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {"response": {"statusCode": 200, "body": "ok"}},
                "error": None,
            },
        )

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )
    results = run_fuzz(client, 5, ["query:u"], {"u": [b"one", b"two"]}, "sniper")

    assert sends == len(results) == 3
    assert results[-1].payloads == ("two",)
    assert results[-1].status == 0
    assert results[-1].error == "SEND_FAILED: payload failed"
    assert results[-1].anomalous is False
    assert results[-1].error_code == "SEND_FAILED"
    rows = [r.__dict__ for r in results]
    assert _fuzz_rows(results, anomalous_only=True)[-1]["error_code"] == "SEND_FAILED"
    assert _fuzz_exit(rows) == 1


def test_terminal_send_error_stops_remaining_payloads() -> None:
    sends = 0

    def handler(req: httpx.Request) -> httpx.Response:
        nonlocal sends
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": {
                            "method": "GET",
                            "url": "https://t.example.com/s?u=base",
                            "headers": [],
                            "body": None,
                        }
                    },
                    "error": None,
                },
            )
        sends += 1
        if sends > 1:
            raise httpx.ConnectError("down", request=req)
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {"response": {"statusCode": 200, "body": "ok"}},
                "error": None,
            },
        )

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )
    results = run_fuzz(client, 5, ["query:u"], {"u": [b"one", b"two", b"three"]}, "sniper")

    assert sends == len(results) == 2
    assert results[-1].error_code == "CONNECTION_REFUSED"


def test_fuzz_error_exit_preserves_connection_category(capsys: pytest.CaptureFixture[str]) -> None:
    rows = [{"error": "CONNECTION_REFUSED: down", "error_code": "CONNECTION_REFUSED"}]

    assert _fuzz_exit(rows) == 3
    assert "attempted-shot rows remain on stdout" in capsys.readouterr().err


def test_fuzz_error_exit_is_json_in_json_mode(capsys: pytest.CaptureFixture[str]) -> None:
    rows = [{"error": "SEND_FAILED: failed", "error_code": "SEND_FAILED"}]

    assert _fuzz_exit(rows, "json") == 1
    diagnostic = json.loads(capsys.readouterr().err)
    assert diagnostic["error"]["code"] == "FUZZ_PARTIAL_FAILURE"


def test_run_fuzz_cluster_bomb_matrix() -> None:
    results = run_fuzz(
        _mock_client(),
        5,
        ["query:u", "query:p"],
        {"u": [b"a", b"b"], "p": [b"1", b"2"]},
        "cluster-bomb",
    )
    assert len(results) == 5  # 1 returned baseline + 2 * 2 payloads
    assert {r.payloads for r in results if not r.baseline} == {
        ("a", "1"),
        ("a", "2"),
        ("b", "1"),
        ("b", "2"),
    }


def test_run_fuzz_returns_one_result_per_send() -> None:
    sends: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": {
                            "method": "GET",
                            "url": "https://t.example.com/s?u=base",
                            "headers": [{"name": "Host", "value": "t.example.com"}],
                            "body": None,
                        },
                        "response": {"statusCode": 200, "body": "baseline"},
                    },
                    "error": None,
                },
            )
        if req.url.path == "/repeater/send":
            sent_url = json.loads(req.content)["request"]["url"]
            sends.append(sent_url)
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "response": {"statusCode": 200, "headers": [], "body": "baseline"},
                        "durationMs": 1,
                    },
                    "error": None,
                },
            )
        return httpx.Response(404)

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )
    results = run_fuzz(client, 5, ["query:u"], {"u": [b"one", b"two"]}, "sniper")

    assert len(results) == 3
    assert len(sends) == len(results)
    assert results[0].baseline is True
    assert results[0].payloads == ()
    assert results[0].index == -1
    assert all(not result.baseline for result in results[1:])
    assert sends[0].endswith("u=base")


# --- [38] invalid attack type must raise ValueError before payload resolution ---


def test_invalid_attack_type_raises_value_error_in_run_fuzz() -> None:
    """[38] fuzz --type <invalid> must raise ValueError mentioning 'unknown attack type'."""
    with pytest.raises(ValueError, match="unknown attack type"):
        run_fuzz(
            _mock_client(),
            5,
            ["query:u"],
            {"u": [b"x"]},
            "turbo-intruder",  # unknown type
        )


def test_invalid_attack_type_payload_lists_raises_before_misleading_error() -> None:
    """[38] _payload_lists with unknown type + payload provided must raise 'unknown attack type',
    not the misleading 'needs --payloads list per position' error."""
    p = Position(5, 6, "query:u")
    with pytest.raises(ValueError, match="unknown attack type"):
        _payload_lists([p], {"u": [b"x"]}, "turbo-intruder")


def test_invalid_attack_type_message_names_valid_types() -> None:
    """[38] error message must include at least one valid type name for actionability."""
    p = Position(5, 6, "query:u")
    with pytest.raises(ValueError, match="sniper"):
        _payload_lists([p], {"u": [b"x"]}, "invalid")


# --- [08] _send(): missing 'response' key must raise BurpError, not KeyError ---


def _mock_client_missing_response() -> BurpClient:
    """Mock where /repeater/send data dict has no 'response' key."""

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "id": 1,
                        "request": {
                            "method": "GET",
                            "url": "https://t.example.com/s?u=x",
                            "headers": [{"name": "Host", "value": "t.example.com"}],
                            "body": None,
                        },
                        "response": {"statusCode": 200, "body": "x"},
                    },
                    "error": None,
                },
            )
        if path == "/repeater/send":
            # data has no 'response' key — simulates unexpected server shape
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"durationMs": 5},  # 'response' key absent
                    "error": None,
                },
            )
        return httpx.Response(
            404, json={"success": False, "data": None, "error": {"code": "X", "message": "no"}}
        )

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )


def test_send_missing_response_key_returns_clean_error_row() -> None:
    results = run_fuzz(_mock_client_missing_response(), 1, ["query:u"], {"u": [b"x"]}, "sniper")

    assert len(results) == 1
    assert results[0].baseline is True
    assert results[0].error == "INVALID_RESPONSE: repeater/send reply missing 'response' object"


@pytest.mark.parametrize(
    ("send_data", "message"),
    [
        ({"response": None}, "missing 'response' object"),
        ({"response": {"statusCode": 200, "body": []}}, "response body is not text"),
        (
            {"response": {"statusCode": 200, "body": "ok"}, "durationMs": "invalid"},
            "invalid 'durationMs'",
        ),
    ],
)
def test_malformed_send_shapes_return_error_rows(
    send_data: dict[str, object], message: str
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        data = (
            {
                "request": {
                    "method": "GET",
                    "url": "https://t.example.com/s?u=base",
                    "headers": [],
                    "body": None,
                }
            }
            if req.url.path.startswith("/proxy/history/")
            else send_data
        )
        return httpx.Response(200, json={"success": True, "data": data, "error": None})

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )
    results = run_fuzz(client, 5, ["query:u"], {"u": [b"one"]}, "sniper")

    assert len(results) == 1
    assert results[0].baseline is True
    assert results[0].error_code == "INVALID_RESPONSE"
    assert message in (results[0].error or "")


# --- [10] _base_raw(): missing 'request' key in history entry must raise BurpError, not KeyError ---


def _mock_client_missing_request() -> BurpClient:
    """Mock where /proxy/history/{id} data dict has no 'request' key."""

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {"id": 1},  # 'request' key absent
                    "error": None,
                },
            )
        return httpx.Response(
            404, json={"success": False, "data": None, "error": {"code": "X", "message": "no"}}
        )

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )


def test_base_raw_missing_request_key_raises_burp_error() -> None:
    """[10] _base_raw() with entry missing 'request' key must raise BurpError(INVALID_RESPONSE),
    not a raw KeyError."""
    from bp.client import BurpError

    with pytest.raises(BurpError) as ei:
        run_fuzz(_mock_client_missing_request(), 1, ["query:u"], {"u": [b"x"]}, "sniper")
    assert ei.value.code == "INVALID_RESPONSE"


@pytest.mark.parametrize(
    "request_data",
    [
        {
            "method": 42,
            "url": "https://t.example.com/s?q=_",
            "headers": [],
            "body": None,
        },
        None,
        {"url": "https://t.example.com/s?q=_", "headers": [], "body": None},
        {"method": "GET", "headers": [], "body": None},
        {
            "method": "GET",
            "url": "https://t.example.com/s?q=_",
            "headers": [{"name": 42, "value": "x"}],
            "body": None,
        },
        {
            "method": "GET",
            "url": "https://t.example.com/s?q=_",
            "headers": [],
            "body": 42,
        },
    ],
)
def test_base_raw_malformed_request_shape_raises_sanitized_burp_error(
    request_data: object,
) -> None:
    sends: list[str] = []
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": request_data,
                    },
                    "error": None,
                },
            )
        sends.append(req.url.path)
        return httpx.Response(500)

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )

    with pytest.raises(BurpError) as ei:
        run_fuzz(client, 1, ["query:q"], {"q": [b"x"]}, "sniper")

    assert ei.value.code == "INVALID_RESPONSE"
    assert ei.value.message == "history entry has invalid request shape"
    assert calls == ["/proxy/history/1"]
    assert sends == []


# --- [08b] _send(): a present 'response' missing/garbled 'statusCode' must also be clean ---


def _mock_client_bad_statuscode(status_value: object | None) -> BurpClient:
    """Mock where /repeater/send 'response' lacks statusCode (None) or has a non-int one."""

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "id": 1,
                        "request": {
                            "method": "GET",
                            "url": "https://t.example.com/s?u=x",
                            "headers": [{"name": "Host", "value": "t.example.com"}],
                            "body": None,
                        },
                        "response": {"statusCode": 200, "body": "x"},
                    },
                    "error": None,
                },
            )
        if path == "/repeater/send":
            resp: dict[str, object] = {"body": "x"}
            if status_value is not None:
                resp["statusCode"] = status_value
            return httpx.Response(
                200,
                json={"success": True, "data": {"response": resp, "durationMs": 5}, "error": None},
            )
        return httpx.Response(
            404, json={"success": False, "data": None, "error": {"code": "X", "message": "no"}}
        )

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )


def test_send_missing_statuscode_returns_clean_error_row() -> None:
    results = run_fuzz(_mock_client_bad_statuscode(None), 1, ["query:u"], {"u": [b"x"]}, "sniper")

    assert results[0].error == "INVALID_RESPONSE: repeater/send reply missing 'statusCode' field"


def test_send_noninteger_statuscode_returns_clean_error_row() -> None:
    results = run_fuzz(
        _mock_client_bad_statuscode("not-a-number"), 1, ["query:u"], {"u": [b"x"]}, "sniper"
    )

    assert (
        results[0].error == "INVALID_RESPONSE: repeater/send reply has a non-integer 'statusCode'"
    )


# --- bounded and all-or-nothing preflight ------------------------------------


def test_over_limit_plan_sends_nothing() -> None:
    sends: list[str] = []
    with pytest.raises(ValueError, match="10,000"):
        run_fuzz(
            _mock_client(sends),
            5,
            ["query:u", "query:p"],
            {"u": [b"u"] * 101, "p": [b"p"] * 100},
            "cluster-bomb",
        )
    assert sends == []


@pytest.mark.parametrize(
    ("attack_type", "payload_map", "expected_shots"),
    [
        ("sniper", {"shared": [b"a", b"b"]}, 4),
        ("battering-ram", {"shared": [b"a", b"b"]}, 2),
        ("pitchfork", {"u": [b"a", b"b", b"c"], "p": [b"1", b"2"]}, 2),
        ("cluster-bomb", {"u": [b"a", b"b", b"c"], "p": [b"1", b"2"]}, 6),
    ],
)
def test_all_attack_types_send_one_baseline_then_exact_shot_count(
    attack_type: str,
    payload_map: dict[str, list[bytes]],
    expected_shots: int,
) -> None:
    sends: list[str] = []

    results = run_fuzz(
        _mock_client(sends),
        5,
        ["query:u", "query:p"],
        payload_map,
        attack_type,
    )

    assert len(sends) == len(results) == expected_shots + 1
    assert results[0].baseline is True
    assert sum(not result.baseline for result in results) == expected_shots


def test_out_of_range_selector_sends_nothing() -> None:
    sends: list[str] = []
    with pytest.raises(PosError, match="out of range"):
        run_fuzz(
            _mock_client(sends),
            5,
            ["offset:0-99999"],
            {"shared": [b"x"]},
            "sniper",
        )
    assert sends == []


def test_overlapping_selectors_send_nothing() -> None:
    sends: list[str] = []
    with pytest.raises(PosError, match="POS_OVERLAP"):
        run_fuzz(
            _mock_client(sends),
            5,
            ["query:u", "query:u"],
            {"u": [b"x"]},
            "battering-ram",
        )
    assert sends == []


def test_crlf_payload_injection_sends_nothing() -> None:
    sends: list[str] = []
    with pytest.raises(ValueError, match="CR|LF|control"):
        run_fuzz(
            _mock_client(sends),
            5,
            ["query:u"],
            {"u": [b"safe", b"x\r\nInjected: yes"]},
            "sniper",
        )
    assert sends == []


def test_baseline_failure_sends_no_payloads() -> None:
    sent_urls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/proxy/history/"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {
                        "request": {
                            "method": "GET",
                            "url": "https://t.example/s?u=base",
                            "headers": [],
                            "body": None,
                        }
                    },
                    "error": None,
                },
            )
        sent_urls.append(json.loads(req.content)["request"]["url"])
        return httpx.Response(
            500,
            json={
                "success": False,
                "data": None,
                "error": {"code": "SEND_FAILED", "message": "baseline failed"},
            },
        )

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test")
    )
    results = run_fuzz(client, 5, ["query:u"], {"u": [b"one", b"two"]}, "sniper")

    assert sent_urls == ["https://t.example/s?u=base"]
    assert len(results) == 1
    assert results[0].baseline is True
    assert results[0].error_code == "SEND_FAILED"
