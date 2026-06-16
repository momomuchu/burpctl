"""Tests for the raw<->structured wire bridge, incl. the full A1+A2+wire fuzz flow."""

from bp.fuzz import Sub, apply_subs
from bp.pos import resolve_pos
from bp.wire import build_raw, to_send_request


def test_build_raw_round_trips_with_resolve_pos() -> None:
    raw = build_raw(
        "POST",
        "https://t.example.com/api/users?id=42",
        [("Authorization", "Bearer x")],
        '{"id":42}',
    )
    assert raw.startswith(b"POST /api/users?id=42 HTTP/1.1\r\n")
    p_auth = resolve_pos(raw, "header:Authorization")
    assert raw[p_auth.start : p_auth.end] == b"Bearer x"
    p_id = resolve_pos(raw, "query:id")
    assert raw[p_id.start : p_id.end] == b"42"


def test_build_raw_injects_host_when_absent() -> None:
    raw = build_raw("GET", "https://h.example.com/p", [], None)
    assert b"Host: h.example.com\r\n" in raw
    assert raw.startswith(b"GET /p HTTP/1.1\r\n")


def test_to_send_request_parses_structured() -> None:
    raw = (
        b"POST /api?x=1 HTTP/1.1\r\n"
        b"Host: h.example.com\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"a":1}'
    )
    sr = to_send_request(raw, "https", "fallback")
    assert sr["method"] == "POST"
    assert sr["url"] == "https://h.example.com/api?x=1"
    assert sr["body"] == '{"a":1}'
    assert {"name": "Host", "value": "h.example.com"} in sr["headers"]


def test_full_fuzz_flow_build_substitute_send() -> None:
    raw = build_raw("GET", "https://h/s?u=_", [], None)
    out = apply_subs(raw, [Sub(resolve_pos(raw, "query:u"), b"admin")])
    sr = to_send_request(out, "https", "h")
    assert sr["url"] == "https://h/s?u=admin"
    assert sr["method"] == "GET"
