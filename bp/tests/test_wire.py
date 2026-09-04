"""Tests for the raw<->structured wire bridge, incl. the full A1+A2+wire fuzz flow."""

import pytest

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
    sr = to_send_request(raw, "https", "h.example.com")
    assert sr["method"] == "POST"
    assert sr["url"] == "https://h.example.com/api?x=1"
    assert sr["body"] == '{"a":1}'
    assert {"name": "Host", "value": "h.example.com"} in sr["headers"]


def test_to_send_request_preserves_whitespace_only_header_value() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: h\r\nX-Test:    \r\n\r\n"

    request = to_send_request(raw, "https", "h")

    assert {"name": "X-Test", "value": "   "} in request["headers"]


def test_to_send_request_preserves_explicit_zero_length_body() -> None:
    raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"

    request = to_send_request(raw, "https", "h")

    assert request["body"] == ""


def test_full_fuzz_flow_build_substitute_send() -> None:
    raw = build_raw("GET", "https://h/s?u=_", [], None)
    out = apply_subs(raw, [Sub(resolve_pos(raw, "query:u"), b"admin")])
    sr = to_send_request(out, "https", "h")
    assert sr["url"] == "https://h/s?u=admin"
    assert sr["method"] == "GET"


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nHost: h\n\n",
        b"GET / HTTP/1.1\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: h\r\n\n",
    ],
)
def test_to_send_request_rejects_mixed_or_ambiguous_line_endings(raw: bytes) -> None:
    with pytest.raises(ValueError, match="line ending|separator"):
        to_send_request(raw, "https", "h")


@pytest.mark.parametrize(
    "raw",
    [
        b"GET /\r\nHost: h\r\n\r\n",
        b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.0\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
        b"GET / HTTP/1.1\r\nMissing-Colon\r\n\r\n",
        b"GET / HTTP/1.1\r\n folded\r\n\r\n",
        b"GET / HTTP/1.1\r\n:authority: h\r\n\r\n",
    ],
)
def test_to_send_request_rejects_malformed_request_line_or_headers(raw: bytes) -> None:
    with pytest.raises(ValueError):
        to_send_request(raw, "https", "h")


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: nope\r\n\r\nx",
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nx",
    ],
)
def test_to_send_request_rejects_ambiguous_or_unpreservable_framing(raw: bytes) -> None:
    with pytest.raises(ValueError):
        to_send_request(raw, "https", "h")


def test_to_send_request_supports_consistent_absolute_form() -> None:
    raw = b"GET https://h.example.com:443/a?q=1 HTTP/1.1\r\nHost: h.example.com\r\n\r\n"

    request = to_send_request(raw, "https", "h.example.com")

    assert request["url"] == "https://h.example.com:443/a?q=1"


@pytest.mark.parametrize(
    "raw",
    [
        b"GET https://other.example/a HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"GET http://h.example/a HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"CONNECT h.example:443 HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"GET /a#fragment HTTP/1.1\r\nHost: h.example\r\n\r\n",
    ],
)
def test_to_send_request_rejects_inconsistent_or_unsupported_targets(raw: bytes) -> None:
    with pytest.raises(ValueError):
        to_send_request(raw, "https", "h.example")


@pytest.mark.parametrize(
    "raw",
    [
        b"GET /\xff HTTP/1.1\r\nHost: h\r\n\r\n",
        b"GET / HTTP/1.1\r\nX-Test: \xff\r\nHost: h\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: h\r\n\r\n\xff",
        b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\n\x00",
        b"GET / HTTP/1.1\r\nHost: h\x00evil\r\n\r\n",
    ],
)
def test_to_send_request_rejects_non_utf8_and_nul_parts(raw: bytes) -> None:
    with pytest.raises(ValueError):
        to_send_request(raw, "https", "h")


@pytest.mark.parametrize(
    ("method", "url", "headers", "body"),
    [
        ("GET\r\nInjected: x", "https://h/", [], None),
        ("GET", "https://h/\r\nInjected: x", [], None),
        ("GET", "https://h/", [("X-Test", "ok\r\nInjected: x")], None),
        ("GET", "https://h/", [(":authority", "h")], None),
        ("POST", "https://h/", [("Content-Length", "1"), ("Content-Length", "1")], "x"),
    ],
)
def test_build_raw_rejects_structured_injection_or_ambiguity(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: str | None,
) -> None:
    with pytest.raises(ValueError):
        build_raw(method, url, headers, body)
