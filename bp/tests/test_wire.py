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


def test_build_raw_strips_fragment_from_captured_url() -> None:
    """Fragments are client-side metadata and must not block replay of a captured request."""
    raw = build_raw("GET", "https://h.example.com/echo?q=old#browser-only", [], None)

    assert raw.startswith(b"GET /echo?q=old HTTP/1.1\r\n")
    assert b"#browser-only" not in raw


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
    assert sr["bodyBase64"] == "eyJhIjoxfQ=="
    assert "body" not in sr
    assert {"name": "Host", "value": "h.example.com"} in sr["headers"]


def test_to_send_request_encodes_unicode_body_as_exact_bytes() -> None:
    """The bridge must not hand UTF-8 bytes to Montoya's lossy String body overload."""
    body = '{"f":"café αβγ 😀"}'.encode()
    raw = (
        b"POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )

    request = to_send_request(raw, "https", "h")

    assert request["bodyBase64"] == "eyJmIjoiY2Fmw6kgzrHOss6zIPCfmIAifQ=="


def test_to_send_request_preserves_whitespace_only_header_value() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: h\r\nX-Test:    \r\n\r\n"

    request = to_send_request(raw, "https", "h")

    assert {"name": "X-Test", "value": "   "} in request["headers"]


def test_to_send_request_preserves_exact_ordered_headers_including_duplicate_cookie() -> None:
    """The bridge intent must not add defaults or collapse an unrelated Cookie field."""
    raw = (
        b"GET / HTTP/1.1\r\n"
        b"Host: h\r\n"
        b"X-Case: exact\r\n"
        b"Cookie: first=one\r\n"
        b"Cookie: later=old\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )

    request = to_send_request(raw, "https", "h")

    assert request["headers"] == [
        {"name": "Host", "value": "h"},
        {"name": "X-Case", "value": "exact"},
        {"name": "Cookie", "value": "first=one"},
        {"name": "Cookie", "value": "later=old"},
        {"name": "Connection", "value": "keep-alive"},
    ]


def test_python_fuzz_intent_changes_only_later_duplicate_cookie() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: h\r\nCookie: first=one\r\nCookie: later=old\r\n\r\n"
    fuzzed = apply_subs(raw, [Sub(resolve_pos(raw, "cookie:later"), b"new")])

    request = to_send_request(fuzzed, "https", "h")

    assert request["headers"] == [
        {"name": "Host", "value": "h"},
        {"name": "Cookie", "value": "first=one"},
        {"name": "Cookie", "value": "later=new"},
    ]


def test_to_send_request_preserves_explicit_zero_length_body() -> None:
    raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"

    request = to_send_request(raw, "https", "h")

    assert request["bodyBase64"] == ""
    assert "body" not in request


def test_build_raw_preserves_empty_body_as_distinct_from_no_body() -> None:
    raw = build_raw("POST", "https://h/", [], "")

    request = to_send_request(raw, "https", "h")

    assert request["bodyBase64"] == ""
    assert {"name": "Content-Length", "value": "0"} in request["headers"]


def test_build_raw_accepts_exact_binary_body_bytes() -> None:
    raw = build_raw("POST", "https://h/", [], b"\xff\x00")

    request = to_send_request(raw, "https", "h")

    assert request["bodyBase64"] == "/wA="
    assert {"name": "Content-Length", "value": "2"} in request["headers"]


def test_to_send_request_omits_both_body_fields_when_no_body_was_expressed() -> None:
    raw = b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"

    request = to_send_request(raw, "https", "h")

    assert "bodyBase64" not in request
    assert "body" not in request


def test_to_send_request_encodes_nul_body_as_exact_bytes() -> None:
    """NUL is ordinary body data; it is forbidden only in request lines and headers."""
    raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\na\x00b"

    request = to_send_request(raw, "https", "h")

    assert request["bodyBase64"] == "YQBi"
    assert "body" not in request


def test_python_fuzz_flow_builds_substituted_send_intent() -> None:
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
    ("raw", "expected_url"),
    [
        (
            b"GET /a?q=1#browser HTTP/1.1\r\nHost: h.example.com\r\n\r\n",
            "https://h.example.com/a?q=1",
        ),
        (
            b"GET https://h.example.com/a?q=1#browser HTTP/1.1\r\nHost: h.example.com\r\n\r\n",
            "https://h.example.com/a?q=1",
        ),
        (
            b"GET https://h.example.com/a?#browser HTTP/1.1\r\nHost: h.example.com\r\n\r\n",
            "https://h.example.com/a?",
        ),
    ],
)
def test_to_send_request_strips_only_captured_fragment(raw: bytes, expected_url: str) -> None:
    request = to_send_request(raw, "https", "h.example.com")

    assert request["url"] == expected_url


def test_build_raw_preserves_empty_query_while_stripping_fragment() -> None:
    raw = build_raw("GET", "https://h.example.com/a?#browser", [], None)

    assert raw.startswith(b"GET /a? HTTP/1.1\r\n")


@pytest.mark.parametrize(
    "raw",
    [
        b"GET https://other.example/a HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"GET http://h.example/a HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"CONNECT h.example:443 HTTP/1.1\r\nHost: h.example\r\n\r\n",
        b"OPTIONS * HTTP/1.1\r\nHost: h.example\r\n\r\n",
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
        b"GET / HTTP/1.1\r\nHost: h\x00evil\r\n\r\n",
    ],
)
def test_to_send_request_rejects_non_utf8_or_nul_request_metadata(raw: bytes) -> None:
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
