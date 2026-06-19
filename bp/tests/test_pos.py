"""RED tests for A1 — the --pos semantic→byte-offset resolver (docs/ALGORITHMS.md A1).

`resolve_pos(raw, selector)` returns a Position{start,end,name} such that
`raw[start:end]` is exactly the value to fuzz.
"""

import pytest

from bp.pos import Position, PosError, resolve_pos

# Fixture request from ALGORITHMS.md A1 (CRLF, HTTP/1.1).
REQ: bytes = (
    b"POST /api/v2/users/42?redirect=/home HTTP/1.1\r\n"
    b"Host: t.example.com\r\n"
    b"Authorization: Bearer abc123\r\n"
    b"Cookie: sid=XYZ; role=user\r\n"
    b"Content-Type: application/json\r\n"
    b"\r\n"
    b'{"id":42,"name":"bob"}'
)


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("header:Authorization", b"Bearer abc123"),
        ("cookie:role", b"user"),
        ("cookie:sid", b"XYZ"),
        ("query:redirect", b"/home"),
        ("path:1", b"api"),  # convention: 1-based, first non-empty segment
        ("path:4", b"42"),
        ("body:id", b"42"),  # JSON number literal
        ("body:name", b"bob"),  # inside the quotes
        ("offset:0-4", b"POST"),
    ],
)
def test_resolve_pos_value(selector: str, expected: bytes) -> None:
    p = resolve_pos(REQ, selector)
    assert isinstance(p, Position)
    assert REQ[p.start : p.end] == expected
    assert p.name == selector


def test_header_match_is_case_insensitive() -> None:
    p = resolve_pos(REQ, "header:authorization")
    assert REQ[p.start : p.end] == b"Bearer abc123"


def test_resolve_pos_not_found() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "header:Nope")
    assert ei.value.code == "POS_NOT_FOUND"


def test_unsupported_selector_kind() -> None:
    with pytest.raises(PosError):
        resolve_pos(REQ, "bogus:thing")


# --- discovery UltraQA: resolver correctness edge cases ---


def test_cookie_found_in_second_cookie_header() -> None:
    """HIGH: a cookie present only in a later Cookie header must still be found."""
    req = b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: target=found\r\n\r\n"
    p = resolve_pos(req, "cookie:target")
    assert req[p.start : p.end] == b"found"


def test_cookie_absent_in_all_headers_raises_not_found() -> None:
    req = b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n"
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "cookie:missing")
    assert ei.value.code == "POS_NOT_FOUND"


def test_json_value_with_escaped_quote_spans_full_value() -> None:
    r"""HIGH: a JSON string value containing \" must not be truncated at the escaped quote."""
    body = b'{"key":"ab\\"cd"}'
    req = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body
    p = resolve_pos(req, "body:key")
    assert req[p.start : p.end] == b'ab\\"cd'


def test_reversed_offset_is_bad_selector() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "offset:5-3")
    assert ei.value.code == "BAD_SELECTOR"


def test_negative_offset_is_bad_selector() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "offset:0--5")
    assert ei.value.code == "BAD_SELECTOR"


def test_offset_beyond_length_is_pos_not_found() -> None:
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "offset:0-99999")
    assert ei.value.code == "POS_NOT_FOUND"


# --- [00] body:FIELD on array/object value must not truncate at first comma ---


def test_json_array_value_full_span() -> None:
    """[00] body:roles on an array value must return the full array, not truncate at ','."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"roles":["admin","user"],"id":1}'
    )
    p = resolve_pos(req, "body:roles")
    assert req[p.start : p.end] == b'["admin","user"]'


def test_json_object_value_full_span() -> None:
    """[00] body:data on a nested object value must return the full object."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"data":{"x":1,"y":2},"id":3}'
    )
    p = resolve_pos(req, "body:data")
    assert req[p.start : p.end] == b'{"x":1,"y":2}'


def test_json_nested_array_with_braces_full_span() -> None:
    """[00] array containing objects must be fully captured."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"items":[{"a":1},{"b":2}],"z":0}'
    )
    p = resolve_pos(req, "body:items")
    assert req[p.start : p.end] == b'[{"a":1},{"b":2}]'


# --- [01] body:FIELD must resolve TOP-LEVEL key only, not nested matches ---


def test_json_top_level_id_wins_over_nested() -> None:
    """[01] top-level 'id' must be 42, not the nested 99 inside 'data'."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"data":{"id":99},"id":42}'
    )
    p = resolve_pos(req, "body:id")
    assert req[p.start : p.end] == b"42"


def test_json_key_absent_at_top_level_raises_not_found() -> None:
    """[01] key present only in a nested object must raise POS_NOT_FOUND."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"data":{"id":99}}'
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:id")
    assert ei.value.code == "POS_NOT_FOUND"


# --- [03] path:0 and path:-1 must raise BAD_SELECTOR ---


def test_path_index_zero_raises_bad_selector() -> None:
    """[03] path:0 is not valid (1-based); must raise BAD_SELECTOR."""
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "path:0")
    assert ei.value.code == "BAD_SELECTOR"


def test_path_index_negative_raises_bad_selector() -> None:
    """[03] path:-1 must raise BAD_SELECTOR, not POS_NOT_FOUND."""
    with pytest.raises(PosError) as ei:
        resolve_pos(REQ, "path:-1")
    assert ei.value.code == "BAD_SELECTOR"


# --- [05] body:FIELD on JSON with no Content-Type must route to JSON resolver ---


def test_json_body_without_content_type_resolves_field() -> None:
    """[05] JSON body (starts with '{') with no Content-Type must use the JSON resolver."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
        b'{"id":1}'
    )
    p = resolve_pos(req, "body:id")
    assert req[p.start : p.end] == b"1"


def test_form_body_without_content_type_still_resolves() -> None:
    """[05] Form body (no '{'/']' prefix) without Content-Type must still work as before."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
        b"foo=bar&baz=qux"
    )
    p = resolve_pos(req, "body:foo")
    assert req[p.start : p.end] == b"bar"


# --- [20] query:NAME must not include the URL fragment in the resolved value ---


def test_query_last_param_strips_fragment() -> None:
    """[20] query:q on /search?q=hello#section2 must resolve to b'hello', not b'hello#section2'."""
    req = b"GET /search?q=hello#section2 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    p = resolve_pos(req, "query:q")
    assert req[p.start : p.end] == b"hello"


def test_query_middle_param_strips_fragment() -> None:
    """[20] query:q on /a?x=1&q=hello#frag must resolve to b'hello', not b'hello#frag'."""
    req = b"GET /a?x=1&q=hello#frag HTTP/1.1\r\nHost: example.com\r\n\r\n"
    p = resolve_pos(req, "query:q")
    assert req[p.start : p.end] == b"hello"


def test_query_no_fragment_unchanged() -> None:
    """[20] query:q on a URL with no fragment must still resolve correctly."""
    req = b"GET /search?q=world&n=5 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    p = resolve_pos(req, "query:q")
    assert req[p.start : p.end] == b"world"
