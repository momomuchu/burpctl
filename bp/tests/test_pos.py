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


# --- regression coverage: resolver correctness edge cases ---


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


# --- [00] JSON key unescape: body:FIELD must match the logical (unescaped) key name ---


def test_json_escaped_newline_key_resolved_by_logical_name() -> None:
    r"""[00] body containing {"a\nb":1} (key with literal \n escape) must be reachable
    by its logical Python name 'a\nb' (a real newline character)."""
    body = b'{"a\\nb":1}'
    req = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body
    p = resolve_pos(req, "body:a\nb")  # logical key: real newline
    assert req[p.start : p.end] == b"1"


def test_json_escaped_quote_key_resolved_by_logical_name() -> None:
    r"""[00] body containing {"a\"b":2} must be reachable by logical key 'a"b'."""
    body = b'{"a\\"b":2}'
    req = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body
    p = resolve_pos(req, 'body:a"b')  # logical key: real double-quote
    assert req[p.start : p.end] == b"2"


def test_json_unescaped_plain_key_still_resolves() -> None:
    """[00] regression: a plain key (no escapes) must still resolve correctly."""
    body = b'{"plain":99}'
    req = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body
    p = resolve_pos(req, "body:plain")
    assert req[p.start : p.end] == b"99"


def test_json_escaped_backslash_key_resolved_by_logical_name() -> None:
    r"""[00] body {"a\\\\b":3} (wire: a\\b, logical: a\b) resolved by 'a\b'."""
    body = b'{"a\\\\b":3}'
    req = b"POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body
    p = resolve_pos(req, "body:a\\b")  # logical key: single backslash
    assert req[p.start : p.end] == b"3"


# --- [03] body:FIELD on a JSON ARRAY must raise UNSUPPORTED_BODY, not POS_NOT_FOUND ---


def test_json_array_body_raises_unsupported_body() -> None:
    """[03] body:x on a top-level JSON array must raise PosError(UNSUPPORTED_BODY),
    not POS_NOT_FOUND (which implies the field is simply missing)."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b"[1,2,3]"
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:x")
    assert ei.value.code == "UNSUPPORTED_BODY"


def test_json_array_body_no_ct_raises_unsupported_body() -> None:
    """[03] no Content-Type + array body also raises UNSUPPORTED_BODY (auto-detect path)."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
        b'[{"a":1}]'
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:a")
    assert ei.value.code == "UNSUPPORTED_BODY"


def test_json_object_body_still_resolves_normally() -> None:
    """[03] regression: a JSON object body must still resolve field correctly."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"x":7}'
    )
    p = resolve_pos(req, "body:x")
    assert req[p.start : p.end] == b"7"


# --- [00] _resolve_json_or_reclassify must NOT claim "JSON array" for non-arrays ---


def test_empty_body_with_json_ct_raises_pos_not_found_not_array_message() -> None:
    """[00] body:x on an empty body (Content-Type: application/json) must raise
    POS_NOT_FOUND, not UNSUPPORTED_BODY with a misleading 'JSON array' message."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:x")
    # Must NOT be reclassified as UNSUPPORTED_BODY (that would be the bug)
    assert ei.value.code == "POS_NOT_FOUND"
    # Must NOT claim the body is a JSON array
    assert "array" not in str(ei.value).lower()


def test_whitespace_only_body_with_json_ct_raises_pos_not_found() -> None:
    """[00] body:x on a whitespace-only body must also raise POS_NOT_FOUND, not the
    array UNSUPPORTED_BODY — whitespace is not an array."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b"   \r\n"
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:x")
    assert ei.value.code == "POS_NOT_FOUND"
    assert "array" not in str(ei.value).lower()


def test_json_scalar_number_body_raises_pos_not_found_not_array_message() -> None:
    """[00] body:x on a JSON scalar number (42) must NOT claim 'JSON array'."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b"42"
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:x")
    # code can be POS_NOT_FOUND or UNSUPPORTED_BODY, but must NOT say "array"
    assert "array" not in str(ei.value).lower()


def test_json_scalar_string_body_raises_without_array_message() -> None:
    """[00] body:x on a JSON scalar string ("hello") must NOT claim 'JSON array'."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'"hello"'
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:x")
    assert "array" not in str(ei.value).lower()


def test_json_array_body_still_raises_unsupported_body_mentioning_array() -> None:
    """[00] regression: a real JSON array body must still raise UNSUPPORTED_BODY
    with a message that mentions 'array'."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b"[1,2,3]"
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:x")
    assert ei.value.code == "UNSUPPORTED_BODY"
    assert "array" in str(ei.value).lower()


def test_json_object_body_resolves_correctly_after_fix() -> None:
    """[00] regression: a valid JSON object body must still resolve normally after fix."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"id":99}'
    )
    p = resolve_pos(req, "body:id")
    assert req[p.start : p.end] == b"99"


# --- [A] form body with leading whitespace must still resolve ---


def test_form_body_leading_spaces_resolves_field() -> None:
    """[A] body:a on a form body with leading spaces must find field 'a'.

    Before the fix, _resolve_form passes the raw body to _scan_kv which does a
    byte-exact key comparison; '   a=b' fails to match key 'a' because the segment
    is '   a', not 'a'.  After the fix, leading whitespace is stripped before the
    key scan and the returned offsets still point at the correct bytes in raw.
    """
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"   a=b"
    )
    p = resolve_pos(req, "body:a")
    assert req[p.start : p.end] == b"b"


def test_form_body_leading_spaces_offset_is_original_relative() -> None:
    """[A] resolved offsets must be relative to the original raw bytes, not the stripped body."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"   a=hello"
    )
    p = resolve_pos(req, "body:a")
    # The slice using the returned offsets must yield the value bytes in the original request.
    assert req[p.start : p.end] == b"hello"


def test_form_body_no_leading_spaces_still_resolves() -> None:
    """[A] regression: a normal form body (no leading whitespace) must still work."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"foo=bar&baz=qux"
    )
    p = resolve_pos(req, "body:foo")
    assert req[p.start : p.end] == b"bar"


def test_form_body_leading_spaces_second_field_resolves() -> None:
    """[A] a second field after leading-space prefix is also accessible."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"   a=1&b=2"
    )
    p = resolve_pos(req, "body:b")
    assert req[p.start : p.end] == b"2"


def test_form_body_missing_field_still_raises() -> None:
    """[A] regression: a missing field on a leading-space body still raises POS_NOT_FOUND."""
    req = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"   a=b"
    )
    with pytest.raises(PosError) as ei:
        resolve_pos(req, "body:missing")
    assert ei.value.code == "POS_NOT_FOUND"


# --- [00] cookie resolver: TAB (0x09) after ';' is valid OWS (RFC 6265 §4.2.1) ---


def test_cookie_tab_ows_finds_second_cookie() -> None:
    """[00] cookie:b on 'Cookie: a=1;\\tb=2' must resolve to b'2'.

    RFC 6265 §4.2.1 / RFC 7230 §3.2.3 define OWS = *(SP / HTAB).  A TAB
    after the ';' is valid optional whitespace; the resolver must skip it just
    like a plain space so that the key comparison hits 'b', not '\\tb'.
    """
    req = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1;\tb=2\r\n\r\n"
    p = resolve_pos(req, "cookie:b")
    assert req[p.start : p.end] == b"2"


def test_cookie_tab_ows_first_cookie_still_resolves() -> None:
    """[00] regression: the first cookie (no leading OWS) must still resolve correctly."""
    req = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1;\tb=2\r\n\r\n"
    p = resolve_pos(req, "cookie:a")
    assert req[p.start : p.end] == b"1"


def test_cookie_space_ows_still_resolves() -> None:
    """[00] regression: space OWS (existing behaviour) must still work after the TAB fix."""
    req = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1; b=2\r\n\r\n"
    p = resolve_pos(req, "cookie:b")
    assert req[p.start : p.end] == b"2"


def test_cookie_mixed_ows_tab_and_space() -> None:
    """[00] a TAB immediately followed by a space before the key must both be skipped."""
    req = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1;\t b=2\r\n\r\n"
    p = resolve_pos(req, "cookie:b")
    assert req[p.start : p.end] == b"2"
