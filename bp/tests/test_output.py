"""Tests for the output rendering layer (docs/OUTPUT.md)."""

import base64

import pytest

from bp.config import redact_data
from bp.output import render

# ---------------------------------------------------------------------------
# [19] & [20] — _render_table field validation must match _render_json
# ---------------------------------------------------------------------------


def test_table_unknown_field_raises_value_error() -> None:
    """[20] render(list, 'table', fields=['zzz']) must raise ValueError like json path."""
    with pytest.raises(ValueError):
        render([{"a": 1}], "table", fields=["zzz"])


def test_table_field_absent_from_first_row_raises_value_error() -> None:
    """[19] REVISED by [08]: field 'b' is in the union of row keys → no error; row missing
    it gets a blank cell.  The old over-strict behaviour (raise when absent from ANY row)
    was wrong per OUTPUT.md §2.1 which says unknown = absent from EVERY row (union-based).
    Test updated to the spec-correct expectation.
    """
    out = render([{"a": 1}, {"a": 2, "b": 3}], "table", fields=["b"])
    lines = out.splitlines()
    # Header must be 'B' (uppercase per [06])
    assert lines[0].strip() == "B"
    # First row has no 'b' key → blank body cell
    assert lines[1].strip() == ""
    # Second row has b=3
    assert lines[2].strip() == "3"


# ---------------------------------------------------------------------------
# [21] — _essential must not render None as the literal string 'None'
# ---------------------------------------------------------------------------


def test_quiet_none_essential_value_is_empty_string() -> None:
    """[21] render([{status: None}], 'quiet') → empty line, not 'None'."""
    assert render([{"status": None}], "quiet") == ""


def test_quiet_none_non_dict_item_renders_empty() -> None:
    """[21] A None item in a quiet list renders '' not 'None'."""
    assert render([None], "quiet") == ""


# ---------------------------------------------------------------------------
# [22] — _render_table column union across all rows (heterogeneous rows)
# ---------------------------------------------------------------------------


def test_table_heterogeneous_rows_include_all_columns() -> None:
    """[22] Both 'a' and 'b' columns must appear when rows have disjoint keys.
    Updated per [06-NEW]: header uses UPPERCASE names per OUTPUT.md §1.2 F-TABLE.
    """
    out = render([{"a": 1}, {"b": 2}], "table")
    header = out.splitlines()[0]
    assert "A" in header and "B" in header


# ---------------------------------------------------------------------------
# [23] — raw format on a list is a usage error; --fields with raw is also an error
# ---------------------------------------------------------------------------


def test_raw_list_raises_value_error() -> None:
    """[23] render(list, 'raw') must raise ValueError — OUTPUT.md §1.3 R-RAW-SINGLE."""
    with pytest.raises(ValueError, match="raw requires a single record"):
        render([{"a": 1}], "raw")


def test_raw_list_error_does_not_reference_index_flag() -> None:
    """[04] The raw-on-list error must NOT reference --index (non-existent flag).
    It must tell the user to use --format json instead."""
    with pytest.raises(ValueError) as exc_info:
        render([{"a": 1}], "raw")
    msg = str(exc_info.value)
    assert "--index" not in msg, f"message must not mention --index: {msg!r}"
    assert "--format json" in msg, f"message must suggest --format json: {msg!r}"


def test_raw_with_fields_raises_value_error() -> None:
    """[23] render(obj, 'raw', fields=[...]) must raise ValueError."""
    with pytest.raises(ValueError, match="--fields is not valid with --format raw"):
        render({"a": 1}, "raw", fields=["a"])


def _history_record() -> dict[str, object]:
    return {
        "id": 7,
        "source": "repeater",
        "method": "POST",
        "url": "https://example.test/a?q=1",
        "host": "example.test",
        "reqHeaders": [{"name": "Host", "value": "example.test"}],
        "reqBody": "hello",
        "statusCode": 201,
        "resHeaders": [{"name": "Content-Type", "value": "text/plain"}],
        "resBody": "world",
        "durationMs": 1,
        "timestamp": "2026-01-01T00:00:00Z",
    }


def test_raw_proxy_request_emits_http_request_and_response() -> None:
    """K33 ceiling: response `body` is a text projection, not verbatim binary-byte proof."""
    data = {
        "id": 3,
        "request": {
            "method": "GET",
            "url": "https://example.test/a?q=1",
            "headers": [{"name": "Host", "value": "example.test"}],
            "body": None,
            "bodyBase64": None,
        },
        "response": {
            "statusCode": 200,
            "headers": [{"name": "Content-Type", "value": "text/plain"}],
            "body": "ok",
        },
    }

    out = render(data, "raw", command_path="bp req")

    assert out.startswith(b"GET /a?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
    assert (
        b"\x1e\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok" in out
    )


def test_raw_proxy_request_null_body_base64_falls_back_to_text() -> None:
    data = {
        "id": 4,
        "request": {
            "method": "POST",
            "url": "https://example.test/a",
            "headers": [],
            "body": "café",
            "bodyBase64": None,
        },
        "response": None,
    }

    assert render(data, "raw", command_path="bp req").endswith(b"\r\n\r\ncaf\xc3\xa9")


def test_raw_body_base64_cannot_reconstruct_a_structurally_redacted_secret() -> None:
    """A duplicate encoded body cannot bypass masking of its text sibling."""
    secret = b"password=raw-body-secret"
    data = {
        "id": 5,
        "request": {
            "method": "POST",
            "url": "https://example.test/a",
            "headers": [],
            "body": secret.decode(),
            "bodyBase64": base64.b64encode(secret).decode(),
        },
        "response": None,
    }

    out = render(redact_data(data), "raw", command_path="bp req")

    assert secret not in out
    assert b"raw-body-secret" not in out
    assert b"password=***" in out


def test_raw_redaction_recomputes_content_length_from_emitted_bytes() -> None:
    secret = b"password=raw-body-secret"
    data = {
        "id": 6,
        "request": {
            "method": "POST",
            "url": "https://example.test/a",
            "headers": [{"name": "Content-Length", "value": str(len(secret))}],
            "body": secret.decode(),
            "bodyBase64": base64.b64encode(secret).decode(),
        },
        "response": None,
    }

    out = render(redact_data(data), "raw", command_path="bp req")
    head, body = out.split(b"\r\n\r\n", 1)

    assert body == b"password=***"
    assert f"Content-Length: {len(body)}".encode() in head.split(b"\r\n")
    assert f"Content-Length: {len(secret)}".encode() not in head.split(b"\r\n")


def test_raw_reconstruction_has_one_truthful_content_length_for_every_capture_shape() -> None:
    """Synthetic HTTP/1.1 framing describes emitted bytes, never captured framing metadata."""
    cases = [
        ({}, [], None),
        ({"body": ""}, [], 0),
        ({"body": "abc"}, [], 3),
        (
            {"body": "abc", "httpVersion": "HTTP/2"},
            [{"name": "Content-Length", "value": "999"}],
            3,
        ),
        (
            {"body": "abc"},
            [
                {"name": "Transfer-Encoding", "value": "chunked"},
                {"name": "Trailer", "value": "X-Checksum"},
                {"name": "X-Checksum", "value": "secret-trailer"},
                {"name": "Content-Length", "value": "1"},
                {"name": "Content-Length", "value": "2"},
            ],
            3,
        ),
    ]
    for body_fields, headers, expected_length in cases:
        data = {
            "request": {
                "method": "POST",
                "url": "https://example.test/a",
                "headers": headers,
                **body_fields,
            },
            "response": None,
        }

        out = render(data, "raw", command_path="bp req")
        head, body = out.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        content_lengths = [line for line in lines if line.lower().startswith(b"content-length:")]

        assert not any(line.lower().startswith(b"transfer-encoding:") for line in lines)
        assert not any(line.lower().startswith(b"trailer:") for line in lines)
        assert not any(line.lower().startswith(b"x-checksum:") for line in lines)
        if expected_length is None:
            assert content_lengths == []
        else:
            assert content_lengths == [f"Content-Length: {len(body)}".encode()]
            assert len(body) == expected_length


def test_raw_bodyless_response_preserves_representation_content_length() -> None:
    """HEAD/304 metadata is true even though no response body bytes were captured."""
    data = {
        "request": {"method": "HEAD", "url": "https://example.test/a", "headers": []},
        "response": {
            "statusCode": 200,
            "headers": [{"name": "Content-Length", "value": "24"}],
            "body": None,
        },
    }

    out = render(data, "raw", command_path="bp req")

    assert b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n" in out


def test_raw_reconstruction_preserves_an_empty_query_delimiter() -> None:
    data = {
        "request": {
            "method": "GET",
            "url": "https://example.test/a?",
            "headers": [],
        },
        "response": None,
    }

    out = render(data, "raw", command_path="bp req")

    assert out.startswith(b"GET /a? HTTP/1.1\r\n")


def test_raw_send_emits_response_only() -> None:
    data = {
        "request": {"method": "GET", "url": "https://example.test/", "headers": []},
        "response": {"statusCode": 204, "headers": [], "body": None},
    }
    assert render(data, "raw", command_path="bp send") == b"HTTP/1.1 204 No Content\r\n\r\n"


def test_raw_history_get_emits_stored_request_and_response() -> None:
    out = render(_history_record(), "raw", command_path="bp history get")
    assert out.startswith(b"POST /a?q=1 HTTP/1.1")
    assert b"\r\n\r\nhello\r\n\x1e\r\nHTTP/1.1 201 Created" in out
    assert out.endswith(b"\r\n\r\nworld")


def test_raw_history_replay_emits_replayed_request_and_response() -> None:
    record = _history_record()
    out = render(
        {"original": {**record, "statusCode": 418}, "replayed": record},
        "raw",
        command_path="bp history replay",
    )
    assert b"HTTP/1.1 201 Created" in out
    assert b"418" not in out


# ---------------------------------------------------------------------------
# [07] — quiet format with --fields is a usage error (silently ignored before fix)
# ---------------------------------------------------------------------------


def test_quiet_with_fields_raises_value_error() -> None:
    """[07] render(obj, 'quiet', fields=[...]) must raise ValueError mentioning quiet.

    Before the fix, quiet silently ignored --fields and returned the essential
    value (status=200) instead of honouring the requested field ('id').
    This is a usage error parallel to the existing raw+fields guard.
    """
    with pytest.raises(ValueError, match="--fields is not valid with --format quiet"):
        render({"id": 42, "status": 200}, "quiet", fields=["id"])


def test_quiet_with_fields_list_raises_value_error() -> None:
    """[07] quiet+fields on a list input also raises ValueError."""
    with pytest.raises(ValueError, match="--fields is not valid with --format quiet"):
        render([{"id": 1}, {"id": 2}], "quiet", fields=["id"])


def test_quiet_without_fields_still_works() -> None:
    """[07] quiet with no fields argument is unaffected by the guard."""
    assert render({"id": 42, "status": 200}, "quiet") == "200"


def test_quiet_fields_none_explicit_still_works() -> None:
    """[07] quiet with fields=None (explicit) is the same as omitting fields."""
    assert render({"status": "ok"}, "quiet", fields=None) == "ok"


def test_json_dict_is_compact() -> None:
    assert render({"a": 1, "b": 2}, "json") == '{"a":1,"b":2}'


def test_json_list_is_ndjson() -> None:
    assert render([{"id": 1}, {"id": 2}], "json") == '{"id":1}\n{"id":2}'


def test_table_dict_key_value() -> None:
    # [06-NEW] Dict-form table renders key column UPPERCASE per OUTPUT.md §1.2 F-TABLE.
    out = render({"status": "ok", "uptime": 42}, "table")
    assert "STATUS" in out
    assert "ok" in out


def test_table_list_aligned_with_header() -> None:
    # [06-NEW] Header is UPPERCASE per OUTPUT.md §1.2 F-TABLE.
    out = render([{"id": 1, "m": "GET"}, {"id": 2, "m": "POST"}], "table")
    lines = out.splitlines()
    assert lines[0].split()[:2] == ["ID", "M"]
    assert len(lines) == 3  # header + 2 rows


def test_quiet_picks_essential_value() -> None:
    assert render({"status": "ok", "x": 1}, "quiet") == "ok"


def test_quiet_list_one_per_line() -> None:
    assert render([{"id": 1}, {"id": 2}], "quiet") == "1\n2"


@pytest.mark.parametrize(
    ("command_path", "data", "expected"),
    [
        (
            "bp collab new",
            {"payloads": [{"payload": "abc.oastify.com", "interactionId": "abc"}]},
            "abc.oastify.com",
        ),
        ("bp collab poll", {"found": False, "interactions": []}, "none"),
        (
            "bp collab poll",
            {"found": True, "interactions": [{"id": "interaction-7"}]},
            "interaction-7",
        ),
        ("bp scope check", {"url": "https://t", "inScope": True}, "in-scope"),
        ("bp scope check", {"url": "https://t", "inScope": False}, "out-of-scope"),
        ("bp scope add", {"url": "https://t", "inScope": True}, ""),
        ("bp scope remove", {"url": "https://t", "inScope": False}, ""),
        ("bp config get project", {"config": {"nested": True}}, ""),
        ("bp config get user", {"config": {"nested": True}}, ""),
        ("bp config set user", {"config": {"nested": True}}, ""),
        ("bp ext", {"extensions": [{"name": "burp-rest"}], "total": 1}, ""),
        (
            "bp scan issues",
            {"scanId": "scan-7", "issues": [{"severity": "HIGH", "name": "SQLi"}], "total": 1},
            "HIGH",
        ),
        ("bp scan issues", {"scanId": "scan-8", "issues": None, "total": None}, ""),
        ("bp proxy", [{"id": 7, "status": 500}], "7"),
        ("bp req", {"id": 8, "status": 404}, "8"),
        ("bp history list", [{"id": 9, "statusCode": 201}], "9"),
        ("bp history get", {"id": 10, "statusCode": 202}, "10"),
        ("bp log", [{"id": "op-11", "status": "ok"}], "op-11"),
        ("bp tag", {"id": "op-12", "tag": "reviewed", "status": "tagged"}, "op-12"),
    ],
)
def test_command_specific_quiet_contract(command_path: str, data: object, expected: str) -> None:
    """C3: quiet emits the command's stable scalar, never a wrapper or Python repr."""
    assert render(data, "quiet", command_path=command_path) == expected


@pytest.mark.parametrize(
    "command_path",
    [
        "bp version",
        "bp ws",
        "bp intercept",
        "bp tab",
        "bp scan crawl",
        "bp scan audit",
        "bp scan all",
        "bp scan status",
        "bp scan defs",
        "bp scope show",
        "bp scope set",
        "bp scope add",
        "bp scope remove",
        "bp sitemap",
        "bp encode",
        "bp decode",
        "bp hash",
        "bp config get project",
        "bp config get user",
        "bp config set project",
        "bp config set user",
        "bp ext",
        "bp session set",
        "bp session get",
        "bp session clear",
        "bp session send",
        "bp session cookies",
        "bp diff",
        "bp endpoints",
        "bp history sitemap",
        "bp history replay",
        "bp history clear",
    ],
)
def test_quiet_without_documented_essential_never_invents_one(command_path: str) -> None:
    """D33 gap: undefined quiet contracts are silent rather than heuristic assertions."""
    data = {"status": "invented-status", "enabled": True, "nested": [{"value": 7}]}

    assert render(data, "quiet", command_path=command_path) == ""


def test_quiet_generic_nested_value_is_json_not_python_repr() -> None:
    assert render({"wrapper": {"enabled": True}}, "quiet") == '{"enabled":true}'


def test_quiet_generic_boolean_is_lowercase() -> None:
    assert render({"enabled": True}, "quiet") == "true"


def test_collaborator_generation_fields_address_payload_records() -> None:
    data = {
        "payloads": [
            {"id": "a", "payload": "a.oastify.com", "interactionId": "a"},
            {"id": "b", "payload": "b.oastify.com", "interactionId": "b"},
        ]
    }
    assert render(
        data,
        "json",
        fields=["payload", "id"],
        command_path="bp collab new",
    ) == ('{"payload":"a.oastify.com","id":"a"}\n{"payload":"b.oastify.com","id":"b"}')


def test_collaborator_poll_fields_address_interaction_records() -> None:
    data = {
        "found": True,
        "interactions": [
            {
                "id": "i-7",
                "type": "DNS",
                "clientIp": "127.0.0.1",
                "timestamp": "2026-09-04T00:00:00Z",
            }
        ],
        "queriedPayloadId": "p-7",
    }
    assert (
        render(
            data,
            "json",
            fields=["interactionId", "type", "clientIp", "timestamp"],
            command_path="bp collab poll",
        )
        == '{"interactionId":"i-7","type":"DNS","clientIp":"127.0.0.1","timestamp":"2026-09-04T00:00:00Z"}'
    )


def test_fields_selects_and_orders() -> None:
    assert render({"a": 1, "b": 2, "c": 3}, "json", fields=["c", "a"]) == '{"c":3,"a":1}'


def test_unknown_field_raises_usage_error() -> None:
    """OUTPUT.md §2.1: an unknown --fields name is a usage error, not a silent ``None`` value."""
    with pytest.raises(ValueError):
        render({"a": 1, "b": 2}, "json", fields=["nope"])


def test_known_field_subset_ok() -> None:
    assert render({"a": 1, "b": 2}, "json", fields=["a"]) == '{"a":1}'


def test_table_renders_none_as_blank_not_literal_none() -> None:
    """F6/OUTPUT.md: a null field is a blank cell, never the Python literal ``None``.
    Updated per [06-NEW]: key column is UPPERCASE, so line starts with 'BURPVERSION'.
    """
    out = render({"burpVersion": None, "status": "ok"}, "table")
    line = next(ln for ln in out.splitlines() if ln.startswith("BURPVERSION"))
    assert "None" not in line


def test_table_renders_nested_dict_as_json_not_python_repr() -> None:
    """F6: nested dict/list values render as compact JSON, not Python repr with single quotes."""
    out = render({"config": {"type": "project"}}, "table")
    assert '{"type":"project"}' in out
    assert "'type'" not in out  # no Python repr leak


def test_table_list_renders_none_and_dict_cleanly() -> None:
    """F6: the list/aligned table path gets the same clean-cell treatment as the dict path."""
    out = render([{"id": 1, "meta": {"k": "v"}}, {"id": 2, "meta": None}], "table")
    assert "'k'" not in out and "None" not in out
    assert '{"k":"v"}' in out


# ---------------------------------------------------------------------------
# [06] — quiet format on all-None/empty list must produce '' not '\n'
# ---------------------------------------------------------------------------


def test_quiet_all_none_essential_multi_row_returns_empty_string() -> None:
    """[06] render with all-None essential values → '' not '\\n' (no spurious blank line)."""
    result = render([{"status": None}, {"status": None}], "quiet")
    assert result == "", f"expected '' but got {result!r}"


def test_quiet_all_empty_essential_multi_row_returns_empty_string() -> None:
    """[06] render with all-empty essential values → '' not '\\n'."""
    result = render([{"unknown_key_xyz": None}, {"unknown_key_xyz": None}], "quiet")
    assert result == "", f"expected '' but got {result!r}"


def test_quiet_mixed_none_and_value_preserves_interior_blank() -> None:
    """[06] ['a', None] → 'a\\n' — the value row is present; the blank is an interior gap."""
    result = render([{"status": "a"}, {"status": None}], "quiet")
    assert result == "a\n", f"expected 'a\\n' but got {result!r}"


def test_quiet_value_none_value_preserves_interior_blank() -> None:
    """[06] [value, None, value] → interior blank line kept ('a\\n\\nb')."""
    result = render([{"status": "a"}, {"status": None}, {"status": "b"}], "quiet")
    assert result == "a\n\nb", f"expected 'a\\n\\nb' but got {result!r}"


# ---------------------------------------------------------------------------
# [08] — _cell() must render bool as JSON-style 'true'/'false', not Python 'True'/'False'
# ---------------------------------------------------------------------------


def test_cell_true_renders_lowercase_true() -> None:
    """[08] _cell(True) must return 'true' (JSON-style), not Python 'True'."""
    from bp.output import _cell

    assert _cell(True) == "true"


def test_cell_false_renders_lowercase_false() -> None:
    """[08] _cell(False) must return 'false' (JSON-style), not Python 'False'."""
    from bp.output import _cell

    assert _cell(False) == "false"


def test_cell_int_zero_unchanged() -> None:
    """[08] bool is a subclass of int; int 0 must still render as '0', not 'false'."""
    from bp.output import _cell

    assert _cell(0) == "0"


def test_cell_int_one_unchanged() -> None:
    """[08] int 1 must still render as '1', not 'true'."""
    from bp.output import _cell

    assert _cell(1) == "1"


def test_table_bool_column_renders_lowercase() -> None:
    """[08] A table row with a boolean column must show 'true'/'false', not 'True'/'False'."""
    out = render([{"active": True, "deleted": False}], "table")
    assert "true" in out
    assert "false" in out
    assert "True" not in out
    assert "False" not in out


def test_table_dict_bool_value_renders_lowercase() -> None:
    """[08] Single-record dict table with bool value must render lowercase."""
    out = render({"enabled": True}, "table")
    assert "true" in out
    assert "True" not in out


# ---------------------------------------------------------------------------
# [06-NEW] — table header row must be UPPERCASE (OUTPUT.md §1.2 F-TABLE)
# ---------------------------------------------------------------------------


def test_table_header_is_uppercase_list() -> None:
    """[06-NEW] Header line must be uppercase field names; body rows unchanged."""
    out = render([{"status": 200, "url": "http://x"}], "table")
    lines = out.splitlines()
    header = lines[0]
    assert "STATUS" in header
    assert "URL" in header
    # lowercase versions must NOT appear in the header (only in body)
    assert "status" not in header
    assert "url" not in header
    # body row still has the raw value (not uppercased)
    body = lines[1]
    assert "200" in body
    assert "http://x" in body


def test_table_header_uppercase_single_dict() -> None:
    """[06-NEW] Dict-form table also renders keys uppercase in the key column."""
    out = render({"status": "ok", "host": "example.com"}, "table")
    # In dict-form the key is the left column; it must be uppercase.
    assert "STATUS" in out
    assert "HOST" in out
    assert "status" not in out
    assert "host" not in out


def test_table_header_uppercase_with_fields() -> None:
    """[06-NEW] Header must still be uppercase when --fields restricts columns."""
    out = render([{"a": 1, "b": 2, "c": 3}], "table", fields=["b", "a"])
    header = out.splitlines()[0]
    assert "B" in header and "A" in header
    assert "b" not in header and "a" not in header


# ---------------------------------------------------------------------------
# [07-NEW] — --fields matching is case-insensitive; output uses canonical casing
#             (OUTPUT.md §2.1 R-FIELDS)
# ---------------------------------------------------------------------------


def test_fields_case_insensitive_selects_lowercase_key_json() -> None:
    """[07-NEW] --fields STATUS on record with key 'status' selects it; renders as 'status'."""
    out = render({"status": 200, "url": "http://x"}, "json", fields=["STATUS"])
    assert out == '{"status":200}'


def test_fields_case_insensitive_selects_lowercase_key_table() -> None:
    """[07-NEW] --fields STATUS in table: header UPPERCASE, body value present."""
    out = render([{"status": 200}], "table", fields=["STATUS"])
    lines = out.splitlines()
    assert "STATUS" in lines[0]
    assert "200" in lines[1]


def test_fields_mixed_case_selects_multiple_keys() -> None:
    """[07-NEW] --fields ID,Url matches 'id' and 'url'; canonical (lowercase) keys used."""
    out = render({"id": 1, "url": "http://x", "method": "GET"}, "json", fields=["ID", "Url"])
    assert out == '{"id":1,"url":"http://x"}'


def test_fields_case_insensitive_canonical_casing_in_table_body() -> None:
    """[07-NEW] Canonical key casing (not the requested casing) is used in table body."""
    out = render([{"contentType": "text/html"}], "table", fields=["CONTENTTYPE"])
    lines = out.splitlines()
    # Header must be CONTENTTYPE (uppercase of canonical key 'contentType')
    assert "CONTENTTYPE" in lines[0]
    # Body must have the value
    assert "text/html" in lines[1]


def test_fields_unknown_still_raises_on_json() -> None:
    """[07-NEW] A truly unknown field (any case) still raises ValueError."""
    with pytest.raises(ValueError):
        render({"status": 200}, "json", fields=["NOSUCHFIELD"])


def test_fields_unknown_still_raises_on_table() -> None:
    """[07-NEW] A truly unknown field raises ValueError on table path too."""
    with pytest.raises(ValueError):
        render([{"status": 200}], "table", fields=["NOSUCHFIELD"])


# ---------------------------------------------------------------------------
# [08-NEW] — unknown field = absent from ALL rows (union-based); per-row absent
#             → blank cell, no error  (OUTPUT.md §2.1 R-FIELDS)
# ---------------------------------------------------------------------------


def test_fields_union_absent_from_one_row_no_error_table() -> None:
    """[08-NEW] 'b' is in union of keys → no error; row missing 'b' gets blank cell."""
    out = render([{"a": 1, "b": 2}, {"a": 3}], "table", fields=["b"])
    lines = out.splitlines()
    assert lines[0].strip() == "B"  # uppercase header
    assert lines[1].strip() == "2"  # first row has b=2
    assert lines[2].strip() == ""  # second row: b absent → blank


def test_fields_union_absent_from_one_row_no_error_json() -> None:
    """[08-NEW] json path: 'b' in union → row missing it renders as null, no error."""
    out = render([{"a": 1, "b": 2}, {"a": 3}], "json", fields=["b"])
    lines = out.splitlines()
    assert lines[0] == '{"b":2}'
    assert lines[1] == '{"b":null}'


def test_fields_genuinely_unknown_raises_with_union_valid_list() -> None:
    """[08-NEW] 'zzz' absent from ALL rows → ValueError; valid list shows union {a, b}."""
    with pytest.raises(ValueError, match="zzz") as exc_info:
        render([{"a": 1, "b": 2}, {"a": 3}], "table", fields=["zzz"])
    msg = str(exc_info.value)
    assert "a" in msg and "b" in msg


def test_fields_genuinely_unknown_json_raises_with_union_valid_list() -> None:
    """[08-NEW] json path: 'zzz' absent from ALL rows → ValueError with union in message."""
    with pytest.raises(ValueError, match="zzz") as exc_info:
        render([{"a": 1, "b": 2}, {"a": 3}], "json", fields=["zzz"])
    msg = str(exc_info.value)
    assert "a" in msg and "b" in msg


def test_fields_union_mixed_absent_blank_json() -> None:
    """[08-NEW] Multiple rows, field in some but not all → blank (null) for missing, no error."""
    records = [{"a": 1}, {"a": 2, "b": 99}, {"a": 3}]
    out = render(records, "json", fields=["b"])
    lines = out.splitlines()
    assert lines[0] == '{"b":null}'
    assert lines[1] == '{"b":99}'
    assert lines[2] == '{"b":null}'


def test_empty_list_with_fields_is_empty_in_both_json_and_table() -> None:
    """Round-8: an empty result set + --fields must return '' (exit 0) in BOTH formats —
    json previously raised 'unknown field' while table returned '' (OUTPUT.md A1 parity)."""
    assert render([], "json", fields=["status"]) == ""
    assert render([], "table", fields=["status"]) == ""


# ---------------------------------------------------------------------------
# [07] — _render_json: non-empty list with no dict rows + --fields is a usage error
# ---------------------------------------------------------------------------


def test_json_fields_empty_list_returns_empty_string() -> None:
    """[07] Truly empty list + --fields → '' (exit 0). Round-8 parity must not regress."""
    assert render([], "json", fields=["x"]) == ""


def test_json_fields_nonempty_non_dict_list_raises_value_error() -> None:
    """[07] Non-empty list with NO dict rows + --fields → ValueError (usage error).

    Before the fix, _select_list_rows([], fields) short-circuited to [] and the
    --fields flag was silently ignored.  Per OUTPUT.md §2.1 R-FIELDS, an unknown
    field must be a usage error; a non-dict-only list has no field schema to honor.
    """
    with pytest.raises(ValueError, match="--fields"):
        render(["a", "b"], "json", fields=["x"])


def test_json_fields_nonempty_non_dict_list_single_item_raises() -> None:
    """[07] Single non-dict item in list + --fields → ValueError, not silent."""
    with pytest.raises(ValueError):
        render([42], "json", fields=["status"])


def test_json_fields_nonempty_non_dict_list_none_items_raises() -> None:
    """[07] List of None values + --fields → ValueError (no dict rows to honor --fields)."""
    with pytest.raises(ValueError):
        render([None, None], "json", fields=["status"])


def test_json_fields_mixed_dict_and_non_dict_still_works() -> None:
    """[07] A list with at least one dict row + --fields should NOT raise.

    Only the pure-non-dict case is the bug; mixed lists with dicts
    go through _select_list_rows normally.
    """
    # Has one dict row → no error; non-dict items pass through without field selection
    out = render([{"status": 200}, "extra"], "json", fields=["status"])
    assert '{"status":200}' in out


def test_json_no_fields_nonempty_non_dict_list_still_works() -> None:
    """[07] Non-dict list without --fields is untouched (no regression)."""
    out = render(["a", "b"], "json")
    assert out == '"a"\n"b"'
