"""Tests for the output rendering layer (docs/OUTPUT.md)."""

import pytest

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
    from bp.output import _cell  # type: ignore[attr-defined]

    assert _cell(True) == "true"


def test_cell_false_renders_lowercase_false() -> None:
    """[08] _cell(False) must return 'false' (JSON-style), not Python 'False'."""
    from bp.output import _cell  # type: ignore[attr-defined]

    assert _cell(False) == "false"


def test_cell_int_zero_unchanged() -> None:
    """[08] bool is a subclass of int; int 0 must still render as '0', not 'false'."""
    from bp.output import _cell  # type: ignore[attr-defined]

    assert _cell(0) == "0"


def test_cell_int_one_unchanged() -> None:
    """[08] int 1 must still render as '1', not 'true'."""
    from bp.output import _cell  # type: ignore[attr-defined]

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
    assert lines[0].strip() == "B"   # uppercase header
    assert lines[1].strip() == "2"   # first row has b=2
    assert lines[2].strip() == ""    # second row: b absent → blank


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
