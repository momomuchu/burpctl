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
    """[19] field 'b' absent from row 0 → ValueError, consistent with json behaviour."""
    with pytest.raises(ValueError):
        render([{"a": 1}, {"a": 2, "b": 3}], "table", fields=["b"])


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
    """[22] Both 'a' and 'b' columns must appear when rows have disjoint keys."""
    out = render([{"a": 1}, {"b": 2}], "table")
    header = out.splitlines()[0]
    assert "a" in header and "b" in header


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
    out = render({"status": "ok", "uptime": 42}, "table")
    assert "status" in out
    assert "ok" in out


def test_table_list_aligned_with_header() -> None:
    out = render([{"id": 1, "m": "GET"}, {"id": 2, "m": "POST"}], "table")
    lines = out.splitlines()
    assert lines[0].split()[:2] == ["id", "m"]
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
    """F6/OUTPUT.md: a null field is a blank cell, never the Python literal ``None``."""
    out = render({"burpVersion": None, "status": "ok"}, "table")
    line = next(ln for ln in out.splitlines() if ln.startswith("burpVersion"))
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
