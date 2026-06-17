"""Tests for the output rendering layer (docs/OUTPUT.md)."""

import pytest

from bp.output import render


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
