"""Tests for bp history commands — findings [34], [35], [37].

RED-first (TDD per project disciplines):
  [34] history list unwraps entries so --fields id,url works on entry-level fields.
  [35] _history_rows() flattens each entry to {id, method, url, statusCode} (no blob).
  [37] history get default projection excludes reqHeaders/resHeaders blobs.
"""

from __future__ import annotations

import pytest

from bp.commands.history import _history_rows
from bp.models import HistoryEntryResponse, HistoryPageResponse


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

ENTRY_DICT: dict = {
    "id": 42,
    "source": "proxy",
    "method": "GET",
    "url": "http://example.com/api",
    "host": "example.com",
    "reqHeaders": [{"name": "Host", "value": "example.com"}],
    "reqBody": None,
    "statusCode": 200,
    "resHeaders": [{"name": "Content-Type", "value": "application/json"}],
    "resBody": '{"ok":true}',
    "durationMs": 123,
    "timestamp": "2026-06-19T10:00:00Z",
}

PAGE_DICT: dict = {
    "entries": [ENTRY_DICT],
    "total": 1,
    "page": 0,
    "pageSize": 50,
}


# ---------------------------------------------------------------------------
# [34] HistoryEntryResponse / HistoryPageResponse model validation
# ---------------------------------------------------------------------------


def test_history_entry_response_model_parses_flat_shape() -> None:
    """HistoryEntryResponse must parse the flat wire shape from the server."""
    entry = HistoryEntryResponse.model_validate(ENTRY_DICT)
    assert entry.id == 42
    assert entry.source == "proxy"
    assert entry.method == "GET"
    assert entry.url == "http://example.com/api"
    assert entry.host == "example.com"
    assert entry.statusCode == 200
    assert entry.durationMs == 123
    assert entry.timestamp == "2026-06-19T10:00:00Z"


def test_history_page_response_model_parses_page_shape() -> None:
    """HistoryPageResponse must parse the page-wrapper wire shape."""
    page = HistoryPageResponse.model_validate(PAGE_DICT)
    assert page.total == 1
    assert page.page == 0
    assert page.pageSize == 50
    assert len(page.entries) == 1
    assert page.entries[0].id == 42


def test_history_list_unwrapped_rows_accept_entry_level_fields() -> None:
    """[34] Unwrapped entry rows must contain entry-level keys (id, url) so that
    the output layer's --fields validation does NOT reject them.

    Previously the raw page dict {entries, total, page, pageSize} was passed
    to render(), so --fields id,url raised 'unknown field(s): id, url; valid: entries, total, ...'
    """
    from bp.output import render

    rows = _history_rows([ENTRY_DICT])
    # render must not raise ValueError for entry-level fields
    out = render(rows, "table", fields=["id", "url"])
    assert "42" in out
    assert "http://example.com/api" in out


def test_history_list_entry_fields_not_rejected_by_output_layer() -> None:
    """[34] Passing 'id' or 'url' to render() on a raw page dict raises ValueError;
    after the fix the unwrapped rows must accept those fields cleanly.
    """
    from bp.output import _select

    # Confirm the OLD behaviour was broken: the page wrapper dict does NOT have 'id'
    page_wrapper = {"entries": [], "total": 0, "page": 0, "pageSize": 50}
    with pytest.raises(ValueError, match="unknown field"):
        _select(page_wrapper, ["id", "url"])

    # With unwrapped entry rows, 'id' and 'url' are valid
    row = _history_rows([ENTRY_DICT])[0]
    selected = _select(row, ["id", "url"])
    assert selected == {"id": 42, "url": "http://example.com/api"}


# ---------------------------------------------------------------------------
# [35] _history_rows() flattening — no blob cells
# ---------------------------------------------------------------------------


def test_history_rows_produces_one_row_per_entry() -> None:
    """[35] _history_rows() must yield exactly one dict per entry."""
    rows = _history_rows([ENTRY_DICT, ENTRY_DICT])
    assert len(rows) == 2


def test_history_rows_contains_expected_columns() -> None:
    """[35] Each row must have id, method, url, statusCode."""
    row = _history_rows([ENTRY_DICT])[0]
    assert row["id"] == 42
    assert row["method"] == "GET"
    assert row["url"] == "http://example.com/api"
    assert row["statusCode"] == 200


def test_history_rows_excludes_header_blob_columns() -> None:
    """[35] reqHeaders and resHeaders must NOT appear in display rows (no giant blob cell)."""
    row = _history_rows([ENTRY_DICT])[0]
    assert "reqHeaders" not in row
    assert "resHeaders" not in row
    assert "reqBody" not in row
    assert "resBody" not in row


def test_history_rows_table_render_has_no_blob() -> None:
    """[35] Table render of _history_rows output must not contain raw JSON array blob."""
    from bp.output import render

    rows = _history_rows([ENTRY_DICT])
    out = render(rows, "table")
    # The header blob would look like [{"name":... — must not appear
    assert '[{"name"' not in out
    # Essential columns are present
    assert "GET" in out
    assert "42" in out


def test_history_rows_handles_missing_status() -> None:
    """[35] Entry with no statusCode renders None gracefully."""
    entry = {**ENTRY_DICT, "statusCode": None}
    row = _history_rows([entry])[0]
    assert row["statusCode"] is None


def test_history_rows_empty_list() -> None:
    """[35] Empty input yields empty list."""
    assert _history_rows([]) == []


# ---------------------------------------------------------------------------
# [37] history get default projection excludes blob fields
# ---------------------------------------------------------------------------


def test_history_get_display_projection_excludes_blobs() -> None:
    """[37] The display projection for a single entry must exclude reqHeaders/resHeaders blobs."""
    from bp.commands.history import _history_entry_display

    proj = _history_entry_display(ENTRY_DICT)
    assert "reqHeaders" not in proj
    assert "resHeaders" not in proj
    assert "reqBody" not in proj
    assert "resBody" not in proj


def test_history_get_display_projection_includes_core_fields() -> None:
    """[37] Display projection must include id, source, method, url, host, statusCode,
    durationMs, timestamp — the fields documented for 'history get' default output.
    """
    from bp.commands.history import _history_entry_display

    proj = _history_entry_display(ENTRY_DICT)
    assert proj["id"] == 42
    assert proj["source"] == "proxy"
    assert proj["method"] == "GET"
    assert proj["url"] == "http://example.com/api"
    assert proj["host"] == "example.com"
    assert proj["statusCode"] == 200
    assert proj["durationMs"] == 123
    assert proj["timestamp"] == "2026-06-19T10:00:00Z"


def test_history_get_display_table_render_has_no_blob() -> None:
    """[37] Table render of _history_entry_display must not show JSON blob values."""
    from bp.commands.history import _history_entry_display
    from bp.output import render

    proj = _history_entry_display(ENTRY_DICT)
    out = render(proj, "table")
    assert '[{"name"' not in out
    assert "id" in out
