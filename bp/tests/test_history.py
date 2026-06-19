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
    # Table headers/keys are uppercase per OUTPUT.md §1.2 F-TABLE.
    assert "ID" in out


# ---------------------------------------------------------------------------
# [12] history replay default output must not leak headers/bodies
# ---------------------------------------------------------------------------

ENTRY_WITH_SECRETS: dict = {
    "id": 7,
    "source": "proxy",
    "method": "POST",
    "url": "http://target.example.com/login",
    "host": "target.example.com",
    "reqHeaders": [
        {"name": "Cookie", "value": "session=abc123secret"},
        {"name": "Authorization", "value": "Bearer tok_supersecret"},
    ],
    "reqBody": "username=admin&password=hunter2",
    "statusCode": 200,
    "resHeaders": [
        {"name": "Set-Cookie", "value": "session=newsecret; HttpOnly"},
    ],
    "resBody": '{"token":"jwt_verysecret"}',
    "durationMs": 55,
    "timestamp": "2026-06-19T09:00:00Z",
}

REPLAY_RESPONSE: dict = {
    "original": ENTRY_WITH_SECRETS,
    "replayed": {**ENTRY_WITH_SECRETS, "id": 0, "source": "replay", "statusCode": 201},
}


def test_replay_display_excludes_blobs() -> None:
    """[12] _replay_display must strip reqHeaders/resHeaders/reqBody/resBody from both entries."""
    from bp.commands.history import _replay_display

    result = _replay_display(REPLAY_RESPONSE)
    for key in ("original", "replayed"):
        entry = result[key]
        assert "reqHeaders" not in entry, f"{key}: reqHeaders leaked"
        assert "resHeaders" not in entry, f"{key}: resHeaders leaked"
        assert "reqBody" not in entry, f"{key}: reqBody leaked"
        assert "resBody" not in entry, f"{key}: resBody leaked"


def test_replay_display_includes_core_fields() -> None:
    """[12] _replay_display must include id/source/method/url/host/statusCode/durationMs/timestamp."""
    from bp.commands.history import _replay_display

    result = _replay_display(REPLAY_RESPONSE)
    orig = result["original"]
    assert orig["id"] == 7
    assert orig["source"] == "proxy"
    assert orig["method"] == "POST"
    assert orig["url"] == "http://target.example.com/login"
    assert orig["host"] == "target.example.com"
    assert orig["statusCode"] == 200
    assert orig["durationMs"] == 55
    assert orig["timestamp"] == "2026-06-19T09:00:00Z"

    repl = result["replayed"]
    assert repl["id"] == 0
    assert repl["source"] == "replay"
    assert repl["statusCode"] == 201


def test_replay_display_cookie_value_not_in_rendered_output() -> None:
    """[12] Cookie/Authorization values must NOT appear in default table render of replay output."""
    from bp.commands.history import _replay_display
    from bp.output import render

    projected = _replay_display(REPLAY_RESPONSE)
    out = render(projected, "table")
    assert "abc123secret" not in out, "Cookie value leaked in table output"
    assert "tok_supersecret" not in out, "Authorization value leaked in table output"
    assert "newsecret" not in out, "Set-Cookie value leaked in table output"
    assert "hunter2" not in out, "Request body leaked in table output"
    assert "jwt_verysecret" not in out, "Response body leaked in table output"


def test_replay_display_essential_fields_present_in_rendered_output() -> None:
    """[12] id, method, url, statusCode must be visible in the default table render."""
    from bp.commands.history import _replay_display
    from bp.output import render

    projected = _replay_display(REPLAY_RESPONSE)
    out = render(projected, "table")
    assert "7" in out, "original id missing from output"
    assert "POST" in out, "method missing from output"
    assert "target.example.com" in out, "host/url missing from output"
    assert "200" in out, "original statusCode missing from output"


# ---------------------------------------------------------------------------
# [17] _replay_display defensive validation — no bare KeyError on bad shape
# ---------------------------------------------------------------------------


def test_replay_display_missing_original_key_raises_validation_error_not_key_error() -> None:
    """[17] _replay_display({'status':'ok'}) — missing 'original'/'replayed' keys must NOT
    raise a bare KeyError (which leaks tracebacks).  It must raise pydantic.ValidationError
    so cliutil.run() catches it and emits a clean 'unexpected response shape' message.
    """
    from pydantic import ValidationError

    from bp.commands.history import _replay_display

    with pytest.raises(ValidationError):
        _replay_display({"status": "ok"})


def test_replay_display_missing_replayed_key_raises_validation_error_not_key_error() -> None:
    """[17] Replay response missing 'replayed' key must raise ValidationError, not KeyError."""
    from pydantic import ValidationError

    from bp.commands.history import _replay_display

    with pytest.raises(ValidationError):
        _replay_display({"original": ENTRY_WITH_SECRETS})


def test_replay_display_empty_dict_raises_validation_error_not_key_error() -> None:
    """[17] Empty replay response dict must raise ValidationError, not KeyError."""
    from pydantic import ValidationError

    from bp.commands.history import _replay_display

    with pytest.raises(ValidationError):
        _replay_display({})


def test_replay_display_well_formed_still_projects_correctly() -> None:
    """[17] A well-formed replay dict must still project both entries correctly after the fix."""
    from bp.commands.history import _replay_display

    result = _replay_display(REPLAY_RESPONSE)
    assert result["original"]["id"] == 7
    assert result["replayed"]["id"] == 0
    assert result["replayed"]["source"] == "replay"


# ---------------------------------------------------------------------------
# [12] HistoryEntryResponse.reqHeaders required — no silent [] default
# ---------------------------------------------------------------------------


def test_history_entry_missing_req_headers_raises_validation_error() -> None:
    """[12] reqHeaders is non-nullable/no-default in Kotlin — a payload missing it must
    raise pydantic.ValidationError (not silently yield []).
    """
    from pydantic import ValidationError

    payload = {k: v for k, v in ENTRY_DICT.items() if k != "reqHeaders"}
    with pytest.raises(ValidationError):
        HistoryEntryResponse.model_validate(payload)


def test_history_entry_complete_payload_still_validates() -> None:
    """[12] A complete payload including reqHeaders must still validate without error."""
    entry = HistoryEntryResponse.model_validate(ENTRY_DICT)
    assert entry.reqHeaders[0].name == "Host"


def test_history_entry_empty_req_headers_list_is_valid() -> None:
    """[12] reqHeaders=[] (empty list) is a valid non-nullable value and must parse fine."""
    payload = {**ENTRY_DICT, "reqHeaders": []}
    entry = HistoryEntryResponse.model_validate(payload)
    assert entry.reqHeaders == []


# ---------------------------------------------------------------------------
# [11] HistoryPageResponse.entries required — no spurious [] default
# ---------------------------------------------------------------------------


def test_history_page_missing_entries_raises_validation_error() -> None:
    """[11] entries is non-nullable/no-default in Kotlin HistoryPageResponse —
    a payload missing 'entries' must raise pydantic.ValidationError, not silently
    yield an empty list.
    """
    from pydantic import ValidationError

    payload = {k: v for k, v in PAGE_DICT.items() if k != "entries"}
    with pytest.raises(ValidationError):
        HistoryPageResponse.model_validate(payload)


def test_history_page_complete_payload_still_validates() -> None:
    """[11] A complete HistoryPageResponse payload including entries must still validate."""
    page = HistoryPageResponse.model_validate(PAGE_DICT)
    assert len(page.entries) == 1
    assert page.entries[0].id == 42


def test_history_page_empty_entries_list_is_valid() -> None:
    """[11] entries=[] (empty list) is a valid non-nullable value and must parse fine."""
    payload = {**PAGE_DICT, "entries": []}
    page = HistoryPageResponse.model_validate(payload)
    assert page.entries == []
