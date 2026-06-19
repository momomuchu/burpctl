"""Guards on the cliutil.run chokepoint via the real CLI app.

These exercise the parts of the chokepoint that need no running Burp: option validation that
must fail fast with a clean usage error (exit 2) instead of leaking a Python traceback.
"""

import pytest
import typer
from typer.testing import CliRunner

from bp.cli import app
from bp.cliutil import parse_header, parse_headers
from bp.output import render

runner = CliRunner()


# ---------------------------------------------------------------------------
# [18] — empty render output must produce zero bytes on stdout (no lone '\n')
# ---------------------------------------------------------------------------


def test_empty_render_produces_no_output(capsys: pytest.CaptureFixture[str]) -> None:
    """[18] render([]) returns '' and echo must be suppressed so stdout is zero bytes.

    This test invokes render() directly (the guard lives in cliutil.run before typer.echo).
    The contract: if render returns '', no echo call happens → stdout stays empty.
    We verify the render contract here; the cliutil guard is what makes it work end-to-end.
    """
    result = render([], "json")
    assert result == "", f"render([]) should be '' but got {result!r}"


def test_empty_table_render_produces_no_output() -> None:
    """[18] render([], 'table') must also return '' so the empty-output guard triggers."""
    assert render([], "table") == ""


def test_invalid_format_is_usage_error_not_traceback() -> None:
    """``--format bogus`` must be rejected before any server call, as a clean usage error.

    Regression: previously the bad format reached render() after the command ran, raising an
    uncaught ValueError that printed a Rich traceback and exited 1. It is now validated in the
    callback, so it fails with exit 2 and never contacts Burp.
    """
    result = runner.invoke(app, ["--format", "bogus", "health"])
    assert result.exit_code == 2


def test_parse_header_splits_name_value() -> None:
    assert parse_header("X-Role: admin") == ("X-Role", "admin")


def test_parse_header_strips_surrounding_whitespace() -> None:
    assert parse_header("  A :  b ") == ("A", "b")


def test_parse_header_missing_colon_raises_with_flag_name() -> None:
    """The shared helper names the offending flag (--set-header vs --header) in the error."""
    with pytest.raises(ValueError, match="--header"):
        parse_header("nocolon", "--header")


def test_parse_headers_builds_dict() -> None:
    assert parse_headers(["A: 1", "B: 2"]) == {"A": "1", "B": "2"}


def test_parse_headers_bad_input_is_usage_exit() -> None:
    """All three call sites now share exit 2 (one previously used a hardcoded literal)."""
    with pytest.raises(typer.Exit) as ei:
        parse_headers(["nocolon"])
    assert ei.value.exit_code == 2


# ---------------------------------------------------------------------------
# [15] — SERVICE_UNAVAILABLE BurpError code must map to EXIT_PRO (exit 4)
# ---------------------------------------------------------------------------


def test_service_unavailable_maps_to_exit_pro() -> None:
    """[15] _EXIT_BY_CODE['SERVICE_UNAVAILABLE'] must equal EXIT_PRO (4).

    Community Burp returns SERVICE_UNAVAILABLE for Pro-only scanner surfaces.
    The docs contract is exit 4; the map previously fell through to EXIT_GENERIC=1.
    """
    from bp.cliutil import EXIT_PRO, _EXIT_BY_CODE  # type: ignore[attr-defined]

    assert "SERVICE_UNAVAILABLE" in _EXIT_BY_CODE, (
        "_EXIT_BY_CODE missing SERVICE_UNAVAILABLE key"
    )
    assert _EXIT_BY_CODE["SERVICE_UNAVAILABLE"] == EXIT_PRO, (
        f"expected EXIT_PRO={EXIT_PRO}, got {_EXIT_BY_CODE['SERVICE_UNAVAILABLE']}"
    )
