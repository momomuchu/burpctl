"""Guards on the cliutil.run chokepoint via the real CLI app.

These exercise the parts of the chokepoint that need no running Burp: option validation that
must fail fast with a clean usage error (exit 2) instead of leaking a Python traceback.
"""

import pytest
import typer
from typer.testing import CliRunner

from bp.cli import app
from bp.cliutil import parse_header, parse_headers

runner = CliRunner()


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
