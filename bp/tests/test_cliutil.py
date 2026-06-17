"""Guards on the cliutil.run chokepoint via the real CLI app.

These exercise the parts of the chokepoint that need no running Burp: option validation that
must fail fast with a clean usage error (exit 2) instead of leaking a Python traceback.
"""

from typer.testing import CliRunner

from bp.cli import app

runner = CliRunner()


def test_invalid_format_is_usage_error_not_traceback() -> None:
    """``--format bogus`` must be rejected before any server call, as a clean usage error.

    Regression: previously the bad format reached render() after the command ran, raising an
    uncaught ValueError that printed a Rich traceback and exited 1. It is now validated in the
    callback, so it fails with exit 2 and never contacts Burp.
    """
    result = runner.invoke(app, ["--format", "bogus", "health"])
    assert result.exit_code == 2
