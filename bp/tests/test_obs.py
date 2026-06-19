"""Tests for bp obs commands (bp log / bp tag). Local-only, no Burp required."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import os
from unittest.mock import patch

from typer.testing import CliRunner

from bp.cli import app


def test_tag_exits_nonzero_when_ledger_disabled() -> None:
    """D2: `bp tag` must fail (exit 1) when the ledger is disabled — the tag was NOT applied.

    Previously it bare-returned (exit 0), so a script checking the exit code believed the tag
    had been written. No Burp needed: tag is a local ledger operation.
    """
    entry = (
        "import os; os.environ['BP_NO_LEDGER']='1'; "
        "import sys; sys.argv=['bp','tag','someop','mytag']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 1, f"expected exit 1 when ledger disabled, got {r.returncode}: {r.stderr}"


# [28] RED — bp log must also exit 1 when ledger is disabled (consistent with bp tag).
def test_log_exits_nonzero_when_ledger_disabled() -> None:
    """`bp log` exits 1 when the ledger is disabled.

    Previously it bare-returned (exit 0), misleading scripts into believing a query succeeded.
    Must be consistent with `bp tag` which already exits 1 for the same condition.
    """
    entry = (
        "import os; os.environ['BP_NO_LEDGER']='1'; "
        "import sys; sys.argv=['bp','log']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 1, f"expected exit 1 when ledger disabled, got {r.returncode}: {r.stderr}"


# [09] RED — bp log must emit ZERO bytes on stdout when the ledger returns zero rows.
# OUTPUT.md §4.4: empty stdout + exit 0 = zero records. typer.echo('') writes '\n' which
# breaks the contract. The fix (guarded echo in log_cmd) must suppress the lone newline.
def test_log_empty_ledger_zero_stdout_bytes() -> None:
    """`bp log` writes zero bytes to stdout when the ledger has no matching rows (exit 0).

    Uses a fresh empty temp ledger via BP_LEDGER_PATH so no rows exist. The zero-records
    contract (OUTPUT.md §4.4) forbids a lone newline on stdout. This is the regression lock
    for the spurious '\\n' emitted by the bare typer.echo(render(...)) on line 90 of obs.py.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_path = os.path.join(tmpdir, "ledger.db")
        entry = (
            f"import os; os.environ['BP_LEDGER_PATH']={ledger_path!r}; "
            "import sys; sys.argv=['bp','log']; "
            "from bp.cli import cli_main; cli_main()"
        )
        r = subprocess.run([sys.executable, "-c", entry], capture_output=True)
    assert r.returncode == 0, f"expected exit 0 for empty ledger, got {r.returncode}: {r.stderr!r}"
    assert r.stdout == b"", (
        f"expected zero stdout bytes for empty ledger, got {r.stdout!r}"
    )


# ---------------------------------------------------------------------------
# [06] RED — Ledger() construction failure → clean error, exit 1, no traceback
# ---------------------------------------------------------------------------

def test_log_ledger_oserror_clean_stderr_no_traceback() -> None:
    """`bp log` exits 1 with a clean 'error: ledger unavailable' message when Ledger()
    raises OSError on construction. No traceback, no 'sqlite3'/'pathlib' class names.
    """
    runner = CliRunner()
    with patch("bp.commands.obs.Ledger", side_effect=OSError("read-only filesystem")):
        result = runner.invoke(app, ["log"])
    assert result.exit_code == 1, (
        f"expected exit 1 on OSError, got {result.exit_code}; output={result.output!r}"
    )
    combined = result.output + result.stderr
    assert "error: ledger unavailable" in combined, (
        f"expected 'error: ledger unavailable' in output/stderr, got {combined!r}"
    )
    assert "Traceback" not in combined, f"traceback leaked: {combined!r}"
    assert "sqlite3" not in combined, f"'sqlite3' class name leaked: {combined!r}"
    assert "pathlib" not in combined, f"'pathlib' class name leaked: {combined!r}"
    assert "OSError" not in combined, f"'OSError' class name leaked: {combined!r}"


def test_log_ledger_sqlite_error_clean_stderr_no_traceback() -> None:
    """`bp log` exits 1 with a clean message when Ledger() raises sqlite3.OperationalError."""
    import sqlite3

    runner = CliRunner()
    with patch(
        "bp.commands.obs.Ledger",
        side_effect=sqlite3.OperationalError("unable to open database"),
    ):
        result = runner.invoke(app, ["log"])
    assert result.exit_code == 1, (
        f"expected exit 1 on sqlite3.OperationalError, got {result.exit_code}"
    )
    combined = result.output + result.stderr
    assert "error: ledger unavailable" in combined, (
        f"expected 'error: ledger unavailable' in output/stderr, got {combined!r}"
    )
    assert "Traceback" not in combined, f"traceback leaked: {combined!r}"
    assert "sqlite3" not in combined, f"'sqlite3' class name leaked: {combined!r}"


def test_tag_ledger_oserror_clean_stderr_no_traceback() -> None:
    """`bp tag` exits 1 with a clean 'error: ledger unavailable' message when Ledger()
    raises OSError on construction. No traceback, no internal class names.
    """
    runner = CliRunner()
    with patch("bp.commands.obs.Ledger", side_effect=OSError("permission denied")):
        result = runner.invoke(app, ["tag", "op123", "mytag"])
    assert result.exit_code == 1, (
        f"expected exit 1 on OSError, got {result.exit_code}"
    )
    combined = result.output + result.stderr
    assert "error: ledger unavailable" in combined, (
        f"expected 'error: ledger unavailable' in output/stderr, got {combined!r}"
    )
    assert "Traceback" not in combined, f"traceback leaked: {combined!r}"
    assert "sqlite3" not in combined, f"'sqlite3' class name leaked: {combined!r}"
    assert "pathlib" not in combined, f"'pathlib' class name leaked: {combined!r}"
    assert "OSError" not in combined, f"'OSError' class name leaked: {combined!r}"


def test_tag_ledger_sqlite_error_clean_stderr_no_traceback() -> None:
    """`bp tag` exits 1 with a clean message when Ledger() raises sqlite3.OperationalError."""
    import sqlite3

    runner = CliRunner()
    with patch(
        "bp.commands.obs.Ledger",
        side_effect=sqlite3.OperationalError("unable to open database"),
    ):
        result = runner.invoke(app, ["tag", "op123", "mytag"])
    assert result.exit_code == 1, (
        f"expected exit 1 on sqlite3.OperationalError, got {result.exit_code}"
    )
    combined = result.output + result.stderr
    assert "error: ledger unavailable" in combined, (
        f"expected 'error: ledger unavailable' in output/stderr, got {combined!r}"
    )
    assert "Traceback" not in combined, f"traceback leaked: {combined!r}"
    assert "sqlite3" not in combined, f"'sqlite3' class name leaked: {combined!r}"
