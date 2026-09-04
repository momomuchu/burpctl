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
    assert r.returncode == 1, (
        f"expected exit 1 when ledger disabled, got {r.returncode}: {r.stderr}"
    )


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
    assert r.returncode == 1, (
        f"expected exit 1 when ledger disabled, got {r.returncode}: {r.stderr}"
    )


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
    assert r.stdout == b"", f"expected zero stdout bytes for empty ledger, got {r.stdout!r}"


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
    assert result.exit_code == 1, f"expected exit 1 on OSError, got {result.exit_code}"
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


# ---------------------------------------------------------------------------
# [09] RED — ledger.query() / ledger.tag() sqlite3.Error propagates uncaught
# The Ledger() constructor is already guarded; these tests cover the CONTEXT
# MANAGER body (query/tag calls) which are still outside any try/except.
# ---------------------------------------------------------------------------


def test_log_ledger_query_sqlite_error_clean_no_traceback() -> None:
    """[09] `bp log` exits 1 with a clean error when ledger.query() raises sqlite3.Error.

    The Ledger() constructor succeeds (returns a real-looking context manager), but the
    .query() call inside the `with` block raises sqlite3.OperationalError (e.g. locked db).
    Without the fix, this propagates as a raw traceback.
    """
    import sqlite3
    from unittest.mock import MagicMock

    runner = CliRunner()
    mock_ledger = MagicMock()
    mock_ledger.__enter__ = MagicMock(return_value=mock_ledger)
    mock_ledger.__exit__ = MagicMock(return_value=False)
    mock_ledger.query.side_effect = sqlite3.OperationalError("database is locked")

    with patch("bp.commands.obs.Ledger", return_value=mock_ledger):
        result = runner.invoke(app, ["log"])

    assert result.exit_code == 1, (
        f"[09] expected exit 1 when query() raises sqlite3.Error, got {result.exit_code}; "
        f"output={result.output!r}"
    )
    combined = result.output + result.stderr
    assert "error: ledger unavailable" in combined, (
        f"[09] expected 'error: ledger unavailable' in output, got {combined!r}"
    )
    assert "Traceback" not in combined, f"[09] traceback leaked: {combined!r}"
    assert "OperationalError" not in combined, f"[09] class name leaked: {combined!r}"


def test_tag_ledger_tag_sqlite_error_clean_no_traceback() -> None:
    """[09] `bp tag` exits 1 with a clean error when ledger.tag() raises sqlite3.Error.

    The Ledger() constructor succeeds, but ledger.tag() raises sqlite3.OperationalError
    (e.g. disk-full or corrupt db). Without the fix, raw traceback with internal names.
    """
    import sqlite3
    from unittest.mock import MagicMock

    runner = CliRunner()
    mock_ledger = MagicMock()
    mock_ledger.__enter__ = MagicMock(return_value=mock_ledger)
    mock_ledger.__exit__ = MagicMock(return_value=False)
    mock_ledger.tag.side_effect = sqlite3.OperationalError("disk I/O error")

    with patch("bp.commands.obs.Ledger", return_value=mock_ledger):
        result = runner.invoke(app, ["tag", "op123", "mytag"])

    assert result.exit_code == 1, (
        f"[09] expected exit 1 when tag() raises sqlite3.Error, got {result.exit_code}; "
        f"output={result.output!r}"
    )
    combined = result.output + result.stderr
    assert "error: ledger unavailable" in combined, (
        f"[09] expected 'error: ledger unavailable' in output, got {combined!r}"
    )
    assert "Traceback" not in combined, f"[09] traceback leaked: {combined!r}"
    assert "OperationalError" not in combined, f"[09] class name leaked: {combined!r}"


# ---------------------------------------------------------------------------
# [10] RED — --no-ledger / BP_NO_LEDGER ignored by bp log / bp tag
# _require_ledger() must honour ctx.obj.no_ledger (the State flag).
# ---------------------------------------------------------------------------


def test_log_honors_no_ledger_state_flag() -> None:
    """[10] `bp log` respects --no-ledger flag — takes the ledger-disabled path.

    Previously _require_ledger() called load_config() with no args, so the State flag
    was invisible to it. The Ledger() must NOT be constructed when --no-ledger is set.

    Note: runner.invoke obj=state is overwritten by the CLI callback, so we pass
    --no-ledger as a real CLI flag to exercise the full path through ctx.obj.no_ledger.
    """
    runner = CliRunner()
    # Patch Ledger to detect if it gets called despite --no-ledger.
    with patch("bp.commands.obs.Ledger") as mock_ledger_cls:
        result = runner.invoke(app, ["--no-ledger", "log"])

    assert result.exit_code == 1, (
        f"[10] expected exit 1 when --no-ledger, got {result.exit_code}; output={result.output!r}"
    )
    mock_ledger_cls.assert_not_called()


def test_tag_honors_no_ledger_state_flag() -> None:
    """[10] `bp tag` respects --no-ledger flag — takes the ledger-disabled path.

    Same gap as bp log: State.no_ledger was invisible to _require_ledger().
    """
    runner = CliRunner()
    with patch("bp.commands.obs.Ledger") as mock_ledger_cls:
        result = runner.invoke(app, ["--no-ledger", "tag", "op123", "mytag"])

    assert result.exit_code == 1, (
        f"[10] expected exit 1 when --no-ledger, got {result.exit_code}; output={result.output!r}"
    )
    mock_ledger_cls.assert_not_called()


# ---------------------------------------------------------------------------
# [15] RED — ledger-disabled path emits "note:" prefix (must be "error:")
# Severity label must agree with exit code: exit 1 → "error:", not "note:".
# ---------------------------------------------------------------------------


def test_log_ledger_disabled_emits_error_prefix() -> None:
    """[15] `bp log` emits 'error:' (not 'note:') when the ledger is disabled.

    Emitting 'note:' while exiting 1 is contradictory: note signals non-fatal/informational
    but exit 1 signals failure. The prefix must be 'error:'.
    Uses --no-ledger CLI flag (not obj=state) because the callback overwrites ctx.obj.
    """
    runner = CliRunner()
    result = runner.invoke(app, ["--no-ledger", "log"])

    assert result.exit_code == 1, f"[15] expected exit 1, got {result.exit_code}"
    combined = result.output + result.stderr
    assert "error:" in combined, f"[15] expected 'error:' prefix in output/stderr, got {combined!r}"
    assert "note:" not in combined, (
        f"[15] 'note:' prefix must not appear when exiting 1, got {combined!r}"
    )


def test_tag_ledger_disabled_emits_error_prefix() -> None:
    """[15] `bp tag` emits 'error:' (not 'note:') when the ledger is disabled."""
    runner = CliRunner()
    result = runner.invoke(app, ["--no-ledger", "tag", "op123", "mytag"])

    assert result.exit_code == 1, f"[15] expected exit 1, got {result.exit_code}"
    combined = result.output + result.stderr
    assert "error:" in combined, f"[15] expected 'error:' prefix in output/stderr, got {combined!r}"
    assert "note:" not in combined, (
        f"[15] 'note:' prefix must not appear when exiting 1, got {combined!r}"
    )
