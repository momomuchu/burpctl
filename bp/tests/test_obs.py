"""Tests for bp obs commands (bp log / bp tag). Local-only, no Burp required."""

from __future__ import annotations

import subprocess
import sys


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
