"""[39] RED tests — bp scan status stub note must not appear on error path.

bp scan status <nonexistent-id> should only print the error, NOT the
crawlProgress/auditProgress stub note (which was previously printed unconditionally
at function entry, before any response was received).
No Burp required: pointing at a dead port produces a connection-refused error.
"""

from __future__ import annotations

import subprocess
import sys


def test_scan_status_error_no_stub_note() -> None:
    """[39] When scan status fails (conn refused), the stub note must NOT appear in stderr."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','scan','status','abc123']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    # Connection refused → exit 3 (EXIT_CONNECTION)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused), got {r.returncode}\nstderr={r.stderr!r}"
    )
    assert "crawlProgress" not in r.stderr, (
        f"stub note must not appear on error path:\n{r.stderr!r}"
    )
    assert "auditProgress" not in r.stderr, (
        f"stub note must not appear on error path:\n{r.stderr!r}"
    )
