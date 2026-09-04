"""RED tests — bp scan commands: notes/warnings must not appear on error path.

[39] bp scan status <id> — crawlProgress/auditProgress stub note must only appear
     after a successful API response, not before the call.
[17] bp scan audit <url> — url-ignored warning must only appear after a successful
     API response, not before the call.
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


def test_scan_audit_error_no_warning() -> None:
    """[17] When scan audit fails (conn refused), the url-ignored warning must NOT appear in stderr."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','scan','audit','http://example.com']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    # Connection refused → exit 3 (EXIT_CONNECTION)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused), got {r.returncode}\nstderr={r.stderr!r}"
    )
    assert "audit ignores" not in r.stderr, f"warning must not appear on error path:\n{r.stderr!r}"
    assert "Burp UI scope" not in r.stderr, f"warning must not appear on error path:\n{r.stderr!r}"
