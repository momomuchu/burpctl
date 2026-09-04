"""[16] RED tests — bp collab poll caveat note must not appear on error path.

bp collab poll (with or without id) should only print the caveat note AFTER a
successful API response, not before the call.  On a PRO_REQUIRED failure or a
connection-refused error the note must be absent from stderr.

No Burp required: pointing at a dead port (9999) produces a connection-refused
error (exit 3), which is sufficient to prove the note is emitted before the call.
"""

from __future__ import annotations

import subprocess
import sys


def test_collab_poll_error_no_caveat_note() -> None:
    """[16] When collab poll fails (conn refused), the caveat note must NOT appear in stderr."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','collab','poll']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    # Connection refused → exit 3 (EXIT_CONNECTION)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused), got {r.returncode}\nstderr={r.stderr!r}"
    )
    assert "timestamp" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"
    assert "poll time" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"


def test_collab_poll_id_error_no_caveat_note() -> None:
    """[16] When collab poll <id> fails (conn refused), the caveat note must NOT appear in stderr."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','collab','poll','abc123']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused), got {r.returncode}\nstderr={r.stderr!r}"
    )
    assert "timestamp" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"
    assert "poll time" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"
