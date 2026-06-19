"""[04/27/29] RED tests — --payloads NAME=FILE missing-file guard.

bp fuzz <id> --payloads x=/nonexistent/file must exit 2 with a clean stderr
message and NO traceback instead of a raw FileNotFoundError (exit 1 + traceback).
No Burp required: the file-open happens before any network call.
"""

from __future__ import annotations

import subprocess
import sys


def test_payloads_missing_file_exits_usage() -> None:
    """[04/27/29] Missing payload file → exit 2, no traceback."""
    entry = (
        "import sys; sys.argv=['bp','fuzz','1','--payloads','x=/nonexistent/does-not-exist.txt']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 2, (
        f"expected exit 2 (EXIT_USAGE), got {r.returncode}\nstdout={r.stdout!r}\nstderr={r.stderr!r}"
    )


def test_payloads_missing_file_no_traceback() -> None:
    """[04/27/29] Missing payload file stderr must NOT contain 'Traceback'."""
    entry = (
        "import sys; sys.argv=['bp','fuzz','1','--payloads','x=/nonexistent/does-not-exist.txt']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert "Traceback" not in r.stderr, f"got a traceback:\n{r.stderr}"
    assert "Traceback" not in r.stdout, f"got a traceback in stdout:\n{r.stdout}"


def test_payloads_missing_file_clean_error_message() -> None:
    """[04/27/29] Missing payload file stderr contains 'cannot read payload file'."""
    entry = (
        "import sys; sys.argv=['bp','fuzz','1','--payloads','x=/nonexistent/does-not-exist.txt']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert "cannot read payload file" in r.stderr, (
        f"expected 'cannot read payload file' in stderr:\n{r.stderr!r}"
    )
