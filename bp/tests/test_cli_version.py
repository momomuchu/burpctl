"""F5 — `bp --version` must print the version and exit 0 (was: 'No such option')."""

from __future__ import annotations

import subprocess
import sys

from bp import __version__

_ENTRY = "import sys; sys.argv=['bp','--version']; from bp.cli import cli_main; cli_main()"


def test_version_flag_prints_version_and_exits_zero() -> None:
    r = subprocess.run([sys.executable, "-c", _ENTRY], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == __version__
