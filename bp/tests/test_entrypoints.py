"""[rebrand] Lock the console entry points declared in pyproject.toml.

The rebrand (ADR-0011) makes `burpctl` the primary command and keeps `bp` as a
2-char alias; both must map to `bp.cli:cli_main`. Nothing else tested the
`[project.scripts]` table, so a future edit could silently drop `burpctl`.
No Burp required: this reads the packaging metadata only.
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _scripts() -> dict[str, str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return dict(data["project"]["scripts"])


def test_both_commands_are_declared() -> None:
    """[rebrand] both `burpctl` and `bp` are installed as console scripts."""
    scripts = _scripts()
    assert set(scripts) >= {"burpctl", "bp"}, (
        f"expected both 'burpctl' and 'bp' entry points, got {sorted(scripts)}"
    )


def test_both_commands_point_at_the_same_entry() -> None:
    """[rebrand] both commands invoke the identical CLI entry point."""
    scripts = _scripts()
    assert scripts["burpctl"] == "bp.cli:cli_main"
    assert scripts["bp"] == "bp.cli:cli_main"


def _usage_prog(invoked_as: str) -> str:
    """Run `--help` with argv[0]=invoked_as and return the program name in the Usage line."""
    entry = (
        f"import sys; sys.argv=[{invoked_as!r}, '--help']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.strip().startswith("Usage:"):
            return line.split("Usage:", 1)[1].split()[0]
    raise AssertionError(f"no Usage line in --help output:\n{r.stdout}\n{r.stderr}")


def test_usage_reflects_the_invoked_command_name() -> None:
    """[rebrand] `burpctl --help` says burpctl, `bp --help` says bp (not a hardcoded name)."""
    assert _usage_prog("/usr/local/bin/burpctl") == "burpctl"
    assert _usage_prog("/usr/local/bin/bp") == "bp"
