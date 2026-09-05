"""[rebrand] Lock the console entry points declared in pyproject.toml.

`bp` is the primary command; `burpctl` is an installed alias (ADR-0012). Both
must map to `bp.cli:cli_main`. Nothing else tested the `[project.scripts]`
table, so a future edit could silently drop either command.
No Burp required: this reads the packaging metadata only.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

import bp.cli as cli_module

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _scripts() -> dict[str, str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return dict(data["project"]["scripts"])


def test_declared_typer_floor_contains_the_vendored_click_module() -> None:
    """The lowest installable Typer must provide the private module imported by cli.py."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    dependencies = list(data["project"]["dependencies"])

    assert "typer>=0.26.0" in dependencies


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
    """Run `--help` with argv[0]=invoked_as and return the program name in the Usage line.

    Rich colorizes help output when a color-capable environment is detected (e.g.
    CI sets FORCE_COLOR), so the raw line can be wrapped in ANSI escapes. Force a
    plain, wide render *and* strip any residual ANSI so the parse is deterministic.
    """
    entry = (
        f"import sys; sys.argv=[{invoked_as!r}, '--help']; from bp.cli import cli_main; cli_main()"
    )
    env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"}
    env.pop("FORCE_COLOR", None)
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True, env=env)
    text = _ANSI.sub("", f"{r.stdout}\n{r.stderr}")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Usage:"):
            return stripped.split("Usage:", 1)[1].split()[0]
    raise AssertionError(f"no Usage line in --help output:\n{text}")


def test_top_level_unexpected_exception_is_redacted_without_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No uncaught exception may quote a credential through the interpreter traceback."""
    secret = "sk-live-abc123"

    def explode(**_kwargs: Any) -> None:
        raise ValueError(f"invalid literal for int() with base 10: {secret!r}")

    monkeypatch.setattr(cli_module, "app", explode)
    monkeypatch.setattr(sys, "argv", ["bp", "health"])
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BP_AGENT", "1")
    monkeypatch.setenv("BP_REDACT", "on")

    with pytest.raises(SystemExit) as exc_info:
        cli_module.cli_main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 1
    assert captured.out == ""
    assert secret not in captured.err
    assert "Traceback" not in captured.err
    assert '"code":"INTERNAL_ERROR"' in captured.err


def test_usage_reflects_the_invoked_command_name() -> None:
    """[rebrand] `burpctl --help` says burpctl, `bp --help` says bp (not a hardcoded name)."""
    assert _usage_prog("/usr/local/bin/burpctl") == "burpctl"
    assert _usage_prog("/usr/local/bin/bp") == "bp"
