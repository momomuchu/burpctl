"""Machine-readable Click/Typer parse failures at the installed CLI boundary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Never

import pytest


_ENTRYPOINT = "import sys; sys.argv=sys.argv[1:]; from bp.cli import cli_main; cli_main()"


def _invoke(
    invoked_as: str,
    *args: str,
    agent: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "200"}
    env.pop("FORCE_COLOR", None)
    if agent:
        env["BP_AGENT"] = "1"
    else:
        env.pop("BP_AGENT", None)
    return subprocess.run(
        [sys.executable, "-c", _ENTRYPOINT, invoked_as, *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@pytest.mark.parametrize(
    ("invoked_as", "args"),
    [
        ("bp", ("--format", "bogus", "health")),
        ("bp", ("missing-crosscutting-command",)),
        ("burpctl", ("missing-crosscutting-command",)),
        ("bp", ("health", "--", "--format", "json")),
    ],
)
def test_agent_parser_errors_are_one_json_record(
    invoked_as: str,
    args: tuple[str, ...],
) -> None:
    result = _invoke(invoked_as, *args)

    assert result.returncode == 2
    assert result.stdout == ""
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    diagnostic = json.loads(lines[0])
    assert diagnostic["error"]["code"] == "USAGE_ERROR"
    assert diagnostic["error"]["message"]


def test_explicit_table_keeps_human_parser_error_in_agent_environment() -> None:
    result = _invoke("bp", "--format", "table", "missing-crosscutting-command")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Usage: bp" in result.stderr
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.stderr)


def test_explicit_json_selects_machine_parser_errors_without_agent_environment() -> None:
    result = _invoke("bp", "--format", "json", "missing-crosscutting-command", agent=False)

    assert result.returncode == 2
    assert result.stdout == ""
    diagnostic = json.loads(result.stderr)
    assert diagnostic["error"]["code"] == "USAGE_ERROR"


@pytest.mark.parametrize("flag", ["--help", "--version"])
def test_agent_mode_preserves_eager_success_options(flag: str) -> None:
    result = _invoke("bp", flag)

    assert result.returncode == 0
    assert result.stdout
    assert result.stderr == ""


def test_agent_entrypoint_does_not_mask_unknown_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bp.cli as cli

    def crash(*, args: list[str], prog_name: str, standalone_mode: bool) -> Never:
        del args, prog_name, standalone_mode
        raise RuntimeError("unknown-exception-sentinel")

    monkeypatch.setenv("BP_AGENT", "1")
    monkeypatch.setattr(sys, "argv", ["bp", "health"])
    monkeypatch.setattr(cli, "app", crash)

    with pytest.raises(RuntimeError, match="unknown-exception-sentinel"):
        cli.cli_main()
