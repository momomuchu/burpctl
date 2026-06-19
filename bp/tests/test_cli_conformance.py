"""CLI grammar conformance — every docs/CLI.md command must be reachable (exit 0 on --help).

This is the objective gate that green unit tests alone cannot provide: passing units != conformant command tree.
Grouped verbs (scan/check/scope/collab/config/session/history) are sub-Typers; everything else
is a FLAT top-level command per CLI.md §Principe ``bp <command> [subject]``.
"""

import pytest
from typer.testing import CliRunner

from bp.cli import app

runner = CliRunner()

# Each entry must resolve to a real command/group (––help exits 0; missing => exit 2).
CLI_COMMANDS: list[list[str]] = [
    ["health"],
    ["version"],
    ["proxy"],
    ["fuzz"],
    ["req"],
    ["ws"],
    ["intercept"],
    ["send"],
    ["tab"],
    ["collab", "new"],
    ["collab", "poll"],
    ["scan", "crawl"],
    ["scan", "audit"],
    ["scan", "all"],
    ["scan", "status"],
    ["scan", "issues"],
    ["scan", "defs"],
    ["check", "auth"],
    ["check", "idor"],
    ["check", "headers"],
    ["check", "cors"],
    ["check", "endpoints"],
    ["scope", "show"],
    ["scope", "set"],
    ["scope", "add"],
    ["scope", "remove"],
    ["scope", "check"],
    ["sitemap"],
    ["encode"],
    ["decode"],
    ["hash"],
    ["config", "get"],
    ["config", "set"],
    ["ext"],
    ["session", "set"],
    ["session", "get"],
    ["session", "clear"],
    ["session", "send"],
    ["session", "cookies"],
    ["diff"],
    ["endpoints"],
    ["history"],
    ["history", "list"],
    ["history", "get"],
    ["history", "sitemap"],
    ["history", "replay"],
    ["history", "clear"],
    ["log"],
    ["tag"],
]


@pytest.mark.parametrize("cmd", CLI_COMMANDS, ids=lambda c: " ".join(c))
def test_command_reachable(cmd: list[str]) -> None:
    result = runner.invoke(app, [*cmd, "--help"])
    assert result.exit_code == 0, f"`bp {' '.join(cmd)}` not reachable (exit {result.exit_code})"
