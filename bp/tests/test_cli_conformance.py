"""CLI grammar conformance — every docs/CLI.md command must be reachable (exit 0 on --help).

This is the objective gate that green unit tests alone cannot provide: passing units != conformant command tree.
Grouped verbs (scan/check/scope/collab/config/session/history) are sub-Typers; everything else
is a FLAT top-level command per CLI.md §Principe ``bp <command> [subject]``.
"""

import re

import pytest
from typer.testing import CliRunner

from bp.cli import app

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain_help(args: list[str]) -> str:
    return " ".join(_ANSI.sub("", runner.invoke(app, args).stdout).split())


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


def test_fuzz_help_discloses_raw_framing_limit() -> None:
    result = runner.invoke(app, ["fuzz", "--help"])

    assert result.exit_code == 0
    assert "not a raw-framing transport" in result.stdout
    assert "Content-Length" in result.stdout


def test_session_send_help_names_server_side_history() -> None:
    result = runner.invoke(app, ["session", "send", "--help"])

    assert result.exit_code == 0
    assert "server-side history" in result.stdout
    assert "proxy history" not in result.stdout


def test_session_help_matches_clear_and_origin_contracts() -> None:
    set_help = _plain_help(["session", "set", "--help"])
    clear_help = _plain_help(["session", "clear", "--help"])
    cookies_help = _plain_help(["session", "cookies", "--help"])

    assert "origin" in set_help
    for text in (clear_help, cookies_help):
        assert "survives" not in text
        assert "does NOT wipe" not in text
        assert "leaves the cookie-jar intact" not in text
    assert "cookie jar" in clear_help and "clear" in clear_help


def test_scope_show_and_set_help_state_unavailable_contract() -> None:
    for command in (["scope", "show", "--help"], ["scope", "set", "--help"]):
        text = _plain_help(command).lower()
        assert "unavailable" in text
        assert "501" in text


def test_check_auth_help_states_marker_detection_limit_verbatim() -> None:
    expected = (
        "Without a server-held marker, `check auth` cannot distinguish a cookie-only bypass where "
        "FULL, COOKIES_ONLY, and NONE all return the same representation from an intentionally "
        "public route; that case is not confirmed."
    )
    text = _plain_help(["check", "auth", "--help"])
    assert expected in text


@pytest.mark.parametrize("command", ["auth", "idor", "headers", "cors", "endpoints"])
def test_check_help_exposes_probe_and_operation_timeouts(command: str) -> None:
    result = runner.invoke(app, ["check", command, "--help"], terminal_width=140)
    text = " ".join(_ANSI.sub("", result.stdout).split())
    assert "--probe-timeout-ms" in text
    assert "--deadline-ms" in text
    assert "5000" in text


def test_check_probe_timeout_zero_is_local_usage() -> None:
    result = runner.invoke(
        app,
        ["--format", "json", "check", "cors", "https://example.test", "--probe-timeout-ms", "0"],
    )
    assert result.exit_code == 2
    assert result.stdout == ""


def test_check_operation_timeout_override_is_reachable_and_validated() -> None:
    result = runner.invoke(
        app,
        [
            "--format",
            "json",
            "check",
            "idor",
            "https://example.test/{id}",
            "--param",
            "id",
            "--own",
            "1",
            "--target",
            "2",
            "--deadline-ms",
            "0",
        ],
    )
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "deadline-ms" in _ANSI.sub("", result.stderr)


def test_global_help_labels_json_list_output_as_ndjson() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "json (NDJSON for lists)" in result.stdout


def test_scope_set_help_does_not_claim_full_replacement() -> None:
    result = runner.invoke(app, ["scope", "set", "--help"])

    assert result.exit_code == 0
    assert "FULL-REPLACE" not in result.stdout
    assert "wipes all scope" not in result.stdout
    assert "extension-managed" in result.stdout


def test_scope_help_discloses_classification_only() -> None:
    result = runner.invoke(app, ["scope", "--help"])

    assert result.exit_code == 0
    assert "does not block proxy traffic" in result.stdout


def test_log_help_discloses_control_plane_coverage() -> None:
    output = _plain_help(["log", "--help"])

    assert "bp-to-extension REST operations" in output
    assert "not a proxy traffic log" in output
    assert "REST listener host" in output
    assert "Burp REST listener host[:port]" in output
