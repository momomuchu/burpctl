"""Agent-mode diagnostics emitted before or around REST command execution."""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from bp.cli import app


runner = CliRunner()


@pytest.mark.parametrize(
    "args",
    [
        ["session", "send", "https://example.test", "--set-header", "invalid"],
        ["history", "clear"],
        ["scope", "set"],
        ["config", "set", "project", "--json", "{"],
        ["config", "set", "user", "--json", "{"],
        ["session", "set", "--json", "{"],
        ["decode", "payload", "--enc", "rot13"],
    ],
)
def test_agent_local_usage_errors_are_one_json_object(args: list[str]) -> None:
    result = runner.invoke(
        app,
        args,
        env={
            "BP_AGENT": "1",
            "BP_NO_LEDGER": "1",
            "BURP_REST_URL": "http://127.0.0.1:1",
        },
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["error"]["code"] == "USAGE_ERROR"


@pytest.mark.parametrize(
    "args,note_fragment",
    [
        (["ext"], "active extension"),
        (
            ["session", "set", "--json", '{"cookies":{}}'],
            "full replace",
        ),
        (["session", "clear"], "cookie-jar"),
        (["diff", "https://a.test", "https://b.test"], "set-based"),
        (["intercept", "forward"], "unavailable"),
    ],
)
def test_agent_runtime_error_suppresses_success_note(args: list[str], note_fragment: str) -> None:
    result = runner.invoke(
        app,
        args,
        env={
            "BP_AGENT": "1",
            "BP_NO_LEDGER": "1",
            "BURP_REST_URL": "http://127.0.0.1:1",
        },
    )

    assert result.exit_code == 3
    assert result.stdout == ""
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    diagnostic = json.loads(lines[0])
    assert diagnostic["error"]["code"] == "CONNECTION_REFUSED"
    assert note_fragment not in result.stderr


@pytest.mark.parametrize(
    "args,note_fragment",
    [
        (["ext"], "active extension"),
        (
            ["session", "set", "--json", '{"cookies":{}}'],
            "full replace",
        ),
        (["session", "clear"], "cookie-jar"),
        (["diff", "https://a.test", "https://b.test"], "set-based"),
        (["intercept", "forward"], "unavailable"),
    ],
)
def test_agent_success_note_is_structured(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    note_fragment: str,
) -> None:
    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    result = runner.invoke(
        app,
        args,
        env={"BP_AGENT": "1", "BP_NO_LEDGER": "1"},
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"ok": True}
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    diagnostic = json.loads(lines[0])
    assert set(diagnostic) == {"note"}
    assert note_fragment in diagnostic["note"]["message"]


def test_agent_success_distinguishes_note_from_config_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    result = runner.invoke(
        app,
        ["ext"],
        env={
            "BP_AGENT": "1",
            "BP_NO_LEDGER": "1",
            "BP_THROTTLE_MS": "invalid",
        },
    )

    assert result.exit_code == 0, result.output
    diagnostics = [json.loads(line) for line in result.stderr.splitlines()]
    assert [next(iter(item)) for item in diagnostics] == ["warning", "note"]


def test_agent_response_note_is_structured_after_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"vulnerableCount": 0, "findings": [], "note": "server scan caveat"}

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    result = runner.invoke(
        app,
        [
            "check",
            "idor",
            "https://target.test/orders/2",
            "--param",
            "id",
            "--own",
            "1",
            "--target",
            "2",
        ],
        env={"BP_AGENT": "1", "BP_NO_LEDGER": "1"},
    )

    assert result.exit_code == 0, result.output
    assert "server scan caveat" not in result.stdout
    diagnostic = json.loads(result.stderr)
    assert diagnostic["note"] == {
        "code": "SECURITY_SCAN_NOTE",
        "message": "server scan caveat",
    }


def test_human_local_error_and_success_note_keep_plain_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = runner.invoke(app, ["history", "clear"])
    assert invalid.exit_code == 2
    assert invalid.stderr.startswith("warning: 'bp history clear'")

    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True}

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    success = runner.invoke(app, ["ext"], env={"BP_NO_LEDGER": "1"})
    assert success.exit_code == 0, success.output
    assert success.stderr.startswith("note: /extensions only reports")
