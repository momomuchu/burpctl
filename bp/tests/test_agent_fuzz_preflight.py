"""Agent-mode preflight errors for the fuzz command."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from bp.cli import app


def test_agent_missing_payload_file_is_one_json_usage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing payload file fails before REST, target, or ledger setup."""
    monkeypatch.setenv("BP_AGENT", "1")
    runner = CliRunner()

    with patch("bp.cli.run", side_effect=AssertionError("REST path was reached")):
        result = runner.invoke(
            app,
            [
                "fuzz",
                "0",
                "--pos",
                "query:id",
                "--payloads",
                "id=/missing/file",
            ],
        )

    assert result.exit_code == 2
    assert result.stdout == ""
    lines = result.stderr.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {
        "error": {
            "code": "USAGE_ERROR",
            "message": "cannot read payload file /missing/file: [Errno 2] No such file or directory: '/missing/file'",
        }
    }
