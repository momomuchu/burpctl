from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from bp.cli import app
from bp.commands.config import _parse_config_json


def test_parse_config_json_preserves_nested_types() -> None:
    parsed = _parse_config_json(
        '{"proxy":{"enabled":true,"ports":[8080,8081]},"retries":2,"note":null}'
    )

    assert parsed == {
        "proxy": {"enabled": True, "ports": [8080, 8081]},
        "retries": 2,
        "note": None,
    }


def test_config_set_preserves_nested_payload(monkeypatch: Any) -> None:
    captured: list[dict[str, Any]] = []

    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        captured.append({"method": method, "path": path, **kwargs})
        return {"config": kwargs["json"]["config"]}

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    monkeypatch.setenv("BP_NO_LEDGER", "1")
    result = CliRunner().invoke(
        app,
        [
            "--format",
            "json",
            "config",
            "set",
            "project",
            "--json",
            '{"proxy":{"enabled":true},"ports":[8080]}',
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured == [
        {
            "method": "PUT",
            "path": "/config/project",
            "json": {"config": {"proxy": {"enabled": True}, "ports": [8080]}},
        }
    ]


@pytest.mark.parametrize("scope", ["project", "user"])
@pytest.mark.parametrize(
    ("output_args", "expected_stdout"),
    [
        (["--format", "quiet"], ""),
        (["--format", "json", "--fields", "applied"], '{"applied":true}\n'),
        (["--format", "json"], None),
        (["--format", "table"], None),
    ],
)
def test_applied_unverifiable_import_warning_always_reaches_stderr(
    monkeypatch: Any,
    scope: str,
    output_args: list[str],
    expected_stdout: str | None,
) -> None:
    """R5: output narrowing must not hide an applied import's do-not-retry warning."""
    requests: list[tuple[str, str]] = []
    warning = (
        f"{scope.title()} configuration import completed, but Burp could not export the "
        "applied options; do not retry the import."
    )

    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        requests.append((method, path))
        return {
            "applied": True,
            "config": None,
            "excludedPaths": [],
            "warning": warning,
        }

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    monkeypatch.setenv("BP_NO_LEDGER", "1")

    result = CliRunner().invoke(
        app,
        [*output_args, "config", "set", scope, "--json", '{"proxy":{"enabled":true}}'],
    )

    assert result.exit_code == 0, result.output
    assert requests == [("PUT", f"/config/{scope}")]
    if expected_stdout is not None:
        assert result.stdout == expected_stdout
    assert "do not retry the import" in result.stderr.lower(), (
        "the caller must see that the applied import is unsafe to retry even when stdout is narrowed"
    )
