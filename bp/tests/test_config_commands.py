from __future__ import annotations

from typing import Any

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
