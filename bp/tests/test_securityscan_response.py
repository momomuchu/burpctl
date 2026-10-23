"""Response-contract checks for ``bp check`` scan verdicts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest
from typer.testing import CliRunner

from bp.cli import app
from bp.client import BurpClient, BurpError
from bp.commands.securityscan import _validate_scan_verdict
from bp.ledger import Ledger


def test_check_endpoints_rejects_null_findings_before_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A successful REST envelope cannot carry a malformed scan verdict."""
    db_path = tmp_path / "ledger.db"
    rest_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        rest_paths.append(request.url.path)
        return httpx.Response(
            200,
            json={
                "success": True,
                "data": {"findings": None, "scanned": 1, "durationMs": 1},
                "error": None,
            },
        )

    def client_factory(
        _url: str,
        *,
        ledger: Ledger | None = None,
        redact: bool = True,
        command: str = "",
    ) -> BurpClient:
        return BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(handler), base_url="http://fixture.invalid"
            ),
            ledger=ledger,
            redact=redact,
            command=command,
        )

    monkeypatch.setattr("bp.cliutil.Ledger", lambda: Ledger(db_path=db_path))
    monkeypatch.setattr("bp.cliutil.BurpClient", client_factory)

    result = CliRunner().invoke(
        app,
        ["--format", "json", "check", "endpoints", "fixture.invalid", "--limit", "1"],
    )

    assert result.exit_code == 1
    assert result.stdout == ""
    assert json.loads(result.stderr) == {
        "error": {
            "code": "INVALID_RESPONSE",
            "message": "server returned an unexpected response shape",
        }
    }
    assert "Traceback" not in result.stderr
    assert "fixture.invalid" not in result.stderr
    assert "securityscan.py" not in result.stderr
    assert rest_paths == ["/scan/endpoints"]
    with Ledger(db_path=db_path) as ledger:
        rows = ledger.query()
    assert len(rows) == 1
    assert rows[0].exit_code == 1


@pytest.mark.parametrize(
    ("args", "rest_path", "data"),
    [
        (["auth", "https://fixture.invalid"], "/scan/auth-bypass", {"vulnerableCount": None}),
        (
            [
                "idor",
                "https://fixture.invalid/orders/{id}",
                "--param",
                "id",
                "--own",
                "1",
                "--target",
                "2",
            ],
            "/scan/idor",
            {"vulnerableCount": None},
        ),
        (["headers", "https://fixture.invalid"], "/scan/headers", {"vulnerableCount": None}),
        (["cors", "https://fixture.invalid"], "/scan/cors", {"vulnerableCount": None}),
        (["endpoints", "fixture.invalid"], "/scan/endpoints", {"findings": None}),
    ],
)
def test_every_check_command_validates_its_finding_indicator(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    rest_path: str,
    data: dict[str, Any],
) -> None:
    rest_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        rest_paths.append(request.url.path)
        return httpx.Response(200, json={"success": True, "data": data, "error": None})

    def client_factory(
        _url: str,
        *,
        ledger: Ledger | None = None,
        redact: bool = True,
        command: str = "",
    ) -> BurpClient:
        return BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(handler), base_url="http://fixture.invalid"
            ),
            ledger=ledger,
            redact=redact,
            command=command,
        )

    monkeypatch.setattr("bp.cliutil.BurpClient", client_factory)

    result = CliRunner().invoke(app, ["--format", "json", "--no-ledger", "check", *args])

    assert result.exit_code == 1
    assert result.stdout == ""
    assert '"code":"INVALID_RESPONSE"' in result.stderr
    assert "Traceback" not in result.stderr
    assert rest_paths == [rest_path]


@pytest.mark.parametrize(
    ("data", "finding_field"),
    [
        ({}, "vulnerableCount"),
        ({"vulnerableCount": None}, "vulnerableCount"),
        ({"vulnerableCount": "1"}, "vulnerableCount"),
        ({"vulnerableCount": True}, "vulnerableCount"),
        ({"vulnerableCount": -1}, "vulnerableCount"),
        ({}, "findings"),
        ({"findings": None}, "findings"),
        ({"findings": {}}, "findings"),
        ({"vulnerableCount": 0, "inconclusiveCount": None}, "vulnerableCount"),
        ({"vulnerableCount": 0, "errors": None}, "vulnerableCount"),
        ({"vulnerableCount": 0, "anomalousCount": 1.5}, "vulnerableCount"),
    ],
)
def test_scan_verdict_rejects_missing_null_and_wrong_typed_fields(
    data: dict[str, Any],
    finding_field: Literal["vulnerableCount", "findings"],
) -> None:
    with pytest.raises(BurpError, match="INVALID_RESPONSE"):
        _validate_scan_verdict(data, finding_field)


@pytest.mark.parametrize(
    ("data", "finding_field"),
    [
        ({"vulnerableCount": 0, "inconclusiveCount": 0}, "vulnerableCount"),
        ({"vulnerableCount": 0, "inconclusiveCount": 1}, "vulnerableCount"),
        ({"vulnerableCount": 2, "errors": []}, "vulnerableCount"),
        ({"findings": [], "inconclusiveCount": 0, "errors": []}, "findings"),
        ({"findings": [{"endpoint": "/admin"}]}, "findings"),
    ],
)
def test_scan_verdict_preserves_valid_clean_inconclusive_and_vulnerable_shapes(
    data: dict[str, Any],
    finding_field: Literal["vulnerableCount", "findings"],
) -> None:
    assert _validate_scan_verdict(data, finding_field) is data
