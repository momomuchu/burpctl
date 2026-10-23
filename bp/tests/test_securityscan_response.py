"""Response-contract checks for ``bp check`` scan verdicts."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from bp.cli import app
from bp.client import BurpClient, BurpError
from bp.commands.securityscan import _has_findings, _project_for_display, _validate_scan_response
from bp.ledger import Ledger
from bp.models import (
    AuthBypassResponse,
    CorsResponse,
    EndpointsScanResponse,
    HeadersBypassResponse,
    IdorResponse,
)

_AUTH_PROBE: dict[str, Any] = {
    "status": 200,
    "length": 12,
    "durationMs": 3,
}
_IDOR_PROBE: dict[str, Any] = {
    "value": "1",
    "status": 200,
    "length": 12,
    "bodyPreview": None,
    "sameAsBaseline": True,
    "vulnerable": False,
}
_ENDPOINT_FINDING: dict[str, Any] = {
    "endpoint": "https://fixture.invalid/admin",
    "method": "GET",
    "test": "auth-bypass",
    "detail": "accessible without auth",
    "severity": "high",
}
_VALID_RESPONSES: dict[str, dict[str, Any]] = {
    "/scan/auth-bypass": {
        "results": [],
        "totalScanned": 0,
        "vulnerableCount": 0,
    },
    "/scan/idor": {
        "baseline": _IDOR_PROBE,
        "results": [],
        "vulnerableCount": 0,
    },
    "/scan/headers": {
        "baseline": _AUTH_PROBE,
        "results": [],
        "anomalousCount": 0,
        "vulnerableCount": 0,
    },
    "/scan/cors": {
        "results": [],
        "vulnerableCount": 0,
    },
    "/scan/endpoints": {
        "scanned": 0,
        "findings": [],
        "durationMs": 1,
    },
}
_ResponseModel = type[
    AuthBypassResponse | IdorResponse | HeadersBypassResponse | CorsResponse | EndpointsScanResponse
]


@pytest.mark.parametrize(
    ("args", "rest_path", "data"),
    [
        (
            ["auth", "https://fixture.invalid"],
            "/scan/auth-bypass",
            {"vulnerableCount": 0},
        ),
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
            {"vulnerableCount": 0},
        ),
        (
            ["headers", "https://fixture.invalid"],
            "/scan/headers",
            {"vulnerableCount": 0},
        ),
        (
            ["cors", "https://fixture.invalid"],
            "/scan/cors",
            {"vulnerableCount": 0},
        ),
        (
            ["endpoints", "fixture.invalid"],
            "/scan/endpoints",
            {"findings": []},
        ),
    ],
)
def test_every_check_command_rejects_an_incomplete_success_dto_before_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    args: list[str],
    rest_path: str,
    data: dict[str, Any],
) -> None:
    """A verdict field alone cannot turn an incomplete success DTO into a clean result."""
    db_path = tmp_path / "ledger.db"
    rest_requests: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        rest_requests.append((request.method, request.url.path))
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

    monkeypatch.setattr("bp.cliutil.Ledger", lambda: Ledger(db_path=db_path))
    monkeypatch.setattr("bp.cliutil.BurpClient", client_factory)

    result = CliRunner().invoke(app, ["--format", "json", "check", *args])

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
    assert rest_requests == [("POST", rest_path)]
    with Ledger(db_path=db_path) as ledger:
        rows = ledger.query()
    assert len(rows) == 1
    assert rows[0].exit_code == 1


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
    ("args", "rest_path", "finding_field"),
    [
        (["auth", "https://fixture.invalid"], "/scan/auth-bypass", "vulnerableCount"),
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
            "vulnerableCount",
        ),
        (["headers", "https://fixture.invalid"], "/scan/headers", "vulnerableCount"),
        (["cors", "https://fixture.invalid"], "/scan/cors", "vulnerableCount"),
        (["endpoints", "fixture.invalid"], "/scan/endpoints", "findings"),
    ],
)
def test_every_check_command_validates_its_finding_indicator(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    rest_path: str,
    finding_field: str,
) -> None:
    rest_paths: list[str] = []
    data = deepcopy(_VALID_RESPONSES[rest_path])
    data[finding_field] = None

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
    ("args", "rest_path", "data", "expected_exit"),
    [
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
            {**_VALID_RESPONSES["/scan/idor"], "note": 123},
            1,
        ),
        (
            ["endpoints", "fixture.invalid"],
            "/scan/endpoints",
            {**_VALID_RESPONSES["/scan/endpoints"], "vulnerableCount": 1},
            0,
        ),
        (
            ["auth", "https://fixture.invalid"],
            "/scan/auth-bypass",
            {**_VALID_RESPONSES["/scan/auth-bypass"], "findings": [_ENDPOINT_FINDING]},
            0,
        ),
    ],
)
def test_check_commands_use_only_their_authoritative_verdict_field(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    rest_path: str,
    data: dict[str, Any],
    expected_exit: int,
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

    assert result.exit_code == expected_exit
    assert rest_paths == [rest_path]
    if expected_exit == 1:
        assert result.stdout == ""
        assert '"code":"INVALID_RESPONSE"' in result.stderr
        assert "Traceback" not in result.stderr
        assert "fixture.invalid" not in result.stderr
        assert "securityscan.py" not in result.stderr
    else:
        assert json.loads(result.stdout) == data
        assert result.stderr == ""


@pytest.mark.parametrize(
    ("response_model", "data"),
    [
        (
            AuthBypassResponse,
            {**_VALID_RESPONSES["/scan/auth-bypass"], "vulnerableCount": "0"},
        ),
        (
            AuthBypassResponse,
            {**_VALID_RESPONSES["/scan/auth-bypass"], "vulnerableCount": -1},
        ),
        (
            IdorResponse,
            {
                **_VALID_RESPONSES["/scan/idor"],
                "baseline": {key: value for key, value in _IDOR_PROBE.items() if key != "value"},
            },
        ),
        (
            HeadersBypassResponse,
            {
                **_VALID_RESPONSES["/scan/headers"],
                "baseline": {**_AUTH_PROBE, "durationMs": "3"},
            },
        ),
        (
            CorsResponse,
            {
                "results": [
                    {
                        "origin": "https://evil.com",
                        "acao": None,
                        "acac": None,
                        "vulnerable": 0,
                    }
                ],
                "vulnerableCount": 0,
            },
        ),
        (
            EndpointsScanResponse,
            {**_VALID_RESPONSES["/scan/endpoints"], "findings": [{"endpoint": "/admin"}]},
        ),
        (
            AuthBypassResponse,
            {**_VALID_RESPONSES["/scan/auth-bypass"], "findings": [{"endpoint": "/admin"}]},
        ),
        (
            EndpointsScanResponse,
            {**_VALID_RESPONSES["/scan/endpoints"], "vulnerableCount": True},
        ),
    ],
)
def test_scan_response_rejects_malformed_required_nested_and_extra_fields(
    response_model: _ResponseModel,
    data: dict[str, Any],
) -> None:
    with pytest.raises(BurpError, match="INVALID_RESPONSE"):
        _validate_scan_response(data, response_model)


@pytest.mark.parametrize(
    ("response_model", "data"),
    [
        (AuthBypassResponse, _VALID_RESPONSES["/scan/auth-bypass"]),
        (
            IdorResponse,
            {
                **_VALID_RESPONSES["/scan/idor"],
                "note": "manual review advised",
                "ignoredOwnValues": ["2"],
            },
        ),
        (HeadersBypassResponse, _VALID_RESPONSES["/scan/headers"]),
        (CorsResponse, _VALID_RESPONSES["/scan/cors"]),
        (
            EndpointsScanResponse,
            {**_VALID_RESPONSES["/scan/endpoints"], "vulnerableCount": 1},
        ),
        (
            AuthBypassResponse,
            {**_VALID_RESPONSES["/scan/auth-bypass"], "findings": [_ENDPOINT_FINDING]},
        ),
        (
            AuthBypassResponse,
            {**_VALID_RESPONSES["/scan/auth-bypass"], "futureServerField": {"value": 1}},
        ),
    ],
)
def test_scan_response_preserves_valid_dto_and_well_typed_extra_fields(
    response_model: _ResponseModel,
    data: dict[str, Any],
) -> None:
    assert _validate_scan_response(data, response_model) is data


def test_has_findings_uses_the_selected_authoritative_field() -> None:
    contradictory = {"vulnerableCount": 0, "findings": [_ENDPOINT_FINDING]}
    assert _has_findings(contradictory, "vulnerableCount") is False
    assert _has_findings(contradictory, "findings") is True

    contradictory = {"vulnerableCount": 1, "findings": []}
    assert _has_findings(contradictory, "vulnerableCount") is True
    assert _has_findings(contradictory, "findings") is False


def test_projected_idor_verdict_ignores_unrelated_findings() -> None:
    response = {"vulnerableCount": 0, "findings": [_ENDPOINT_FINDING]}
    projected = _project_for_display(response, finding_field="vulnerableCount")
    assert projected["verdict"] == "clean"
    assert projected["findings"] == [_ENDPOINT_FINDING]
