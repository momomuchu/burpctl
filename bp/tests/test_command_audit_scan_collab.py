"""Subprocess audit for the Collaborator and Scanner command leaves.

# noqa: SIZE_OK -- the sealed L01-L08 scenario table is the module's single responsibility.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, TypeAlias

import pytest

from audit_fixture import AuditFixture, FixtureRoot, RequestEffect

ROOT: Final = Path(__file__).resolve().parents[2]
ORACLES: Final = ROOT / "quality" / "command-audit" / "oracles.json"
OBSERVATIONS: Final = ROOT / "quality" / "command-audit" / "observations-scan-collab.json"
CANDIDATE: Final = "3af139dc0b4020923f831099338c92af3265d7e2"
EVIDENCE_ENV: Final = "BP_AUDIT_EVIDENCE_DIR"
RECORD_ENV: Final = "BP_AUDIT_RECORD"
JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class Case:
    """One predeclared CLI invocation and its fixture response."""

    row_id: str
    variant: str
    argv: tuple[str, ...]
    method: str
    path: str
    status: int
    response: bytes
    request_body: str | None
    exit_code: int
    stdout: str
    stderr: str
    domain_effect: str
    limits: tuple[str, ...]


def _ok(data: str) -> bytes:
    return f'{{"success":true,"data":{data},"error":null}}'.encode()


def _error(code: str, message: str) -> bytes:
    return (
        f'{{"success":false,"data":null,"error":{{"code":"{code}","message":"{message}"}}}}'
    ).encode()


def _stderr(error: tuple[str, str, int], route: tuple[str, str]) -> str:
    code, message, status = error
    method, path = route
    detail = {
        "error": {
            "code": code,
            "message": message,
            "status": status,
            "http_status": status,
            "op": f"{method} {path}",
        }
    }
    return json.dumps(detail, separators=(",", ":")) + "\n"


PRO_LIMIT: Final = (
    "The loopback REST response simulates a Pro server; the CLI fixture does not create a real Montoya task or Collaborator payload.",
)
ZERO_TASK_LIMIT: Final = (
    "The CLI fixture observes the 501 response and zero target traffic, not Montoya internals; ScannerServiceTest proves zero scanner/Burp API calls.",
)

PAYLOADS = (
    '{"payloads":[{"id":"cid-001","payload":"cid-001.oastify.test","interactionId":"cid-001"}]}'
)
POLL = '{"found":false,"interactions":[],"queriedPayloadId":"cid-001"}'
START = '{"scanId":"sid-001","status":"running"}'
STATUS = '{"scanId":"sid-001","status":"Running","crawlProgress":null,"auditProgress":null,"issueCount":1,"statusMessage":"Running","requestCount":2,"errorCount":0}'
ISSUES = '{"scanId":"sid-001","issues":[{"name":"fixture issue","url":"{{TARGET}}/issue","severity":"LOW","confidence":"FIRM"}],"total":1}'
DEFS = '{"definitions":[{"name":"fixture definition","typeIndex":1,"description":"fixture","remediation":"fixture"}],"total":1}'
EMPTY_DEFS = '{"definitions":[],"total":0}'


CASES: Final = (
    Case(
        "L01",
        "normal",
        ("bp", "collab", "new"),
        "POST",
        "/collaborator/generate",
        200,
        _ok(PAYLOADS),
        None,
        0,
        PAYLOADS + "\n",
        "",
        "simulated collaborator generation response",
        PRO_LIMIT,
    ),
    Case(
        "L01",
        "contrast",
        ("bp", "collab", "new"),
        "POST",
        "/collaborator/generate",
        503,
        _error("PRO_REQUIRED", "Burp Suite Professional is required"),
        None,
        4,
        "",
        _stderr(
            ("PRO_REQUIRED", "Burp Suite Professional is required", 503),
            ("POST", "/collaborator/generate"),
        ),
        "zero provider effect",
        PRO_LIMIT,
    ),
    Case(
        "L01",
        "providerFailure",
        ("bp", "collab", "new"),
        "POST",
        "/collaborator/generate",
        503,
        _error("SERVICE_UNAVAILABLE", "Burp Collaborator provider operation failed"),
        None,
        1,
        "",
        _stderr(
            ("SERVICE_UNAVAILABLE", "Burp Collaborator provider operation failed", 503),
            ("POST", "/collaborator/generate"),
        ),
        "provider failure",
        PRO_LIMIT,
    ),
    Case(
        "L02",
        "normal",
        ("bp", "collab", "poll", "cid-001"),
        "GET",
        "/collaborator/poll/cid-001",
        200,
        _ok(POLL),
        None,
        0,
        POLL + "\n",
        "",
        "simulated collaborator read",
        PRO_LIMIT,
    ),
    Case(
        "L02",
        "contrast",
        ("bp", "collab", "poll", "unknown"),
        "GET",
        "/collaborator/poll/unknown",
        404,
        _error("NOT_FOUND", "Collaborator payload not found"),
        None,
        1,
        "",
        _stderr(
            ("NOT_FOUND", "Collaborator payload not found", 404),
            ("GET", "/collaborator/poll/unknown"),
        ),
        "zero provider effect",
        PRO_LIMIT,
    ),
    Case(
        "L02",
        "providerFailure",
        ("bp", "collab", "poll", "cid-001"),
        "GET",
        "/collaborator/poll/cid-001",
        503,
        _error("SERVICE_UNAVAILABLE", "Burp Collaborator provider operation failed"),
        None,
        1,
        "",
        _stderr(
            ("SERVICE_UNAVAILABLE", "Burp Collaborator provider operation failed", 503),
            ("GET", "/collaborator/poll/cid-001"),
        ),
        "provider failure",
        PRO_LIMIT,
    ),
    Case(
        "L03",
        "normal",
        ("bp", "scan", "crawl", "{{TARGET}}/"),
        "POST",
        "/scanner/crawl",
        200,
        _ok(START),
        '{"url":"{{TARGET}}/","config":{}}',
        0,
        START + "\n",
        "",
        "simulated scanner task response",
        PRO_LIMIT,
    ),
    Case(
        "L03",
        "contrast",
        ("bp", "scan", "crawl", "{{TARGET}}/"),
        "POST",
        "/scanner/crawl",
        503,
        _error("PRO_REQUIRED", "this operation requires Burp Suite Professional"),
        '{"url":"{{TARGET}}/","config":{}}',
        4,
        "",
        _stderr(
            ("PRO_REQUIRED", "this operation requires Burp Suite Professional", 503),
            ("POST", "/scanner/crawl"),
        ),
        "zero scanner task",
        PRO_LIMIT,
    ),
    Case(
        "L04",
        "normal",
        ("bp", "scan", "audit", "{{TARGET}}/"),
        "POST",
        "/scanner/audit",
        200,
        _ok(START),
        '{"url":"{{TARGET}}/","config":{}}',
        0,
        START + "\n",
        "",
        "simulated scanner task response",
        PRO_LIMIT,
    ),
    Case(
        "L04",
        "contrast",
        ("bp", "scan", "audit", "{{TARGET}}/"),
        "POST",
        "/scanner/audit",
        503,
        _error("PRO_REQUIRED", "this operation requires Burp Suite Professional"),
        '{"url":"{{TARGET}}/","config":{}}',
        4,
        "",
        _stderr(
            ("PRO_REQUIRED", "this operation requires Burp Suite Professional", 503),
            ("POST", "/scanner/audit"),
        ),
        "zero scanner task",
        PRO_LIMIT,
    ),
    Case(
        "L05",
        "normal",
        ("bp", "scan", "all", "{{TARGET}}/"),
        "POST",
        "/scanner/crawl-and-audit",
        501,
        _error("UNSUPPORTED", "linked crawl and audit is unsupported"),
        '{"url":"{{TARGET}}/","config":{}}',
        1,
        "",
        _stderr(
            ("UNSUPPORTED", "linked crawl and audit is unsupported", 501),
            ("POST", "/scanner/crawl-and-audit"),
        ),
        "zero scanner task",
        ZERO_TASK_LIMIT,
    ),
    Case(
        "L05",
        "contrast",
        ("bp", "scan", "all", "{{TARGET}}/"),
        "POST",
        "/scanner/crawl-and-audit",
        501,
        _error("UNSUPPORTED", "linked crawl and audit is unsupported"),
        '{"url":"{{TARGET}}/","config":{}}',
        1,
        "",
        _stderr(
            ("UNSUPPORTED", "linked crawl and audit is unsupported", 501),
            ("POST", "/scanner/crawl-and-audit"),
        ),
        "zero scanner task",
        ZERO_TASK_LIMIT,
    ),
    Case(
        "L06",
        "normal",
        ("bp", "scan", "status", "sid-001"),
        "GET",
        "/scanner/sid-001/status",
        200,
        _ok(STATUS),
        None,
        0,
        STATUS + "\n",
        "",
        "one scanner state read",
        PRO_LIMIT,
    ),
    Case(
        "L06",
        "contrast",
        ("bp", "scan", "status", "unknown"),
        "GET",
        "/scanner/unknown/status",
        404,
        _error("NOT_FOUND", "scanner task was not found"),
        None,
        1,
        "",
        _stderr(
            ("NOT_FOUND", "scanner task was not found", 404), ("GET", "/scanner/unknown/status")
        ),
        "zero task mutation",
        PRO_LIMIT,
    ),
    Case(
        "L07",
        "normal",
        ("bp", "scan", "issues", "sid-001"),
        "GET",
        "/scanner/sid-001/issues",
        200,
        _ok(ISSUES),
        None,
        0,
        ISSUES + "\n",
        "",
        "one scanner issue read",
        PRO_LIMIT,
    ),
    Case(
        "L07",
        "contrast",
        ("bp", "scan", "issues", "unknown"),
        "GET",
        "/scanner/unknown/issues",
        404,
        _error("NOT_FOUND", "scanner task was not found"),
        None,
        1,
        "",
        _stderr(
            ("NOT_FOUND", "scanner task was not found", 404), ("GET", "/scanner/unknown/issues")
        ),
        "zero task mutation",
        PRO_LIMIT,
    ),
    Case(
        "L08",
        "normal",
        ("bp", "scan", "defs"),
        "GET",
        "/scanner/issue-definitions",
        200,
        _ok(DEFS),
        None,
        0,
        DEFS + "\n",
        "",
        "one scanner definition read",
        PRO_LIMIT,
    ),
    Case(
        "L08",
        "contrast",
        ("bp", "scan", "defs"),
        "GET",
        "/scanner/issue-definitions",
        200,
        _ok(EMPTY_DEFS),
        None,
        0,
        EMPTY_DEFS + "\n",
        "",
        "Community-safe empty list",
        (
            "The sealed oracle contrast predicts empty stdout plus a typed stderr despite exit 0; current Kotlin and CLI behavior returns JSON on stdout.",
        ),
    ),
)


def _materialize(value: str, fixture: AuditFixture) -> str:
    return value.replace("{{TARGET}}", fixture.manifest.target_url)


def _write_sealed(path: Path, record: JsonObject) -> str:
    canonical = json.dumps(record, separators=(",", ":"), sort_keys=True).encode()
    seal = hashlib.sha256(canonical).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        json.dump({**record, "preRunSeal": seal}, stream, indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return seal


def _effect(effect: RequestEffect) -> JsonObject:
    return {
        "method": effect.method,
        "path": effect.path,
        "bodySha256": effect.body_sha256,
        "bodyLength": effect.body_length,
        "status": effect.status,
    }


def _effects(effects: tuple[RequestEffect, ...]) -> list[JsonValue]:
    return [_effect(effect) for effect in effects]


def _oracle_rows() -> dict[str, JsonObject]:
    document = json.loads(ORACLES.read_text(encoding="utf-8"))
    return {
        row["id"]: row for row in document["rows"] if row["id"] in {f"L0{i}" for i in range(1, 9)}
    }


def _run(case: Case, tmp_path: Path) -> JsonObject:
    with FixtureRoot(tmp_path) as fixture:
        argv = [_materialize(part, fixture) for part in case.argv]
        response = _materialize(case.response.decode(), fixture).encode()
        body = _materialize(case.request_body, fixture).encode() if case.request_body else None
        if body is None:
            fixture.add_rest_route(case.method, case.path, status=case.status, body=response)
        else:
            fixture.expect_rest_route(
                case.method, case.path, expected_body=body, status=case.status, body=response
            )
        env: JsonObject = {
            "BP_AGENT": "1",
            "BP_CONFIG_PATH": str(fixture.manifest.config_path),
            "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
            "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
            "BURP_REST_URL": fixture.manifest.rest_url,
            "HOME": str(fixture.manifest.home),
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
        expected_at = datetime.now(UTC).isoformat()
        expected: JsonObject = {
            "exit": case.exit_code,
            "stdout": _materialize(case.stdout, fixture),
            "stderr": case.stderr,
            "route": f"{case.method} {case.path}",
            "effect": case.domain_effect,
            "environment": env,
        }
        preflight: JsonObject = {
            "id": case.row_id,
            "variant": case.variant,
            "argv": [*fixture.command(argv[0]), *argv[1:]],
            "expected": expected,
            "expectedAt": expected_at,
        }
        evidence_root = Path(os.environ.get(EVIDENCE_ENV, tmp_path))
        stem = f"task-8-{case.row_id.lower()}-{case.variant}"
        preflight_path = evidence_root / f"{stem}-preflight.json"
        seal = _write_sealed(preflight_path, preflight)
        frozen = preflight_path.read_bytes()
        before = fixture.snapshot()
        completed = fixture.run(argv[1:], executable=argv[0])
        after = fixture.snapshot()
        observed_at = datetime.now(UTC).isoformat()
        assert preflight_path.read_bytes() == frozen
        assert before.rest_effects == () and before.target_effects == ()
        assert completed.returncode == case.exit_code
        assert completed.stdout == _materialize(case.stdout, fixture)
        assert completed.stderr == case.stderr
        assert len(after.rest_effects) == 1
        assert after.rest_effects[0].method == case.method
        assert after.rest_effects[0].path == case.path
        assert after.rest_effects[0].status == case.status
        if body is not None:
            assert after.rest_effects[0].body_sha256 == hashlib.sha256(body).hexdigest()
        assert after.target_effects == ()
        assert expected_at < observed_at
        target_log = _effects(after.target_effects)
        record: JsonObject = {
            "preRunSeal": {"sha256": seal, "expectedAt": expected_at},
            "argv": preflight["argv"],
            "expected": expected,
            "actual": {
                "observedAt": observed_at,
                "exit": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "restLog": _effects(after.rest_effects),
                "targetLog": target_log,
            },
            "verdict": "PASS",
            "limits": list(case.limits),
        }
        actual_path = evidence_root / f"{stem}-actual.json"
        actual_path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return record


def _capture_all(tmp_path: Path) -> list[JsonObject]:
    by_row: dict[str, JsonObject] = {}
    rows = _oracle_rows()
    for case in CASES:
        seal = rows[case.row_id]["seal"]
        assert isinstance(seal, dict)
        oracle_hash = seal["hash"]
        assert isinstance(oracle_hash, str)
        row = by_row.setdefault(
            case.row_id,
            {
                "id": case.row_id,
                "oracleHash": oracle_hash,
                "candidate": CANDIDATE,
            },
        )
        record = _run(case, tmp_path)
        if case.variant in {"normal", "contrast"}:
            row[case.variant] = record
        else:
            additional = row.setdefault("additional", [])
            assert isinstance(additional, list)
            additional.append({"case": case.variant, **record})
    l08 = next(row for row in by_row.values() if row["id"] == "L08")
    contrast = l08["contrast"]
    assert isinstance(contrast, dict)
    contrast["verdict"] = "ORACLE_MISMATCH"
    limits = contrast["limits"]
    assert isinstance(limits, list)
    limits.append(
        "Manifest L08 contrast expects empty stdout and typed stderr; observed Community-safe JSON agrees with ScannerService.issueDefinitions()."
    )
    return list(by_row.values())


def _semantic(document: list[JsonObject]) -> list[tuple[str, str, int, str, int]]:
    result: list[tuple[str, str, int, str, int]] = []
    for row in document:
        for variant in ("normal", "contrast"):
            record = row[variant]
            assert isinstance(record, dict)
            actual = record["actual"]
            assert isinstance(actual, dict)
            rest_log = actual["restLog"]
            assert isinstance(rest_log, list) and len(rest_log) == 1
            exit_code = actual["exit"]
            target_log = actual["targetLog"]
            assert isinstance(exit_code, int) and not isinstance(exit_code, bool)
            assert isinstance(target_log, list)
            result.append(
                (str(row["id"]), variant, exit_code, str(record["verdict"]), len(target_log))
            )
    return result


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.variant == "normal"],
    ids=lambda case: f"{case.row_id}-pro",
)
def test_pro(case: Case, tmp_path: Path) -> None:
    _run(case, tmp_path)


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.variant == "contrast"],
    ids=lambda case: f"{case.row_id}-community-or-scan-all",
)
def test_community_or_scan_all(case: Case, tmp_path: Path) -> None:
    _run(case, tmp_path)


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.variant == "providerFailure"],
    ids=lambda case: f"{case.row_id}-service-failure",
)
def test_service_failure(case: Case, tmp_path: Path) -> None:
    _run(case, tmp_path)


def test_observation_artifact_matches_fresh_cli_audit(tmp_path: Path) -> None:
    if os.environ.get(RECORD_ENV) == "1":
        observed = _capture_all(tmp_path)
        OBSERVATIONS.write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8")
    committed = json.loads(OBSERVATIONS.read_text(encoding="utf-8"))
    expected = [
        (
            case.row_id,
            case.variant,
            case.exit_code,
            "ORACLE_MISMATCH" if (case.row_id, case.variant) == ("L08", "contrast") else "PASS",
            0,
        )
        for case in CASES
        if case.variant in {"normal", "contrast"}
    ]
    assert _semantic(committed) == expected
    assert all(row["candidate"] == CANDIDATE for row in committed)
    assert all(
        row["normal"]["preRunSeal"]["expectedAt"] < row["normal"]["actual"]["observedAt"]
        for row in committed
    )
    assert all(
        row["contrast"]["preRunSeal"]["expectedAt"] < row["contrast"]["actual"]["observedAt"]
        for row in committed
    )
