"""Installed-CLI audit for the five security-check leaves (L09-L13)."""

# allow: SIZE_OK — the excess is one immutable ten-case audit table; Task 9 owns one test file.

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

import pytest

from audit_fixture import AuditFixture, FixtureRoot


StreamMode = Literal["empty", "json", "nonempty"]


@dataclass(frozen=True, slots=True)
class CheckCase:
    """One predeclared normal or contrast invocation."""

    name: str
    row_id: str
    variant: Literal["normal", "contrast"]
    argv: tuple[str, ...]
    route: str | None
    request_json: str | None
    data_json: str | None
    rest_status: int
    exit_code: int
    stdout: StreamMode
    stderr: StreamMode


CASES: Final[tuple[CheckCase, ...]] = (
    CheckCase(
        "auth_denial_clean",
        "L09",
        "normal",
        ("check", "auth", "{{TARGET}}", "--endpoint", "/private"),
        "/scan/auth-bypass",
        '{"endpoints":["/private"],"baseUrl":"{{TARGET}}","method":"GET"}',
        '{"results":[],"totalScanned":1,"vulnerableCount":0,"inconclusiveCount":0}',
        200,
        0,
        "json",
        "empty",
    ),
    CheckCase(
        "auth_authorized_confirmed",
        "L09",
        "contrast",
        ("check", "auth", "{{TARGET}}", "--endpoint", "/private"),
        "/scan/auth-bypass",
        '{"endpoints":["/private"],"baseUrl":"{{TARGET}}","method":"GET"}',
        '{"results":[{"vulnerable":true}],"totalScanned":1,"vulnerableCount":1,"inconclusiveCount":0}',
        200,
        5,
        "json",
        "empty",
    ),
    CheckCase(
        "idor_own_other_clean",
        "L10",
        "normal",
        ("check", "idor", "{{TARGET}}/item/{id}", "--param", "id", "--own", "1", "--target", "2"),
        "/scan/idor",
        '{"endpoint":"{{TARGET}}/item/{id}","param":"id","ownValues":["1"],"targetValues":["2"],"method":"GET"}',
        '{"baseline":{"status":200,"inconclusive":false},"results":[{"vulnerable":false}],"vulnerableCount":0,"inconclusiveCount":0,"ignoredOwnValues":[]}',
        200,
        0,
        "json",
        "empty",
    ),
    CheckCase(
        "invalid_idor",
        "L10",
        "contrast",
        (
            "check",
            "idor",
            "{{TARGET}}/item/{id}",
            "--param",
            "id",
            "--own",
            "1",
            "--target",
            "2",
            "--header",
            "broken",
        ),
        None,
        None,
        None,
        0,
        2,
        "empty",
        "nonempty",
    ),
    CheckCase(
        "headers_anomaly",
        "L11",
        "normal",
        ("check", "headers", "{{TARGET}}/private", "--marker", "SECRET"),
        "/scan/headers",
        '{"url":"{{TARGET}}/private","method":"GET","protectedContentMarker":"SECRET"}',
        '{"baseline":{"status":403},"results":[{"anomalous":true,"vulnerable":false}],"anomalousCount":1,"vulnerableCount":0,"inconclusiveCount":0}',
        200,
        0,
        "json",
        "empty",
    ),
    CheckCase(
        "headers_confirmed",
        "L11",
        "contrast",
        ("check", "headers", "{{TARGET}}/private", "--marker", "SECRET"),
        "/scan/headers",
        '{"url":"{{TARGET}}/private","method":"GET","protectedContentMarker":"SECRET"}',
        '{"baseline":{"status":403},"results":[{"anomalous":true,"vulnerable":true}],"anomalousCount":1,"vulnerableCount":1,"inconclusiveCount":0}',
        200,
        5,
        "json",
        "empty",
    ),
    CheckCase(
        "cors_target_origin_clean",
        "L12",
        "normal",
        ("check", "cors", "{{TARGET}}/cors"),
        "/scan/cors",
        '{"url":"{{TARGET}}/cors","method":"GET"}',
        '{"results":[{"origin":"{{TARGET}}","acao":"{{TARGET}}","acac":"true","vulnerable":false}],"vulnerableCount":0,"inconclusiveCount":0}',
        200,
        0,
        "json",
        "empty",
    ),
    CheckCase(
        "cors_attacker_origin_confirmed",
        "L12",
        "contrast",
        ("check", "cors", "{{TARGET}}/cors"),
        "/scan/cors",
        '{"url":"{{TARGET}}/cors","method":"GET"}',
        '{"results":[{"origin":"https://evil.invalid","acao":"https://evil.invalid","acac":"true","vulnerable":true}],"vulnerableCount":1,"inconclusiveCount":0}',
        200,
        5,
        "json",
        "empty",
    ),
    CheckCase(
        "endpoints_host",
        "L13",
        "normal",
        ("check", "endpoints", "127.0.0.1", "--limit", "2"),
        "/scan/endpoints",
        '{"host":"127.0.0.1","tests":["auth-bypass","method-switch"],"limit":2}',
        '{"scanned":2,"findings":[],"durationMs":1,"source":"extension-h2-send-history","sourceCounts":{"repeater":1,"session":1},"errors":[],"inconclusiveCount":0}',
        200,
        0,
        "json",
        "empty",
    ),
    CheckCase(
        "unavailable_h2",
        "L13",
        "contrast",
        ("check", "endpoints", "127.0.0.1", "--limit", "2"),
        "/scan/endpoints",
        '{"host":"127.0.0.1","tests":["auth-bypass","method-switch"],"limit":2}',
        None,
        503,
        1,
        "empty",
        "json",
    ),
)
OBSERVATIONS: Final[Path] = (
    Path(__file__).resolve().parents[2] / "quality" / "command-audit" / "observations-checks.json"
)


def _materialize(value: str, target: str) -> str:
    return value.replace("{{TARGET}}", target)


def _response(case: CheckCase, target: str) -> bytes:
    if case.data_json is None:
        return b'{"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"H2 unavailable"}}'
    data = _materialize(case.data_json, target)
    return f'{{"success":true,"data":{data},"error":null}}'.encode()


def _stream_matches(mode: StreamMode, value: str) -> bool:
    match mode:
        case "empty":
            return value == ""
        case "json":
            try:
                return isinstance(json.loads(value), dict)
            except json.JSONDecodeError:
                return False
        case "nonempty":
            return bool(value)


def _json_matches(value: str, expected: str) -> bool:
    try:
        return bool(json.loads(value) == json.loads(expected))
    except json.JSONDecodeError:
        return False


def _expected_stdout(case: CheckCase, target: str) -> str:
    assert case.data_json is not None
    expected = _materialize(case.data_json, target)
    if case.row_id == "L10":
        verdict = "vulnerable" if case.exit_code == 5 else "clean"
        return expected.replace(',"ignoredOwnValues":[]}', f',"verdict":"{verdict}"}}')
    return expected


def _classifier_projection(case: CheckCase) -> dict[str, int | bool | None]:
    has_payload = case.stdout == "json"
    return {
        "anomalousCount": 1 if has_payload and case.row_id == "L11" else None,
        "confirmed": has_payload and case.exit_code == 5,
        "findingsCount": 0 if has_payload and case.row_id == "L13" else None,
        "vulnerableCount": (1 if case.exit_code == 5 else 0)
        if has_payload and case.row_id != "L13"
        else None,
    }


def _write_once(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _run_case(case: CheckCase, fixture: AuditFixture, evidence_dir: Path) -> None:
    target = fixture.manifest.target_url
    argv = [_materialize(part, target) for part in case.argv]
    request = _materialize(case.request_json, target).encode() if case.request_json else None
    if case.route is not None and request is not None:
        fixture.expect_rest_route(
            "POST",
            case.route,
            expected_body=request,
            status=case.rest_status,
            body=_response(case, target),
        )

    expected_stdout_json = _expected_stdout(case, target) if case.stdout == "json" else None
    expected_stderr_json = (
        '{"error":{"code":"SERVICE_UNAVAILABLE","message":"H2 unavailable",'
        '"status":503,"http_status":503,"op":"POST /scan/endpoints"}}'
        if case.stderr == "json"
        else None
    )

    expected: dict[str, object] = {
        "argv": [*fixture.command("bp"), *argv],
        "environment": {
            "BP_AGENT": "1",
            "BURP_REST_URL": fixture.manifest.rest_url,
            "HOME": str(fixture.manifest.home),
            "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
            "BP_CONFIG_PATH": str(fixture.manifest.config_path),
            "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
            "NO_COLOR": "1",
            "TERM": "dumb",
        },
        "expected": {
            "exit": case.exit_code,
            "stdout": case.stdout,
            "stderr": case.stderr,
            "stdoutJson": expected_stdout_json,
            "stderrJson": expected_stderr_json,
            "classifier": _classifier_projection(case),
            "restRoute": f"POST {case.route}" if case.route else "none",
            "restEffectCount": 1 if case.route else 0,
            "fixtureTargetEffectCount": 0,
            "endToEndTargetEffectCount": "INCONCLUSIVE",
        },
        "id": case.row_id,
        "variant": case.variant,
    }
    canonical = json.dumps(expected, separators=(",", ":"), sort_keys=True).encode()
    run_id = f"{time.time_ns()}-{case.row_id.lower()}-{case.variant}"
    expected["preRunSeal"] = {
        "algorithm": "sha256",
        "hash": hashlib.sha256(canonical).hexdigest(),
        "sealedAt": datetime.now(UTC).isoformat(),
    }
    _write_once(evidence_dir / f"task-9-{run_id}-expected.json", expected)

    before = fixture.snapshot()
    result = fixture.run(argv, executable="bp")
    after = fixture.snapshot()
    expected_routes = [] if case.route is None else [("POST", case.route)]
    actual_routes = [(effect.method, effect.path) for effect in after.rest_effects]
    stdout_content_matches = expected_stdout_json is None or _json_matches(
        result.stdout, expected_stdout_json
    )
    stderr_content_matches = expected_stderr_json is None or _json_matches(
        result.stderr, expected_stderr_json
    )
    rest_content_matches = (
        after.rest_effects == ()
        if request is None
        else len(after.rest_effects) == 1
        and after.rest_effects[0].status == case.rest_status
        and after.rest_effects[0].body_length == len(request)
        and after.rest_effects[0].body_sha256 == hashlib.sha256(request).hexdigest()
    )
    matches = (
        before.rest_effects == before.target_effects == ()
        and result.returncode == case.exit_code
        and _stream_matches(case.stdout, result.stdout)
        and _stream_matches(case.stderr, result.stderr)
        and stdout_content_matches
        and stderr_content_matches
        and actual_routes == expected_routes
        and rest_content_matches
        and after.target_effects == ()
    )
    actual: dict[str, object] = {
        "actual": {
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "restLog": [asdict(effect) for effect in after.rest_effects],
            "targetLog": [asdict(effect) for effect in after.target_effects],
        },
        "id": case.row_id,
        "observedAt": datetime.now(UTC).isoformat(),
        "preRunSeal": expected["preRunSeal"],
        "variant": case.variant,
        "verdict": "PASS" if matches else "FAIL",
    }
    _write_once(evidence_dir / f"task-9-{run_id}-actual.json", actual)

    assert matches, actual


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_installed_check_normal_and_contrast(case: CheckCase, tmp_path: Path) -> None:
    """Seal the concrete oracle, invoke installed bp, then capture actual effects."""
    evidence_dir = Path(os.environ.get("BP_AUDIT_EVIDENCE_DIR", tmp_path / "evidence"))
    with FixtureRoot(tmp_path) as fixture:
        _run_case(case, fixture, evidence_dir)


def test_observations_are_complete_and_temporally_ordered() -> None:
    """Committed audit rows contain both sealed predictions and later observations."""
    rows = json.loads(OBSERVATIONS.read_text(encoding="utf-8"))
    assert isinstance(rows, list)
    assert [row["id"] for row in rows] == ["L09", "L10", "L11", "L12", "L13"]
    for row in rows:
        assert set(row) == {"id", "oracleHash", "candidate", "normal", "contrast"}
        assert len(row["oracleHash"]) == 64
        for variant_name in ("normal", "contrast"):
            variant = row[variant_name]
            assert set(variant) == {
                "preRunSeal",
                "argv",
                "environment",
                "expected",
                "actual",
                "verdict",
                "limits",
                "evidence",
            }
            frozen = {
                "argv": variant["argv"],
                "environment": variant["environment"],
                "expected": variant["expected"],
                "id": row["id"],
                "variant": variant_name,
            }
            canonical = json.dumps(frozen, separators=(",", ":"), sort_keys=True).encode()
            assert variant["preRunSeal"]["hash"] == hashlib.sha256(canonical).hexdigest()
            assert datetime.fromisoformat(
                variant["preRunSeal"]["sealedAt"]
            ) < datetime.fromisoformat(variant["actual"]["observedAt"])
            assert len(variant["preRunSeal"]["hash"]) == 64
            assert variant["actual"].keys() >= {"exit", "stdout", "stderr", "restLog", "targetLog"}
            assert variant["expected"]["endToEndTargetEffectCount"] == "INCONCLUSIVE"
            assert variant["verdict"] in {"PASS", "FAIL"}
            expected_file = variant["evidence"]["expectedFile"]
            actual_file = variant["evidence"]["actualFile"]
            assert expected_file.removesuffix("-expected.json") == actual_file.removesuffix(
                "-actual.json"
            )
            evidence_dir_raw = os.environ.get("BP_AUDIT_EVIDENCE_DIR")
            if evidence_dir_raw is not None:
                evidence_dir = Path(evidence_dir_raw)
                expected_artifact = json.loads(
                    (evidence_dir / expected_file).read_text(encoding="utf-8")
                )
                actual_artifact = json.loads(
                    (evidence_dir / actual_file).read_text(encoding="utf-8")
                )
                assert expected_artifact["preRunSeal"] == variant["preRunSeal"]
                assert actual_artifact["preRunSeal"] == variant["preRunSeal"]
                assert actual_artifact["actual"] == {
                    key: value for key, value in variant["actual"].items() if key != "observedAt"
                }
