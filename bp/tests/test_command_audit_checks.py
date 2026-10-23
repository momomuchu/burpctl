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
from typing import Final, Literal, TypedDict

import pytest

from audit_fixture import AuditFixture, FixtureRoot


StreamMode = Literal["empty", "json", "nonempty"]
MismatchVerdict = Literal["ORACLE_MISMATCH", "PRODUCT_CONTRACT_DEFECT"]


class ManifestStream(TypedDict):
    mode: StreamMode
    shape: str


class ManifestEffect(TypedDict):
    route: str
    effect: str


class ManifestContrast(TypedDict):
    case: str
    exit: int
    stdout: ManifestStream
    stderr: ManifestStream
    effect: ManifestEffect


class ManifestSeal(TypedDict):
    hash: str


class ManifestRow(TypedDict):
    id: str
    seal: ManifestSeal
    contrast: ManifestContrast


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
ORACLES: Final[Path] = OBSERVATIONS.with_name("oracles.json")
MANIFEST_CONTRASTS: Final[tuple[tuple[str, str, MismatchVerdict], ...]] = (
    ("L09", "auth_denial_clean", "ORACLE_MISMATCH"),
    ("L10", "invalid_idor", "PRODUCT_CONTRACT_DEFECT"),
    ("L11", "headers_anomaly", "ORACLE_MISMATCH"),
    ("L12", "cors_attacker_origin_confirmed", "ORACLE_MISMATCH"),
    ("L13", "unavailable_h2", "ORACLE_MISMATCH"),
)
AUTHORITY_SOURCES: Final[dict[str, list[str]]] = {
    "L09": [
        "docs/CLI.md:113",
        "docs/OUTPUT.md:513-518",
        "bp/src/bp/cliutil.py:145-160,189-210",
        "bp/src/bp/commands/securityscan.py:171-180",
    ],
    "L10": [
        "docs/OUTPUT.md:3-9",
        "bp/src/bp/cliutil.py:213-229",
        "bp/src/bp/commands/securityscan.py:209-223",
    ],
    "L11": [
        "docs/SPEC.md:23",
        "bp/src/bp/commands/securityscan.py:98-112,276-288",
        "bp/src/bp/cliutil.py:189-210",
    ],
    "L12": [
        "docs/CLI.md:113",
        "bp/src/bp/commands/securityscan.py:308-316",
        "bp/src/bp/cliutil.py:189-210",
    ],
    "L13": [
        "docs/SPEC.md:512,514-517",
        "bp/src/bp/commands/securityscan.py:343-357",
        "bp/src/bp/cliutil.py:27-37,145-160",
    ],
}


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


def _manifest_stream_matches(expected: ManifestStream, value: str) -> bool:
    if not _stream_matches(expected["mode"], value):
        return False
    if expected["shape"] != "typed_error":
        return True
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return False
    error = parsed.get("error") if isinstance(parsed, dict) else None
    return (
        isinstance(error, dict)
        and isinstance(error.get("code"), str)
        and isinstance(error.get("message"), str)
    )


def _mismatch_verdict(manifest_match: bool, classification: MismatchVerdict) -> str:
    """Never turn a sealed-manifest mismatch into a local-expectation PASS."""
    return "PASS" if manifest_match else classification


def _required_dict(value: object) -> dict[object, object]:
    assert isinstance(value, dict)
    return value


def _required_str(value: object) -> str:
    assert isinstance(value, str)
    return value


def _stream_mode(value: object) -> StreamMode:
    if value == "empty":
        return "empty"
    if value == "json":
        return "json"
    if value == "nonempty":
        return "nonempty"
    raise AssertionError(f"invalid stream mode: {value!r}")


def _manifest_stream(value: object) -> ManifestStream:
    raw = _required_dict(value)
    return {"mode": _stream_mode(raw.get("mode")), "shape": _required_str(raw.get("shape"))}


def _manifest_row(row_id: str) -> ManifestRow:
    document: object = json.loads(ORACLES.read_text(encoding="utf-8"))
    raw_rows = _required_dict(document).get("rows")
    assert isinstance(raw_rows, list)
    for value in raw_rows:
        row = _required_dict(value)
        if row.get("id") != row_id:
            continue
        raw_seal = _required_dict(row.get("seal"))
        raw_contrast = _required_dict(row.get("contrast"))
        raw_effect = _required_dict(raw_contrast.get("effect"))
        exit_code = raw_contrast.get("exit")
        assert isinstance(exit_code, int) and not isinstance(exit_code, bool)
        return {
            "id": row_id,
            "seal": {"hash": _required_str(raw_seal.get("hash"))},
            "contrast": {
                "case": _required_str(raw_contrast.get("case")),
                "exit": exit_code,
                "stdout": _manifest_stream(raw_contrast.get("stdout")),
                "stderr": _manifest_stream(raw_contrast.get("stderr")),
                "effect": {
                    "route": _required_str(raw_effect.get("route")),
                    "effect": _required_str(raw_effect.get("effect")),
                },
            },
        }
    raise AssertionError(f"missing manifest row: {row_id}")


def _case(name: str) -> CheckCase:
    return next(case for case in CASES if case.name == name)


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


@pytest.mark.parametrize(
    ("row_id", "case_name", "classification"),
    MANIFEST_CONTRASTS,
    ids=[item[0] for item in MANIFEST_CONTRASTS],
)
def test_exact_sealed_manifest_contrast(
    row_id: str,
    case_name: str,
    classification: MismatchVerdict,
    tmp_path: Path,
) -> None:
    """Compare a fresh concrete invocation directly with the sealed contrast."""
    evidence_dir = Path(os.environ.get("BP_AUDIT_EVIDENCE_DIR", tmp_path / "evidence"))
    manifest_row = _manifest_row(row_id)
    expected = manifest_row["contrast"]
    assert isinstance(expected, dict)
    case = _case(case_name)

    with FixtureRoot(tmp_path) as fixture:
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

        sealed: dict[str, object] = {
            "argv": [*fixture.command("bp"), *argv],
            "authorityClassification": classification,
            "authoritySources": AUTHORITY_SOURCES[row_id],
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
            "expected": expected,
            "id": row_id,
            "oracleHash": manifest_row["seal"]["hash"],
            "scenario": "original-manifest-contrast",
        }
        canonical = json.dumps(sealed, separators=(",", ":"), sort_keys=True).encode()
        run_id = f"{time.time_ns()}-{row_id.lower()}-manifest-contrast"
        sealed["preRunSeal"] = {
            "algorithm": "sha256",
            "hash": hashlib.sha256(canonical).hexdigest(),
            "sealedAt": datetime.now(UTC).isoformat(),
        }
        expected_name = f"task-9-manifest-contrast-{run_id}-expected.json"
        actual_name = f"task-9-manifest-contrast-{run_id}-actual.json"
        _write_once(evidence_dir / expected_name, sealed)

        before = fixture.snapshot()
        result = fixture.run(argv, executable="bp")
        after = fixture.snapshot()
        expected_route = expected["effect"]["route"]
        actual_routes = [f"{effect.method} {effect.path}" for effect in after.rest_effects]
        route_match = actual_routes == ([] if expected_route == "none" else [expected_route])
        comparison = {
            "exitMatch": result.returncode == expected["exit"],
            "stdoutMatch": _manifest_stream_matches(expected["stdout"], result.stdout),
            "stderrMatch": _manifest_stream_matches(expected["stderr"], result.stderr),
            "routeMatch": route_match,
            "effectMatch": after.target_effects == ()
            if expected["effect"]["effect"] == "zero"
            else False,
        }
        manifest_match = before.rest_effects == before.target_effects == () and all(
            comparison.values()
        )
        comparison["manifestMatch"] = manifest_match
        verdict = _mismatch_verdict(manifest_match, classification)
        actual: dict[str, object] = {
            "actual": {
                "exit": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "restLog": [asdict(effect) for effect in after.rest_effects],
                "targetLog": [asdict(effect) for effect in after.target_effects],
            },
            "comparison": comparison,
            "evidence": {"actualFile": actual_name, "expectedFile": expected_name},
            "id": row_id,
            "limits": [
                "The loopback REST fixture proves CLI routing and payload only; it does not execute Kotlin probes.",
                "End-to-end target effects remain INCONCLUSIVE; no external vulnerability claim is made.",
            ],
            "observedAt": datetime.now(UTC).isoformat(),
            "oracleHash": manifest_row["seal"]["hash"],
            "preRunSeal": sealed["preRunSeal"],
            "scenario": "original-manifest-contrast",
            "verdict": verdict,
        }
        _write_once(evidence_dir / actual_name, actual)

        assert manifest_match is False
        assert verdict == classification


def test_observations_are_complete_and_temporally_ordered() -> None:
    """Committed audit rows contain both sealed predictions and later observations."""
    rows = json.loads(OBSERVATIONS.read_text(encoding="utf-8"))
    assert isinstance(rows, list)
    assert [row["id"] for row in rows[:5]] == ["L09", "L10", "L11", "L12", "L13"]
    assert [row["id"] for row in rows[5:]] == ["L09", "L10", "L11", "L12", "L13"]
    for row in rows[:5]:
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

    classifications = dict(
        (row_id, classification) for row_id, _, classification in MANIFEST_CONTRASTS
    )
    for row in rows[5:]:
        manifest_row = _manifest_row(row["id"])
        assert row["scenario"] == "original-manifest-contrast"
        assert row["oracleHash"] == manifest_row["seal"]["hash"]
        assert row["expected"] == manifest_row["contrast"]
        frozen = {
            "argv": row["argv"],
            "authorityClassification": row["authorityClassification"],
            "authoritySources": row["authoritySources"],
            "environment": row["environment"],
            "expected": row["expected"],
            "id": row["id"],
            "oracleHash": row["oracleHash"],
            "scenario": row["scenario"],
        }
        canonical = json.dumps(frozen, separators=(",", ":"), sort_keys=True).encode()
        assert row["preRunSeal"]["hash"] == hashlib.sha256(canonical).hexdigest()
        assert datetime.fromisoformat(row["preRunSeal"]["sealedAt"]) < datetime.fromisoformat(
            row["actual"]["observedAt"]
        )
        assert row["comparison"]["manifestMatch"] is False
        assert row["verdict"] == classifications[row["id"]]
        assert row["verdict"] != "PASS"
        assert _mismatch_verdict(False, classifications[row["id"]]) != "PASS"
        assert row["actual"].keys() >= {"exit", "stdout", "stderr", "restLog", "targetLog"}
        assert len(row["limits"]) >= 2
        expected_file = row["evidence"]["expectedFile"]
        actual_file = row["evidence"]["actualFile"]
        assert expected_file.removesuffix("-expected.json") == actual_file.removesuffix(
            "-actual.json"
        )
        evidence_dir_raw = os.environ.get("BP_AUDIT_EVIDENCE_DIR")
        if evidence_dir_raw is not None:
            evidence_dir = Path(evidence_dir_raw)
            expected_artifact = json.loads(
                (evidence_dir / expected_file).read_text(encoding="utf-8")
            )
            actual_artifact = json.loads((evidence_dir / actual_file).read_text(encoding="utf-8"))
            assert expected_artifact["preRunSeal"] == row["preRunSeal"]
            assert expected_artifact["expected"] == manifest_row["contrast"]
            assert actual_artifact["preRunSeal"] == row["preRunSeal"]
            assert actual_artifact["actual"] == {
                key: value for key, value in row["actual"].items() if key != "observedAt"
            }
            assert actual_artifact["comparison"] == row["comparison"]
            assert actual_artifact["verdict"] == row["verdict"]
