"""Installed-CLI audit for flat commands that can trigger downstream effects."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypeAlias, assert_never

from audit_fixture import AuditFixture, FixtureRoot, RequestEffect

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | Sequence["JsonValue"] | Mapping[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
StreamRule: TypeAlias = Literal["empty", "json", "typed-json", "note"]

ORACLE_HASHES = {
    "F03": "5d462453d007f8008faf0259e5cec51835a619b2ebfd29cdb81dadb0077f4f6d",
    "F04": "ba7014b78ab8b01799d179133120ac4264b95f5a28258a72c66e9024fbd4f83d",
    "F05": "a7cfcbf9bece8ae10e411b5312ee511d18d541200b42d27bd485dfb20ec6c2a6",
    "F07": "cbf55075e6fedb0a6a5dd8477e19baf739dd5791355aa9f6f96b2a8e23d30374",
    "F08": "8d45561951b69e3992e80c58d58e2bc5253f70ae54322f32c8663c1cfcf04334",
    "F09": "52d64ecd3651538e1b344dc28c72fe4031d7a44555886099a137e0d936f45dd9",
    "F15": "40559bca31545b0c08fb6d083266538875a558c923afad676fe57f0b4fc0326d",
    "F16": "cb176568f2ac98733f3807a0a7ecdbaee3809cfd1e667c39bfa929cd67323714",
}


@dataclass(frozen=True, slots=True)
class Expected:
    exit: int
    stdout: StreamRule
    stderr: StreamRule
    rest: tuple[tuple[str, str, int], ...]
    target_count: int | None
    ledger_delta: int
    target_effect: str


@dataclass(frozen=True, slots=True)
class Case:
    feature: str
    variant: str
    argv: tuple[str, ...]
    expected: Expected


def _api(data: Mapping[str, JsonValue]) -> bytes:
    return json.dumps(
        {"success": True, "data": data, "error": None}, separators=(",", ":")
    ).encode()


def _error(code: str, message: str) -> bytes:
    return json.dumps(
        {"success": False, "data": None, "error": {"code": code, "message": message}},
        separators=(",", ":"),
    ).encode()


def _json_body(data: Mapping[str, JsonValue]) -> bytes:
    return json.dumps(data, separators=(",", ":")).encode()


def _ledger_count(path: Path) -> int:
    if not path.exists():
        return 0
    with sqlite3.connect(path) as database:
        row = database.execute("SELECT COUNT(*) FROM ops").fetchone()
    assert row is not None
    return int(row[0])


def _effect_rows(effects: tuple[RequestEffect, ...]) -> list[JsonObject]:
    return [asdict(effect) for effect in effects]


def _write_evidence(name: str, value: JsonObject) -> None:
    root = os.environ.get("BP_AUDIT_EVIDENCE_DIR")
    if root is None:
        return
    destination = Path(root) / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as evidence:
        evidence.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _stream_matches(rule: StreamRule, value: str) -> bool:
    match rule:
        case "empty":
            return value == ""
        case "json":
            try:
                for line in value.splitlines():
                    json.loads(line)
            except json.JSONDecodeError:
                return False
            return bool(value.splitlines())
        case "typed-json":
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return False
            return isinstance(parsed, dict) and isinstance(parsed.get("error"), dict)
        case "note":
            return value.startswith("note:")
        case unreachable:
            assert_never(unreachable)


def _invoke(fixture: AuditFixture, case: Case) -> JsonObject:
    before = fixture.snapshot()
    ledger_before = _ledger_count(fixture.manifest.ledger_path)
    timestamp = datetime.now(timezone.utc).isoformat()
    expected: JsonObject = {
        "exit": case.expected.exit,
        "stdout": case.expected.stdout,
        "stderr": case.expected.stderr,
        "rest": case.expected.rest,
        "target_count": case.expected.target_count,
        "ledger_delta": case.expected.ledger_delta,
        "target_effect": case.expected.target_effect,
    }
    pre_run: JsonObject = {
        "id": case.feature,
        "variant": case.variant,
        "candidate": os.environ.get(
            "BP_AUDIT_CANDIDATE", "3af139dc0b4020923f831099338c92af3265d7e2"
        ),
        "oracleHash": ORACLE_HASHES[case.feature],
        "preRunSeal": timestamp,
        "argv": [*fixture.command("bp"), *case.argv],
        "env": {
            "BP_AGENT": "1",
            "BURP_REST_URL": fixture.manifest.rest_url,
            "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
            "HOME": str(fixture.manifest.home),
        },
        "prestate": {
            "rest": _effect_rows(before.rest_effects),
            "target": _effect_rows(before.target_effects),
        },
        "expected": expected,
    }
    seal_input = json.dumps(pre_run, sort_keys=True, separators=(",", ":")).encode()
    pre_run["sealSha256"] = hashlib.sha256(seal_input).hexdigest()
    prefix = os.environ.get("BP_AUDIT_RUN_ID", "local")
    stem = f"task-7-{prefix}-{case.feature}-{case.variant}"
    _write_evidence(f"{stem}-expected.json", pre_run)

    result = fixture.run(case.argv, executable="bp")
    after = fixture.snapshot()
    rest_delta = after.rest_effects[len(before.rest_effects) :]
    target_delta = after.target_effects[len(before.target_effects) :]
    actual: JsonObject = {
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "exit": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "rest": _effect_rows(rest_delta),
        "target": _effect_rows(target_delta),
        "ledgerDelta": _ledger_count(fixture.manifest.ledger_path) - ledger_before,
    }
    comparison = {
        "exit": result.returncode == case.expected.exit,
        "stdout": _stream_matches(case.expected.stdout, result.stdout),
        "stderr": _stream_matches(case.expected.stderr, result.stderr),
        "rest": tuple((effect.method, effect.path, effect.status) for effect in rest_delta)
        == case.expected.rest,
        "target": case.expected.target_count is None
        or len(target_delta) == case.expected.target_count,
        "ledger": actual["ledgerDelta"] == case.expected.ledger_delta,
    }
    observation: JsonObject = dict(pre_run)
    observation["actual"] = actual
    observation["comparison"] = comparison
    observation["verdict"] = "PASS" if all(comparison.values()) else "FAIL"
    _write_evidence(f"{stem}-actual.json", observation)
    return observation


def _assert_verdict(observation: JsonObject, verdict: str = "PASS") -> None:
    assert observation["verdict"] == verdict, json.dumps(observation, indent=2)


def test_proxy_setup_normal_and_contrast(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        entry: JsonObject = {
            "id": 7,
            "request": {
                "method": "GET",
                "url": f"{fixture.manifest.target_url}/captured",
                "headers": [],
                "body": None,
            },
            "response": {"statusCode": 200, "headers": [], "body": None},
        }
        fixture.add_rest_route(
            "GET", "/proxy/history?host=127.0.0.1&limit=1&offset=0", body=_api({"entries": [entry]})
        )
        normal = Case(
            "F03",
            "normal",
            ("proxy", "--host", "127.0.0.1", "--limit", "1", "--offset", "0"),
            Expected(
                0,
                "json",
                "empty",
                (("GET", "/proxy/history?host=127.0.0.1&limit=1&offset=0", 200),),
                0,
                1,
                "read only; absolute ID 7 projected",
            ),
        )
        _assert_verdict(_invoke(fixture, normal))
        contrast = Case(
            "F03",
            "contrast",
            ("proxy", "--limit", "-1"),
            Expected(2, "empty", "typed-json", (), 0, 0, "usage preflight; zero target"),
        )
        _assert_verdict(_invoke(fixture, contrast), "FAIL")


def test_req_setup_normal_and_contrast(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        entry: JsonObject = {
            "id": 0,
            "request": {
                "method": "GET",
                "url": f"{fixture.manifest.target_url}/?id=base",
                "headers": [],
                "body": None,
            },
        }
        fixture.add_rest_route("GET", "/proxy/history/0", body=_api(entry))
        fixture.add_rest_route(
            "GET", "/proxy/history/99", status=404, body=_error("NOT_FOUND", "missing request")
        )
        _assert_verdict(
            _invoke(
                fixture,
                Case(
                    "F05",
                    "normal",
                    ("req", "0"),
                    Expected(
                        0, "json", "empty", (("GET", "/proxy/history/0", 200),), 0, 1, "read only"
                    ),
                ),
            )
        )
        _assert_verdict(
            _invoke(
                fixture,
                Case(
                    "F05",
                    "contrast",
                    ("req", "99"),
                    Expected(
                        1,
                        "empty",
                        "typed-json",
                        (("GET", "/proxy/history/99", 404),),
                        0,
                        1,
                        "missing ID; zero target",
                    ),
                ),
            )
        )


def _prepare_fuzz(fixture: AuditFixture, payloads: bytes) -> Path:
    path = fixture.manifest.payload_dir / "id.txt"
    path.write_bytes(payloads)
    entry: JsonObject = {
        "id": 0,
        "request": {
            "method": "GET",
            "url": f"{fixture.manifest.target_url}/?id=base",
            "headers": [],
            "body": None,
        },
    }
    fixture.add_rest_route("GET", "/proxy/history/0", body=_api(entry))
    return path


def test_fuzz_replay_baseline_and_shots(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        payload_file = _prepare_fuzz(fixture, b"one\ntwo\n")
        fixture.add_rest_route(
            "POST",
            "/repeater/send",
            body=_api({"response": {"statusCode": 200, "body": "ok"}, "durationMs": 1}),
        )
        rest = (("GET", "/proxy/history/0", 200),) + (("POST", "/repeater/send", 200),) * 3
        case = Case(
            "F04",
            "normal",
            (
                "fuzz",
                "0",
                "--pos",
                "query:id",
                "--payloads",
                f"id={payload_file}",
                "--type",
                "sniper",
            ),
            Expected(
                0, "json", "empty", rest, 0, 4, "CLI fixture does not execute Montoya target sends"
            ),
        )
        _assert_verdict(_invoke(fixture, case))


def test_fuzz_bad_selector_has_zero_send(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        payload_file = _prepare_fuzz(fixture, b"one\n")
        case = Case(
            "F04",
            "bad-selector",
            ("fuzz", "0", "--pos", "query:missing", "--payloads", f"missing={payload_file}"),
            Expected(
                2,
                "empty",
                "typed-json",
                (("GET", "/proxy/history/0", 200),),
                0,
                1,
                "preflight proves zero repeater sends",
            ),
        )
        _assert_verdict(_invoke(fixture, case))


def test_fuzz_shot_cap_has_zero_send(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        payload_file = _prepare_fuzz(fixture, b"x\n" * 10_001)
        case = Case(
            "F04",
            "shot-cap",
            ("fuzz", "0", "--pos", "query:id", "--payloads", f"id={payload_file}"),
            Expected(
                2,
                "empty",
                "typed-json",
                (("GET", "/proxy/history/0", 200),),
                0,
                1,
                "cap preflight proves zero repeater sends",
            ),
        )
        _assert_verdict(_invoke(fixture, case))


def test_fuzz_post_send_failure_is_unknown(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        payload_file = _prepare_fuzz(fixture, b"one\n")
        fixture.add_rest_route(
            "POST", "/repeater/send", status=500, body=_error("SEND_FAILED", "unknown completion")
        )
        rest = (("GET", "/proxy/history/0", 200), ("POST", "/repeater/send", 500))
        case = Case(
            "F04",
            "post-send-failure",
            ("fuzz", "0", "--pos", "query:id", "--payloads", f"id={payload_file}"),
            Expected(
                1,
                "json",
                "typed-json",
                rest,
                None,
                2,
                "post-route completion unknown; do not retry from fixture evidence",
            ),
        )
        _assert_verdict(_invoke(fixture, case))


def test_intercept_on_and_forward_unsupported(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        fixture.expect_rest_route(
            "POST", "/proxy/intercept/enable", expected_body=b"", body=_api({"enabled": True})
        )
        fixture.expect_rest_route(
            "POST",
            "/proxy/intercept/forward",
            expected_body=b"",
            status=501,
            body=_error("UNSUPPORTED", "forward unavailable"),
        )
        _assert_verdict(
            _invoke(
                fixture,
                Case(
                    "F07",
                    "normal",
                    ("intercept", "on"),
                    Expected(
                        0,
                        "json",
                        "empty",
                        (("POST", "/proxy/intercept/enable", 200),),
                        0,
                        1,
                        "state effect represented by stub only",
                    ),
                ),
            )
        )
        contrast = Case(
            "F07",
            "contrast",
            ("intercept", "forward"),
            Expected(
                1,
                "empty",
                "typed-json",
                (("POST", "/proxy/intercept/forward", 501),),
                0,
                1,
                "UNSUPPORTED; zero forward engine effect",
            ),
        )
        _assert_verdict(_invoke(fixture, contrast), "FAIL")


def test_send_replay_and_missing_id(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        payload = _json_body({"requestId": 0, "modifications": {"method": "GET", "path": "/echo"}})
        fixture.expect_rest_route(
            "POST",
            "/repeater/send",
            expected_body=payload,
            body=_api({"response": {"statusCode": 200, "body": "ok"}, "durationMs": 1}),
        )
        normal = Case(
            "F08",
            "normal",
            ("send", "0", "--method", "GET", "--path", "/echo"),
            Expected(
                0,
                "json",
                "empty",
                (("POST", "/repeater/send", 200),),
                0,
                1,
                "target completion not observed at CLI fixture",
            ),
        )
        _assert_verdict(_invoke(fixture, normal))
        fixture.expect_rest_route(
            "POST",
            "/repeater/send",
            expected_body=_json_body({"requestId": 99}),
            status=404,
            body=_error("NOT_FOUND", "missing request"),
        )
        contrast = Case(
            "F08",
            "contrast",
            ("send", "99"),
            Expected(
                1,
                "empty",
                "typed-json",
                (("POST", "/repeater/send", 404),),
                0,
                1,
                "missing ID; Kotlin service supplies zero-target proof",
            ),
        )
        _assert_verdict(_invoke(fixture, contrast))


def test_tab_normal_and_missing_id(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        fixture.expect_rest_route(
            "POST",
            "/repeater/tab/create",
            expected_body=_json_body({"requestId": 0, "name": "audit"}),
            body=_api({"created": True}),
        )
        normal = Case(
            "F09",
            "normal",
            ("tab", "0", "--name", "audit"),
            Expected(
                0,
                "json",
                "empty",
                (("POST", "/repeater/tab/create", 200),),
                0,
                1,
                "tab effect represented by stub; zero CLI target traffic",
            ),
        )
        _assert_verdict(_invoke(fixture, normal))
        fixture.expect_rest_route(
            "POST",
            "/repeater/tab/create",
            expected_body=_json_body({"requestId": 99}),
            status=404,
            body=_error("NOT_FOUND", "missing request"),
        )
        contrast = Case(
            "F09",
            "contrast",
            ("tab", "99"),
            Expected(
                1,
                "empty",
                "typed-json",
                (("POST", "/repeater/tab/create", 404),),
                0,
                1,
                "missing ID; zero CLI target traffic",
            ),
        )
        _assert_verdict(_invoke(fixture, contrast))


def test_diff_normal_and_invalid_target(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        a, b = f"{fixture.manifest.target_url}/a", f"{fixture.manifest.target_url}/b"
        fixture.expect_rest_route(
            "POST",
            "/utils/diff",
            expected_body=_json_body(
                {"a": {"url": a, "method": "GET"}, "b": {"url": b, "method": "GET"}}
            ),
            body=_api(
                {
                    "statusA": 200,
                    "statusB": 200,
                    "lengthA": 1,
                    "lengthB": 1,
                    "lengthDiff": 0,
                    "headerDiffs": [],
                }
            ),
        )
        normal = Case(
            "F15",
            "normal",
            ("diff", a, b),
            Expected(
                0,
                "json",
                "empty",
                (("POST", "/utils/diff", 200),),
                0,
                1,
                "two extension fetches not observed at CLI fixture",
            ),
        )
        _assert_verdict(_invoke(fixture, normal), "FAIL")
        invalid = "relative-target"
        fixture.expect_rest_route(
            "POST",
            "/utils/diff",
            expected_body=_json_body(
                {"a": {"url": invalid, "method": "GET"}, "b": {"url": b, "method": "GET"}}
            ),
            status=400,
            body=_error("INVALID_REQUEST", "invalid target"),
        )
        contrast = Case(
            "F15",
            "contrast",
            ("diff", invalid, b),
            Expected(
                2,
                "empty",
                "typed-json",
                (("POST", "/utils/diff", 400),),
                0,
                1,
                "server preflight; zero extension target fetch",
            ),
        )
        _assert_verdict(_invoke(fixture, contrast), "FAIL")


def test_endpoints_normal_and_external_bundle_report(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        page = f"{fixture.manifest.target_url}/page"
        body = _json_body({"url": page})
        fixture.expect_rest_route(
            "POST",
            "/utils/extract-endpoints",
            expected_body=body,
            body=_api(
                {
                    "endpoints": ["/api"],
                    "bundlesDiscovered": 1,
                    "bundlesAttempted": 1,
                    "bundlesFetched": 1,
                    "bundlesFailed": 0,
                    "failures": [],
                }
            ),
        )
        normal = Case(
            "F16",
            "normal",
            ("endpoints", page),
            Expected(
                0,
                "json",
                "empty",
                (("POST", "/utils/extract-endpoints", 200),),
                0,
                1,
                "page and bundle fetches not observed at CLI fixture",
            ),
        )
        _assert_verdict(_invoke(fixture, normal))
        fixture.expect_rest_route(
            "POST",
            "/utils/extract-endpoints",
            expected_body=body,
            body=_api(
                {
                    "endpoints": [],
                    "bundlesDiscovered": 1,
                    "bundlesAttempted": 1,
                    "bundlesFetched": 0,
                    "bundlesFailed": 1,
                    "failures": [{"url": "https://external.invalid/app.js", "error": "denied"}],
                }
            ),
        )
        contrast = Case(
            "F16",
            "contrast",
            ("endpoints", page),
            Expected(
                0,
                "json",
                "empty",
                (("POST", "/utils/extract-endpoints", 200),),
                0,
                1,
                "external bundle denial represented by stub only",
            ),
        )
        _assert_verdict(_invoke(fixture, contrast))
