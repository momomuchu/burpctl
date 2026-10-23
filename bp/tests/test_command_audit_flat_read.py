"""Installed-CLI audit for flat read, pure, and local-ledger commands.

# allow: SIZE_OK — the ten-row audit matrix is one indivisible evidence table.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Final, Literal, TypeAlias, cast
from collections.abc import Mapping, Sequence
from urllib.parse import quote

import pytest

from audit_fixture import AuditFixture, FixtureRoot, FixtureSnapshot
from bp import __version__
from bp.ledger import Ledger, OpRecord


ROOT: Final = Path(__file__).resolve().parents[2]
ORACLES: Final = ROOT / "quality" / "command-audit" / "oracles.json"
ASSIGNED: Final = ("F01", "F02", "F06", "F10", "F11", "F12", "F13", "F14", "F17", "F18")
EMPTY_SHA256: Final = hashlib.sha256(b"").hexdigest()
JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | Sequence["JsonValue"] | Mapping[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class Case:
    audit_id: str
    argv: tuple[str, ...]
    method: str | None
    path: str | None
    response_data: JsonObject | None
    expected_stdout: JsonValue
    expected_verdict: str


NORMAL_CASES: Final = (
    Case(
        "F01",
        ("health",),
        "GET",
        "/health",
        None,
        {"status": "ok", "version": "fixture", "uptime": 1, "burpVersion": None},
        "PASS",
    ),
    Case(
        "F02",
        ("version",),
        "GET",
        "/version",
        {"version": "extension-9.9", "name": "Burp REST API", "burpVersion": "fixture"},
        {"version": "extension-9.9", "name": "Burp REST API", "burpVersion": "fixture"},
        "PASS",
    ),
    Case(
        "F06",
        ("ws",),
        "GET",
        "/proxy/websocket/history",
        {
            "total": 1,
            "entries": [
                {
                    "id": 7,
                    "url": "ws://fixture/ws",
                    "direction": "CLIENT_TO_SERVER",
                    "payload": "audit",
                    "timestamp": "2026-10-23T10:00:00Z",
                    "webSocketId": 41,
                    "payloadBase64": "YXVkaXQ=",
                    "editedPayloadBase64": None,
                    "time": "2026-10-23T10:00:00Z",
                    "listenerPort": 8080,
                }
            ],
        },
        {
            "total": 1,
            "entries": [
                {
                    "id": 7,
                    "url": "ws://fixture/ws",
                    "direction": "CLIENT_TO_SERVER",
                    "payload": "audit",
                    "timestamp": "2026-10-23T10:00:00Z",
                    "webSocketId": 41,
                    "payloadBase64": "YXVkaXQ=",
                    "editedPayloadBase64": None,
                    "time": "2026-10-23T10:00:00Z",
                    "listenerPort": 8080,
                }
            ],
        },
        "PASS",
    ),
    Case(
        "F10",
        ("sitemap", "http://127.0.0.1/"),
        "GET",
        "/target/sitemap?url=http%3A%2F%2F127.0.0.1%2F",
        {
            "entries": [
                {
                    "url": "http://127.0.0.1/a",
                    "method": "GET",
                    "statusCode": 200,
                    "mimeType": "text/plain",
                }
            ],
            "total": 1,
        },
        {
            "entries": [
                {
                    "url": "http://127.0.0.1/a",
                    "method": "GET",
                    "statusCode": 200,
                    "mimeType": "text/plain",
                }
            ],
            "total": 1,
        },
        "PASS",
    ),
    Case(
        "F11",
        ("encode", "a b", "--enc", "url"),
        "POST",
        "/decoder/encode",
        {"result": "a%20b", "encoding": "url"},
        {"result": "a%20b", "encoding": "url"},
        "PASS",
    ),
    Case(
        "F12",
        ("decode", "YQ==", "--enc", "base64"),
        "POST",
        "/decoder/decode",
        {"result": "a", "encoding": "base64"},
        {"result": "a", "encoding": "base64"},
        "PASS",
    ),
    Case(
        "F13",
        ("hash", "abc", "--algo", "sha256"),
        "POST",
        "/decoder/hash",
        {
            "result": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "algorithm": "sha256",
        },
        {
            "result": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "algorithm": "sha256",
        },
        "PASS",
    ),
    Case(
        "F14",
        ("ext",),
        "GET",
        "/extensions",
        {
            "extensions": [
                {"name": "Burp REST API", "enabled": True, "filename": "/fixture/burp-rest.jar"}
            ],
            "total": 1,
            "scope": "current-extension-only",
        },
        {
            "extensions": [
                {"name": "Burp REST API", "enabled": True, "filename": "/fixture/burp-rest.jar"}
            ],
            "total": 1,
            "scope": "current-extension-only",
        },
        "FAIL",
    ),
)


def _envelope(data: Mapping[str, JsonValue] | None = None, *, code: str | None = None) -> bytes:
    value: JsonObject
    if code is None:
        value = {"success": True, "data": data, "error": None}
    else:
        value = {
            "success": False,
            "data": None,
            "error": {"code": code, "message": "fixture rejection"},
        }
    return json.dumps(value, separators=(",", ":")).encode()


def _effects(
    snapshot: FixtureSnapshot, name: Literal["rest_effects", "target_effects"]
) -> list[JsonObject]:
    effects = snapshot.rest_effects if name == "rest_effects" else snapshot.target_effects
    return [cast(JsonObject, asdict(effect)) for effect in effects]


def _ledger(path: Path) -> list[JsonObject]:
    if not path.exists():
        return []
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, ts, command, burp_op, target, tag, status, exit_code FROM ops ORDER BY ts, id"
        ).fetchall()
    return [cast(JsonObject, dict(row)) for row in rows]


def _json_object(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return cast(JsonObject, value)


def _json_list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return cast(list[JsonValue], value)


def _json_int(value: JsonValue) -> int:
    assert isinstance(value, int) and not isinstance(value, bool)
    return value


def _oracle(audit_id: str) -> JsonObject:
    document = cast(JsonObject, json.loads(ORACLES.read_text()))
    rows = _json_list(document["rows"])
    return next(row for value in rows if (row := _json_object(value))["id"] == audit_id)


def _parse_stdout(stdout: str) -> JsonValue:
    lines = stdout.splitlines()
    if not lines:
        return None
    try:
        parsed = [cast(JsonValue, json.loads(line)) for line in lines]
    except json.JSONDecodeError:
        return stdout.rstrip("\n")
    return parsed[0] if len(parsed) == 1 else parsed


def _evidence_dir(tmp_path: Path) -> Path:
    configured = os.environ.get("BP_AUDIT_EVIDENCE_DIR")
    directory = Path(configured) if configured else tmp_path / "audit-evidence"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_once(path: Path, value: Mapping[str, JsonValue]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _save_observation(observation: JsonObject, case_name: str) -> None:
    configured = os.environ.get("BP_AUDIT_OBSERVATIONS_PATH")
    if configured is None or case_name not in {"normal", "contrast"}:
        return
    path = Path(configured)
    rows = cast(list[JsonObject], json.loads(path.read_text())) if path.exists() else []
    audit_id = str(observation["id"])
    row = next((item for item in rows if item["id"] == audit_id), None)
    if row is None:
        row = {
            "id": audit_id,
            "oracleHash": observation["oracleHash"],
            "candidate": observation["candidate"],
        }
        rows.append(row)
    row[case_name] = {
        key: value
        for key, value in observation.items()
        if key not in {"id", "oracleHash", "candidate"}
    }
    rows.sort(key=lambda item: ASSIGNED.index(item["id"]))
    path.write_text(json.dumps(rows, indent=2, sort_keys=False) + "\n")


def _invoke(
    fixture: AuditFixture,
    tmp_path: Path,
    audit_id: str,
    case_name: str,
    argv: tuple[str, ...],
    expected: Mapping[str, JsonValue],
    *,
    executable: str = "bp",
) -> JsonObject:
    oracle = _oracle(audit_id)
    before = fixture.snapshot()
    ledger_before = _ledger(fixture.manifest.ledger_path)
    sequence = time.time_ns()
    expected_at = time.time_ns()
    full_argv = [*fixture.command(executable), *argv]
    oracle_seal = _json_object(oracle["seal"])
    expected_object = dict(expected)
    pre: JsonObject = {
        "id": audit_id,
        "case": case_name,
        "candidate": "3af139dc0b4020923f831099338c92af3265d7e2",
        "oracleHash": oracle_seal["hash"],
        "source": oracle["authority"],
        "expectedAtNs": expected_at,
        "argv": full_argv,
        "environment": {
            "HOME": str(fixture.manifest.home),
            "BURP_REST_URL": fixture.manifest.rest_url,
            "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
            "BP_CONFIG_PATH": str(fixture.manifest.config_path),
            "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
            "BP_AGENT": "1",
            "NO_COLOR": "1",
            "TERM": "dumb",
        },
        "prestate": {
            "rest": _effects(before, "rest_effects"),
            "target": _effects(before, "target_effects"),
            "ledger": ledger_before,
        },
        "expected": expected_object,
    }
    canonical = json.dumps(pre, separators=(",", ":"), sort_keys=True).encode()
    pre["preRunSeal"] = hashlib.sha256(canonical).hexdigest()
    stem = f"task-6-{audit_id.lower()}-{case_name}-{executable}-{sequence}"
    _write_once(_evidence_dir(tmp_path) / f"{stem}-expected.json", pre)

    result = fixture.run(argv, executable=executable)
    actual_at = time.time_ns()
    after = fixture.snapshot()
    actual: JsonObject = {
        "exit": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "restLog": _effects(after, "rest_effects"),
        "targetLog": _effects(after, "target_effects"),
        "ledger": _ledger(fixture.manifest.ledger_path),
    }
    checks_bool = {
        "exit": result.returncode == expected_object["exit"],
        "stdout": _parse_stdout(result.stdout) == expected_object["stdout"],
        "stderr": _stderr_matches(result.stderr, str(expected_object["stderr"])),
        "rest": _effects(after, "rest_effects") == expected_object["restLog"],
        "target": _effects(after, "target_effects") == expected_object["targetLog"],
        "ledger": _ledger_matches(_ledger(fixture.manifest.ledger_path), expected_object["ledger"]),
    }
    verdict = "PASS" if all(checks_bool.values()) else "FAIL"
    checks = cast(JsonObject, checks_bool)
    observation: JsonObject = {
        "id": audit_id,
        "oracleHash": oracle_seal["hash"],
        "candidate": "3af139dc0b4020923f831099338c92af3265d7e2",
        "preRunSeal": pre["preRunSeal"],
        "expectedAtNs": expected_at,
        "actualAtNs": actual_at,
        "argv": full_argv,
        "expected": expected_object,
        "actual": actual,
        "verdict": verdict,
        "checks": checks,
        "limits": "loopback fixture plus isolated HOME/config/ledger; no external target",
    }
    _write_once(_evidence_dir(tmp_path) / f"{stem}-actual.json", observation)
    _save_observation(observation, case_name)
    return observation


def _typed_error(stderr: str, code: str) -> bool:
    try:
        value = _json_object(cast(JsonValue, json.loads(stderr)))
    except json.JSONDecodeError:
        return False
    error = value.get("error")
    return isinstance(error, dict) and error.get("code") == code


def _stderr_matches(stderr: str, expected: str) -> bool:
    if expected == "empty":
        return stderr == ""
    if expected == "plain_usage":
        return stderr.startswith("error:")
    return _typed_error(stderr, expected)


def _ledger_matches(actual: list[JsonObject], expected: JsonValue) -> bool:
    if isinstance(expected, list):
        return actual == expected
    if not isinstance(expected, dict):
        return False
    if len(actual) != expected["count"]:
        return False
    latest = actual[-1]
    return all(latest.get(key) == value for key, value in expected.items() if key != "count")


def _network_expected(
    *,
    method: str,
    path: str,
    stdout: JsonValue,
    exit_code: int = 0,
    stderr: str = "empty",
    request_body: bytes = b"",
    ledger_status: str = "ok",
) -> JsonObject:
    return {
        "exit": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "restLog": [
            {
                "method": method,
                "path": path,
                "body_sha256": hashlib.sha256(request_body).hexdigest(),
                "body_length": len(request_body),
                "status": 200,
            }
        ],
        "targetLog": [],
        "ledger": {
            "count": 1,
            "burp_op": f"{method} {path.partition('?')[0]}",
            "status": ledger_status,
            "exit_code": exit_code,
        },
    }


def _assert_observed(observation: JsonObject, verdict: str) -> None:
    assert _json_int(observation["actualAtNs"]) > _json_int(observation["expectedAtNs"])
    assert observation["verdict"] == verdict, observation
    assert _json_object(observation["actual"])["targetLog"] == []


@pytest.mark.parametrize("case", NORMAL_CASES, ids=lambda case: case.audit_id)
def test_normal_cases(case: Case, tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        bodies = {
            "F11": b'{"data":"a b","encoding":"url"}',
            "F12": b'{"data":"YQ==","encoding":"base64"}',
            "F13": b'{"data":"abc","algorithm":"sha256"}',
        }
        request_body = bodies.get(case.audit_id, b"")
        argv = case.argv
        path = case.path or "/"
        if case.audit_id == "F10":
            target = f"{fixture.manifest.target_url}/"
            argv = ("sitemap", target)
            path = f"/target/sitemap?url={quote(target, safe='')}"
        if case.response_data is not None:
            if request_body:
                fixture.expect_rest_route(
                    case.method or "GET",
                    path,
                    expected_body=request_body,
                    body=_envelope(case.response_data),
                )
            else:
                fixture.add_rest_route(
                    case.method or "GET", path, body=_envelope(case.response_data)
                )
        assert isinstance(case.expected_stdout, dict)
        expected = _network_expected(
            method=case.method or "GET",
            path=path,
            stdout=case.expected_stdout,
            request_body=request_body,
        )
        observation = _invoke(fixture, tmp_path, case.audit_id, "normal", argv, expected)
        _assert_observed(observation, case.expected_verdict)


def test_f17_normal_uses_two_newest_seeded_rows(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        with Ledger(fixture.manifest.ledger_path) as ledger:
            first = ledger.record(
                OpRecord(status="ok", command="bp first", target="http://fixture.invalid")
            )
            second = ledger.record(
                OpRecord(
                    status="error",
                    command="bp second --token secret",
                    target="http://fixture.invalid",
                )
            )
            third = ledger.record(
                OpRecord(status="refused", command="bp third", target="http://fixture.invalid")
            )
            expected_rows = [cast(JsonObject, row.as_dict()) for row in ledger.query()][:2]
        seeded = _ledger(fixture.manifest.ledger_path)
        expected: JsonObject = {
            "exit": 0,
            "stdout": expected_rows,
            "stderr": "empty",
            "restLog": [],
            "targetLog": [],
            "ledger": seeded,
        }
        observation = _invoke(fixture, tmp_path, "F17", "normal", ("log", "--limit", "2"), expected)
        _assert_observed(observation, "PASS")
        assert first not in {second, third}
        assert "secret" not in str(_json_object(observation["actual"])["stdout"])


def test_f18_normal_updates_only_seeded_opid(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        with Ledger(fixture.manifest.ledger_path) as ledger:
            op_id = ledger.record(OpRecord(status="ok", command="bp seeded"))
        before = _ledger(fixture.manifest.ledger_path)
        after = [dict(row, tag="audit") if row["id"] == op_id else row for row in before]
        expected: JsonObject = {
            "exit": 0,
            "stdout": {"id": op_id, "tag": "audit", "status": "tagged"},
            "stderr": "empty",
            "restLog": [],
            "targetLog": [],
            "ledger": after,
        }
        observation = _invoke(fixture, tmp_path, "F18", "normal", ("tag", op_id, "audit"), expected)
        _assert_observed(observation, "PASS")


def _refused_fixture(fixture: AuditFixture) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    fixture.manifest = replace(fixture.manifest, rest_url=f"http://127.0.0.1:{port}")


@pytest.mark.parametrize("audit_id,argv", [("F01", ("health",)), ("F14", ("ext",))])
def test_contrast_transport_refusal(audit_id: str, argv: tuple[str, ...], tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        _refused_fixture(fixture)
        expected: JsonObject = {
            "exit": 3,
            "stdout": None,
            "stderr": "CONNECTION_REFUSED",
            "restLog": [],
            "targetLog": [],
            "ledger": {
                "count": 1,
                "burp_op": f"GET /{'health' if audit_id == 'F01' else 'extensions'}",
                "status": "error",
                "exit_code": 3,
            },
        }
        observation = _invoke(fixture, tmp_path, audit_id, "contrast", argv, expected)
        _assert_observed(observation, "FAIL" if audit_id == "F14" else "PASS")


def test_f02_contrast_local_version_is_not_extension_version(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        sealed: JsonObject = {
            "exit": 0,
            "stdout": None,
            "stderr": "typed_error",
            "restLog": [],
            "targetLog": [],
            "ledger": [],
        }
        observation = _invoke(fixture, tmp_path, "F02", "contrast", ("--version",), sealed)
        _assert_observed(observation, "FAIL")
        assert _json_object(observation["actual"])["stdout"] == f"{__version__}\n"


@pytest.mark.parametrize(
    "audit_id,argv,path,data",
    [
        ("F06", ("ws",), "/proxy/websocket/history", {"total": 0, "entries": []}),
        (
            "F10",
            ("sitemap", "http://127.0.0.1/"),
            "/target/sitemap?url=http%3A%2F%2F127.0.0.1%2F",
            {"entries": [], "total": 0},
        ),
    ],
)
def test_contrast_empty_result_still_reads_route(
    audit_id: str, argv: tuple[str, ...], path: str, data: JsonObject, tmp_path: Path
) -> None:
    with FixtureRoot(tmp_path) as fixture:
        if audit_id == "F10":
            target = f"{fixture.manifest.target_url}/"
            argv = ("sitemap", target)
            path = f"/target/sitemap?url={quote(target, safe='')}"
        fixture.add_rest_route("GET", path, body=_envelope(data))
        sealed: JsonObject = {
            "exit": 0,
            "stdout": None,
            "stderr": "typed_error",
            "restLog": [],
            "targetLog": [],
            "ledger": {
                "count": 1,
                "burp_op": f"GET {path.partition('?')[0]}",
                "status": "ok",
                "exit_code": 0,
            },
        }
        observation = _invoke(fixture, tmp_path, audit_id, "contrast", argv, sealed)
        _assert_observed(observation, "FAIL")
        rest_log = _json_list(_json_object(observation["actual"])["restLog"])
        assert _json_object(rest_log[0])["path"] == path


def test_f11_contrast_invalid_encoding_is_usage_without_http(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        sealed: JsonObject = {
            "exit": 2,
            "stdout": None,
            "stderr": "USAGE_ERROR",
            "restLog": [],
            "targetLog": [],
            "ledger": [],
        }
        observation = _invoke(
            fixture, tmp_path, "F11", "contrast", ("encode", "a b", "--enc", "rot13"), sealed
        )
        _assert_observed(observation, "FAIL")
        assert str(_json_object(observation["actual"])["stderr"]).startswith("error: --enc")


@pytest.mark.parametrize(
    "audit_id,argv,path",
    [
        ("F12", ("decode", "%%%", "--enc", "base64"), "/decoder/decode"),
        ("F13", ("hash", "abc", "--algo", "not-a-hash"), "/decoder/hash"),
    ],
)
def test_contrast_server_rejection_has_one_post(
    audit_id: str, argv: tuple[str, ...], path: str, tmp_path: Path
) -> None:
    with FixtureRoot(tmp_path) as fixture:
        fixture.add_rest_route("POST", path, status=400, body=_envelope(code="INVALID_REQUEST"))
        sealed: JsonObject = {
            "exit": 1,
            "stdout": None,
            "stderr": "INVALID_REQUEST",
            "restLog": [],
            "targetLog": [],
            "ledger": {"count": 1, "burp_op": f"POST {path}", "status": "error", "exit_code": 1},
        }
        observation = _invoke(fixture, tmp_path, audit_id, "contrast", argv, sealed)
        _assert_observed(observation, "FAIL")
        rest_log = _json_list(_json_object(observation["actual"])["restLog"])
        assert _json_object(rest_log[0])["path"] == path


def test_f17_contrast_invalid_status_is_typed_usage(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected: JsonObject = {
            "exit": 2,
            "stdout": None,
            "stderr": "USAGE_ERROR",
            "restLog": [],
            "targetLog": [],
            "ledger": [],
        }
        observation = _invoke(
            fixture, tmp_path, "F17", "contrast", ("log", "--status", "unknown"), expected
        )
        _assert_observed(observation, "PASS")


def test_unknown_opid_contrast_has_no_effect(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        with Ledger(fixture.manifest.ledger_path) as ledger:
            known = ledger.record(OpRecord(status="ok", command="bp seed"))
        unchanged = _ledger(fixture.manifest.ledger_path)
        expected: JsonObject = {
            "exit": 1,
            "stdout": None,
            "stderr": "NOT_FOUND",
            "restLog": [],
            "targetLog": [],
            "ledger": unchanged,
        }
        observation = _invoke(
            fixture, tmp_path, "F18", "contrast", ("tag", "unknown-opid", "audit"), expected
        )
        _assert_observed(observation, "PASS")
        assert known == unchanged[0]["id"]


def test_alias_parity_and_global_placement(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        data: JsonObject = {
            "result": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "algorithm": "sha256",
        }
        fixture.add_rest_route("POST", "/decoder/hash", body=_envelope(data))
        expected = _network_expected(
            method="POST",
            path="/decoder/hash",
            stdout=data,
            request_body=b'{"data":"abc","algorithm":"sha256"}',
        )
        expected["ledger"] = []
        bp = _invoke(
            fixture,
            tmp_path,
            "F13",
            "alias-bp",
            ("hash", "abc", "--algo", "sha256", "--format", "json", "--no-ledger"),
            expected,
            executable="bp",
        )
        first_rest_log = _json_list(expected["restLog"])
        expected["restLog"] = [*first_rest_log, first_rest_log[0]]
        alias = _invoke(
            fixture,
            tmp_path,
            "F13",
            "alias-burpctl",
            ("hash", "abc", "--algo", "sha256", "--format", "json", "--no-ledger"),
            expected,
            executable="burpctl",
        )
        bp_actual = _json_object(bp["actual"])
        alias_actual = _json_object(alias["actual"])
        assert (bp_actual["exit"], bp_actual["stdout"], bp_actual["stderr"]) == (
            alias_actual["exit"],
            alias_actual["stdout"],
            alias_actual["stderr"],
        )


def test_invalid_format_has_usage_exit_and_zero_effects(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected: JsonObject = {
            "exit": 2,
            "stdout": None,
            "stderr": "typed_error",
            "restLog": [],
            "targetLog": [],
            "ledger": [],
        }
        observation = _invoke(
            fixture, tmp_path, "F01", "invalid-format", ("health", "--format", "yaml"), expected
        )
        actual = _json_object(observation["actual"])
        assert actual["exit"] == 2
        assert actual["restLog"] == actual["targetLog"] == []


def test_raw_rejects_structured_output_after_one_local_read(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = _network_expected(
            method="GET", path="/health", stdout=None, exit_code=2, stderr="plain_usage"
        )
        expected["ledger"] = []
        observation = _invoke(
            fixture,
            tmp_path,
            "F01",
            "raw-rejection",
            ("health", "--format", "raw", "--no-ledger"),
            expected,
        )
        _assert_observed(observation, "PASS")
