"""Installed-CLI audit for scope and session leaves.

The loopback fixture proves CLI routes, payloads, streams, exits, and ledger
records. Kotlin tests separately prove mocked Montoya interactions; this file
never upgrades a REST acceptance into a live engine or target-send claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal
from urllib.parse import quote, urlsplit

import pytest

from audit_fixture import AuditFixture, FixtureRoot, RequestEffect
from test_command_audit_modes import require_historical_live

require_historical_live()

# allow: SIZE_OK — the single pure-data matrix keeps all twenty sealed invocations auditable.

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
Lane = Literal["normal", "contrast"]
Group = Literal["scope_add_check", "scope_unsupported", "same_origin_session", "cross_origin"]
StreamKind = Literal["empty", "json", "text"]

ROOT: Final = Path(__file__).resolve().parents[2]
MANIFEST_PATH: Final = ROOT / "quality" / "command-audit" / "oracles.json"
TESTED_REVISION: Final = "3af139dc0b4020923f831099338c92af3265d7e2"
SECRET_SENTINELS: Final = (
    "AUDIT_COOKIE_SECRET_23",
    "AUDIT_AUTH_SECRET_24",
    "AUDIT_SET_COOKIE_SECRET_26",
    "AUDIT_JAR_SECRET_27",
)


@dataclass(frozen=True, slots=True)
class WireRoute:
    """One exact fixture route and response."""

    method: str
    path: str
    status: int
    data: JsonValue | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_body: str | None = None


@dataclass(frozen=True, slots=True)
class Case:
    """One predeclared normal or contrast subprocess invocation."""

    row_id: str
    lane: Lane
    group: Group
    argv: tuple[str, ...]
    exit_code: int
    stdout_kind: StreamKind
    stderr_kind: StreamKind
    route: WireRoute | None
    stderr_code: str | None = None
    stderr_fragment: str | None = None
    limits: tuple[str, ...] = ()


def _session_info(*, populated: bool) -> dict[str, JsonValue]:
    if populated:
        return {
            "name": "audit",
            "cookieCount": 1,
            "headerCount": 1,
            "cookies": {"audit": SECRET_SENTINELS[0]},
            "headers": {"Authorization": f"Bearer {SECRET_SENTINELS[1]}"},
            "origin": "{{TARGET}}",
        }
    return {
        "name": "default",
        "cookieCount": 0,
        "headerCount": 0,
        "cookies": {},
        "headers": {},
        "origin": None,
    }


def _authenticated_response() -> dict[str, JsonValue]:
    return {
        "statusCode": 200,
        "headers": [
            {
                "name": "Set-Cookie",
                "value": f"sid={SECRET_SENTINELS[2]}; Path=/; HttpOnly",
            }
        ],
        "body": "fixture response",
        "durationMs": 2,
        "hasResponse": True,
        "persistence": {
            "status": "NOT_CONFIGURED",
            "historyPersisted": False,
            "sitemapPersisted": False,
            "historyId": None,
            "warning": None,
        },
    }


def _cookie_jar(*, populated: bool) -> dict[str, JsonValue]:
    cookies: list[JsonValue] = []
    if populated:
        cookies.append(
            {
                "domain": "127.0.0.1",
                "name": "sid",
                "value": SECRET_SENTINELS[3],
                "path": "/",
                "secure": False,
                "expiresAt": None,
                "hostOnly": True,
            }
        )
    return {"cookies": cookies, "total": len(cookies)}


ENGINE_LIMIT: Final = (
    "CLI boundary passed; the REST fixture does not execute a real or mocked Montoya scope engine.",
    "TargetServiceTest is the independent mocked-engine proof; live Burp scope remains unobserved.",
)
SESSION_LIMIT: Final = (
    "CLI boundary passed; the REST fixture does not mutate SessionService or H2 state.",
    "SessionServiceTest is independent mocked-service proof; live Burp session state remains unobserved.",
)
SEND_LIMIT: Final = (
    "The CLI POST was observed, but the static REST fixture does not forward it to the target server.",
    "Target send and credential non-disclosure at the destination are INCONCLUSIVE here; SessionServiceTest supplies mocked-service evidence only.",
)


CASES: Final = (
    Case(
        "L14",
        "normal",
        "scope_unsupported",
        ("scope", "show"),
        1,
        "empty",
        "json",
        WireRoute(
            "GET",
            "/target/scope",
            501,
            error_code="UNSUPPORTED",
            error_message="scope listing is unsupported",
        ),
        limits=ENGINE_LIMIT,
    ),
    Case(
        "L14",
        "contrast",
        "scope_unsupported",
        ("scope", "show"),
        1,
        "empty",
        "json",
        WireRoute(
            "GET",
            "/target/scope",
            501,
            error_code="UNSUPPORTED",
            error_message="scope listing is unsupported",
        ),
        limits=(
            "The manifest contrast predicts no route, but the CLI must contact the server to receive UNSUPPORTED.",
        ),
    ),
    Case(
        "L15",
        "normal",
        "scope_unsupported",
        ("scope", "set", "--include", "{{TARGET}}", "--confirm"),
        1,
        "empty",
        "json",
        WireRoute(
            "POST",
            "/target/scope",
            501,
            error_code="UNSUPPORTED",
            error_message="scope replacement is unsupported",
            request_body='{"includes":["{{TARGET}}"],"excludes":[]}',
        ),
        limits=ENGINE_LIMIT,
    ),
    Case(
        "L15",
        "contrast",
        "scope_unsupported",
        ("scope", "set", "--include", "{{TARGET}}"),
        2,
        "empty",
        "text",
        None,
        stderr_fragment="Pass --confirm",
        limits=(
            "The manifest predicts typed JSON stderr; the command emits a plain-text warning before client construction.",
        ),
    ),
    Case(
        "L16",
        "normal",
        "scope_add_check",
        ("scope", "add", "{{TARGET}}/"),
        0,
        "json",
        "empty",
        WireRoute(
            "POST",
            "/target/scope/add",
            200,
            data={"url": "{{TARGET}}/", "inScope": True},
            request_body='{"url":"{{TARGET}}/"}',
        ),
        limits=ENGINE_LIMIT,
    ),
    Case(
        "L16",
        "contrast",
        "scope_add_check",
        ("scope", "add", "{{TARGET}}/"),
        1,
        "empty",
        "json",
        WireRoute(
            "POST",
            "/target/scope/add",
            400,
            error_code="INVALID_REQUEST",
            error_message="engine rejected scope addition",
            request_body='{"url":"{{TARGET}}/"}',
        ),
        limits=(
            "The manifest predicts no route for engine rejection; the observed rejection necessarily follows one REST call.",
        ),
    ),
    Case(
        "L17",
        "normal",
        "scope_add_check",
        ("scope", "remove", "{{TARGET}}/"),
        0,
        "json",
        "empty",
        WireRoute(
            "POST",
            "/target/scope/remove",
            200,
            data={"url": "{{TARGET}}/", "inScope": False},
            request_body='{"url":"{{TARGET}}/"}',
        ),
        limits=ENGINE_LIMIT,
    ),
    Case(
        "L17",
        "contrast",
        "scope_add_check",
        ("scope", "remove", "{{TARGET}}/"),
        1,
        "empty",
        "json",
        WireRoute(
            "POST",
            "/target/scope/remove",
            400,
            error_code="INVALID_REQUEST",
            error_message="engine rejected scope removal",
            request_body='{"url":"{{TARGET}}/"}',
        ),
        limits=(
            "The manifest predicts no route for engine rejection; the observed rejection necessarily follows one REST call.",
        ),
    ),
    Case(
        "L18",
        "normal",
        "scope_add_check",
        ("scope", "check", "{{TARGET}}/"),
        0,
        "json",
        "empty",
        WireRoute(
            "GET",
            "/target/scope/check?url={{TARGET_QUOTED}}%2F",
            200,
            data={"url": "{{TARGET}}/", "inScope": True},
        ),
        limits=ENGINE_LIMIT,
    ),
    Case(
        "L18",
        "contrast",
        "scope_add_check",
        ("scope", "check", "{{TARGET}}/"),
        1,
        "empty",
        "json",
        WireRoute(
            "GET",
            "/target/scope/check?url={{TARGET_QUOTED}}%2F",
            400,
            error_code="INVALID_REQUEST",
            error_message="engine rejected scope check",
        ),
        limits=(
            "The manifest predicts no route for engine rejection; the observed rejection necessarily follows one REST call.",
        ),
    ),
    Case(
        "L23",
        "normal",
        "same_origin_session",
        ("session", "set", "--json", '{"cookies":{"audit":"local"}}'),
        0,
        "json",
        "text",
        WireRoute(
            "POST",
            "/session/set",
            200,
            data=_session_info(populated=True),
            request_body='{"cookies":{"audit":"local"}}',
        ),
        stderr_fragment="full replace",
        limits=SESSION_LIMIT,
    ),
    Case(
        "L23",
        "contrast",
        "cross_origin",
        ("session", "set", "--json", '{"cookies":'),
        2,
        "empty",
        "text",
        None,
        stderr_fragment="--json is not valid JSON",
        limits=(
            "The manifest predicts typed JSON stderr; local JSON parsing emits a plain-text usage error.",
        ),
    ),
    Case(
        "L24",
        "normal",
        "same_origin_session",
        ("session", "get"),
        0,
        "json",
        "empty",
        WireRoute("GET", "/session/get", 200, data=_session_info(populated=True)),
        limits=SESSION_LIMIT,
    ),
    Case(
        "L24",
        "contrast",
        "cross_origin",
        ("session", "get"),
        0,
        "json",
        "empty",
        WireRoute("GET", "/session/get", 200, data=_session_info(populated=False)),
        limits=(
            "Current SessionService returns an empty SessionInfo; the sealed contrast predicts exit 1.",
        ),
    ),
    Case(
        "L25",
        "normal",
        "same_origin_session",
        ("session", "clear"),
        0,
        "json",
        "text",
        WireRoute("DELETE", "/session/clear", 200, data=_session_info(populated=False)),
        stderr_fragment="leaves the cookie-jar intact",
        limits=SESSION_LIMIT,
    ),
    Case(
        "L25",
        "contrast",
        "cross_origin",
        ("session", "clear"),
        1,
        "empty",
        "json",
        WireRoute(
            "DELETE",
            "/session/clear",
            503,
            error_code="SERVICE_UNAVAILABLE",
            error_message="session persistence unavailable",
        ),
        stderr_fragment="leaves the cookie-jar intact",
        limits=(
            "The manifest predicts no route, while a persistence failure occurs after one accepted DELETE.",
        ),
    ),
    Case(
        "L26",
        "normal",
        "same_origin_session",
        ("session", "send", "{{TARGET}}/echo"),
        0,
        "json",
        "empty",
        WireRoute(
            "POST",
            "/session/send",
            200,
            data=_authenticated_response(),
            request_body='{"method":"GET","url":"{{TARGET}}/echo"}',
        ),
        limits=SEND_LIMIT,
    ),
    Case(
        "L26",
        "contrast",
        "cross_origin",
        ("session", "send", "{{REST}}/cross-origin"),
        1,
        "empty",
        "json",
        WireRoute(
            "POST",
            "/session/send",
            400,
            error_code="INVALID_REQUEST",
            error_message="session credentials are bound to another origin",
            request_body='{"method":"GET","url":"{{REST}}/cross-origin"}',
        ),
        limits=(
            "The REST rejection and zero fixture target calls are observed; only SessionServiceTest proves zero mocked Http calls before rejection.",
        ),
    ),
    Case(
        "L27",
        "normal",
        "same_origin_session",
        ("session", "cookies"),
        0,
        "json",
        "empty",
        WireRoute("GET", "/session/cookie-jar", 200, data=_cookie_jar(populated=True)),
        limits=SESSION_LIMIT,
    ),
    Case(
        "L27",
        "contrast",
        "cross_origin",
        ("session", "cookies"),
        0,
        "json",
        "empty",
        WireRoute("GET", "/session/cookie-jar", 200, data=_cookie_jar(populated=False)),
        limits=(
            "Current SessionService returns an empty jar successfully; the sealed contrast predicts exit 1.",
        ),
    ),
)

EXPECTED_STDOUT: Final[dict[tuple[str, Lane], JsonValue]] = {
    ("L16", "normal"): {"url": "{{TARGET}}/", "inScope": True},
    ("L17", "normal"): {"url": "{{TARGET}}/", "inScope": False},
    ("L18", "normal"): {"url": "{{TARGET}}/", "inScope": True},
    ("L23", "normal"): {
        "name": "audit",
        "cookieCount": 1,
        "headerCount": 1,
        "cookies": {"audit": "***"},
        "headers": {"Authorization": "***"},
        "origin": "{{TARGET}}",
    },
    ("L24", "normal"): {
        "name": "audit",
        "cookieCount": 1,
        "headerCount": 1,
        "cookies": {"audit": "***"},
        "headers": {"Authorization": "***"},
        "origin": "{{TARGET}}",
    },
    ("L24", "contrast"): _session_info(populated=False),
    ("L25", "normal"): _session_info(populated=False),
    ("L26", "normal"): {
        "statusCode": 200,
        "headers": [{"name": "Set-Cookie", "value": "***"}],
        "body": "fixture response",
        "durationMs": 2,
        "hasResponse": True,
        "persistence": {
            "status": "NOT_CONFIGURED",
            "historyPersisted": False,
            "sitemapPersisted": False,
            "historyId": None,
            "warning": None,
        },
    },
    ("L27", "normal"): {
        "cookies": [
            {
                "domain": "***",
                "name": "***",
                "value": "***",
                "path": "***",
                "secure": False,
                "expiresAt": None,
                "hostOnly": True,
            }
        ],
        "total": 1,
    },
    ("L27", "contrast"): _cookie_jar(populated=False),
}


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _materialize(value: str, fixture: AuditFixture) -> str:
    target = fixture.manifest.target_url
    return (
        value.replace("{{TARGET_QUOTED}}", quote(target, safe=""))
        .replace("{{TARGET}}", target)
        .replace("{{REST}}", fixture.manifest.rest_url)
    )


def _materialize_json(value: JsonValue, fixture: AuditFixture) -> JsonValue:
    if isinstance(value, str):
        return _materialize(value, fixture)
    if isinstance(value, list):
        return [_materialize_json(item, fixture) for item in value]
    if isinstance(value, dict):
        return {key: _materialize_json(item, fixture) for key, item in value.items()}
    return value


def _wire(route: WireRoute, fixture: AuditFixture) -> bytes:
    if route.error_code is None:
        payload: JsonValue = {
            "success": True,
            "data": _materialize_json(route.data, fixture),
            "error": None,
        }
    else:
        payload = {
            "success": False,
            "data": None,
            "error": {"code": route.error_code, "message": route.error_message},
        }
    return json.dumps(payload, separators=(",", ":")).encode()


def _write_once(path: Path, payload: JsonValue) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _effect(effect: RequestEffect) -> dict[str, JsonValue]:
    return {
        "method": effect.method,
        "path": effect.path,
        "bodySha256": effect.body_sha256,
        "bodyLength": effect.body_length,
        "status": effect.status,
    }


def _ledger(path: Path) -> list[dict[str, JsonValue]]:
    if not path.is_file():
        return []
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT burp_op,status,exit_code,req_sha256,resp_sha256,resp_status,error_code "
            "FROM ops ORDER BY ts,id"
        ).fetchall()
    return [
        {
            "burpOp": row[0],
            "status": row[1],
            "exit": row[2],
            "requestSha256": row[3],
            "responseSha256": row[4],
            "responseStatus": row[5],
            "errorCode": row[6],
        }
        for row in rows
    ]


def _expected_ledger(
    case: Case, path: str, body: bytes | None, response: bytes
) -> dict[str, JsonValue]:
    """Build the exact safe ledger projection from the predeclared wire contract."""
    assert case.route is not None
    parsed = urlsplit(path)
    if case.route.method == "GET":
        request_identity = parsed.query.encode() if parsed.query else None
    else:
        request_identity = json.dumps(json.loads(body)).encode() if body is not None else None
    return {
        "burpOp": f"{case.route.method} {parsed.path}",
        "status": "ok" if case.route.error_code is None else "error",
        "exit": case.exit_code,
        "requestSha256": (
            hashlib.sha256(request_identity).hexdigest() if request_identity is not None else None
        ),
        "responseSha256": hashlib.sha256(response).hexdigest(),
        "responseStatus": case.route.status,
        "errorCode": case.route.error_code,
    }


def _manifest() -> tuple[dict[str, JsonValue], dict[str, dict[str, JsonValue]]]:
    document = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    rows = {
        row["id"]: row for row in document["rows"] if row["id"] in {case.row_id for case in CASES}
    }
    return document, rows


def _expected(row: dict[str, JsonValue], case: Case, fixture: AuditFixture) -> dict[str, JsonValue]:
    source = row["expected"] if case.lane == "normal" else row["contrast"]
    assert isinstance(source, dict)
    effect = source["effect"]
    assert isinstance(effect, dict)
    route = effect.get("route", "none")
    route_text = route if isinstance(route, str) else "none"
    rest_count = 0 if route_text == "none" else 1
    target_count = 1 if effect.get("effect") == "one target send" else 0
    return {
        "exit": source["exit"],
        "stdout": source["stdout"],
        "stderr": source["stderr"],
        "route": _materialize(route_text, fixture),
        "effects": {
            "engine": effect.get("effect"),
            "restCount": rest_count,
            "targetCount": target_count,
            "ledgerCount": rest_count,
        },
    }


def _environment(fixture: AuditFixture) -> dict[str, JsonValue]:
    return {
        "HOME": str(fixture.manifest.home),
        "BURP_REST_URL": fixture.manifest.rest_url,
        "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
        "BP_CONFIG_PATH": str(fixture.manifest.config_path),
        "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
        "BP_AGENT": "1",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }


def _configure(
    fixture: AuditFixture, route: WireRoute | None
) -> tuple[str | None, bytes | None, bytes | None]:
    if route is None:
        return None, None, None
    path = _materialize(route.path, fixture)
    body = _materialize(route.request_body, fixture).encode() if route.request_body else None
    response = _wire(route, fixture)
    if body is None:
        fixture.add_rest_route(route.method, path, status=route.status, body=response)
    else:
        fixture.expect_rest_route(
            route.method,
            path,
            expected_body=body,
            status=route.status,
            body=response,
        )
    return path, body, response


def _json_stream(raw: str) -> JsonValue:
    records: list[JsonValue] = [json.loads(line) for line in raw.splitlines() if line]
    return records[0] if len(records) == 1 else records


def _assert_streams(case: Case, fixture: AuditFixture, stdout: str, stderr: str) -> None:
    if case.stdout_kind == "empty":
        assert stdout == ""
    elif case.stdout_kind == "json":
        expected_stdout = EXPECTED_STDOUT[(case.row_id, case.lane)]
        assert _json_stream(stdout) == _materialize_json(expected_stdout, fixture)
    if case.stderr_kind == "empty":
        assert stderr == ""
    elif case.stderr_kind == "json":
        json_lines = [line for line in stderr.splitlines() if line.startswith("{")]
        assert len(json_lines) == 1
        error = json.loads(json_lines[0])
        assert isinstance(error, dict)
        detail = error.get("error")
        assert isinstance(detail, dict)
        expected_code = case.stderr_code
        if expected_code is None and case.route is not None:
            expected_code = case.route.error_code
        assert detail.get("code") == expected_code
        if case.stderr_fragment is not None:
            assert case.stderr_fragment in stderr
    elif case.stderr_kind == "text":
        assert case.stderr_fragment is not None
        assert case.stderr_fragment in stderr


def _listener_is_closed(url: str) -> bool:
    parsed = urlsplit(url)
    assert parsed.hostname is not None and parsed.port is not None
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=0.2):
            return False
    except OSError:
        return True


def _verdict(
    row: dict[str, JsonValue],
    case: Case,
    expected: dict[str, JsonValue],
    actual: dict[str, JsonValue],
) -> str:
    source = row["expected"] if case.lane == "normal" else row["contrast"]
    assert isinstance(source, dict)
    if actual["exit"] != source["exit"]:
        return "ORACLE_MISMATCH"
    expected_effects = expected["effects"]
    assert isinstance(expected_effects, dict)
    rest_log = actual["restLog"]
    assert isinstance(rest_log, list)
    if len(rest_log) != expected_effects["restCount"]:
        return "ORACLE_MISMATCH"
    expected_stdout = source["stdout"]
    expected_stderr = source["stderr"]
    assert isinstance(expected_stdout, dict) and isinstance(expected_stderr, dict)
    if expected_stdout.get("mode") == "empty" and actual["stdout"] != "":
        return "ORACLE_MISMATCH"
    if expected_stderr.get("mode") == "empty" and actual["stderr"] != "":
        return "ORACLE_MISMATCH"
    if expected_stderr.get("mode") == "json" and case.stderr_kind != "json":
        return "ORACLE_MISMATCH"
    if expected_stderr.get("mode") == "json":
        try:
            json.loads(str(actual["stderr"]).strip())
        except json.JSONDecodeError:
            return "ORACLE_MISMATCH"
    return "INCONCLUSIVE"


def _run_case(
    parent: Path,
    case: Case,
    row: dict[str, JsonValue],
    *,
    evidence_dir: Path | None = None,
    sequence: int = 0,
) -> dict[str, JsonValue]:
    fixture_root: Path
    rest_url: str
    target_url: str
    with FixtureRoot(parent) as fixture:
        fixture_root = fixture.root
        rest_url = fixture.manifest.rest_url
        target_url = fixture.manifest.target_url
        path, body, response = _configure(fixture, case.route)
        argv = [_materialize(part, fixture) for part in case.argv]
        expected = _expected(row, case, fixture)
        sealed_at = _timestamp()
        seal_payload: dict[str, JsonValue] = {
            "id": case.row_id,
            "lane": case.lane,
            "argv": ["bp", *argv],
            "environment": _environment(fixture),
            "expected": expected,
            "sealedAt": sealed_at,
        }
        digest = hashlib.sha256(
            json.dumps(seal_payload, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        seal_record: dict[str, JsonValue] = {**seal_payload, "sha256": digest}
        seal_path = (evidence_dir or fixture.root) / (
            f"task-10-{sequence:02d}-{case.row_id.lower()}-{case.lane}-seal.json"
        )
        _write_once(seal_path, seal_record)
        frozen_seal = seal_path.read_bytes()
        before = fixture.snapshot()
        ledger_before = _ledger(fixture.manifest.ledger_path)
        result = fixture.run(argv, executable="bp")
        observed_at = _timestamp()
        after = fixture.snapshot()
        ledger_after = _ledger(fixture.manifest.ledger_path)
        assert seal_path.read_bytes() == frozen_seal
        assert sealed_at < observed_at
        assert before.rest_effects == () and before.target_effects == ()
        assert ledger_before == []
        assert result.returncode == case.exit_code
        _assert_streams(case, fixture, result.stdout, result.stderr)
        expected_rest_count = 0 if case.route is None else 1
        assert len(after.rest_effects) == expected_rest_count
        assert after.target_effects == ()
        if case.route is not None:
            effect = after.rest_effects[0]
            assert path is not None
            assert (effect.method, effect.path, effect.status) == (
                case.route.method,
                path,
                case.route.status,
            )
            if body is not None:
                assert effect.body_sha256 == hashlib.sha256(body).hexdigest()
            assert response is not None
            assert ledger_after == [_expected_ledger(case, path, body, response)]
        else:
            assert ledger_after == []
        combined_output = result.stdout + result.stderr
        ledger_bytes = (
            fixture.manifest.ledger_path.read_bytes()
            if fixture.manifest.ledger_path.is_file()
            else b""
        )
        for secret in SECRET_SENTINELS:
            assert secret not in combined_output
            assert secret.encode() not in ledger_bytes
        rest_log: list[JsonValue] = [_effect(item) for item in after.rest_effects]
        target_log: list[JsonValue] = []
        target_effect: RequestEffect
        for target_effect in after.target_effects:
            target_log.append(_effect(target_effect))
        ledger_before_json: list[JsonValue] = list(ledger_before)
        ledger_after_json: list[JsonValue] = list(ledger_after)
        actual: dict[str, JsonValue] = {
            "observedAt": observed_at,
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "restLog": rest_log,
            "targetLog": target_log,
            "ledgerBefore": ledger_before_json,
            "ledgerAfter": ledger_after_json,
        }
        verdict = _verdict(row, case, expected, actual)
    cleanup: dict[str, JsonValue] = {
        "fixtureRoot": str(fixture_root),
        "fixtureRootRemoved": not fixture_root.exists(),
        "restListenerClosed": _listener_is_closed(rest_url),
        "targetListenerClosed": _listener_is_closed(target_url),
    }
    assert cleanup["fixtureRootRemoved"] is True
    assert cleanup["restListenerClosed"] is True
    assert cleanup["targetListenerClosed"] is True
    record: dict[str, JsonValue] = {
        "preRunSeal": {"sealedAt": sealed_at, "sha256": digest, "evidence": str(seal_path)},
        "argv": ["bp", *argv],
        "expected": expected,
        "actual": actual,
        "verdict": verdict,
        "limits": list(case.limits),
        "cleanup": cleanup,
    }
    if evidence_dir is not None:
        _write_once(
            evidence_dir / f"task-10-{sequence:02d}-{case.row_id.lower()}-{case.lane}-actual.json",
            record,
        )
    return record


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.group == "scope_add_check"],
    ids=lambda case: f"{case.row_id}-{case.lane}",
)
def test_scope_add_check(tmp_path: Path, case: Case) -> None:
    _, rows = _manifest()
    _run_case(tmp_path, case, rows[case.row_id])


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.group == "scope_unsupported"],
    ids=lambda case: f"{case.row_id}-{case.lane}",
)
def test_scope_unsupported(tmp_path: Path, case: Case) -> None:
    _, rows = _manifest()
    _run_case(tmp_path, case, rows[case.row_id])


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.group == "same_origin_session"],
    ids=lambda case: case.row_id,
)
def test_same_origin_session(tmp_path: Path, case: Case) -> None:
    _, rows = _manifest()
    _run_case(tmp_path, case, rows[case.row_id])


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case.group == "cross_origin"],
    ids=lambda case: case.row_id,
)
def test_cross_origin(tmp_path: Path, case: Case) -> None:
    _, rows = _manifest()
    _run_case(tmp_path, case, rows[case.row_id])


def record_observations(
    parent: Path, evidence_dir: Path, output: Path
) -> list[dict[str, JsonValue]]:
    """Run all twenty invocations and persist immutable aggregate evidence."""
    manifest, oracle_rows = _manifest()
    grouped: dict[str, dict[str, JsonValue]] = {}
    cleanup: list[JsonValue] = []
    for sequence, case in enumerate(CASES, start=1):
        record = _run_case(
            parent,
            case,
            oracle_rows[case.row_id],
            evidence_dir=evidence_dir,
            sequence=sequence,
        )
        row = grouped.setdefault(case.row_id, {})
        row[case.lane] = record
        cleanup_record = record["cleanup"]
        cleanup.append({"id": case.row_id, "lane": case.lane, "receipt": cleanup_record})
    candidate: dict[str, JsonValue] = {
        "manifest": manifest["candidate"],
        "testedRevision": TESTED_REVISION,
    }
    observations: list[dict[str, JsonValue]] = []
    for row_id, lanes in sorted(grouped.items()):
        seal = oracle_rows[row_id]["seal"]
        assert isinstance(seal, dict)
        oracle_hash = seal["hash"]
        assert isinstance(oracle_hash, str)
        observations.append(
            {
                "id": row_id,
                "oracleHash": oracle_hash,
                "candidate": candidate,
                "normal": lanes["normal"],
                "contrast": lanes["contrast"],
            }
        )
    observation_payload: list[JsonValue] = list(observations)
    normal_payload: list[JsonValue] = [row["normal"] for row in observations]
    contrast_payload: list[JsonValue] = [row["contrast"] for row in observations]
    _write_once(output, observation_payload)
    _write_once(
        evidence_dir / "task-10-scope-session.json",
        {"candidate": candidate, "normal": normal_payload},
    )
    _write_once(
        evidence_dir / "task-10-scope-session-error.json",
        {"candidate": candidate, "contrast": contrast_payload},
    )
    _write_once(evidence_dir / "task-10-cleanup.json", cleanup)
    return observations


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: test_command_audit_scope_session.py ROOT EVIDENCE_DIR OUTPUT", file=sys.stderr
        )
        return 2
    record_observations(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
