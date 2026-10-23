"""Installed-CLI audit for config/history leaves and bare command groups.

The data table is deliberately kept beside the runner so every subprocess has a
sealed, concrete oracle before it starts.  The REST fixture proves the CLI
boundary only; Montoya and H2 effects remain separately evidenced.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from os import replace
from pathlib import Path
from typing import Final, Literal

import pytest

from audit_fixture import AuditFixture, FixtureRoot, RequestEffect

# allow: SIZE_OK — one auditable matrix keeps every sealed command case and runner together.

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
StreamKind = Literal["empty", "help", "json", "text"]

ROOT: Final = Path(__file__).resolve().parents[2]
MANIFEST_PATH: Final = ROOT / "quality" / "command-audit" / "oracles.json"
OBSERVATIONS_PATH: Final = ROOT / "quality" / "command-audit" / "observations-config-history.json"
CANDIDATE_REVISION: Final = "3af139dc0b4020923f831099338c92af3265d7e2"


def _wire(data: JsonValue, *, success: bool = True) -> bytes:
    payload: JsonValue = {"success": success, "data": data, "error": None}
    return json.dumps(payload, separators=(",", ":")).encode()


def _wire_error(code: str, message: str) -> bytes:
    payload: JsonValue = {
        "success": False,
        "data": None,
        "error": {"code": code, "message": message},
    }
    return json.dumps(payload, separators=(",", ":")).encode()


CONFIG_DATA: Final[dict[str, JsonValue]] = {"config": {"audit": {"enabled": True}, "threshold": 3}}
ENTRY: Final[dict[str, JsonValue]] = {
    "id": 1,
    "source": "fixture",
    "method": "GET",
    "url": "http://127.0.0.1:18080/audit",
    "host": "127.0.0.1",
    "reqHeaders": [],
    "reqBody": None,
    "statusCode": 200,
    "resHeaders": [],
    "resBody": "ok",
    "durationMs": 2,
    "timestamp": "2026-10-23T10:00:00Z",
}
LIST_DATA: Final[dict[str, JsonValue]] = {
    "entries": [ENTRY],
    "total": 1,
    "page": 0,
    "pageSize": 50,
}
LIST_STDOUT: Final[dict[str, JsonValue]] = {
    "id": 1,
    "method": "GET",
    "url": ENTRY["url"],
    "statusCode": 200,
}
SITEMAP_DATA: Final[dict[str, JsonValue]] = {
    "entries": [
        {
            "host": "127.0.0.1",
            "path": "/audit",
            "method": "GET",
            "lastSeen": "2026-10-23T10:00:00Z",
            "hitCount": 1,
        }
    ],
    "total": 1,
}
REPLAY_DATA: Final[dict[str, JsonValue]] = {
    "original": ENTRY,
    "replayed": {**ENTRY, "id": 0, "source": "replay", "statusCode": 201},
}
CONFIG_BODY: Final = b'{"config":{"audit":{"enabled":true}}}'
UNAVAILABLE: Final = _wire_error("SERVICE_UNAVAILABLE", "history storage is unavailable")
MISSING: Final = _wire_error("INVALID_REQUEST", "History entry 1 not found")
HISTORY_503_LIMIT: Final = (
    "CLI 503 SERVICE_UNAVAILABLE mapping observed. Current docs/SPEC.md:26 and "
    "UnavailableRoutes.kt:14-25 supersede historical 404 prose in docs/SPEC.md:669-701 "
    "and docs/bdd/13-history.feature."
)


@dataclass(frozen=True, slots=True)
class Route:
    method: str
    path: str
    response: bytes
    status: int = 200
    request_body: bytes | None = None


@dataclass(frozen=True, slots=True)
class Case:
    row_id: str
    lane: str
    argv: tuple[str, ...]
    exit_code: int
    stdout_kind: StreamKind
    stderr_kind: StreamKind
    stdout_json: JsonValue | None = None
    stderr_code: str | None = None
    text_fragment: str | None = None
    route: Route | None = None
    verdict: Literal["PASS", "FAIL", "INCONCLUSIVE"] = "PASS"
    limits: str = "CLI boundary observed through the owned loopback REST fixture."
    oracle_expected: dict[str, JsonValue] | None = None


JSON_USAGE_ORACLE: Final[dict[str, JsonValue]] = {
    "exit": 2,
    "stdout": {"kind": "empty", "json": None},
    "stderr": {"kind": "json", "code": "USAGE_ERROR", "fragment": None},
    "route": None,
    "effect": {"restCount": 0, "targetCount": 0},
    "authority": [
        "docs/OUTPUT.md:5-15",
        "docs/adr/0013-truthful-executable-contracts.md:16-23",
    ],
}


def _group_cases() -> tuple[Case, ...]:
    return tuple(
        Case(group_id, "normal", (name,), 2, "help", "empty")
        for group_id, name in zip(
            ("G01", "G02", "G03", "G04", "G05", "G06", "G07"),
            ("collab", "scan", "check", "scope", "config", "session", "history"),
            strict=True,
        )
    ) + tuple(
        Case(group_id, "contrast", (name, "--help"), 0, "help", "empty")
        for group_id, name in zip(
            ("G01", "G02", "G03", "G04", "G05", "G06", "G07"),
            ("collab", "scan", "check", "scope", "config", "session", "history"),
            strict=True,
        )
    )


CONFIG_CASES: Final = (
    Case(
        "L19",
        "normal",
        ("config", "get", "project"),
        0,
        "json",
        "empty",
        CONFIG_DATA,
        route=Route("GET", "/config/project", _wire(CONFIG_DATA)),
        limits="Nested CLI output and GET route observed; live Montoya config was not read.",
    ),
    Case(
        "L20",
        "normal",
        ("config", "get", "user"),
        0,
        "json",
        "empty",
        CONFIG_DATA,
        route=Route("GET", "/config/user", _wire(CONFIG_DATA)),
        limits="Nested CLI output and GET route observed; live Montoya config was not read.",
    ),
    Case(
        "L21",
        "normal",
        ("config", "set", "project", "--json", '{"audit":{"enabled":true}}'),
        0,
        "json",
        "empty",
        CONFIG_DATA,
        route=Route("PUT", "/config/project", _wire(CONFIG_DATA), request_body=CONFIG_BODY),
        verdict="INCONCLUSIVE",
        limits="Exact nested PUT body observed; live Montoya project config mutation was not observed.",
    ),
    Case(
        "L22",
        "normal",
        ("config", "set", "user", "--json", '{"audit":{"enabled":true}}'),
        0,
        "json",
        "empty",
        CONFIG_DATA,
        route=Route("PUT", "/config/user", _wire(CONFIG_DATA), request_body=CONFIG_BODY),
        verdict="INCONCLUSIVE",
        limits="Exact nested PUT body observed; live Montoya user config mutation was not observed.",
    ),
    Case(
        "L19",
        "contrast",
        ("config", "get", "project"),
        1,
        "empty",
        "json",
        stderr_code="INVALID_RESPONSE",
        route=Route("GET", "/config/project", b"not-json"),
    ),
    Case(
        "L20",
        "contrast",
        ("config", "get", "user"),
        1,
        "empty",
        "json",
        stderr_code="INVALID_RESPONSE",
        route=Route("GET", "/config/user", b"not-json"),
    ),
    Case(
        "L21",
        "contrast",
        ("config", "set", "project", "--json", '{"audit":'),
        2,
        "empty",
        "text",
        text_fragment="error: --json is not valid JSON",
        verdict="FAIL",
        limits=(
            "Zero PUT observed, but BP_AGENT=1 received plain text; "
            "docs/OUTPUT.md:5-15 requires one JSON stderr object."
        ),
        oracle_expected=JSON_USAGE_ORACLE,
    ),
    Case(
        "L22",
        "contrast",
        ("config", "set", "user", "--json", '{"audit":'),
        2,
        "empty",
        "text",
        text_fragment="error: --json is not valid JSON",
        verdict="FAIL",
        limits=(
            "Zero PUT observed, but BP_AGENT=1 received plain text; "
            "docs/OUTPUT.md:5-15 requires one JSON stderr object."
        ),
        oracle_expected=JSON_USAGE_ORACLE,
    ),
)

HISTORY_CASES: Final = (
    Case(
        "L28",
        "normal",
        ("history", "list", "--page", "0"),
        0,
        "json",
        "empty",
        LIST_STDOUT,
        route=Route("GET", "/history?page=0", _wire(LIST_DATA)),
        verdict="INCONCLUSIVE",
        limits="CLI list route/output observed; actual H2 rows were not read through this fixture.",
    ),
    Case(
        "L29",
        "normal",
        ("history", "get", "1"),
        0,
        "json",
        "empty",
        ENTRY,
        route=Route("GET", "/history/1", _wire(ENTRY)),
        verdict="INCONCLUSIVE",
        limits="CLI get route/output observed; actual H2 lookup was not exercised here.",
    ),
    Case(
        "L30",
        "normal",
        ("history", "sitemap"),
        0,
        "json",
        "empty",
        SITEMAP_DATA,
        route=Route("GET", "/history/sitemap", _wire(SITEMAP_DATA)),
        verdict="INCONCLUSIVE",
        limits="CLI sitemap route/output observed; actual H2 sitemap was not read here.",
    ),
    Case(
        "L31",
        "normal",
        ("history", "replay", "1"),
        0,
        "json",
        "empty",
        REPLAY_DATA,
        route=Route("POST", "/history/1/replay", _wire(REPLAY_DATA)),
        verdict="INCONCLUSIVE",
        limits="CLI POST/output observed; the server-side Montoya target send was not observed.",
    ),
    Case(
        "L32",
        "normal",
        ("history", "clear", "--confirm"),
        0,
        "json",
        "empty",
        {"cleared": True},
        route=Route("DELETE", "/history", _wire({"cleared": True})),
        verdict="INCONCLUSIVE",
        limits=(
            "CLI DELETE observed; transactional H2 history+sitemap clearing was not observed here. "
            "HistoryRoutes.kt:116-119 supersedes stale nontransactional prose in "
            "docs/SPEC.md:669-701 and the Python command docstring."
        ),
    ),
    Case(
        "L28",
        "contrast",
        ("history", "list", "--page", "0"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("GET", "/history?page=0", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
    Case(
        "L29",
        "contrast",
        ("history", "get", "1"),
        1,
        "empty",
        "json",
        stderr_code="INVALID_REQUEST",
        route=Route("GET", "/history/1", MISSING, status=400),
    ),
    Case(
        "L30",
        "contrast",
        ("history", "sitemap"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("GET", "/history/sitemap", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
    Case(
        "L31",
        "contrast",
        ("history", "replay", "1"),
        1,
        "empty",
        "json",
        stderr_code="INVALID_REQUEST",
        route=Route("POST", "/history/1/replay", MISSING, status=400),
        limits="Typed missing-ID error and zero fixture target effects observed.",
    ),
    Case(
        "L32",
        "contrast",
        ("history", "clear"),
        2,
        "empty",
        "text",
        text_fragment="Pass --confirm to proceed",
        verdict="FAIL",
        limits=(
            "Zero DELETE observed, but BP_AGENT=1 received plain text; "
            "docs/OUTPUT.md:5-15 requires one JSON stderr object."
        ),
        oracle_expected=JSON_USAGE_ORACLE,
    ),
)

H01_CASES: Final = (
    Case(
        "H01",
        "normal",
        ("history",),
        2,
        "help",
        "empty",
        verdict="FAIL",
        limits=(
            "Preserves the caller's H01 oracle and "
            "bp/src/bp/commands/history.py:289-295 default-list claim."
        ),
        oracle_expected={
            "exit": 0,
            "stdout": {"kind": "json", "json": LIST_STDOUT},
            "stderr": {"kind": "empty", "code": None, "fragment": None},
            "route": {
                "method": "GET",
                "path": "/history",
                "requestBodySha256": None,
                "status": 200,
            },
            "effect": {"restCount": 1, "targetCount": 0},
            "authority": [
                "caller H01 pre-execution oracle",
                "bp/src/bp/commands/history.py:289-295",
            ],
        },
    ),
    Case(
        "H01",
        "contrast",
        ("history", "list"),
        0,
        "json",
        "empty",
        LIST_STDOUT,
        route=Route("GET", "/history", _wire(LIST_DATA)),
        limits="Explicit list control reached GET /history on the same fixture contract.",
    ),
)

UNAVAILABLE_CASES: Final = (
    Case(
        "L28",
        "db503",
        ("history", "list", "--page", "0"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("GET", "/history?page=0", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
    Case(
        "L29",
        "db503",
        ("history", "get", "1"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("GET", "/history/1", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
    Case(
        "L30",
        "db503",
        ("history", "sitemap"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("GET", "/history/sitemap", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
    Case(
        "L31",
        "db503",
        ("history", "replay", "1"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("POST", "/history/1/replay", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
    Case(
        "L32",
        "db503",
        ("history", "clear", "--confirm"),
        1,
        "empty",
        "json",
        stderr_code="SERVICE_UNAVAILABLE",
        route=Route("DELETE", "/history", UNAVAILABLE, status=503),
        limits=HISTORY_503_LIMIT,
    ),
)


def _json_stream(raw: str) -> JsonValue:
    rows = [json.loads(line) for line in raw.splitlines() if line]
    return rows[0] if len(rows) == 1 else rows


def _expected(case: Case) -> dict[str, JsonValue]:
    if case.oracle_expected is not None:
        return case.oracle_expected
    return {
        "exit": case.exit_code,
        "stdout": {"kind": case.stdout_kind, "json": case.stdout_json},
        "stderr": {
            "kind": case.stderr_kind,
            "code": case.stderr_code,
            "fragment": case.text_fragment,
        },
        "route": None
        if case.route is None
        else {
            "method": case.route.method,
            "path": case.route.path,
            "status": case.route.status,
            "requestBodySha256": None
            if case.route.request_body is None
            else hashlib.sha256(case.route.request_body).hexdigest(),
        },
        "effect": {"restCount": 0 if case.route is None else 1, "targetCount": 0},
    }


def _configure(fixture: AuditFixture, route: Route | None) -> None:
    if route is None:
        return
    if route.request_body is None:
        fixture.add_rest_route(route.method, route.path, status=route.status, body=route.response)
    else:
        fixture.expect_rest_route(
            route.method,
            route.path,
            expected_body=route.request_body,
            status=route.status,
            body=route.response,
        )


def _assert_streams(case: Case, stdout: str, stderr: str) -> None:
    if case.stdout_kind == "empty":
        assert stdout == ""
    elif case.stdout_kind == "help":
        assert "Usage:" in stdout
    elif case.stdout_kind == "json":
        assert _json_stream(stdout) == case.stdout_json
    if case.stderr_kind == "empty":
        assert stderr == ""
    elif case.stderr_kind == "json":
        error = _json_stream(stderr)
        assert isinstance(error, dict)
        detail = error.get("error")
        assert isinstance(detail, dict)
        assert detail.get("code") == case.stderr_code
    elif case.stderr_kind == "text":
        assert case.text_fragment is not None and case.text_fragment in stderr


def _effect_json(effect: RequestEffect) -> dict[str, JsonValue]:
    return {
        "method": effect.method,
        "path": effect.path,
        "bodySha256": effect.body_sha256,
        "bodyLength": effect.body_length,
        "status": effect.status,
    }


def _run_case(
    tmp_path: Path, case: Case, *, evidence_dir: Path | None = None, sequence: int = 0
) -> dict[str, JsonValue]:
    with FixtureRoot(tmp_path) as fixture:
        _configure(fixture, case.route)
        env: dict[str, JsonValue] = {
            "HOME": str(fixture.manifest.home),
            "BURP_REST_URL": fixture.manifest.rest_url,
            "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
            "BP_CONFIG_PATH": str(fixture.manifest.config_path),
            "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
            "BP_AGENT": "1",
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
        expected = _expected(case)
        seal_payload: dict[str, JsonValue] = {
            "id": case.row_id,
            "lane": case.lane,
            "argv": [*fixture.command("bp"), *case.argv],
            "env": env,
            "expected": expected,
        }
        seal_hash = hashlib.sha256(
            json.dumps(seal_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        pre_run: dict[str, JsonValue] = {"sealedAt": _timestamp(), "sha256": seal_hash}
        persistence_dir = evidence_dir or (tmp_path / "sealed")
        sealed_record = dict(seal_payload)
        sealed_record["preRunSeal"] = pre_run
        _write_once(
            persistence_dir / f"task-11-{sequence:02d}-{case.row_id}-{case.lane}-seal.json",
            sealed_record,
        )
        before = fixture.snapshot()
        result = fixture.run(case.argv, executable="bp")
        after = fixture.snapshot()
        assert before.rest_effects == () and before.target_effects == ()
        assert result.returncode == case.exit_code
        _assert_streams(case, result.stdout, result.stderr)
        assert len(after.rest_effects) == (0 if case.route is None else 1)
        assert after.target_effects == ()
        rest_log: list[JsonValue] = []
        for rest_effect in after.rest_effects:
            rest_log.append(_effect_json(rest_effect))
        target_log: list[JsonValue] = []
        actual: dict[str, JsonValue] = {
            "observedAt": _timestamp(),
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "restLog": rest_log,
            "targetLog": target_log,
        }
        _write_once(
            persistence_dir / f"task-11-{sequence:02d}-{case.row_id}-{case.lane}-actual.json",
            actual,
        )
        record: dict[str, JsonValue] = {
            "preRunSeal": pre_run,
            "argv": [*fixture.command("bp"), *case.argv],
            "expected": expected,
            "actual": actual,
            "verdict": case.verdict,
            "limits": case.limits,
        }
        return record


def _timestamp() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _write_once(path: Path, payload: JsonValue) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


@pytest.mark.parametrize("case", CONFIG_CASES, ids=lambda case: f"{case.row_id}-{case.lane}")
def test_nested_config(tmp_path: Path, case: Case) -> None:
    _run_case(tmp_path, case)


@pytest.mark.parametrize("case", HISTORY_CASES[:5], ids=lambda case: case.row_id)
def test_history_lifecycle(tmp_path: Path, case: Case) -> None:
    _run_case(tmp_path, case)


@pytest.mark.parametrize("case", _group_cases(), ids=lambda case: f"{case.row_id}-{case.lane}")
def test_bare_groups(tmp_path: Path, case: Case) -> None:
    _run_case(tmp_path, case)


@pytest.mark.parametrize("case", H01_CASES, ids=lambda case: case.lane)
def test_history_h01_control(tmp_path: Path, case: Case) -> None:
    _run_case(tmp_path, case)


@pytest.mark.parametrize("case", (HISTORY_CASES[6], HISTORY_CASES[8]), ids=lambda case: case.row_id)
def test_history_lifecycle_missing_id(tmp_path: Path, case: Case) -> None:
    _run_case(tmp_path, case)


@pytest.mark.parametrize("case", UNAVAILABLE_CASES, ids=lambda case: case.row_id)
def test_unavailable_db(tmp_path: Path, case: Case) -> None:
    _run_case(tmp_path, case)


def test_clear_without_confirm(tmp_path: Path) -> None:
    case = HISTORY_CASES[9]
    _run_case(tmp_path, case)


def test_observation_aggregate_has_complete_ordered_rows() -> None:
    rows = json.loads(OBSERVATIONS_PATH.read_text(encoding="utf-8"))
    expected_ids = {
        "G01",
        "G02",
        "G03",
        "G04",
        "G05",
        "G06",
        "G07",
        "H01",
        "L19",
        "L20",
        "L21",
        "L22",
        "L28",
        "L29",
        "L30",
        "L31",
        "L32",
    }
    assert {row["id"] for row in rows} == expected_ids
    for row in rows:
        assert {"id", "oracleHash", "candidate", "normal", "contrast"} <= row.keys()
        for lane_name in ("normal", "contrast"):
            lane = row[lane_name]
            assert {"preRunSeal", "argv", "expected", "actual", "verdict", "limits"} <= lane.keys()
            assert lane["preRunSeal"]["sealedAt"] < lane["actual"]["observedAt"]
            assert lane["actual"]["restLog"] is not None
            assert lane["actual"]["targetLog"] is not None
    h01 = next(row for row in rows if row["id"] == "H01")
    assert h01["normal"]["expected"]["route"]["path"] == "/history"
    assert h01["normal"]["actual"]["exit"] == 2
    assert h01["normal"]["actual"]["restLog"] == []


def record_observations(root: Path, evidence_dir: Path, output: Path) -> None:
    """Run the full audit once and persist immutable per-invocation and aggregate records."""
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    hashes = {row["id"]: row["seal"]["hash"] for row in manifest["rows"]}
    cases = (*_group_cases(), *CONFIG_CASES, *HISTORY_CASES, *H01_CASES)
    grouped: dict[str, dict[str, JsonValue]] = {}
    for sequence, case in enumerate(cases, start=1):
        result = _run_case(root, case, evidence_dir=evidence_dir, sequence=sequence)
        grouped.setdefault(case.row_id, {})[case.lane] = result
    candidate: dict[str, JsonValue] = {
        "revision": CANDIDATE_REVISION,
        "branch": "codex/qa-config-history",
        "oracleSourceRevision": manifest["candidate"]["revision"],
        "contract": manifest["candidate"]["contract"],
    }
    rows: list[dict[str, JsonValue]] = []
    for row_id, lanes in sorted(grouped.items()):
        row: dict[str, JsonValue] = {
            "id": row_id,
            "oracleHash": hashes.get(row_id, "caller-H01-preexisting-oracle"),
            "candidate": candidate,
            "normal": lanes["normal"],
            "contrast": lanes["contrast"],
        }
        rows.append(row)
    rows_payload: list[JsonValue] = []
    rows_payload.extend(rows)
    normal_rows: list[JsonValue] = [row for row in rows if row["id"] != "H01"]
    contrasts: list[JsonValue] = [row["contrast"] for row in rows]
    _write_once(output, rows_payload)
    _write_once(
        evidence_dir / "task-11-config-history.json",
        {"candidate": candidate, "rows": normal_rows},
    )
    h01 = next(row for row in rows if row["id"] == "H01")
    _write_once(evidence_dir / "task-11-history-h01.json", h01)
    _write_once(
        evidence_dir / "task-11-config-history-error.json",
        {"candidate": candidate, "contrasts": contrasts},
    )


def reopen_output_oracles(root: Path, evidence_dir: Path, output: Path) -> None:
    """Version four rows after current output authority was supplied during execution."""
    rows = json.loads(output.read_text(encoding="utf-8"))
    selected = (CONFIG_CASES[6], CONFIG_CASES[7], HISTORY_CASES[9], H01_CASES[0])
    by_id = {row["id"]: row for row in rows}
    revisions: list[JsonValue] = []
    for sequence, case in enumerate(selected, start=35):
        prior = by_id[case.row_id][case.lane]
        result = _run_case(root, case, evidence_dir=evidence_dir, sequence=sequence)
        reason = (
            "The caller's preexisting H01 oracle was restored without changing its observed result."
            if case.row_id == "H01"
            else (
                "Current docs/OUTPUT.md:5-15 authority supplied during execution; "
                "original evidence retained."
            )
        )
        result["reopenedFrom"] = {
            "preRunSeal": prior["preRunSeal"],
            "reason": reason,
        }
        by_id[case.row_id][case.lane] = result
        revisions.append({"id": case.row_id, "lane": case.lane, "result": result})
    temporary = output.with_suffix(".v2.tmp")
    _write_once(temporary, rows)
    replace(temporary, output)
    _write_once(
        evidence_dir / "task-11-output-authority.json",
        {
            "authority": [
                "docs/OUTPUT.md:5-15",
                "docs/adr/0013-truthful-executable-contracts.md:16-23",
            ],
            "revisions": revisions,
        },
    )


def record_unavailable(root: Path, evidence_dir: Path) -> None:
    """Persist the all-five-route CLI 503 control without changing core contrast rows."""
    rows: list[JsonValue] = []
    for sequence, case in enumerate(UNAVAILABLE_CASES, start=39):
        row: dict[str, JsonValue] = {
            "id": case.row_id,
            "result": _run_case(root, case, evidence_dir=evidence_dir, sequence=sequence),
        }
        rows.append(row)
    _write_once(
        evidence_dir / "task-11-db503.json",
        {
            "candidate": {"revision": CANDIDATE_REVISION, "branch": "codex/qa-config-history"},
            "limits": (
                "This proves CLI mapping through a stubbed 503 REST boundary. "
                "Kotlin route availability is separately evidenced by AuditStateFixtureTest."
            ),
            "rows": rows,
        },
    )
