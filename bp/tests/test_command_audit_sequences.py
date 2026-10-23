"""Execute sealed Task 12 commands against an owned, stateful loopback REST fixture.

The fixture proves CLI/REST and local SQLite behavior. It cannot prove Montoya
network sends, proxy capture, provider state, or extension H2 persistence.
# noqa: SIZE_OK
The sealed 50-step trace and its independent provenance checks share one owner.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections import deque
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final, TypeAlias, cast
from unittest.mock import patch
from urllib.parse import quote, urlsplit

import pytest

from audit_fixture import AuditFixture, FixtureRoot, RequestEffect, _FixtureHandler

ROOT: Final = Path(__file__).resolve().parents[2]
ORACLES: Final = ROOT / "quality" / "command-audit" / "sequence-oracles.json"
OBSERVATIONS: Final = ROOT / "quality" / "command-audit" / "observations-sequences.json"
ORACLE_SHA: Final = "407b2609a746cecd64b38f05413c571300eec6119374944bb276486c5219cbc3"
Json: TypeAlias = None | bool | int | float | str | list["Json"] | dict[str, "Json"]
Obj: TypeAlias = dict[str, Json]


@dataclass(frozen=True, slots=True)
class Reply:
    status: int
    data: Json = None
    code: str = "NOT_FOUND"
    drop: bool = False


def _api(reply: Reply) -> bytes:
    return json.dumps(
        {
            "success": reply.status < 400,
            "data": reply.data if reply.status < 400 else None,
            "error": None if reply.status < 400 else {"code": reply.code, "message": "fixture"},
        },
        separators=(",", ":"),
    ).encode()


def _ledger(path: Path) -> list[Obj]:
    if not path.exists():
        return []
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        return [
            dict(row)
            for row in connection.execute(
                "SELECT id, command, burp_op, status, exit_code, error_code, tag FROM ops ORDER BY rowid"
            )
        ]


def _effect(item: RequestEffect) -> Obj:
    return {
        "method": item.method,
        "path": item.path,
        "status": item.status,
        "body_sha256": item.body_sha256,
        "body_length": item.body_length,
    }


def _materialize(value: str, fixture: AuditFixture, payload: Path, op_id: str) -> str:
    replacements = {
        "{{LOOPBACK_URL}}": fixture.manifest.target_url,
        "{{OTHER_LOOPBACK_ORIGIN}}": fixture.manifest.rest_url,
        "{{PROXY_ID}}": "1",
        "{{HISTORY_ID}}": "1",
        "{{CRAWL_ID}}": "sid-001",
        "{{AUDIT_ID}}": "sid-002",
        "{{COLLAB_ID}}": "cid-001",
        "{{OP_ID}}": op_id,
        "{{PAYLOAD_FILE}}": str(payload),
    }
    for token, replacement in replacements.items():
        value = value.replace(token, replacement)
    assert "{{" not in value
    return value


def _seal(step: Obj, argv: list[str] | None, destination: Path) -> Obj:
    expected = cast(Obj, step["expected"])
    content: Obj = {
        "step": step["id"],
        "oracle_hash": cast(Obj, step["seal"])["hash"],
        "expected": expected,
        "expected_sha256": hashlib.sha256(
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "argv": cast(Json, argv),
        "sealed_at_ns": time.time_ns(),
    }
    with destination.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(content, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return content


def _run_all(evidence_dir: Path) -> tuple[list[Obj], dict[str, Obj]]:
    oracle_bytes = ORACLES.read_bytes()
    assert hashlib.sha256(oracle_bytes).hexdigest() == ORACLE_SHA
    document = cast(Obj, json.loads(oracle_bytes))
    evidence_dir.mkdir(parents=True, exist_ok=True)
    seal_path = evidence_dir / "task-12-real-seals.jsonl"
    seal_path.write_text("", encoding="utf-8")
    records: list[Obj] = []
    seals_by_step: dict[str, Obj] = {}
    queue: dict[str, deque[Reply]] = {}
    dispatched: list[tuple[str, str]] = []
    state_events: list[Obj] = []
    scope = False
    session: Obj = {
        "name": "default",
        "cookies": {},
        "headers": {},
        "origin": None,
        "cookieCount": 0,
        "headerCount": 0,
    }
    original_dispatch = _FixtureHandler._dispatch

    def dispatch(handler: _FixtureHandler, method: str) -> None:
        nonlocal scope, session
        path = handler.path
        owned = path.startswith("/target/scope/") or path.startswith("/session/")
        if owned:
            length = int(handler.headers.get("Content-Length", "0"))
            body = handler.rfile.read(length)
            body_sha = hashlib.sha256(body).hexdigest()
            before_state: Obj = {
                "scope": scope,
                "session": {
                    "name": session["name"],
                    "cookieCount": session["cookieCount"],
                    "headerCount": session["headerCount"],
                    "origin": session["origin"],
                },
            }
            status = 200
            code = "INVALID_REQUEST"
            data: Json = {}
            parsed: Obj = {}
            if body:
                try:
                    decoded = json.loads(body)
                    parsed = decoded if isinstance(decoded, dict) else {}
                except json.JSONDecodeError:
                    status = 400
            target_url = fixture.manifest.target_url
            if status == 200:
                if method == "GET" and path == "/target/scope/check?url=" + quote(
                    target_url, safe=""
                ):
                    data = {"url": target_url, "inScope": scope}
                elif method == "POST" and path in {"/target/scope/add", "/target/scope/remove"}:
                    if parsed.get("url") != target_url:
                        status = 400
                    else:
                        scope = path == "/target/scope/add"
                        data = {"url": target_url, "inScope": scope}
                elif method == "GET" and path == "/session/get":
                    data = deepcopy(session)
                elif method == "POST" and path == "/session/set":
                    cookies = parsed.get("cookies")
                    headers = parsed.get("headers", {})
                    if not isinstance(cookies, dict) or not isinstance(headers, dict):
                        status = 400
                    else:
                        session = {
                            "name": parsed.get("name", "default"),
                            "cookies": cookies,
                            "headers": headers,
                            "origin": None,
                            "cookieCount": len(cookies),
                            "headerCount": len(headers),
                        }
                        data = deepcopy(session)
                elif method == "POST" and path == "/session/send":
                    request_url = parsed.get("url")
                    if not isinstance(request_url, str):
                        status = 400
                    elif (
                        session["origin"] is not None
                        and urlsplit(request_url).netloc != urlsplit(str(session["origin"])).netloc
                    ):
                        status = 403
                        code = "CROSS_ORIGIN_SESSION"
                    else:
                        if session["origin"] is None:
                            session["origin"] = (
                                f"{urlsplit(request_url).scheme}://{urlsplit(request_url).netloc}"
                            )
                        data = {
                            "statusCode": 200,
                            "headers": [],
                            "body": "fixture",
                            "hasResponse": True,
                        }
                elif method == "GET" and path == "/session/cookie-jar":
                    data = {"cookies": [], "total": 0}
                elif method == "DELETE" and path == "/session/clear":
                    session = {
                        "name": "default",
                        "cookies": {},
                        "headers": {},
                        "origin": None,
                        "cookieCount": 0,
                        "headerCount": 0,
                    }
                    data = deepcopy(session)
                else:
                    status = 404
                    code = "NOT_FOUND"
            effect = RequestEffect(method, path, body_sha, len(body), status)
            handler.server.state.effects.append(effect)
            dispatched.append((method, path))
            state_events.append(
                {
                    "method": method,
                    "path": path,
                    "body_sha256": body_sha,
                    "status": status,
                    "rest_effect_index": len(handler.server.state.effects) - 1,
                    "before": before_state,
                    "after": {
                        "scope": scope,
                        "session": {
                            "name": session["name"],
                            "cookieCount": session["cookieCount"],
                            "headerCount": session["headerCount"],
                            "origin": session["origin"],
                        },
                    },
                }
            )
            response = _api(Reply(status, data, code))
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(response)))
            handler.end_headers()
            handler.wfile.write(response)
            return
        replies = queue.get(path)
        if replies:
            reply = replies.popleft()
            if reply.drop:
                length = int(handler.headers.get("Content-Length", "0"))
                body = handler.rfile.read(length)
                handler.server.state.effects.append(
                    RequestEffect(
                        method, path, hashlib.sha256(body).hexdigest(), len(body), reply.status
                    )
                )
                dispatched.append((method, path))
                handler.connection.close()
                return
            handler.server.state.routes[(method, path)] = (
                reply.status,
                _api(reply),
                "application/json",
                None,
            )
        dispatched.append((method, path))
        original_dispatch(handler, method)

    with (
        TemporaryDirectory(prefix="bp-sequences-") as temporary,
        patch.object(_FixtureHandler, "_dispatch", dispatch),
        FixtureRoot(Path(temporary)) as fixture,
    ):
        assert urlsplit(fixture.manifest.target_url).hostname == "127.0.0.1"
        payload = fixture.manifest.payload_dir / "task-12.txt"
        payload.write_text("p1\np2\np3\n", encoding="utf-8")
        history: list[Obj] = []
        entry: Obj = {
            "id": 1,
            "request": {
                "method": "GET",
                "url": fixture.manifest.target_url + "/fuzz?id=base",
                "headers": [],
                "body": None,
            },
            "response": {"statusCode": 200, "headers": [], "body": "fixture"},
        }
        history_entry: Obj = {
            "id": 1,
            "source": "proxy",
            "method": "GET",
            "url": fixture.manifest.target_url + "/captured",
            "host": "127.0.0.1",
            "reqHeaders": [],
            "reqBody": None,
            "statusCode": 200,
            "resHeaders": [],
            "resBody": "fixture",
            "durationMs": 1,
            "timestamp": "2026-10-23T12:00:00Z",
        }
        fuzz_runs: dict[str, Obj] = {}
        s6_steps = {
            str(item["id"]): item
            for sequence in cast(list[Obj], document["sequences"])
            if sequence["id"] == "S6"
            for item in cast(list[Obj], sequence["steps"])
        }
        for sequence in cast(list[Obj], document["sequences"]):
            sequence_id = str(sequence["id"])
            for step in cast(list[Obj], sequence["steps"]):
                step_id = str(step["id"])
                invocation = cast(Obj, step["invocation"])
                expected = cast(Obj, step["expected"])
                rest = cast(Obj, step["rest"])
                ledger_before = _ledger(fixture.manifest.ledger_path)
                before = fixture.snapshot()
                event_start = len(dispatched)
                state_start = len(state_events)
                op_id = str(ledger_before[0]["id"]) if ledger_before else "1"
                argv: list[str] | None = None
                if "argv_template" in invocation:
                    argv = [
                        _materialize(str(arg), fixture, payload, op_id)
                        for arg in cast(list[Json], invocation["argv_template"])
                    ]
                elif sequence_id == "S6" and step_id not in {"S6.8", "S6.9", "S6.10"}:
                    argv = [
                        _materialize(str(arg), fixture, payload, op_id)
                        for arg in cast(list[Json], sequence["command_argv_template"])
                    ]
                seal = seals_by_step.get(step_id)
                if seal is None:
                    seal = _seal(step, argv, seal_path)
                    seals_by_step[step_id] = seal
                if step_id == "S6.1":
                    assert argv is not None
                    for phase_id in ("S6.2", "S6.5"):
                        seals_by_step[phase_id] = _seal(s6_steps[phase_id], argv, seal_path)
                route = rest.get("path")
                path = (
                    _materialize(str(route), fixture, payload, op_id)
                    if isinstance(route, str)
                    else None
                )
                if path == "/target/scope/check":
                    path += "?url=" + quote(fixture.manifest.target_url, safe="")
                reply = Reply(200, {})
                if sequence_id == "S3":
                    if step_id == "S3.2":
                        reply = Reply(200, entry)
                    elif step_id in {"S3.3", "S3.5"}:
                        reply = Reply(
                            200,
                            {
                                "original": history_entry,
                                "replayed": {**history_entry, "id": 0, "source": "replay"},
                            },
                        )
                    elif step_id == "S3.6":
                        reply = Reply(200, drop=True)
                    elif step_id == "S3.7":
                        reply = Reply(
                            200,
                            {
                                "original": history_entry,
                                "replayed": {**history_entry, "id": 0, "source": "replay"},
                            },
                        )
                    elif step_id in {"S3.4", "S3.9"}:
                        reply = Reply(
                            200,
                            {
                                "entries": cast(Json, history),
                                "total": len(history),
                                "page": 0,
                                "pageSize": 50,
                            },
                        )
                    elif step_id == "S3.8":
                        history.clear()
                        reply = Reply(200, {"cleared": True})
                    else:
                        reply = Reply(
                            200,
                            {
                                "statusCode": 200,
                                "headers": [],
                                "body": "fixture",
                                "hasResponse": True,
                            },
                        )
                elif sequence_id == "S4":
                    if step_id in {"S4.7", "S4.8"}:
                        reply = Reply(503, code="PRO_REQUIRED")
                    elif step_id == "S4.9":
                        reply = Reply(501, code="UNSUPPORTED")
                    elif step_id in {"S4.2", "S4.5"}:
                        reply = Reply(
                            200, {"scanId": "sid-001", "status": "Running", "issueCount": 0}
                        )
                    elif step_id in {"S4.3", "S4.6"}:
                        reply = Reply(200, {"scanId": "sid-001", "issues": [], "total": 0})
                    else:
                        reply = Reply(200, {"scanId": "sid-001", "status": "running"})
                elif sequence_id == "S5":
                    if step_id in {"S5.3", "S5.4", "S5.5"}:
                        reply = Reply(
                            404 if step_id == "S5.3" else 501,
                            code="NOT_FOUND" if step_id == "S5.3" else "UNSUPPORTED",
                        )
                    elif step_id == "S5.1":
                        reply = Reply(
                            200,
                            {
                                "payloads": [
                                    {
                                        "id": "cid-001",
                                        "payload": "cid-001.oastify.test",
                                        "interactionId": "cid-001",
                                    }
                                ]
                            },
                        )
                    else:
                        reply = Reply(
                            200, {"found": False, "interactions": [], "queriedPayloadId": "cid-001"}
                        )
                if path and sequence_id not in {"S1", "S2", "S6"}:
                    if step_id == "S3.6":
                        queue[path] = deque([reply])
                    else:
                        fixture.add_rest_route(
                            str(rest["method"]), path, status=reply.status, body=_api(reply)
                        )
                actual: Obj | None = None
                process_ref: str | None = None
                phase_range: tuple[int, int] | None = None
                if step_id == "S3.1":
                    pass  # No Burp proxy listener exists in this fixture.
                elif sequence_id == "S6":
                    # One real command supplies the preflight, baseline, and shots phase records.
                    run_key = (
                        "normal"
                        if step_id in {"S6.1", "S6.2", "S6.5", "S6.8"}
                        else "baseline_transport"
                        if step_id == "S6.3"
                        else "baseline_invalid"
                        if step_id == "S6.4"
                        else "ordinary_p2"
                        if step_id in {"S6.6", "S6.9"}
                        else "transport_p2"
                    )
                    if run_key not in fuzz_runs and step_id not in {"S6.8", "S6.9", "S6.10"}:
                        assert argv is not None
                        phase_ids = {
                            "normal": ("S6.1", "S6.2", "S6.5"),
                            "baseline_transport": ("S6.3",),
                            "baseline_invalid": ("S6.4",),
                            "ordinary_p2": ("S6.6",),
                            "transport_p2": ("S6.7",),
                        }[run_key]
                        assert all(phase_id in seals_by_step for phase_id in phase_ids)
                        fixture.add_rest_route(
                            "GET", "/proxy/history/1", body=_api(Reply(200, entry))
                        )
                        success = Reply(
                            200,
                            {"response": {"statusCode": 200, "body": "fixture"}, "durationMs": 1},
                        )
                        ordinary = Reply(400, code="SEND_FAILED")
                        transport = Reply(200, drop=True)
                        invalid = Reply(200, {"response": {"body": "fixture"}})
                        responses = {
                            "normal": [success] * 4,
                            "baseline_transport": [transport],
                            "baseline_invalid": [invalid],
                            "ordinary_p2": [success, success, ordinary, success],
                            "transport_p2": [success, success, transport],
                        }[run_key]
                        queue["/repeater/send"] = deque(responses)
                        fuzz_before = fixture.snapshot()
                        ledger_start = len(_ledger(fixture.manifest.ledger_path))
                        process_started_at_ns = time.time_ns()
                        assert all(
                            cast(int, seals_by_step[phase_id]["sealed_at_ns"])
                            < process_started_at_ns
                            for phase_id in phase_ids
                        )
                        started = time.perf_counter_ns()
                        result = fixture.run(argv[1:])
                        duration_ms = (time.perf_counter_ns() - started) / 1_000_000
                        completed_at_ns = time.time_ns()
                        fuzz_after = fixture.snapshot()
                        fuzz_runs[run_key] = {
                            "process_ref": run_key,
                            "started_at_ns": process_started_at_ns,
                            "completed_at_ns": completed_at_ns,
                            "rest_event_start_index": len(fuzz_before.rest_effects),
                            "phase_ids": cast(Json, list(phase_ids)),
                            "phase_seal_times_ns": cast(
                                Json,
                                {
                                    phase_id: seals_by_step[phase_id]["sealed_at_ns"]
                                    for phase_id in phase_ids
                                },
                            ),
                            "argv": cast(Json, argv),
                            "actual": {
                                "exit": result.returncode,
                                "stdout": result.stdout,
                                "stderr": result.stderr,
                                "duration_ms": duration_ms,
                            },
                            "rest": [
                                _effect(item)
                                for item in fuzz_after.rest_effects[len(fuzz_before.rest_effects) :]
                            ],
                            "ledger": cast(
                                Json, _ledger(fixture.manifest.ledger_path)[ledger_start:]
                            ),
                        }
                    run = fuzz_runs.get(run_key)
                    if step_id in {"S6.8", "S6.9", "S6.10"}:
                        run_ids = (
                            {row["id"] for row in cast(list[Obj], run["ledger"])} if run else set()
                        )
                        started = time.perf_counter_ns()
                        local_rows = [
                            row
                            for row in _ledger(fixture.manifest.ledger_path)
                            if row["id"] in run_ids
                        ]
                        actual = {
                            "exit": 0,
                            "stdout": json.dumps(
                                {"ledger_rows": local_rows}, separators=(",", ":")
                            ),
                            "stderr": "",
                            "duration_ms": (time.perf_counter_ns() - started) / 1_000_000,
                        }
                        argv = None
                    elif run:
                        actual = cast(Obj, run["actual"])
                        offset = {
                            "S6.1": (0, 1),
                            "S6.2": (1, 2),
                            "S6.5": (2, 5),
                            "S6.3": (1, 2),
                            "S6.4": (1, 2),
                            "S6.6": (2, 5),
                            "S6.7": (2, 4),
                        }[step_id]
                        process_ref = run_key
                        phase_range = offset
                else:
                    assert argv is not None and argv[0] == "bp"
                    started = time.perf_counter_ns()
                    result = fixture.run(argv[1:])
                    actual = {
                        "exit": result.returncode,
                        "stdout": result.stdout,
                        "stderr": result.stderr,
                        "duration_ms": (time.perf_counter_ns() - started) / 1_000_000,
                    }
                after = fixture.snapshot()
                rest_effects = [
                    _effect(item) for item in after.rest_effects[len(before.rest_effects) :]
                ]
                if sequence_id == "S6" and step_id not in {"S6.8", "S6.9", "S6.10"}:
                    run = fuzz_runs.get(run_key)
                    assert run is not None
                    rest_effects = cast(list[Obj], run["rest"])[offset[0] : offset[1]]
                target_effects = [
                    _effect(item) for item in after.target_effects[len(before.target_effects) :]
                ]
                ledger_after = _ledger(fixture.manifest.ledger_path)
                if sequence_id == "S6" and step_id not in {"S6.8", "S6.9", "S6.10"}:
                    ledger_delta = cast(list[Obj], fuzz_runs[run_key]["ledger"])[
                        offset[0] : offset[1]
                    ]
                else:
                    ledger_delta = ledger_after[len(ledger_before) :]
                primary_routes = (
                    [(str(effect["method"]), str(effect["path"])) for effect in rest_effects]
                    if sequence_id == "S6"
                    else dispatched[event_start:]
                )
                reconciliation: Obj | None = None
                if step_id == "S3.6":
                    # The POST was dispatched and its response lost. Read H2 through
                    # the CLI; an unchanged stub page still cannot resolve a target send.
                    read_argv = ["bp", "history", "list", "--format", "json"]
                    read_before = fixture.snapshot()
                    started = time.perf_counter_ns()
                    read_result = fixture.run(read_argv[1:])
                    read_after = fixture.snapshot()
                    reconciliation = {
                        "argv": cast(Json, read_argv),
                        "actual": {
                            "exit": read_result.returncode,
                            "stdout": read_result.stdout,
                            "stderr": read_result.stderr,
                            "duration_ms": (time.perf_counter_ns() - started) / 1_000_000,
                        },
                        "rest_effects": cast(
                            Json,
                            [
                                _effect(item)
                                for item in read_after.rest_effects[len(read_before.rest_effects) :]
                            ],
                        ),
                        "target_effect_count": 0,
                        "conclusion": "INCONCLUSIVE: REST stub has no H2 or target-send authority",
                    }
                status = (
                    "NOT_EXECUTED"
                    if actual is None
                    else "ORACLE_MISMATCH"
                    if actual["exit"] != expected["exit"]
                    else "INCONCLUSIVE"
                    if sequence_id in {"S2", "S3", "S4", "S5", "S6"}
                    else "REST_ONLY"
                )
                if step_id == "S3.7":
                    status = "ORACLE_MISMATCH"  # D08 persistence absent from the actual reply.
                if step_id == "S3.11" and actual is not None and actual["exit"] != 0:
                    status = "ORACLE_MISMATCH"
                if step_id in {"S6.8", "S6.9", "S6.10"}:
                    status = "LOCAL_LEDGER_ONLY"
                record: Obj = {
                    "sequence": sequence_id,
                    "step": step_id,
                    "seal": seal,
                    "executed_argv": cast(Json, argv if actual is not None else None),
                    "process_ref": process_ref,
                    "phase_event_range": cast(Json, list(phase_range) if phase_range else None),
                    "global_rest_event_range": cast(
                        Json,
                        [
                            cast(int, fuzz_runs[process_ref]["rest_event_start_index"]) + index
                            for index in phase_range
                        ]
                        if process_ref is not None and phase_range is not None
                        else None,
                    ),
                    "executed_action": (
                        "SELECT id, command, burp_op, status, exit_code, error_code, tag FROM ops ORDER BY rowid"
                        if step_id in {"S6.8", "S6.9", "S6.10"}
                        else None
                    ),
                    "actual": (
                        {
                            "process_ref": process_ref,
                            "phase_event_range": cast(Json, list(phase_range)),
                        }
                        if process_ref is not None and phase_range is not None
                        else actual
                    ),
                    "status": status,
                    "expected": expected,
                    "rest_effects": cast(Json, rest_effects),
                    "state_events": cast(Json, state_events[state_start:]),
                    "target_effects": cast(Json, target_effects),
                    "rest_route_count": len(rest_effects),
                    "live_target_effect_count": len(target_effects),
                    "ledger_rows": cast(Json, ledger_delta),
                    "reconciliation": reconciliation,
                    "state_owner": step["state_owner"],
                    "provenance": (
                        "local SQLite"
                        if step_id in {"S6.8", "S6.9", "S6.10"}
                        else "CLI/REST fixture; Montoya and H2 unobserved"
                    ),
                    "ordered_routes": cast(
                        Json, [[method, route] for method, route in primary_routes]
                    ),
                }
                records.append(record)
        fixture_root = fixture.root
    cleanup: Obj = {
        "fixture_root": str(fixture_root),
        "removed": not fixture_root.exists(),
        "external_target_effect_count": 0,
    }
    assert cleanup["removed"] is True
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    product_digest = hashlib.sha256()
    product_files = sorted((ROOT / "bp" / "src" / "bp").rglob("*.py")) + sorted(
        (ROOT / "src" / "main" / "kotlin").rglob("*.kt")
    )
    for source in product_files:
        product_digest.update(str(source.relative_to(ROOT)).encode())
        product_digest.update(b"\0")
        product_digest.update(source.read_bytes())
        product_digest.update(b"\0")
    output: Obj = {
        "schema": "burpctl.command-audit/sequence-observations",
        "schema_version": 2,
        "candidate_source_sha256": source_sha,
        "candidate_product_tree_sha256": product_digest.hexdigest(),
        "oracle_sha256": ORACLE_SHA,
        "sequence_count": 6,
        "step_count": len(records),
        "process_count": len(fuzz_runs),
        "processes": cast(Json, fuzz_runs),
        "executed_step_count": sum(record["actual"] is not None for record in records),
        "external_target_effect_count": 0,
        "C002": "FAIL",
        "nonexecuted_steps": [
            record["step"] for record in records if record["status"] == "NOT_EXECUTED"
        ],
        "verdict": "FAIL",
        "sequences": cast(Json, records),
    }
    data = json.dumps(output, indent=2, sort_keys=True) + "\n"
    (evidence_dir / "task-12-real-sequences.json").write_text(data, encoding="utf-8")
    (evidence_dir / "task-12-real-state.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )
    (evidence_dir / "task-12-real-processes.json").write_text(
        json.dumps(fuzz_runs, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence_dir / "task-12-real-cleanup.json").write_text(
        json.dumps(cleanup, indent=2) + "\n", encoding="utf-8"
    )
    (evidence_dir / "task-12-real-summary.json").write_text(
        json.dumps(
            {key: value for key, value in output.items() if key not in {"sequences", "processes"}},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if os.environ.get("BP_AUDIT_WRITE_OBSERVATIONS") == "1":
        OBSERVATIONS.write_text(data, encoding="utf-8")
    return records, fuzz_runs


@pytest.fixture(scope="module")
def sequence_records(tmp_path_factory: pytest.TempPathFactory) -> tuple[list[Obj], dict[str, Obj]]:
    target = Path(
        os.environ.get("BP_AUDIT_EVIDENCE_DIR", str(tmp_path_factory.mktemp("task-12-real")))
    )
    return _run_all(target)


def test_scope_session_proxy_history_scan_collab_fuzz(
    sequence_records: tuple[list[Obj], dict[str, Obj]],
) -> None:
    records, processes = sequence_records
    by_step = {str(record["step"]): record for record in records}
    assert len(records) == 50
    assert {record["sequence"] for record in records} == {
        "S1",
        "S2",
        "S3",
        "S4",
        "S5",
        "S6",
    }
    assert [record["step"] for record in records if record["actual"] is None] == ["S3.1"]
    assert all(not record["target_effects"] for record in records)
    assert all(
        record["executed_argv"] == cast(Obj, record["seal"])["argv"]
        for record in records
        if record["executed_argv"] is not None
    )
    assert all(
        record["rest_route_count"] == len(cast(list[Json], record["rest_effects"]))
        for record in records
    )
    assert all(
        record["process_ref"] is not None
        or record["actual"] is None
        or isinstance(cast(Obj, record["actual"])["stdout"], str)
        for record in records
    )
    assert [
        cast(Obj, effect)["path"]
        for record in records
        if record["step"] == "S6.5"
        for effect in cast(list[Json], record["rest_effects"])
    ] == ["/repeater/send"] * 3
    assert not any(
        "/repeater/send" in str(record["rest_effects"])
        for record in records
        if record["step"] in {"S6.8", "S6.9", "S6.10"}
    )
    for step_id, in_scope in (("S1.1", False), ("S1.3", True), ("S1.5", False)):
        actual = cast(Obj, by_step[step_id]["actual"])
        assert cast(Obj, json.loads(str(actual["stdout"])))["inScope"] is in_scope
    assert (
        cast(Obj, json.loads(str(cast(Obj, by_step["S2.3"]["actual"])["stdout"])))["name"]
        == "audit"
    )
    for record in records:
        if record["sequence"] in {"S1", "S2"}:
            events = cast(list[Json], record["state_events"])
            effects = cast(list[Json], record["rest_effects"])
            assert len(events) == len(effects) == 1
            event, effect = cast(Obj, events[0]), cast(Obj, effects[0])
            assert (event["method"], event["path"], event["body_sha256"], event["status"]) == (
                effect["method"],
                effect["path"],
                effect["body_sha256"],
                effect["status"],
            )
            if event["before"] != event["after"]:
                assert event["method"] in {"POST", "DELETE"}
                assert event["status"] == 200
    assert (
        cast(Obj, cast(list[Json], by_step["S1.2"]["state_events"])[0])["before"]
        != cast(Obj, cast(list[Json], by_step["S1.2"]["state_events"])[0])["after"]
    )
    assert (
        cast(Obj, cast(list[Json], by_step["S2.5"]["state_events"])[0])["before"]
        == cast(Obj, cast(list[Json], by_step["S2.5"]["state_events"])[0])["after"]
    )
    for process_id, process in processes.items():
        phase_ids = cast(list[str], process["phase_ids"])
        started_at_ns = int(cast(int, process["started_at_ns"]))
        assert started_at_ns < cast(int, process["completed_at_ns"])
        process_rest = cast(list[Json], process["rest"])
        process_actual = cast(Obj, process["actual"])
        assert isinstance(process_actual["stdout"], str)
        assert isinstance(process_actual["stderr"], str)
        assert {record["step"] for record in records if record["process_ref"] == process_id} == set(
            phase_ids
        )
        for phase_id in phase_ids:
            phase = by_step[phase_id]
            seal = cast(Obj, phase["seal"])
            assert int(cast(int, seal["sealed_at_ns"])) < started_at_ns
            assert phase["executed_argv"] == process["argv"] == seal["argv"]
            event_range = cast(list[int], phase["phase_event_range"])
            assert len(event_range) == 2
            assert process_rest[event_range[0] : event_range[1]] == phase["rest_effects"]
            assert phase["global_rest_event_range"] == [
                cast(int, process["rest_event_start_index"]) + index for index in event_range
            ]
            assert phase["actual"] == {"process_ref": process_id, "phase_event_range": event_range}
    assert cast(Obj, by_step["S3.11"]["actual"])["exit"] == 0
    replay = cast(Obj, json.loads(str(cast(Obj, by_step["S3.7"]["actual"])["stdout"])))
    assert "persistence" not in replay
    assert by_step["S3.7"]["status"] == "ORACLE_MISMATCH"
    for step_id, paths in (
        ("S6.1", ["/proxy/history/1"]),
        ("S6.2", ["/repeater/send"]),
        ("S6.5", ["/repeater/send"] * 3),
        ("S6.6", ["/repeater/send"] * 3),
        ("S6.7", ["/repeater/send"] * 2),
    ):
        assert [
            cast(Obj, effect)["path"]
            for effect in cast(list[Json], by_step[step_id]["rest_effects"])
        ] == paths
        assert len(cast(list[Json], by_step[step_id]["ledger_rows"])) == len(paths)
    assert [
        cast(Obj, effect)["status"] for effect in cast(list[Json], by_step["S6.6"]["rest_effects"])
    ] == [200, 400, 200]
    assert (
        len(
            {
                cast(Obj, effect)["body_sha256"]
                for effect in cast(list[Json], by_step["S6.5"]["rest_effects"])
            }
        )
        == 3
    )
    for step_id, row_count, error_code in (
        ("S6.3", 1, "TRANSPORT_ERROR"),
        ("S6.4", 1, "INVALID_RESPONSE"),
        ("S6.6", 4, "SEND_FAILED"),
        ("S6.7", 3, "TRANSPORT_ERROR"),
    ):
        actual = cast(Obj, processes[str(by_step[step_id]["process_ref"])]["actual"])
        rows = [cast(Obj, json.loads(line)) for line in str(actual["stdout"]).splitlines()]
        assert len(rows) == row_count
        assert any(row["error_code"] == error_code for row in rows)
        assert "FUZZ_PARTIAL_FAILURE" in str(actual["stderr"])
    for step_id, count, exit_code in (("S6.8", 5, 0), ("S6.9", 5, 1), ("S6.10", 4, 3)):
        record = by_step[step_id]
        assert record["rest_effects"] == []
        assert record["executed_argv"] is None
        ledger_rows = cast(
            list[Json],
            cast(Obj, json.loads(str(cast(Obj, record["actual"])["stdout"])))["ledger_rows"],
        )
        assert len(ledger_rows) == count
        assert all(cast(Obj, row)["exit_code"] == exit_code for row in ledger_rows)


def test_timeout_after_send(sequence_records: tuple[list[Obj], dict[str, Obj]]) -> None:
    records, _ = sequence_records
    replay = next(record for record in records if record["step"] == "S3.6")
    assert replay["executed_argv"] == ["bp", "history", "replay", "1", "--format", "json"]
    assert replay["rest_route_count"] == 1
    assert replay["live_target_effect_count"] == 0
    assert replay["status"] in {"INCONCLUSIVE", "ORACLE_MISMATCH"}
    reconciliation = cast(Obj, replay["reconciliation"])
    assert reconciliation["argv"] == ["bp", "history", "list", "--format", "json"]
    assert cast(Obj, reconciliation["actual"])["exit"] == 0
    assert [
        cast(Obj, effect)["path"] for effect in cast(list[Json], reconciliation["rest_effects"])
    ] == ["/history"]
    assert sum(record["step"] == "S3.6" for record in records) == 1
