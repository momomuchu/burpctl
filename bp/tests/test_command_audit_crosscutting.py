"""Installed-CLI audit of shared parsing and output contracts.

# noqa: SIZE_OK — the sealed evidence harness and its cross-cutting matrix are one audit unit.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from collections.abc import Mapping
from typing import Final, Literal, TypeAlias, assert_never

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from audit_fixture import AuditFixture, FixtureRoot
from bp.ledger import Ledger, OpRecord


CANDIDATE: Final = "3af139dc0b4020923f831099338c92af3265d7e2"
StreamMode = Literal["empty", "json", "contains", "usage", "machine_error"]
Verdict = Literal["PASS", "FAIL"]
JsonValue: TypeAlias = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class StreamOracle:
    mode: StreamMode
    json_text: str = ""
    fragments: tuple[str, ...] = ()
    program: str = ""
    error_code: str = ""


class _ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str


class _ErrorEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    error: _ErrorDetail


@dataclass(frozen=True, slots=True)
class Expected:
    exit_code: int
    stdout: StreamOracle
    stderr: StreamOracle
    routes: tuple[tuple[str, str], ...]
    ledger_delta: int
    target_delta: int = 0


@dataclass(frozen=True, slots=True)
class Observation:
    case: str
    candidate: str
    expected_at_ns: int
    actual_at_ns: int
    pre_run_seal: str
    executable: str
    argv: tuple[str, ...]
    expected: Expected
    actual_exit_code: int
    actual_stdout: str
    actual_stderr: str
    actual_routes: tuple[tuple[str, str], ...]
    actual_ledger_delta: int
    actual_target_delta: int
    checks: tuple[tuple[str, bool], ...]
    verdict: Verdict


def _ledger_count(path: Path) -> int:
    if not path.exists():
        return 0
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT COUNT(*) FROM ops").fetchone()
    assert row is not None
    return int(row[0])


def _evidence_dir(tmp_path: Path) -> Path:
    configured = os.environ.get("BP_AUDIT_EVIDENCE_DIR")
    directory = Path(configured) if configured else tmp_path / "audit-evidence"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_once(path: Path, value: Mapping[str, JsonValue]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _matches(actual: str, oracle: StreamOracle) -> bool:
    match oracle.mode:
        case "empty":
            return actual == ""
        case "json":
            try:
                parsed: JsonValue = json.loads(actual)
                expected: JsonValue = json.loads(oracle.json_text)
                return parsed == expected
            except json.JSONDecodeError:
                return False
        case "contains":
            return all(fragment in actual for fragment in oracle.fragments)
        case "usage":
            return f"Usage: {oracle.program} " in actual
        case "machine_error":
            try:
                parsed_error = _ErrorEnvelope.model_validate_json(actual)
            except ValidationError:
                return False
            return parsed_error.error.code == oracle.error_code
        case unreachable:
            assert_never(unreachable)


def _invoke(
    fixture: AuditFixture,
    tmp_path: Path,
    case: str,
    argv: tuple[str, ...],
    expected: Expected,
    *,
    executable: str = "bp",
) -> Observation:
    before = fixture.snapshot()
    ledger_before = _ledger_count(fixture.manifest.ledger_path)
    expected_at_ns = time.time_ns()
    full_argv = tuple([*fixture.command(executable), *argv])
    environment: dict[str, JsonValue] = {
        "HOME": str(fixture.manifest.home),
        "BURP_REST_URL": fixture.manifest.rest_url,
        "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
        "BP_CONFIG_PATH": str(fixture.manifest.config_path),
        "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
        "BP_AGENT": "1",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    pre_run: dict[str, JsonValue] = {
        "case": case,
        "candidate": CANDIDATE,
        "expected_at_ns": expected_at_ns,
        "executable": executable,
        "argv": list(full_argv),
        "environment": environment,
        "expected": json.dumps(asdict(expected), separators=(",", ":"), sort_keys=True),
        "prestate": json.dumps(asdict(before), separators=(",", ":"), sort_keys=True),
    }
    canonical = json.dumps(pre_run, separators=(",", ":"), sort_keys=True).encode()
    pre_run_seal = hashlib.sha256(canonical).hexdigest()
    pre_run["pre_run_seal"] = pre_run_seal
    sequence = f"{expected_at_ns}-{case}-{executable}"
    _write_once(_evidence_dir(tmp_path) / f"task-crosscutting-{sequence}-expected.json", pre_run)

    result = fixture.run(argv, executable=executable)
    actual_at_ns = time.time_ns()
    after = fixture.snapshot()
    routes = tuple(
        (effect.method, effect.path) for effect in after.rest_effects[len(before.rest_effects) :]
    )
    target_delta = len(after.target_effects) - len(before.target_effects)
    ledger_delta = _ledger_count(fixture.manifest.ledger_path) - ledger_before
    checks = (
        ("exit", result.returncode == expected.exit_code),
        ("stdout", _matches(result.stdout, expected.stdout)),
        ("stderr", _matches(result.stderr, expected.stderr)),
        ("route", routes == expected.routes),
        ("ledger", ledger_delta == expected.ledger_delta),
        ("target", target_delta == expected.target_delta),
    )
    verdict: Verdict = "PASS" if all(passed for _, passed in checks) else "FAIL"
    observation = Observation(
        case=case,
        candidate=CANDIDATE,
        expected_at_ns=expected_at_ns,
        actual_at_ns=actual_at_ns,
        pre_run_seal=pre_run_seal,
        executable=executable,
        argv=full_argv,
        expected=expected,
        actual_exit_code=result.returncode,
        actual_stdout=result.stdout,
        actual_stderr=result.stderr,
        actual_routes=routes,
        actual_ledger_delta=ledger_delta,
        actual_target_delta=target_delta,
        checks=checks,
        verdict=verdict,
    )
    actual_path = _evidence_dir(tmp_path) / f"task-crosscutting-{sequence}-actual.json"
    descriptor = os.open(actual_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(asdict(observation), stream, indent=2, sort_keys=True)
        stream.write("\n")
    return observation


def _health_json() -> StreamOracle:
    return StreamOracle(
        "json",
        json_text=json.dumps(
            {"status": "ok", "version": "fixture", "uptime": 1, "burpVersion": None}
        ),
    )


def _envelope(data: dict[str, str]) -> bytes:
    return json.dumps({"success": True, "data": data, "error": None}).encode()


@pytest.mark.parametrize(
    "case,argv",
    [
        ("format-before-command", ("--format", "json", "--no-ledger", "health")),
        ("format-after-command", ("health", "--format", "json", "--no-ledger")),
    ],
)
def test_json_format_is_position_tolerant(case: str, argv: tuple[str, ...], tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = Expected(0, _health_json(), StreamOracle("empty"), (("GET", "/health"),), 0)
        assert _invoke(fixture, tmp_path, case, argv, expected).verdict == "PASS"


def test_agent_default_yields_to_explicit_table(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        implicit = Expected(0, _health_json(), StreamOracle("empty"), (("GET", "/health"),), 0)
        explicit = Expected(
            0,
            StreamOracle("contains", fragments=("STATUS", "ok", "VERSION", "fixture")),
            StreamOracle("empty"),
            (("GET", "/health"),),
            0,
        )
        assert (
            _invoke(
                fixture, tmp_path, "agent-json-default", ("health", "--no-ledger"), implicit
            ).verdict
            == "PASS"
        )
        observed = _invoke(
            fixture,
            tmp_path,
            "explicit-table-over-agent",
            ("--format", "table", "--no-ledger", "health"),
            explicit,
        )
        assert observed.verdict == "PASS"
        assert not observed.actual_stdout.lstrip().startswith("{")


def test_hoisting_stops_at_delimiter(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = Expected(2, StreamOracle("empty"), StreamOracle("usage", program="bp"), (), 0)
        assert (
            _invoke(
                fixture,
                tmp_path,
                "delimiter-stops-hoist",
                ("health", "--", "--format", "json"),
                expected,
            ).verdict
            == "PASS"
        )


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_aliases(flag: str, tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = Expected(0, StreamOracle("usage", program="bp"), StreamOracle("empty"), (), 0)
        assert (
            _invoke(fixture, tmp_path, f"help-{flag.lstrip('-')}", (flag,), expected).verdict
            == "PASS"
        )


def test_invalid_format_exposes_machine_error_regression(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = Expected(
            2,
            StreamOracle("empty"),
            StreamOracle("machine_error", error_code="USAGE_ERROR"),
            (),
            0,
        )
        observed = _invoke(
            fixture,
            tmp_path,
            "invalid-format-machine-error",
            ("health", "--format", "yaml"),
            expected,
        )
        assert observed.actual_exit_code == 2
        assert observed.verdict == "FAIL"
        assert "Usage: bp" in observed.actual_stderr


def test_raw_is_unavailable_for_structured_health(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = Expected(
            2,
            StreamOracle("empty"),
            StreamOracle("contains", fragments=("error:", "raw requires", "structured")),
            (("GET", "/health"),),
            0,
        )
        assert (
            _invoke(
                fixture,
                tmp_path,
                "raw-structured-unavailable",
                ("health", "--format", "raw", "--no-ledger"),
                expected,
            ).verdict
            == "PASS"
        )


def test_fields_redaction_and_no_ledger_share_one_output_contract(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        with Ledger(fixture.manifest.ledger_path) as ledger:
            ledger.record(OpRecord(status="ok", command="seed"))
        fixture.add_rest_route(
            "GET",
            "/config/project",
            body=_envelope({"status": "ok", "Authorization": "Bearer crosscutting-secret"}),
        )
        expected = Expected(
            0,
            StreamOracle("json", json_text='{"Authorization":"***","status":"ok"}'),
            StreamOracle("empty"),
            (("GET", "/config/project"),),
            0,
        )
        observed = _invoke(
            fixture,
            tmp_path,
            "fields-redaction-no-ledger",
            (
                "config",
                "get",
                "project",
                "--fields",
                "authorization,status",
                "--format",
                "json",
                "--no-ledger",
            ),
            expected,
        )
        assert observed.verdict == "PASS"
        assert "crosscutting-secret" not in observed.actual_stdout


@pytest.mark.parametrize("executable", ["bp", "burpctl"])
def test_unknown_command_usage_keeps_invoked_alias(executable: str, tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        expected = Expected(
            2,
            StreamOracle("empty"),
            StreamOracle("usage", program=executable),
            (),
            0,
        )
        observed = _invoke(
            fixture,
            tmp_path,
            "unknown-command-usage",
            ("missing-crosscutting-command",),
            expected,
            executable=executable,
        )
        assert observed.verdict == "PASS"
        assert "No such command" in observed.actual_stderr
