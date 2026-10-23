"""Installed-CLI audit for flat commands that can trigger downstream effects."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypeAlias, assert_never, cast

from audit_fixture import AuditFixture, FixtureRoot, RequestEffect, UnsafeTargetError

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | Sequence["JsonValue"] | Mapping[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
StreamRule: TypeAlias = Literal["empty", "json", "typed-json", "note"]
OracleCase: TypeAlias = Literal["normal", "contrast"]

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
ORACLE_MANIFEST = Path(__file__).resolve().parents[2] / "quality" / "command-audit" / "oracles.json"
INTEGRATION_LIMITED = {
    ("F04", "normal"),
    ("F07", "normal"),
    ("F08", "normal"),
    ("F08", "contrast"),
    ("F09", "normal"),
    ("F09", "contrast"),
    ("F15", "normal"),
    ("F16", "normal"),
    ("F16", "contrast"),
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
    oracle_case: OracleCase | None = None


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


def _oracle_case(case: Case) -> OracleCase | None:
    if case.oracle_case is not None:
        return case.oracle_case
    if case.variant in ("normal", "contrast"):
        return cast(OracleCase, case.variant)
    return None


def _manifest_expected(case: Case) -> JsonObject | None:
    oracle_case = _oracle_case(case)
    if oracle_case is None:
        return None
    manifest = json.loads(ORACLE_MANIFEST.read_text(encoding="utf-8"))
    row = next(item for item in manifest["rows"] if item["id"] == case.feature)
    assert row["seal"]["hash"] == ORACLE_HASHES[case.feature]
    source = row["expected"] if oracle_case == "normal" else row["contrast"]
    return {
        "exit": source["exit"],
        "stdout": source["stdout"],
        "stderr": source["stderr"],
        "effect": source["effect"],
    }


def _manifest_stream_rule(value: JsonValue) -> StreamRule:
    assert isinstance(value, Mapping)
    mode = value.get("mode")
    shape = value.get("shape")
    if mode == "empty":
        return "empty"
    if mode == "json" and shape == "typed_error":
        return "typed-json"
    if mode == "json":
        return "json"
    raise AssertionError(f"unsupported manifest stream: {value!r}")


def _route_matches_manifest(route: str, rest: tuple[tuple[str, str, int], ...]) -> bool:
    if route == "none":
        return not rest
    observed = {(method, path.split("?", 1)[0]) for method, path, _status in rest}
    for part in route.split(";"):
        method, path = part.strip().split(" ", 1)
        if not any(
            actual_method == method and actual_path.startswith(path)
            for actual_method, actual_path in observed
        ):
            return False
    return True


def _oracle_comparison(case: Case, manifest_expected: JsonObject | None) -> JsonObject:
    if manifest_expected is None:
        return {"applicable": False, "classification": "SUPPLEMENTAL_NOT_ORACLE_CASE"}
    effect = manifest_expected["effect"]
    assert isinstance(effect, Mapping)
    route = effect.get("route")
    assert isinstance(route, str)
    comparison: JsonObject = {
        "exit": case.expected.exit == manifest_expected["exit"],
        "stdout": case.expected.stdout == _manifest_stream_rule(manifest_expected["stdout"]),
        "stderr": case.expected.stderr == _manifest_stream_rule(manifest_expected["stderr"]),
        "route": _route_matches_manifest(route, case.expected.rest),
    }
    mismatch = not all(value is True for value in comparison.values())
    oracle_case = _oracle_case(case)
    integration_limited = (case.feature, oracle_case) in INTEGRATION_LIMITED
    classification = (
        "ORACLE_MISMATCH" if mismatch else "INTEGRATION_LIMIT" if integration_limited else "ALIGNED"
    )
    comparison["applicable"] = True
    comparison["classification"] = classification
    return comparison


def _resolved_verdict(comparison: Mapping[str, bool], oracle_classification: JsonValue) -> str:
    if not all(comparison.values()):
        return "FAIL"
    if oracle_classification in {"ORACLE_MISMATCH", "INTEGRATION_LIMIT"}:
        assert isinstance(oracle_classification, str)
        return oracle_classification
    return "PASS"


def _pre_run(fixture: AuditFixture, case: Case) -> tuple[JsonObject, str]:
    before = fixture.snapshot()
    timestamp = datetime.now(timezone.utc).isoformat()
    manifest_expected = _manifest_expected(case)
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
        "oracleCase": _oracle_case(case) or "SUPPLEMENTAL",
        "manifestExpected": manifest_expected,
        "oracleComparison": _oracle_comparison(case, manifest_expected),
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
    return pre_run, stem


def _invoke(fixture: AuditFixture, case: Case) -> JsonObject:
    before = fixture.snapshot()
    ledger_before = _ledger_count(fixture.manifest.ledger_path)
    pre_run, stem = _pre_run(fixture, case)

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
    oracle_comparison = pre_run["oracleComparison"]
    assert isinstance(oracle_comparison, Mapping)
    oracle_classification = oracle_comparison["classification"]
    observation["verdict"] = _resolved_verdict(comparison, oracle_classification)
    _write_evidence(f"{stem}-actual.json", observation)
    return observation


def _invoke_safety_limited(fixture: AuditFixture, case: Case) -> JsonObject:
    before = fixture.snapshot()
    ledger_before = _ledger_count(fixture.manifest.ledger_path)
    pre_run, stem = _pre_run(fixture, case)
    try:
        fixture.run(case.argv, executable="bp")
    except UnsafeTargetError as exc:
        after = fixture.snapshot()
        actual: JsonObject = {
            "observedAt": datetime.now(timezone.utc).isoformat(),
            "subprocessStarted": False,
            "safetyError": str(exc),
            "exit": None,
            "stdout": "",
            "stderr": "",
            "rest": _effect_rows(after.rest_effects[len(before.rest_effects) :]),
            "target": _effect_rows(after.target_effects[len(before.target_effects) :]),
            "ledgerDelta": _ledger_count(fixture.manifest.ledger_path) - ledger_before,
        }
    else:
        raise AssertionError("fixture allowed a non-loopback target subprocess")
    observation: JsonObject = dict(pre_run)
    observation["actual"] = actual
    observation["comparison"] = {"safetyPreflight": True, "zeroEffects": True}
    observation["verdict"] = "SAFETY_LIMITED"
    _write_evidence(f"{stem}-actual.json", observation)
    return observation


def _guarded_diff_data_only(fixture: AuditFixture, external: str, loopback: str) -> JsonObject:
    guard_dir = fixture.root / "process-network-guard"
    guard_dir.mkdir(mode=0o700)
    trace = guard_dir / "trace.jsonl"
    profile = guard_dir / "network.sb"
    sitecustomize = guard_dir / "sitecustomize.py"
    rest_port = fixture.manifest.rest_url.rsplit(":", 1)[1]
    profile_text = "\n".join(
        (
            "(version 1)",
            "(allow default)",
            "(deny network*)",
            f'(allow network-outbound (remote tcp "localhost:{rest_port}"))',
            "",
        )
    )
    guard_text = '''import json
import os
import socket

_HOST = os.environ["BP_GUARD_HOST"]
_PORT = int(os.environ["BP_GUARD_PORT"])
_TRACE = os.environ["BP_GUARD_TRACE"]
_getaddrinfo = socket.getaddrinfo
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex

def _host(value):
    return value.decode("ascii") if isinstance(value, bytes) else str(value)

def _record(event, host, port):
    with open(_TRACE, "a", encoding="utf-8") as output:
        output.write(json.dumps({"event": event, "host": _host(host), "port": port}, sort_keys=True) + "\\n")

def _allowed(host, port):
    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        return False
    return _host(host) == _HOST and normalized_port == _PORT

def guarded_getaddrinfo(host, port, *args, **kwargs):
    if not _allowed(host, port):
        _record("DENY_DNS", host, port)
        raise PermissionError(1, "network guard denied DNS")
    _record("ALLOW_RESOLVE", host, port)
    return _getaddrinfo(host, port, *args, **kwargs)

def guarded_connect(sock, address):
    if not isinstance(address, tuple) or len(address) < 2 or not _allowed(address[0], address[1]):
        host, port = address[:2] if isinstance(address, tuple) and len(address) >= 2 else (address, None)
        _record("DENY_CONNECT", host, port)
        raise PermissionError(1, "network guard denied connection")
    _record("ALLOW_CONNECT", address[0], address[1])
    return _connect(sock, address)

def guarded_connect_ex(sock, address):
    if not isinstance(address, tuple) or len(address) < 2 or not _allowed(address[0], address[1]):
        host, port = address[:2] if isinstance(address, tuple) and len(address) >= 2 else (address, None)
        _record("DENY_CONNECT_EX", host, port)
        return 1
    _record("ALLOW_CONNECT_EX", address[0], address[1])
    return _connect_ex(sock, address)

socket.getaddrinfo = guarded_getaddrinfo
socket.socket.connect = guarded_connect
socket.socket.connect_ex = guarded_connect_ex
_record("GUARD_LOADED", _HOST, _PORT)
'''
    profile.write_text(profile_text, encoding="utf-8")
    sitecustomize.write_text(guard_text, encoding="utf-8")
    cli = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "bp"
    python = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    argv = ["/usr/bin/sandbox-exec", "-f", str(profile), str(cli), "diff", external, loopback]
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(fixture.manifest.home),
            "BURP_REST_URL": fixture.manifest.rest_url,
            "BP_LEDGER_PATH": str(fixture.manifest.ledger_path),
            "BP_CONFIG_PATH": str(fixture.manifest.config_path),
            "BP_PAYLOAD_DIR": str(fixture.manifest.payload_dir),
            "BP_AGENT": "1",
            "NO_COLOR": "1",
            "TERM": "dumb",
            "PYTHONPATH": str(guard_dir),
            "BP_GUARD_HOST": "127.0.0.1",
            "BP_GUARD_PORT": rest_port,
            "BP_GUARD_TRACE": str(trace),
        }
    )
    before = fixture.snapshot()
    ledger_before = _ledger_count(fixture.manifest.ledger_path)
    pre_run: JsonObject = {
        "id": "F15",
        "variant": "manifest-contrast-guarded-data-only",
        "candidate": os.environ.get("BP_AUDIT_CANDIDATE", "3af139dc0b4020923f831099338c92af3265d7e2"),
        "oracleHash": ORACLE_HASHES["F15"],
        "oracleCase": "contrast",
        "preRunSeal": datetime.now(timezone.utc).isoformat(),
        "manifestArgv": ["bp", "diff", external, loopback],
        "argv": argv,
        "env": {key: env[key] for key in ("HOME", "BURP_REST_URL", "BP_LEDGER_PATH", "BP_AGENT", "PYTHONPATH", "BP_GUARD_HOST", "BP_GUARD_PORT", "BP_GUARD_TRACE")},
        "networkGuard": {
            "sandboxProfile": profile_text,
            "sandboxProfileSha256": hashlib.sha256(profile_text.encode()).hexdigest(),
            "sitecustomizeSha256": hashlib.sha256(guard_text.encode()).hexdigest(),
            "allowed": f"127.0.0.1:{rest_port}",
            "denied": "all other network and external DNS",
        },
        "prestate": {"rest": _effect_rows(before.rest_effects), "target": _effect_rows(before.target_effects)},
        "expected": {
            "exit": 2,
            "stdout": "empty",
            "stderr": "typed-json",
            "rest": [],
            "target_count": 0,
            "ledger_delta": 0,
            "target_effect": "original manifest non-loopback usage rejection",
        },
    }
    seal_input = json.dumps(pre_run, sort_keys=True, separators=(",", ":")).encode()
    pre_run["sealSha256"] = hashlib.sha256(seal_input).hexdigest()
    prefix = os.environ.get("BP_AUDIT_RUN_ID", "local")
    stem = f"task-7-{prefix}-F15-manifest-contrast-guarded-data-only"
    _write_evidence(f"{stem}-expected.json", pre_run)

    result = subprocess.run(argv, env=env, capture_output=True, text=True, check=False)
    after_cli = fixture.snapshot()
    cli_trace = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    target_port = fixture.manifest.target_url.rsplit(":", 1)[1]
    os_probe_code = "\n".join(
        (
            "import socket",
            "s = socket.socket(); s.settimeout(0.2)",
            f"try: s.connect(('127.0.0.1', {target_port}))",
            "except PermissionError as error: print(f'DENIED:{error.errno}')",
            "else: raise SystemExit('sandbox unexpectedly allowed target socket')",
        )
    )
    os_probe = subprocess.run(
        ["/usr/bin/sandbox-exec", "-f", str(profile), str(python), "-S", "-c", os_probe_code],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    dns_probe = subprocess.run(
        ["/usr/bin/sandbox-exec", "-f", str(profile), str(python), "-c", "import socket; socket.getaddrinfo('example.invalid', 443)"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    full_trace = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    after_probes = fixture.snapshot()
    rest_delta = after_cli.rest_effects[len(before.rest_effects) :]
    target_delta = after_cli.target_effects[len(before.target_effects) :]
    actual: JsonObject = {
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "exit": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "REST log": _effect_rows(rest_delta),
        "target log": _effect_rows(target_delta),
        "ledgerDelta": _ledger_count(fixture.manifest.ledger_path) - ledger_before,
        "CLI guard trace": cli_trace,
        "DNS guard probe": {"exit": dns_probe.returncode, "stdout": dns_probe.stdout, "stderr": dns_probe.stderr},
        "OS sandbox target probe": {"exit": os_probe.returncode, "stdout": os_probe.stdout, "stderr": os_probe.stderr},
        "full guard trace": full_trace,
        "postProbeTargetLog": _effect_rows(after_probes.target_effects[len(before.target_effects) :]),
    }
    observation: JsonObject = dict(pre_run)
    observation["actual"] = actual
    observation["verdict"] = "ORACLE_MISMATCH"
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
            ),
            "ORACLE_MISMATCH",
        )


def test_local_expected_override_cannot_pass_original_oracle() -> None:
    case = Case(
        "F05",
        "contrast",
        ("req", "99"),
        Expected(
            1, "empty", "typed-json", (("GET", "/proxy/history/99", 404),), 0, 1, "missing ID"
        ),
    )
    comparison = _oracle_comparison(case, _manifest_expected(case))
    assert comparison["classification"] == "ORACLE_MISMATCH"
    assert (
        _resolved_verdict({"localExpected": True}, comparison["classification"])
        == "ORACLE_MISMATCH"
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
        _assert_verdict(_invoke(fixture, case), "INTEGRATION_LIMIT")


def test_fuzz_manifest_missing_payload_file(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        missing = fixture.manifest.payload_dir / "manifest-missing.txt"
        case = Case(
            "F04",
            "manifest-contrast",
            ("fuzz", "0", "--pos", "query:id", "--payloads", f"id={missing}", "--type", "sniper"),
            Expected(
                2, "empty", "typed-json", (), 0, 0, "manifest missing-file preflight; zero effects"
            ),
            oracle_case="contrast",
        )
        observation = _invoke(fixture, case)
        _assert_verdict(observation, "FAIL")
        assert observation["oracleComparison"] == {
            "exit": True,
            "stdout": True,
            "stderr": True,
            "route": True,
            "applicable": True,
            "classification": "ALIGNED",
        }


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
            ),
            "INTEGRATION_LIMIT",
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
        _assert_verdict(_invoke(fixture, normal), "INTEGRATION_LIMIT")
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
        _assert_verdict(_invoke(fixture, contrast), "ORACLE_MISMATCH")


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
        _assert_verdict(_invoke(fixture, normal), "INTEGRATION_LIMIT")
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
        _assert_verdict(_invoke(fixture, contrast), "ORACLE_MISMATCH")


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


def test_diff_manifest_non_loopback_target_is_safety_limited(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        loopback = f"{fixture.manifest.target_url}/b"
        case = Case(
            "F15",
            "manifest-contrast",
            ("diff", "https://example.invalid/a", loopback),
            Expected(
                2,
                "empty",
                "typed-json",
                (),
                0,
                0,
                "fixture rejects unsafe target before subprocess",
            ),
            oracle_case="contrast",
        )
        observation = _invoke_safety_limited(fixture, case)
        _assert_verdict(observation, "SAFETY_LIMITED")
        actual = observation["actual"]
        assert isinstance(actual, Mapping)
        assert actual["subprocessStarted"] is False
        assert actual["rest"] == [] and actual["target"] == [] and actual["ledgerDelta"] == 0


def test_diff_manifest_non_loopback_is_guarded_data_only(tmp_path: Path) -> None:
    with FixtureRoot(tmp_path) as fixture:
        external = "https://example.invalid/a"
        loopback = f"{fixture.manifest.target_url}/b"
        fixture.expect_rest_route(
            "POST",
            "/utils/diff",
            expected_body=_json_body(
                {"a": {"url": external, "method": "GET"}, "b": {"url": loopback, "method": "GET"}}
            ),
            status=400,
            body=_error("INVALID_REQUEST", "non-loopback target denied"),
        )
        observation = _guarded_diff_data_only(fixture, external, loopback)
        _assert_verdict(observation, "ORACLE_MISMATCH")
        actual = observation["actual"]
        assert isinstance(actual, Mapping)
        assert actual["exit"] == 1 and actual["stdout"] == "" and actual["ledgerDelta"] == 1
        assert isinstance(actual["stderr"], str) and actual["stderr"].startswith("note:")
        assert isinstance(actual["REST log"], Sequence) and len(actual["REST log"]) == 1
        assert actual["target log"] == [] and actual["postProbeTargetLog"] == []
        cli_trace = actual["CLI guard trace"]
        assert isinstance(cli_trace, Sequence)
        events = [item["event"] for item in cli_trace if isinstance(item, Mapping)]
        assert "GUARD_LOADED" in events and "ALLOW_CONNECT" in events
        assert not any("DENY" in str(event) for event in events)
        dns_probe = actual["DNS guard probe"]
        os_probe = actual["OS sandbox target probe"]
        assert isinstance(dns_probe, Mapping) and dns_probe["exit"] != 0
        assert "network guard denied DNS" in str(dns_probe["stderr"])
        assert isinstance(os_probe, Mapping) and os_probe["exit"] == 0
        assert os_probe["stdout"] == "DENIED:1\n"


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
        _assert_verdict(_invoke(fixture, normal), "INTEGRATION_LIMIT")
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
        _assert_verdict(_invoke(fixture, contrast), "ORACLE_MISMATCH")
