#!/usr/bin/env python3
"""Live release verification for the shipped Burp REST extension and bp CLI.

The suite is deliberately dependency-free. It owns two loopback targets, records one
structured result per case, and refuses to treat an unattributable or empty run as clean.
"""

from __future__ import annotations

import argparse
import ast
import base64
import dataclasses
import datetime as dt
import hashlib
import http.client
import http.server
import io
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
import tomllib
import traceback
import urllib.parse
import uuid
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VERIFY_ROOT = ROOT / "verify"
RESULTS_ROOT = VERIFY_ROOT / "results"
RELEASE_FIXTURE = VERIFY_ROOT / "fixtures" / "release-artifact.json"
OPENAPI_PATH = ROOT / "src" / "main" / "resources" / "openapi.json"
ALLOWED_DISPOSITIONS = {"released", "held", "spent", "contaminated", "unknown"}
BEHAVIOR_GROUPS = {"rest", "cli"}
SOURCE_ALIGNMENT_DEPENDENT_CASES = {
    "REST-003": "live OpenAPI publication cannot be judged because the deployed JAR embeds the pre-change contract",
    "REST-005": "deployed binary predates the current decoder implementation and contract",
    "REST-006": "deployed binary predates the current decoder implementation and contract",
    "REST-007": "deployed binary predates the current decoder implementation and contract",
}


class VerificationFailure(AssertionError):
    """The observed behavior does not establish the case invariant."""


class MissingPrecondition(RuntimeError):
    """The case could not execute because a named precondition was absent."""


class CustodyUnknown(RuntimeError):
    """A touched mutable resource could not be authoritatively restored."""


@dataclasses.dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes
    json: Any


@dataclasses.dataclass(frozen=True)
class CaseDef:
    case_id: str
    group: str
    layer: str
    invariant: str
    assertion: str
    resources: tuple[str, ...]
    fn: Callable[["RunContext", "CaseContext"], dict[str, Any]]


@dataclasses.dataclass
class CaseContext:
    dispositions: dict[str, dict[str, str]]

    def set_resource(self, name: str, status: str, detail: str) -> None:
        if status not in ALLOWED_DISPOSITIONS:
            raise ValueError(f"invalid resource disposition: {status}")
        self.dispositions[name] = {"status": status, "detail": detail}


@dataclasses.dataclass
class TargetState:
    name: str
    requested_port: int
    server: http.server.ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None
    actual_port: int | None = None
    disposition: str = "unknown"
    detail: str = "not started"


@dataclasses.dataclass
class RunContext:
    run_id: str
    api_url: str
    timeout: float
    marker: str
    expected_hash: str
    expected_extension_name: str
    exclusive_extension_custody: bool
    versions: dict[str, str]
    expected_version: str | None
    binary: dict[str, Any]
    repository: dict[str, Any]
    targets: dict[str, TargetState]
    work_dir: Path
    bp_path: Path
    uptime_samples: list[dict[str, Any]]
    containment_reason: str | None = None

    def target_url(self, name: str, path: str = "") -> str:
        target = self.targets[name]
        if target.actual_port is None or target.server is None:
            raise MissingPrecondition(f"harness-owned target {name} is not listening")
        return f"http://127.0.0.1:{target.actual_port}{path}"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_file_snapshot(path: Path) -> tuple[bytes, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    require(identity_before == identity_after, f"file changed while being read: {path}")
    content = b"".join(chunks)
    require(len(content) == before.st_size, f"short read while measuring file: {path}")
    return content, {
        "sha256": digest.hexdigest(),
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
    }


def sha256_file_snapshot(path: Path) -> dict[str, Any]:
    _content, snapshot = read_file_snapshot(path)
    return snapshot


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationFailure(message)


def compact_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def json_safe_error(exc: BaseException) -> dict[str, str]:
    return {"type": type(exc).__name__, "message": str(exc)}


def require_expected_hash(value: str) -> str:
    normalized = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
        raise argparse.ArgumentTypeError("expected JAR SHA-256 must be exactly 64 hexadecimal characters")
    return normalized


def require_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("target port must be an integer") from exc
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("target port must be between 1024 and 65535")
    return port


def request_http(
    base_url: str,
    method: str,
    path: str,
    *,
    body: Any = None,
    raw_body: bytes | None = None,
    content_type: str | None = "application/json",
    timeout: float = 10.0,
) -> HttpResult:
    if body is not None and raw_body is not None:
        raise ValueError("body and raw_body are mutually exclusive")
    payload = raw_body
    if body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Accept": "application/json", "Connection": "close"}
    if payload is not None and content_type is not None:
        headers["Content-Type"] = content_type
    parsed_base = urllib.parse.urlparse(base_url)
    require(parsed_base.scheme == "http" and parsed_base.hostname is not None, "HTTP base URL is invalid")
    request_path = "/" + path.lstrip("/")
    connection = http.client.HTTPConnection(parsed_base.hostname, parsed_base.port, timeout=timeout)
    try:
        connection.request(method, request_path, body=payload, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        result_headers = {key.lower(): value for key, value in response.getheaders()}
        parsed: Any = None
        if response_body:
            try:
                parsed = json.loads(response_body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                parsed = None
        return HttpResult(int(response.status), result_headers, response_body, parsed)
    finally:
        connection.close()


def require_success_envelope(result: HttpResult) -> dict[str, Any]:
    require(result.status == 200, f"expected HTTP 200, observed {result.status}")
    require(isinstance(result.json, dict), "response was not a JSON object")
    require(set(result.json) == {"success", "data", "error"}, "response envelope keys differ")
    require(result.json["success"] is True, "success envelope did not report true")
    require(result.json["error"] is None, "success envelope carried a non-null error")
    require(isinstance(result.json["data"], dict), "success envelope data was not an object")
    return result.json["data"]


def require_error_envelope(result: HttpResult) -> dict[str, Any]:
    require(400 <= result.status < 600, f"expected error HTTP status, observed {result.status}")
    require(isinstance(result.json, dict), "error response was not a JSON object")
    require(set(result.json) == {"success", "data", "error"}, "error envelope keys differ")
    require(result.json["success"] is False, "error envelope did not report false")
    require(result.json["data"] is None, "error envelope carried non-null data")
    error = result.json["error"]
    require(isinstance(error, dict), "error envelope error was not an object")
    require(isinstance(error.get("code"), str) and bool(error["code"]), "error code absent")
    require(isinstance(error.get("message"), str) and bool(error["message"]), "error message absent")
    return error


def api(ctx: RunContext, method: str, path: str, **kwargs: Any) -> HttpResult:
    return request_http(ctx.api_url, method, path, timeout=ctx.timeout, **kwargs)


def parse_json_without_duplicates(raw: bytes, source: str) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise VerificationFailure(f"{source} contains duplicate JSON member {key!r}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def derive_versions() -> dict[str, str]:
    sources: dict[str, str] = {}
    with (ROOT / "bp" / "pyproject.toml").open("rb") as handle:
        pyproject_version = tomllib.load(handle)["project"]["version"]
    require(isinstance(pyproject_version, str) and bool(pyproject_version), "pyproject version is not a non-empty string")
    sources["bp/pyproject.toml"] = pyproject_version

    init_tree = ast.parse((ROOT / "bp" / "src" / "bp" / "__init__.py").read_text("utf-8"))
    init_versions: list[str] = []
    for node in init_tree.body:
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "__version__" for target in targets):
                init_versions.append(node.value.value)
    require(len(init_versions) == 1, f"bp/src/bp/__init__.py contains {len(init_versions)} literal module-level __version__ assignments")
    sources["bp/src/bp/__init__.py"] = init_versions[0]

    with (ROOT / "bp" / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    lock_matches = [
        item
        for item in lock.get("package", [])
        if item.get("name") == "bp" and item.get("source", {}).get("editable") == "."
    ]
    require(len(lock_matches) == 1, f"uv.lock contains {len(lock_matches)} editable bp package entries")
    require(isinstance(lock_matches[0].get("version"), str), "uv.lock bp version is not a string")
    sources["bp/uv.lock"] = lock_matches[0]["version"]

    gradle_text = (ROOT / "build.gradle.kts").read_text("utf-8")
    gradle_versions = re.findall(r'^version = "([^"]+)"$', gradle_text, re.MULTILINE)
    require(len(gradle_versions) == 1, f"build.gradle.kts contains {len(gradle_versions)} literal top-level versions")
    sources["build.gradle.kts"] = gradle_versions[0]

    identity_text = (
        ROOT / "src" / "main" / "kotlin" / "com" / "burprest" / "BuildIdentity.kt"
    ).read_text("utf-8")
    identity_versions = re.findall(
        r'^const val EXTENSION_VERSION: String = "([^"]+)"$', identity_text, re.MULTILINE
    )
    require(len(identity_versions) == 1, f"BuildIdentity.kt contains {len(identity_versions)} literal EXTENSION_VERSION declarations")
    sources["BuildIdentity.kt"] = identity_versions[0]

    openapi = parse_json_without_duplicates(OPENAPI_PATH.read_bytes(), "openapi.json")
    openapi_version = openapi.get("info", {}).get("version")
    require(isinstance(openapi_version, str), "openapi.json info.version is not a string")
    sources["openapi.json"] = openapi_version

    for source, version in sources.items():
        require(re.fullmatch(r"\d+\.\d+\.\d+", version) is not None, f"{source} has non-release version {version!r}")
    return sources


def command_output(args: list[str], timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)


def file_manifest(paths: list[Path]) -> tuple[dict[str, str], str]:
    unique = sorted({path.resolve() for path in paths if path.is_file()})
    manifest = {str(path.relative_to(ROOT)): sha256_file(path) for path in unique}
    aggregate = sha256_bytes(
        "".join(f"{name}\0{digest}\n" for name, digest in manifest.items()).encode("utf-8")
    )
    return manifest, aggregate


def git_repository_state() -> dict[str, Any]:
    commit = command_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip()
    status = command_output(["git", "-C", str(ROOT), "status", "--porcelain=v1"]).stdout.splitlines()
    cli_paths = list((ROOT / "bp" / "src" / "bp").rglob("*.py"))
    cli_manifest, cli_aggregate = file_manifest(cli_paths)
    release_paths = (
        list((ROOT / "src" / "main").rglob("*"))
        + cli_paths
        + [ROOT / "bp" / "pyproject.toml", ROOT / "bp" / "uv.lock", ROOT / "build.gradle.kts"]
    )
    release_manifest, release_aggregate = file_manifest(release_paths)
    docs_paths = [ROOT / "README.md", ROOT / "bp" / "README.md"] + list((ROOT / "docs").rglob("*.md"))
    _docs_manifest, docs_aggregate = file_manifest(docs_paths)
    return {
        "git_commit": commit,
        "worktree_dirty": bool(status),
        "status_paths": [re.sub(r"^.. ", "", line) for line in status],
        "cli_source_sha256": cli_aggregate,
        "cli_source_files": cli_manifest,
        "release_source_sha256": release_aggregate,
        "release_source_file_count": len(release_manifest),
        "documentation_sha256": docs_aggregate,
        "documentation_file_count": len(_docs_manifest),
        "bp_launcher_sha256": (
            sha256_file(ROOT / "bp" / ".venv" / "bin" / "bp")
            if (ROOT / "bp" / ".venv" / "bin" / "bp").is_file()
            else None
        ),
        "verifier_sha256": sha256_file(Path(__file__).resolve()),
        "verifier_fixture_sha256": sha256_file(RELEASE_FIXTURE),
    }


def parse_option(command: str, option: str) -> str | None:
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    for index, word in enumerate(words):
        if word == option and index + 1 < len(words):
            return words[index + 1]
        prefix = option + "="
        if word.startswith(prefix):
            return word[len(prefix) :]
    return None


def listener_pid(port: int) -> int:
    result = command_output(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fp", "-Fn"], timeout=5
    )
    pids = {int(line[1:]) for line in result.stdout.splitlines() if re.fullmatch(r"p\d+", line)}
    if len(pids) != 1:
        raise VerificationFailure(f"expected one listener PID on {port}, observed {sorted(pids)}")
    return next(iter(pids))


def validate_api_url(api_url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(api_url)
    require(parsed.hostname == "127.0.0.1", "API URL is not literal 127.0.0.1")
    require(parsed.scheme == "http", "API URL is not http")
    require(parsed.port == 8089, "API URL is not the admitted REST listener on 127.0.0.1:8089")
    require(parsed.username is None and parsed.password is None, "API URL must not contain credentials")
    require(parsed.query == "" and parsed.fragment == "", "API URL must not contain query or fragment data")
    require(parsed.path in {"", "/"}, "API URL must identify the REST origin root")
    return parsed


def establish_binary(api_url: str, expected_name: str) -> dict[str, Any]:
    parsed = validate_api_url(api_url)
    pid = listener_pid(parsed.port)
    ps = command_output(["ps", "-p", str(pid), "-o", "lstart=", "-o", "command="], timeout=5)
    require(ps.returncode == 0 and bool(ps.stdout.strip()), "listener process metadata unavailable")
    line = ps.stdout.strip()
    # lstart is the first five whitespace-delimited fields on Darwin.
    fields = line.split(maxsplit=5)
    require(len(fields) == 6, "listener process start/command shape was unexpected")
    process_started = " ".join(fields[:5])
    command = fields[5]
    config_value = parse_option(command, "--user-config-file")
    require(config_value is not None, "Burp process has no --user-config-file argument")
    config_path = Path(config_value).expanduser().resolve()
    require(config_path.is_file(), "Burp user config path is not a readable file")
    config = json.loads(config_path.read_bytes())
    extensions = config.get("user_options", {}).get("extender", {}).get("extensions", [])
    candidates = [
        item
        for item in extensions
        if item.get("loaded") is True
        and item.get("extension_type") == "java"
        and item.get("name") == expected_name
    ]
    require(len(candidates) == 1, f"expected one configured loaded {expected_name!r} extension")
    jar_path = Path(str(candidates[0]["extension_file"])).expanduser().resolve()
    require(jar_path.is_file(), "configured extension JAR is not a readable file")
    jar_bytes, jar_snapshot = read_file_snapshot(jar_path)
    jar_sha = jar_snapshot["sha256"]
    with zipfile.ZipFile(io.BytesIO(jar_bytes)) as archive:
        openapi_candidates = [name for name in archive.namelist() if name == "openapi.json"]
        require(len(openapi_candidates) == 1, "configured JAR does not contain exactly one root openapi.json")
        embedded_openapi = archive.read(openapi_candidates[0])
    source_openapi = OPENAPI_PATH.read_bytes()
    try:
        embedded_structure = parse_json_without_duplicates(embedded_openapi, "JAR embedded openapi.json")
        source_structure = parse_json_without_duplicates(source_openapi, "source openapi.json")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationFailure("embedded or source OpenAPI document is invalid JSON") from exc
    return {
        "api_listener_pid": pid,
        "process_started_at": process_started,
        "process_command_sha256": sha256_bytes(command.encode("utf-8")),
        "user_config_path": str(config_path),
        "user_config_sha256": sha256_file(config_path),
        "configured_auto_reload": candidates[0].get("auto_reload"),
        "deployed_jar_path": str(jar_path),
        "jar_sha256_before": jar_sha,
        "jar_file_snapshot_before": jar_snapshot,
        "jar_size": jar_snapshot["size"],
        "embedded_openapi_sha256": sha256_bytes(embedded_openapi),
        "source_openapi_sha256": sha256_bytes(source_openapi),
        "openapi_structurally_aligned": embedded_structure == source_structure,
        "embedded_openapi_schema_count": len(embedded_structure.get("components", {}).get("schemas", {})),
        "source_openapi_schema_count": len(source_structure.get("components", {}).get("schemas", {})),
        "embedded_openapi_operation_count": sum(
            method.lower() in {"get", "post", "put", "delete", "patch"}
            for path in embedded_structure.get("paths", {}).values()
            for method in path
        ),
        "source_openapi_operation_count": sum(
            method.lower() in {"get", "post", "put", "delete", "patch"}
            for path in source_structure.get("paths", {}).values()
            for method in path
        ),
    }


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "burpctl-live-fixture"
    sys_version = ""

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def _record(self, body: bytes) -> None:
        server = self.server
        record = {
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
        with server.records_lock:  # type: ignore[attr-defined]
            server.records.append(record)  # type: ignore[attr-defined]

    def _send(self, status: int, body: bytes, headers: Mapping[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _dispatch(self) -> None:
        body = self._read_body()
        self._record(body)
        path = urllib.parse.urlsplit(self.path).path
        marker = self.server.marker  # type: ignore[attr-defined]
        if path == "/echo":
            response = {
                "targetMarker": marker,
                "method": self.command,
                "path": self.path,
                "headerMarker": self.headers.get("X-Live-Marker"),
                "authorization": self.headers.get("Authorization"),
                "cookie": self.headers.get("Cookie"),
                "bodyBase64": base64.b64encode(body).decode("ascii"),
            }
            self._send(200, json.dumps(response, separators=(",", ":")).encode(), {"Content-Type": "application/json", "X-Target-Marker": marker})
        elif path == "/set-cookie":
            self._send(200, marker.encode(), {"Content-Type": "text/plain", "Set-Cookie": f"live_cookie={marker}; Path=/; HttpOnly"})
        elif path == "/variant/a":
            self._send(200, ("A-" + marker).encode(), {"X-Variant": "a", "Content-Type": "text/plain"})
        elif path == "/variant/b":
            self._send(201, ("BBBB-" + marker).encode(), {"X-Variant": "b", "Content-Type": "text/plain"})
        elif path == "/page":
            page = f'''<!doctype html><a href="/api/{marker}/one">one</a><script src="/assets/{marker}/app.js"></script>'''.encode()
            self._send(200, page, {"Content-Type": "text/html"})
        elif path.startswith("/assets/") and path.endswith("/app.js"):
            script = f'''fetch("/api/{marker}/two"); const absolute = "http://127.0.0.1:{self.server.server_port}/api/{marker}/three";'''.encode()  # type: ignore[attr-defined]
            self._send(200, script, {"Content-Type": "application/javascript"})
        elif path.startswith("/api/"):
            self._send(200, marker.encode(), {"Content-Type": "text/plain"})
        elif path == "/protected":
            if self.headers.get("Authorization") == f"Bearer {marker}":
                self._send(200, ("protected-" + marker).encode(), {"Content-Type": "text/plain"})
            else:
                self._send(401, b"unauthorized", {"Content-Type": "text/plain"})
        else:
            self._send(404, b"fixture-not-found", {"Content-Type": "text/plain"})

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch
    do_PATCH = _dispatch
    do_DELETE = _dispatch
    do_HEAD = _dispatch


def start_target(state: TargetState, marker: str) -> None:
    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", state.requested_port), FixtureHandler)
        server.daemon_threads = True
        server.marker = marker  # type: ignore[attr-defined]
        server.records = []  # type: ignore[attr-defined]
        server.records_lock = threading.Lock()  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, name=f"verify-{state.name}", daemon=True)
        thread.start()
        state.server = server
        state.thread = thread
        state.actual_port = int(server.server_port)
        state.disposition = "held"
        state.detail = "listening; exclusively owned by this verifier"
    except OSError as exc:
        state.disposition = "released"
        state.detail = f"not acquired: {compact_error(exc)}"


def stop_target(state: TargetState) -> None:
    if state.server is None:
        if state.disposition == "unknown":
            state.disposition = "released"
            state.detail = "never acquired"
        return
    port = state.actual_port
    try:
        state.server.shutdown()
        state.server.server_close()
        if state.thread is not None:
            state.thread.join(timeout=5)
            if state.thread.is_alive():
                raise RuntimeError("fixture server thread did not stop")
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", int(port)))
        finally:
            probe.close()
        state.disposition = "released"
        state.detail = "server stopped, thread joined, and loopback port rebound successfully"
    except Exception as exc:
        state.disposition = "unknown"
        state.detail = f"stop/release confirmation failed: {compact_error(exc)}"


def target_records(ctx: RunContext, name: str, marker_path: str) -> list[dict[str, Any]]:
    target = ctx.targets[name]
    if target.server is None:
        return []
    with target.server.records_lock:  # type: ignore[attr-defined]
        return [
            dict(record)
            for record in target.server.records  # type: ignore[attr-defined]
            if marker_path in str(record.get("path"))
        ]


def require_clean_history(ctx: RunContext) -> None:
    if not ctx.exclusive_extension_custody:
        raise MissingPrecondition("operator did not assert exclusive extension history/session custody")
    data = require_success_envelope(api(ctx, "GET", "/history?page=0&pageSize=1000"))
    sitemap = require_success_envelope(api(ctx, "GET", "/history/sitemap"))
    if data.get("total") != 0 or data.get("entries") != [] or sitemap.get("total") != 0 or sitemap.get("entries") != []:
        raise MissingPrecondition("extension-owned history or its sitemap is not empty, so this case cannot add and globally restore entries")


def restore_clean_history(ctx: RunContext, case: CaseContext) -> None:
    try:
        data = require_success_envelope(api(ctx, "GET", "/history?page=0&pageSize=1000"))
        entries = data.get("entries")
        require(isinstance(entries, list) and data.get("total") == len(entries), "history cleanup could not enumerate every entry")
        owned_prefixes = tuple(ctx.target_url(name) + "/" for name in ("target_a", "target_b"))
        if any(
            not str(entry.get("url", "")).startswith(owned_prefixes)
            or ctx.marker not in str(entry.get("url", ""))
            for entry in entries
        ):
            raise CustodyUnknown("history gained an entry not attributable to this run's owned target markers")
        if entries:
            require_success_envelope(api(ctx, "DELETE", "/history"))
        require_clean_history(ctx)
        case.set_resource("extension_history_state", "released", f"authoritatively restored to empty baseline after {len(entries)} owned entries")
    except CustodyUnknown:
        case.set_resource("extension_history_state", "unknown", "an entry with another owner appeared; destructive cleanup refused")
        raise
    except Exception as exc:
        case.set_resource("extension_history_state", "unknown", f"empty-history restoration unconfirmed: {compact_error(exc)}")
        raise CustodyUnknown("extension history restoration could not be confirmed") from exc


def clean_session_state(ctx: RunContext) -> tuple[dict[str, Any], dict[str, Any]]:
    session = require_success_envelope(api(ctx, "GET", "/session/get"))
    jar = require_success_envelope(api(ctx, "GET", "/session/cookie-jar"))
    return session, jar


def require_clean_session(ctx: RunContext) -> None:
    if not ctx.exclusive_extension_custody:
        raise MissingPrecondition("operator did not assert exclusive extension history/session custody")
    session, jar = clean_session_state(ctx)
    if not (
        session.get("cookieCount") == 0
        and session.get("headerCount") == 0
        and session.get("cookies") == {}
        and session.get("headers") == {}
        and session.get("origin") is None
        and jar.get("total") == 0
        and jar.get("cookies") == []
    ):
        raise MissingPrecondition("session credentials and cookie jar are not at the clean baseline")


def restore_clean_session(ctx: RunContext, case: CaseContext) -> None:
    try:
        require_success_envelope(api(ctx, "DELETE", "/session/clear"))
        require_clean_session(ctx)
        case.set_resource("extension_session_state", "released", "authoritatively restored to clean baseline")
    except Exception as exc:
        case.set_resource("extension_session_state", "unknown", f"clean restoration unconfirmed: {compact_error(exc)}")
        raise CustodyUnknown("extension session state restoration could not be confirmed") from exc


def system_versions(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    require(len(ctx.versions) == 6, f"expected six product version identities, observed {len(ctx.versions)}")
    unique = sorted(set(ctx.versions.values()))
    require(len(unique) == 1, f"product version identities disagree: {ctx.versions}")
    require(ctx.expected_version == unique[0], "derived consensus version was not retained")
    return {"sources": ctx.versions, "consensus": unique[0]}


def system_binary(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    require(bool(ctx.binary), "binary provenance could not be established")
    observed = ctx.binary.get("jar_sha256_before")
    require(observed == ctx.expected_hash, "configured deployed JAR hash differs from release artifact hash")
    return {
        "listenerPid": ctx.binary["api_listener_pid"],
        "processStartedAt": ctx.binary["process_started_at"],
        "deployedJarPath": ctx.binary["deployed_jar_path"],
        "observedSha256": observed,
        "expectedSha256": ctx.expected_hash,
        "jarSize": ctx.binary["jar_size"],
        "configuredAutoReload": ctx.binary["configured_auto_reload"],
        "embeddedOpenApiSha256": ctx.binary["embedded_openapi_sha256"],
        "sourceOpenApiSha256": ctx.binary["source_openapi_sha256"],
        "openApiStructurallyAligned": ctx.binary["openapi_structurally_aligned"],
        "embeddedOpenApiSchemaCount": ctx.binary["embedded_openapi_schema_count"],
        "sourceOpenApiSchemaCount": ctx.binary["source_openapi_schema_count"],
        "embeddedOpenApiOperationCount": ctx.binary["embedded_openapi_operation_count"],
        "sourceOpenApiOperationCount": ctx.binary["source_openapi_operation_count"],
        "userConfigSha256": ctx.binary["user_config_sha256"],
        "processCommandSha256": ctx.binary["process_command_sha256"],
    }


def system_source_alignment(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    require(bool(ctx.binary), "binary provenance could not be established")
    evidence = {
        "embeddedOpenApiSha256": ctx.binary["embedded_openapi_sha256"],
        "sourceOpenApiSha256": ctx.binary["source_openapi_sha256"],
        "embeddedSchemaCount": ctx.binary["embedded_openapi_schema_count"],
        "sourceSchemaCount": ctx.binary["source_openapi_schema_count"],
        "embeddedOperationCount": ctx.binary["embedded_openapi_operation_count"],
        "sourceOperationCount": ctx.binary["source_openapi_operation_count"],
    }
    if ctx.binary.get("openapi_structurally_aligned") is not True:
        raise VerificationFailure(
            "deployed binary predates the current release source: embedded OpenAPI and source OpenAPI differ "
            f"({evidence})"
        )
    return {**evidence, "structurallyAligned": True}


def rest_health(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = api(ctx, "GET", "/health")
    data = require_success_envelope(result)
    require(data.get("status") == "ok", "health status is not ok")
    require(data.get("version") == ctx.expected_version, "health version differs from six-source consensus")
    require(isinstance(data.get("uptime"), int) and data["uptime"] >= 0, "health uptime is not a non-negative integer")
    require(isinstance(data.get("burpVersion"), str) and data["burpVersion"], "Burp version is absent")
    return {"status": data["status"], "version": data["version"], "uptime": data["uptime"], "burpVersion": data["burpVersion"]}


def rest_version(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/version"))
    require(data.get("version") == ctx.expected_version, "version endpoint differs from six-source consensus")
    require(data.get("name") == "burp-rest-extension", "version endpoint product name differs")
    return {"version": data.get("version"), "name": data.get("name"), "burpVersion": data.get("burpVersion")}


def rest_docs(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = api(ctx, "GET", "/docs")
    data = result.json
    require(result.status == 200 and isinstance(data, dict), "live docs were not a JSON object with HTTP 200")
    shipped = json.loads(OPENAPI_PATH.read_bytes())
    require(data == shipped, "live OpenAPI document differs from shipped openapi.json")
    return {"sha256Canonical": sha256_bytes(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()), "pathCount": len(data.get("paths", {})), "version": data.get("info", {}).get("version")}


def rest_extensions(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/extensions"))
    extensions = data.get("extensions")
    require(data.get("scope") == "current-extension-only", "extension listing scope is not current-extension-only")
    require(data.get("total") == 1 and isinstance(extensions, list) and len(extensions) == 1, "extension self-list did not contain exactly one entry")
    entry = extensions[0]
    require(entry.get("enabled") is True, "extension self-list did not report enabled")
    require(Path(str(entry.get("filename"))).resolve() == Path(ctx.binary["deployed_jar_path"]), "self-reported extension path differs from process configuration")
    require(entry.get("name") == ctx.expected_extension_name, "self-reported extension name differs")
    return {"scope": data["scope"], "total": data["total"], "name": entry.get("name"), "enabled": entry.get("enabled"), "filename": entry.get("filename")}


def rest_decoder_roundtrip(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    plain = f"release-{ctx.marker}"
    encoded = require_success_envelope(api(ctx, "POST", "/decoder/encode", body={"data": plain, "encoding": "base64"}))
    expected_encoded = base64.b64encode(plain.encode()).decode()
    require(encoded.get("result") == expected_encoded, "base64 encoding differs from RFC 4648 result")
    decoded = require_success_envelope(api(ctx, "POST", "/decoder/decode", body={"data": expected_encoded, "encoding": "base64"}))
    require(decoded.get("result") == plain, "base64 decode did not recover original Unicode text")
    return {"inputSha256": sha256_bytes(plain.encode()), "encoded": expected_encoded, "decodedMatches": True}


def rest_decoder_hash(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    plain = f"hash-{ctx.marker}"
    expected = hashlib.sha256(plain.encode()).hexdigest()
    data = require_success_envelope(api(ctx, "POST", "/decoder/hash", body={"data": plain, "algorithm": "sha256"}))
    require(data.get("result") == expected, "decoder SHA-256 differs from independent hashlib result")
    require(data.get("algorithm") == "sha256", "decoder did not identify the requested algorithm")
    return {"inputSha256": expected, "result": data.get("result"), "algorithm": data.get("algorithm")}


def rest_smart_decode(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    plain = f"smart-{ctx.marker}"
    twice = base64.b64encode(base64.b64encode(plain.encode())).decode()
    data = require_success_envelope(api(ctx, "POST", "/decoder/smart-decode", body={"data": twice}))
    require(data.get("final") == plain, "smart decode did not recover a two-layer Base64 value")
    require(isinstance(data.get("steps"), list) and len(data["steps"]) == 2, "smart decode did not report both transformations")
    return {"finalMatches": True, "stepEncodings": [step.get("encoding") for step in data["steps"]]}


def rest_media_type(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = api(ctx, "POST", "/decoder/hash", raw_body=b'{"data":"x","algorithm":"sha256"}', content_type="text/plain")
    error = require_error_envelope(result)
    require(result.status == 415, "non-JSON request was not rejected as unsupported media type")
    return {"httpStatus": result.status, "errorCode": error["code"]}


def rest_schema_unknown(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = api(ctx, "POST", "/decoder/hash", body={"data": "x", "algorithm": "sha256", "unexpected": ctx.marker})
    error = require_error_envelope(result)
    require(result.status == 400, "unknown request member was not rejected as invalid input")
    return {"httpStatus": result.status, "errorCode": error["code"], "unknownMemberAccepted": False}


def rest_not_found(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = api(ctx, "GET", f"/verify-does-not-exist-{ctx.marker}")
    error = require_error_envelope(result)
    require(result.status == 404, "unknown route was not reported as not found")
    return {"httpStatus": result.status, "errorCode": error["code"]}


def send_request_payload(url: str, method: str, marker: str, body: str | None = None) -> dict[str, Any]:
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": [{"name": "X-Live-Marker", "value": marker}],
    }
    if body is not None:
        request["body"] = body
    return {"request": request}


def rest_repeater_send(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    path_marker = f"single-{ctx.marker}"
    body = f"body-{ctx.marker}"
    url = ctx.target_url("target_a", f"/echo?case={path_marker}")
    data = require_success_envelope(api(ctx, "POST", "/repeater/send", body=send_request_payload(url, "POST", ctx.marker, body)))
    case.set_resource("target_a_connection", "released", "synchronous send returned; target connection is closed")
    require(data.get("hasResponse") is True, "repeater did not report a response")
    response = data.get("response")
    require(isinstance(response, dict) and response.get("statusCode") == 200, "repeater did not return target HTTP 200")
    decoded = json.loads(str(response.get("body")))
    require(decoded.get("targetMarker") == ctx.marker, "response lacks server-held target marker")
    require(decoded.get("method") == "POST", "target observed a different method")
    require(decoded.get("path") == f"/echo?case={path_marker}", "target observed a different path/query")
    require(decoded.get("headerMarker") == ctx.marker, "target did not observe the supplied header")
    require(base64.b64decode(decoded.get("bodyBase64", "")).decode() == body, "target observed different body bytes")
    records = target_records(ctx, "target_a", path_marker)
    require(len(records) == 1, f"target observed {len(records)} matching requests, expected one")
    case.set_resource("target_a_connection", "released", "one matching request completed and connection closed")
    persistence = data.get("persistence", {})
    return {"targetRequestCount": len(records), "method": decoded["method"], "path": decoded["path"], "responseStatus": response["statusCode"], "targetMarkerMatched": True, "persistence": {key: persistence.get(key) for key in ("status", "historyPersisted", "sitemapPersisted", "historyId")}}


def rest_repeater_batch(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    first = f"batch-one-{ctx.marker}"
    second = f"batch-two-{ctx.marker}"
    requests = [
        send_request_payload(ctx.target_url("target_a", f"/echo?case={first}"), "PUT", first, "one"),
        send_request_payload(ctx.target_url("target_b", f"/echo?case={second}"), "PATCH", second, "two"),
    ]
    data = require_success_envelope(api(ctx, "POST", "/repeater/send/batch", body={"requests": requests}))
    case.set_resource("target_a_connection", "released", "synchronous batch returned; target connection is closed")
    case.set_resource("target_b_connection", "released", "synchronous batch returned; target connection is closed")
    results = data.get("results")
    require(isinstance(results, list) and len(results) == 2, "batch response cardinality differs from request cardinality")
    decoded = [json.loads(str(item.get("response", {}).get("body"))) for item in results]
    require([item.get("method") for item in decoded] == ["PUT", "PATCH"], "batch result order or methods differ")
    require([item.get("headerMarker") for item in decoded] == [first, second], "batch result order or headers differ")
    counts = [len(target_records(ctx, "target_a", first)), len(target_records(ctx, "target_b", second))]
    require(counts == [1, 1], f"targets observed unexpected batch request counts: {counts}")
    case.set_resource("target_a_connection", "released", "one matching batch request completed")
    case.set_resource("target_b_connection", "released", "one matching batch request completed")
    return {"requested": 2, "returned": len(results), "targetCounts": counts, "methodsInOrder": [item["method"] for item in decoded], "totalDurationMsType": type(data.get("totalDurationMs")).__name__}


def rest_repeater_one_of(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    neither = api(ctx, "POST", "/repeater/send", body={})
    both = api(ctx, "POST", "/repeater/send", body={"requestId": 2147483647, "request": {"method": "GET", "url": ctx.target_url("target_a", "/echo")}})
    first_error = require_error_envelope(neither)
    second_error = require_error_envelope(both)
    require(neither.status == 400 and both.status == 400, "exactly-one violations were not invalid requests")
    return {"neither": {"status": neither.status, "errorCode": first_error["code"]}, "both": {"status": both.status, "errorCode": second_error["code"]}}


def finish_session_case(
    ctx: RunContext,
    case: CaseContext,
    failure: BaseException | None,
) -> None:
    if failure is not None and not isinstance(failure, VerificationFailure):
        case.set_resource(
            "extension_session_state",
            "unknown",
            "session-bearing operation ended without a completed typed result; late mutation cannot be excluded",
        )
        raise CustodyUnknown("extension session state is unknown after an ambiguous operation") from failure
    try:
        restore_clean_session(ctx, case)
    except BaseException as cleanup_exc:
        if failure is not None:
            raise CustodyUnknown(
                f"case failed ({compact_error(failure)}) and session cleanup failed ({compact_error(cleanup_exc)})"
            ) from cleanup_exc
        raise
    if failure is not None:
        raise failure


def rest_session_roundtrip(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    require_clean_session(ctx)
    case.set_resource("extension_session_state", "held", "clean baseline confirmed; mutation owned by this case")
    failure: BaseException | None = None
    evidence: dict[str, Any] = {}
    try:
        name = f"verify-{ctx.marker}"
        origin = ctx.target_url("target_a")
        require_success_envelope(api(ctx, "POST", "/session/set", body={"name": name, "cookies": {"fixture_cookie": ctx.marker}, "headers": {"X-Live-Marker": ctx.marker}, "origin": origin}))
        state = require_success_envelope(api(ctx, "GET", "/session/get"))
        require(state.get("name") == name, "session name did not round-trip")
        require(state.get("cookies") == {"fixture_cookie": ctx.marker}, "session cookies did not round-trip")
        require(state.get("headers") == {"X-Live-Marker": ctx.marker}, "session headers did not round-trip")
        require(state.get("origin") == origin, "session origin binding did not round-trip")
        evidence = {"nameMatched": True, "cookieCount": state.get("cookieCount"), "headerCount": state.get("headerCount"), "origin": state.get("origin")}
    except BaseException as exc:
        failure = exc
    finish_session_case(ctx, case, failure)
    return evidence


def rest_session_send(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    require_clean_session(ctx)
    case.set_resource("extension_session_state", "held", "clean baseline confirmed; mutation owned by this case")
    path_marker = f"session-send-{ctx.marker}"
    failure: BaseException | None = None
    evidence: dict[str, Any] = {}
    try:
        require_success_envelope(api(ctx, "POST", "/session/set", body={"cookies": {"fixture_cookie": ctx.marker}, "headers": {"Authorization": f"Bearer {ctx.marker}"}, "origin": ctx.target_url("target_a")}))
        sent = require_success_envelope(api(ctx, "POST", "/session/send", body={"method": "POST", "url": ctx.target_url("target_a", f"/echo?case={path_marker}"), "body": f"session-body-{ctx.marker}", "extraHeaders": {"X-Live-Marker": ctx.marker}}))
        case.set_resource("target_a_connection", "released", "synchronous session send returned; target connection is closed")
        require(sent.get("hasResponse") is True and sent.get("statusCode") == 200, "session send did not return target HTTP 200")
        decoded = json.loads(str(sent.get("body")))
        require(decoded.get("authorization") == f"Bearer {ctx.marker}", "configured authorization header was not injected")
        require(f"fixture_cookie={ctx.marker}" in str(decoded.get("cookie")), "configured cookie was not injected")
        require(decoded.get("headerMarker") == ctx.marker, "per-request extra header was not sent")
        require(len(target_records(ctx, "target_a", path_marker)) == 1, "target did not observe exactly one session request")
        case.set_resource("target_a_connection", "released", "one authenticated fixture request completed")
        evidence = {"responseStatus": sent["statusCode"], "configuredHeaderInjected": True, "configuredCookieInjected": True, "extraHeaderSent": True, "persistence": {key: sent.get("persistence", {}).get(key) for key in ("status", "historyPersisted", "sitemapPersisted", "historyId")}}
    except BaseException as exc:
        failure = exc
    finish_session_case(ctx, case, failure)
    return evidence


def rest_session_cookie_jar(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    require_clean_session(ctx)
    case.set_resource("extension_session_state", "held", "clean baseline confirmed; cookie-jar mutation owned by this case")
    first_marker = f"cookie-set-{ctx.marker}"
    second_marker = f"cookie-send-{ctx.marker}"
    failure: BaseException | None = None
    evidence: dict[str, Any] = {}
    try:
        require_success_envelope(api(ctx, "POST", "/session/set", body={"cookies": {}, "origin": ctx.target_url("target_a")}))
        require_success_envelope(api(ctx, "POST", "/session/send", body={"url": ctx.target_url("target_a", f"/set-cookie?case={first_marker}")}))
        case.set_resource("target_a_connection", "released", "synchronous cookie capture send returned; target connection is closed")
        jar = require_success_envelope(api(ctx, "GET", "/session/cookie-jar"))
        cookies = jar.get("cookies")
        require(jar.get("total") == 1 and isinstance(cookies, list) and len(cookies) == 1, "Set-Cookie was not represented as exactly one jar cookie")
        require(cookies[0].get("name") == "live_cookie" and cookies[0].get("value") == ctx.marker, "jar cookie name/value differs from target Set-Cookie")
        sent = require_success_envelope(api(ctx, "POST", "/session/send", body={"url": ctx.target_url("target_a", f"/echo?case={second_marker}")}))
        decoded = json.loads(str(sent.get("body")))
        require(f"live_cookie={ctx.marker}" in str(decoded.get("cookie")), "captured cookie was not injected into a subsequent same-origin request")
        require(len(target_records(ctx, "target_a", first_marker)) == 1 and len(target_records(ctx, "target_a", second_marker)) == 1, "target request cardinality differed")
        case.set_resource("target_a_connection", "released", "cookie capture and reuse requests both completed")
        evidence = {"jarTotal": jar["total"], "cookieName": cookies[0]["name"], "sameOriginReinjected": True}
    except BaseException as exc:
        failure = exc
    finish_session_case(ctx, case, failure)
    return evidence


def rest_diff(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    first = ctx.target_url("target_a", f"/variant/a?case=diff-{ctx.marker}")
    second = ctx.target_url("target_b", f"/variant/b?case=diff-{ctx.marker}")
    data = require_success_envelope(api(ctx, "POST", "/utils/diff", body={"a": {"url": first}, "b": {"url": second}}))
    case.set_resource("target_a_connection", "released", "synchronous diff returned; arm A connection is closed")
    case.set_resource("target_b_connection", "released", "synchronous diff returned; arm B connection is closed")
    require(data.get("statusA") == 200 and data.get("statusB") == 201, "diff did not preserve independently observed statuses")
    require(data.get("statusMatch") is False, "diff treated distinct statuses as equal")
    require(isinstance(data.get("bodyDiff"), str) and bool(data["bodyDiff"]), "diff omitted a body difference for distinct target bodies")
    require(len(target_records(ctx, "target_a", f"diff-{ctx.marker}")) == 1 and len(target_records(ctx, "target_b", f"diff-{ctx.marker}")) == 1, "diff did not issue exactly one request per arm")
    case.set_resource("target_a_connection", "released", "diff arm A completed")
    case.set_resource("target_b_connection", "released", "diff arm B completed")
    return {key: data.get(key) for key in ("statusA", "statusB", "statusMatch", "lengthA", "lengthB", "lengthDiff", "bodyDiff")}


def rest_extract_endpoints(ctx: RunContext, case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "POST", "/utils/extract-endpoints", body={"url": ctx.target_url("target_a", f"/page?case=endpoints-{ctx.marker}")}))
    case.set_resource("target_a_connection", "released", "synchronous extraction returned; fixture connections are closed")
    serialized = json.dumps(data, sort_keys=True)
    require(f"/api/{ctx.marker}/one" in serialized, "HTML-linked endpoint was absent")
    # The contract must disclose linked-script handling, but the suite only requires a script-derived endpoint
    # if the response says that linked scripts were successfully fetched.
    fetched = data.get("scriptsFetched", data.get("fetchedScripts", 0))
    if isinstance(fetched, list):
        fetched_count = len(fetched)
    elif isinstance(fetched, int):
        fetched_count = fetched
    else:
        fetched_count = 0
    if fetched_count > 0:
        require(f"/api/{ctx.marker}/two" in serialized, "successfully fetched script did not contribute its endpoint")
    page_count = len(target_records(ctx, "target_a", f"endpoints-{ctx.marker}"))
    require(page_count == 1, f"target observed {page_count} page requests, expected one")
    case.set_resource("target_a_connection", "released", "endpoint extraction requests completed")
    endpoints = data.get("endpoints", [])
    return {"endpointCount": len(endpoints) if isinstance(endpoints, list) else None, "htmlEndpointPresent": True, "linkedScriptsReportedFetched": fetched_count, "scriptEndpointRequiredAndPresent": fetched_count > 0, "responseKeys": sorted(data)}


def rest_proxy_history_shape(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/proxy/history?limit=1&offset=0"))
    entries = data.get("entries")
    require(isinstance(entries, list) and len(entries) <= 1, "proxy history did not honor a one-entry page bound")
    require(isinstance(data.get("total"), int) and data["total"] >= len(entries), "proxy history total is incoherent")
    if entries:
        require(isinstance(entries[0].get("id"), int), "proxy history entry has no integer identity")
        require(isinstance(entries[0].get("request"), dict), "proxy history entry has no request object")
    return {"returned": len(entries), "total": data["total"], "entryShapeChecked": bool(entries), "contentRecorded": False}


def rest_websocket_shape(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/proxy/websocket/history?limit=1&offset=0"))
    entries = data.get("entries")
    require(isinstance(entries, list) and len(entries) <= 1, "WebSocket history did not honor a one-entry page bound")
    require(isinstance(data.get("total"), int) and data["total"] >= len(entries), "WebSocket history total is incoherent")
    return {"returned": len(entries), "total": data["total"], "contentRecorded": False}


def rest_intercept_shape(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/proxy/intercept"))
    require(type(data.get("enabled")) is bool, "intercept status is not a boolean")
    return {"enabled": data["enabled"], "mutationAttempted": False}


def rest_history_shape(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/history?page=0&pageSize=1"))
    entries = data.get("entries")
    require(isinstance(entries, list) and len(entries) <= 1, "extension history did not honor a one-entry page bound")
    require(isinstance(data.get("total"), int) and data["total"] >= len(entries), "extension history total is incoherent")
    require(isinstance(data.get("page"), int) and isinstance(data.get("pageSize"), int), "extension history pagination metadata is not typed")
    return {"returned": len(entries), "total": data["total"], "page": data["page"], "pageSize": data["pageSize"], "contentRecorded": False}


def rest_scope_check(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    url = ctx.target_url("target_a", f"/scope-{ctx.marker}")
    data = require_success_envelope(api(ctx, "GET", "/target/scope/check?" + urllib.parse.urlencode({"url": url})))
    require(data.get("url") == url, "scope classifier did not return the classified URL")
    require(type(data.get("inScope")) is bool, "scope classification is not boolean")
    return {"url": data["url"], "inScope": data["inScope"], "scopeMutationAttempted": False}


def rest_sitemap_shape(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/target/sitemap?limit=1&offset=0"))
    entries = data.get("entries")
    require(isinstance(entries, list) and len(entries) <= 1, "target sitemap did not honor a one-entry page bound")
    require(isinstance(data.get("total"), int) and data["total"] >= len(entries), "target sitemap total is incoherent")
    return {"returned": len(entries), "total": data["total"], "contentRecorded": False}


def rest_project_config(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/config/project"))
    require(isinstance(data.get("config"), dict), "project configuration payload was not an object")
    require(isinstance(data.get("excludedPaths"), list), "project configuration exclusions were not a list")
    # Never persist the configuration or a credential-derived digest.
    return {
        "responseKeys": sorted(data),
        "configObject": True,
        "configTopLevelKeys": sorted(data["config"]),
        "excludedPathCount": len(data["excludedPaths"]),
        "configurationContentRecorded": False,
        "configurationDigestRecorded": False,
        "mutationAttempted": False,
    }


def rest_issue_definitions(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    data = require_success_envelope(api(ctx, "GET", "/scanner/issue-definitions"))
    definitions = data.get("definitions")
    require(isinstance(definitions, list), "issue definitions are not a list")
    require(data.get("total") == len(definitions), "issue-definition total differs from list cardinality")
    return {"total": data["total"], "contentRecorded": False}


def cli_environment(ctx: RunContext) -> dict[str, str]:
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["no_proxy"] = "127.0.0.1,localhost"
    env["XDG_CONFIG_HOME"] = str(ctx.work_dir / "xdg-config")
    env["XDG_DATA_HOME"] = str(ctx.work_dir / "xdg-data")
    env["XDG_CACHE_HOME"] = str(ctx.work_dir / "xdg-cache")
    return env


def run_bp(ctx: RunContext, args: list[str], *, alias: bool = False) -> subprocess.CompletedProcess[str]:
    executable = ctx.bp_path.with_name("burpctl") if alias else ctx.bp_path
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise MissingPrecondition(f"CLI executable is unavailable: {executable}")
    return subprocess.run([str(executable), *args], text=True, capture_output=True, timeout=ctx.timeout, check=False, env=cli_environment(ctx), cwd=ROOT)


def parse_single_json_stdout(result: subprocess.CompletedProcess[str]) -> Any:
    require(result.returncode == 0, f"CLI returned nonzero status {result.returncode}")
    require(result.stderr == "", "CLI emitted stderr on a successful command")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    require(len(lines) == 1, f"CLI success emitted {len(lines)} non-empty stdout lines")
    try:
        return json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise VerificationFailure("CLI stdout was not one JSON document") from exc


def cli_version(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = run_bp(ctx, ["--version"])
    require(result.returncode == 0 and result.stderr == "", "bp --version did not succeed cleanly")
    require(result.stdout.strip() == ctx.expected_version, "bp --version differs from six-source consensus")
    return {"version": result.stdout.strip(), "exitSuccess": True}


def cli_alias_version(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = run_bp(ctx, ["--version"], alias=True)
    require(result.returncode == 0 and result.stderr == "", "burpctl --version did not succeed cleanly")
    require(result.stdout.strip() == ctx.expected_version, "burpctl alias version differs from six-source consensus")
    return {"version": result.stdout.strip(), "exitSuccess": True, "alias": "burpctl"}


def cli_health_json(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    result = run_bp(ctx, ["--url", ctx.api_url, "--format", "json", "--no-ledger", "health"])
    data = parse_single_json_stdout(result)
    require(isinstance(data, dict), "CLI health JSON is not an object")
    require(data.get("status") == "ok" and data.get("version") == ctx.expected_version, "CLI health does not establish live identity")
    require(isinstance(data.get("uptime"), int), "CLI health uptime is not an integer")
    return {"status": data["status"], "version": data["version"], "uptime": data["uptime"], "stdoutDocumentCount": 1}


def cli_global_option_position(ctx: RunContext, _case: CaseContext) -> dict[str, Any]:
    before = run_bp(ctx, ["--url", ctx.api_url, "--format", "json", "--no-ledger", "version"])
    after = run_bp(ctx, ["version", "--url", ctx.api_url, "--format", "json", "--no-ledger"])
    first = parse_single_json_stdout(before)
    second = parse_single_json_stdout(after)
    require(first == second, "moving global options across the subcommand changed semantic JSON")
    require(first.get("version") == ctx.expected_version, "equivalent CLI forms did not return expected product identity")
    return {"semanticOutputsEqual": True, "version": first["version"], "formsSucceeded": 2}


def cases() -> list[CaseDef]:
    return [
        CaseDef("SYS-001", "system", "harness", "All six shipped version identities denote one release.", "Parse the six product-owned identities and require exactly one common value.", ("repository_files",), system_versions),
        CaseDef("SYS-002", "system", "Burp", "The API listener is the Burp process configured to load the release artifact being verified.", "Join the OS listener PID to Burp's startup config, hash that configured JAR, and require the independently supplied release hash.", ("api_listener", "deployed_jar"), system_binary),
        CaseDef("SYS-003", "system", "extension", "The responding extension self-identifies the enabled JAR path joined from the listener process.", "Require one current-extension-only entry whose enabled name/path match process configuration.", ("rest_api_connection",), rest_extensions),
        CaseDef("SYS-004", "system", "extension", "Only after six version identities agree, live health reports that same release and a measurable uptime.", "Require a typed healthy response whose version equals the six-source consensus, with non-negative uptime and named Burp version.", ("rest_api_connection",), rest_health),
        CaseDef("SYS-005", "system", "harness", "The deployed artifact embeds the same executable contract as the release source being verified.", "Parse embedded and source OpenAPI JSON and require structural equality before any behavior case runs.", ("deployed_jar", "repository_files"), system_source_alignment),
        CaseDef("REST-001", "rest", "extension", "Health proves a live extension with the release version and a measurable uptime.", "Require a typed success envelope, status ok, consensus version, non-negative integer uptime, and a named Burp version.", ("rest_api_connection",), rest_health),
        CaseDef("REST-002", "rest", "extension", "The version resource identifies this release and product.", "Require the version endpoint's version to equal the six-source consensus and its product name to identify the extension.", ("rest_api_connection",), rest_version),
        CaseDef("REST-003", "rest", "extension", "The live API publishes the exact contract shipped in this repository.", "Parse both OpenAPI documents and require structural JSON equality.", ("rest_api_connection", "repository_files"), rest_docs),
        CaseDef("REST-004", "rest", "extension", "Extension self-metadata identifies the enabled JAR tied to the listener process.", "Require one current-extension-only entry whose enabled name/path match process configuration.", ("rest_api_connection",), rest_extensions),
        CaseDef("REST-005", "rest", "extension", "Explicit Base64 encode/decode is reversible and standards-conformant.", "Compare encoding to independent RFC 4648 output and require decode to recover the original marker.", ("rest_api_connection",), rest_decoder_roundtrip),
        CaseDef("REST-006", "rest", "extension", "SHA-256 hashing returns the standard digest of the supplied bytes.", "Compare the API result to Python hashlib for a fresh inert marker.", ("rest_api_connection",), rest_decoder_hash),
        CaseDef("REST-007", "rest", "extension", "Smart decode applies successive recognizable layers until the original value is recovered.", "Supply two Base64 layers absent from the result and require the original plus two reported transformations.", ("rest_api_connection",), rest_smart_decode),
        CaseDef("REST-008", "rest", "extension", "JSON operations reject a non-JSON representation rather than silently interpreting it.", "Send valid-looking JSON as text/plain and require the documented typed 415 error envelope.", ("rest_api_connection",), rest_media_type),
        CaseDef("REST-009", "rest", "extension", "Closed request schemas reject undeclared members.", "Add one inert unknown member and require a typed invalid-request response without acceptance.", ("rest_api_connection",), rest_schema_unknown),
        CaseDef("REST-010", "rest", "extension", "Unknown routes fail through the API's typed error boundary.", "Request a fresh absent route and require the documented typed 404 envelope.", ("rest_api_connection",), rest_not_found),
        CaseDef("REST-011", "rest", "extension", "Repeater sends the declared method, URL, headers, and body and returns the target response.", "Use a fresh target-held marker and require exactly one matching target observation plus the same response marker.", ("rest_api_connection", "extension_history_state", "target_a_connection"), rest_repeater_send),
        CaseDef("REST-012", "rest", "extension", "Repeater batch sends each request once and preserves request/result order.", "Send two distinct methods and markers to two owned targets; require two ordered results and one observation per target.", ("rest_api_connection", "extension_history_state", "target_a_connection", "target_b_connection"), rest_repeater_batch),
        CaseDef("REST-013", "rest", "extension", "Repeater requires exactly one request source.", "Exercise neither-source and both-source controls; require typed invalid-request outcomes for both.", ("rest_api_connection",), rest_repeater_one_of),
        CaseDef("REST-014", "rest", "extension", "Session configuration is readable as the state that was set and can be fully cleared.", "From a clean baseline set inert cookies/headers/origin, read exact state, then clear and authoritatively re-read the clean baseline.", ("rest_api_connection", "extension_session_state"), rest_session_roundtrip),
        CaseDef("REST-015", "rest", "extension", "Session send injects configured credentials and per-request headers into the owned origin.", "Have the target independently report headers/cookies, require each inert marker, then clear and re-read clean state.", ("rest_api_connection", "extension_session_state", "extension_history_state", "target_a_connection"), rest_session_send),
        CaseDef("REST-016", "rest", "extension", "A same-origin Set-Cookie response enters the session jar and is used on the next request.", "Capture a fresh server-held cookie, read one jar entry, observe it at the target on the next send, then clear and re-read clean state.", ("rest_api_connection", "extension_session_state", "extension_history_state", "target_a_connection"), rest_session_cookie_jar),
        CaseDef("REST-017", "rest", "extension", "Diff reports independently observable response differences without conflating its arms.", "Serve distinct status/body arms, require their exact statuses, an unequal status classification and a reported body difference, and require one request per arm.", ("rest_api_connection", "extension_session_state", "extension_history_state", "target_a_connection", "target_b_connection"), rest_diff),
        CaseDef("REST-018", "rest", "extension", "Endpoint extraction includes links present in fetched owned content and accounts for linked-script handling.", "Require the HTML endpoint; if scripts are reported fetched, also require the script-derived endpoint; require one page fetch.", ("rest_api_connection", "extension_history_state", "target_a_connection"), rest_extract_endpoints),
        CaseDef("REST-019", "rest", "Burp", "Proxy history exposes bounded typed pagination without the verifier disclosing captured content.", "Request at most one row; require list cardinality and coherent total, recording no row content.", ("rest_api_connection",), rest_proxy_history_shape),
        CaseDef("REST-020", "rest", "Burp", "WebSocket history exposes bounded typed pagination without the verifier disclosing captured content.", "Request at most one row; require list cardinality and coherent total, recording no row content.", ("rest_api_connection",), rest_websocket_shape),
        CaseDef("REST-021", "rest", "Burp", "Intercept status is observable without changing Burp interception.", "Require a boolean status from the read-only route and perform no enable/disable action.", ("rest_api_connection",), rest_intercept_shape),
        CaseDef("REST-022", "rest", "extension", "Extension-owned history returns coherent typed pagination.", "Request one row and require bounded list, nonnegative coherent total, and integer pagination metadata without recording content.", ("rest_api_connection",), rest_history_shape),
        CaseDef("REST-023", "rest", "Burp", "Scope check classifies the exact supplied URL without mutating project scope.", "Classify an owned loopback URL and require the echoed URL plus a boolean decision.", ("rest_api_connection",), rest_scope_check),
        CaseDef("REST-024", "rest", "Burp", "Target sitemap exposes bounded typed pagination without the verifier disclosing captured content.", "Request at most one row; require list cardinality and coherent total, recording no row content.", ("rest_api_connection",), rest_sitemap_shape),
        CaseDef("REST-025", "rest", "Burp", "Project configuration is exportable as structured JSON without mutation.", "Require an object; record only top-level keys and a canonical digest, never its potentially sensitive content.", ("rest_api_connection",), rest_project_config),
        CaseDef("REST-026", "rest", "Burp", "Scanner issue definitions return a list whose declared total is its cardinality.", "Require list type and exact total/list agreement without recording definition content.", ("rest_api_connection",), rest_issue_definitions),
        CaseDef("CLI-001", "cli", "CLI", "The primary executable identifies the six-source release version.", "Run bp --version and require clean success with exactly the consensus version.", ("cli_process",), cli_version),
        CaseDef("CLI-002", "cli", "CLI", "The burpctl compatibility alias identifies the same release.", "Run burpctl --version and require clean success with exactly the consensus version.", ("cli_process",), cli_alias_version),
        CaseDef("CLI-003", "cli", "CLI", "CLI JSON health output carries the live release identity as one machine-readable document.", "Run health with explicit loopback URL, JSON and no ledger; require one JSON object with ok/consensus version/uptime.", ("cli_process", "rest_api_connection"), cli_health_json),
        CaseDef("CLI-004", "cli", "CLI", "Documented global options have the same semantics before and after the subcommand.", "Run both placements against version and require identical parsed JSON, not byte-for-byte presentation text.", ("cli_process", "rest_api_connection"), cli_global_option_position),
    ]


def base_dispositions(case: CaseDef) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for resource in case.resources:
        if resource in {"repository_files", "deployed_jar"}:
            output[resource] = {"status": "released", "detail": "read only; no mutation attempted"}
        elif resource == "api_listener":
            output[resource] = {"status": "released", "detail": "OS metadata read only; listener unchanged"}
        elif resource == "rest_api_connection":
            output[resource] = {"status": "released", "detail": "HTTP connection closes after response"}
        elif resource == "cli_process":
            output[resource] = {"status": "released", "detail": "subprocess awaited; isolated XDG state and no ledger where API is contacted"}
        elif resource.endswith("_connection"):
            output[resource] = {"status": "unknown", "detail": "target request has not completed"}
        else:
            output[resource] = {"status": "unknown", "detail": "case must settle this mutable resource"}
    return output


def execute_case(ctx: RunContext, case: CaseDef) -> dict[str, Any]:
    started = time.monotonic()
    case_ctx = CaseContext(base_dispositions(case))
    result: dict[str, Any] = {
        "case_id": case.case_id,
        "group": case.group,
        "layer": case.layer,
        "invariant": case.invariant,
        "assertion": case.assertion,
        "outcome": "FAIL",
        "observed_evidence": {},
        "resource_disposition": case_ctx.dispositions,
        "started_at": utc_now(),
    }
    try:
        case_failure: BaseException | None = None
        evidence: dict[str, Any] = {}
        if "extension_history_state" in case.resources:
            require_clean_history(ctx)
            case_ctx.set_resource("extension_history_state", "held", "empty baseline confirmed; fresh owned entries may be created")
        if "extension_session_state" in case.resources:
            require_clean_session(ctx)
            case_ctx.set_resource("extension_session_state", "held", "clean baseline confirmed; mutation owned by this case")
        try:
            evidence = case.fn(ctx, case_ctx)
        except BaseException as exc:
            case_failure = exc
        if (
            "extension_session_state" in case.resources
            and case_ctx.dispositions["extension_session_state"]["status"] == "held"
        ):
            if case_failure is not None and not isinstance(case_failure, VerificationFailure):
                case_ctx.set_resource(
                    "extension_session_state",
                    "unknown",
                    "session-bearing operation ended without a completed typed result; late mutation cannot be excluded",
                )
                case_failure = CustodyUnknown(
                    f"{case.case_id} ended ambiguously; extension session cleanup cannot prove settled custody"
                )
            else:
                try:
                    restore_clean_session(ctx, case_ctx)
                except BaseException as cleanup_exc:
                    case_failure = CustodyUnknown(
                        f"session cleanup failed after {case.case_id}: {compact_error(cleanup_exc)}"
                    )
        if "extension_history_state" in case.resources:
            if case_failure is not None and not isinstance(
                case_failure, (VerificationFailure, MissingPrecondition)
            ):
                case_ctx.set_resource(
                    "extension_history_state",
                    "unknown",
                    "target-bearing operation ended without a completed typed response; late persistence cannot be excluded",
                )
                raise CustodyUnknown(
                    f"{case.case_id} ended ambiguously; extension history cleanup is unsafe"
                ) from case_failure
            try:
                restore_clean_history(ctx, case_ctx)
            except BaseException as cleanup_exc:
                if case_failure is not None:
                    raise CustodyUnknown(
                        f"case failed ({compact_error(case_failure)}) and history cleanup failed ({compact_error(cleanup_exc)})"
                    ) from cleanup_exc
                raise
        if case_failure is not None:
            raise case_failure
        result["outcome"] = "PASS"
        result["observed_evidence"] = evidence
    except MissingPrecondition as exc:
        result["outcome"] = "COULD_NOT_RUN"
        result["missing_precondition"] = str(exc)
        result["observed_evidence"] = {"exception": json_safe_error(exc)}
        for name, disposition in case_ctx.dispositions.items():
            if disposition["status"] == "unknown":
                disposition.update(status="released", detail="resource not acquired because a precondition was absent")
    except CustodyUnknown as exc:
        result["outcome"] = "FAIL"
        result["observed_evidence"] = {"exception": json_safe_error(exc), "containmentAbort": True}
        ctx.containment_reason = f"{case.case_id}: {exc}"
    except VerificationFailure as exc:
        result["outcome"] = "FAIL"
        result["observed_evidence"] = {"exception": json_safe_error(exc)}
    except Exception as exc:
        result["outcome"] = "FAIL"
        result["observed_evidence"] = {"exception": json_safe_error(exc), "unexpected": True, "tracebackSha256": sha256_bytes(traceback.format_exc().encode())}
    result["resource_disposition"] = case_ctx.dispositions
    unsettled = [name for name, item in case_ctx.dispositions.items() if item["status"] in {"unknown", "contaminated"}]
    if unsettled:
        ctx.containment_reason = ctx.containment_reason or f"{case.case_id}: resources not authoritatively released/restored: {', '.join(unsettled)}"
        result["observed_evidence"]["containmentAbort"] = True
        result["observed_evidence"]["unsettledResources"] = unsettled
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def could_not_run(case: CaseDef, reason: str, *, containment: bool = True) -> dict[str, Any]:
    dispositions = base_dispositions(case)
    for name, item in dispositions.items():
        if item["status"] == "unknown":
            item.update(status="released", detail="not touched because containment prevented execution")
    return {
        "case_id": case.case_id,
        "group": case.group,
        "layer": case.layer,
        "invariant": case.invariant,
        "assertion": case.assertion,
        "outcome": "COULD_NOT_RUN",
        "missing_precondition": reason,
        "observed_evidence": {"containmentAbort": containment},
        "resource_disposition": dispositions,
        "started_at": None,
        "duration_ms": 0.0,
    }


def sample_uptime(ctx: RunContext, label: str) -> int:
    data = require_success_envelope(api(ctx, "GET", "/health"))
    require(data.get("version") == ctx.expected_version, "health sample version differs from six-source consensus")
    uptime = data.get("uptime")
    require(isinstance(uptime, int) and uptime >= 0, "health uptime unavailable or malformed")
    previous = ctx.uptime_samples[-1]["uptime"] if ctx.uptime_samples else None
    require(previous is None or uptime >= previous, f"extension uptime reset from {previous} to {uptime}")
    ctx.uptime_samples.append({"label": label, "observed_at": utc_now(), "uptime": uptime})
    return uptime


def write_result(document: dict[str, Any], requested_path: Path | None = None) -> Path:
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    if requested_path is None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        requested_path = RESULTS_ROOT / f"live-{stamp}.json"
    path = requested_path if requested_path.is_absolute() else ROOT / requested_path
    resolved = path.resolve()
    try:
        resolved.relative_to(RESULTS_ROOT.resolve())
    except ValueError as exc:
        raise ValueError("result path must be under verify/results") from exc
    resolved.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved.with_suffix(resolved.suffix + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", "utf-8")
    os.replace(temporary, resolved)
    return resolved


def select_behavior(all_cases: list[CaseDef], groups: list[str], ids: list[str]) -> list[CaseDef]:
    behavior = [case for case in all_cases if case.group in BEHAVIOR_GROUPS]
    if ids:
        wanted = set(ids)
        return [case for case in behavior if case.case_id in wanted]
    selected_groups = set(groups or ["rest", "cli"])
    return [case for case in behavior if case.group in selected_groups]


def summarize(results: list[dict[str, Any]], registered: int, selected: int) -> dict[str, Any]:
    behavior_results = [item for item in results if item.get("group") in BEHAVIOR_GROUPS]
    counts = {name: sum(item["outcome"] == name for item in behavior_results) for name in ("PASS", "FAIL", "COULD_NOT_RUN")}
    system_failures = sum(
        item["outcome"] != "PASS" for item in results if item.get("group") in {"system", "harness"}
    )
    executed = counts["PASS"] + counts["FAIL"]
    clean = (
        counts["FAIL"] == 0
        and counts["COULD_NOT_RUN"] == 0
        and selected > 0
        and executed > 0
        and system_failures == 0
    )
    return {
        "registered_behavior_cases": registered,
        "selected_behavior_cases": selected,
        "executed_behavior_cases": executed,
        **{name.lower(): value for name, value in counts.items()},
        "system_failures": system_failures,
        "clean": clean,
        "exit_code": 0 if clean else 1,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", default="http://127.0.0.1:8089")
    parser.add_argument(
        "--expected-jar-sha256",
        required=True,
        type=require_expected_hash,
        help="release artifact digest supplied by the build/release gate",
    )
    parser.add_argument("--group", action="append", choices=sorted(BEHAVIOR_GROUPS), default=[])
    parser.add_argument("--case", action="append", default=[], help="exact behavior case ID; repeatable")
    parser.add_argument(
        "--defer-case",
        action="append",
        default=[],
        metavar="CASE_ID=REASON",
        help="select but record a case COULD_NOT_RUN for a named external precondition",
    )
    parser.add_argument("--target-a-port", type=require_port, default=9931)
    parser.add_argument("--target-b-port", type=require_port, default=9932)
    parser.add_argument(
        "--exclusive-extension-custody",
        action="store_true",
        help="assert no other producer owns session or H2 history during this run",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--bp", type=Path, default=ROOT / "bp" / ".venv" / "bin" / "bp")
    parser.add_argument("--result", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        validate_api_url(args.api_url)
    except VerificationFailure as exc:
        parser.error(str(exc))
    if args.target_a_port == args.target_b_port:
        parser.error("--target-a-port and --target-b-port must be distinct")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    deferred: dict[str, str] = {}
    for item in args.defer_case:
        case_id, separator, reason = item.partition("=")
        if not separator or not case_id or not reason:
            parser.error("--defer-case must be CASE_ID=REASON")
        deferred[case_id] = reason

    started_at = utc_now()
    run_id = str(uuid.uuid4())
    marker = "verify-" + run_id.replace("-", "")[:16]
    fixture = json.loads(RELEASE_FIXTURE.read_bytes())
    all_cases = cases()
    system_cases = [case for case in all_cases if case.group == "system"]
    selected = select_behavior(all_cases, args.group, args.case)
    unknown_ids = sorted(set(args.case) - {case.case_id for case in selected})
    registered_ids = {case.case_id for case in all_cases}
    unknown_deferred = sorted(set(deferred) - registered_ids)
    if unknown_deferred:
        parser.error("--defer-case names unknown case IDs: " + ", ".join(unknown_deferred))
    work_dir = RESULTS_ROOT / f".work-{run_id}"
    work_dir.mkdir(parents=True, exist_ok=False)

    document: dict[str, Any] = {
        "schema_version": "1.0",
        "result_schema": "verify/result-schema.json",
        "suite": "burpctl-live-release-verification",
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": None,
        "invocation": {"api_url": args.api_url, "groups": args.group or ["rest", "cli"], "case_ids": args.case, "deferred_cases": deferred, "exclusive_extension_custody": args.exclusive_extension_custody, "target_ports": [args.target_a_port, args.target_b_port]},
        "repository": {},
        "versions": {"sources": {}, "consensus": None},
        "binary": {"expected_jar_sha256": args.expected_jar_sha256, "expected_hash_source": "explicit --expected-jar-sha256 run input", "uptime_samples": []},
        "targets": [],
        "cases": [],
        "resources": [],
        "containment_abort": None,
        "proof_ceiling": [
            "Only the configured extension JAR path and unchanged file hash, process/config join, self-metadata, and monotonic uptime tie observations to one candidate binary; the suite does not attest the already-loaded in-memory byte image independently of Burp.",
            "No external host, DNS name, or Collaborator was contacted. Collaborator verification is excluded by this lane's assignment and remains a separate release gate.",
            "No active Scanner or Intruder job was created, no proxy interception or project scope was changed, no history was cleared, and no project/user configuration was imported.",
            "Read-only history/sitemap cases establish bounded typed representations, not the correctness, completeness, ownership, or secrecy of ambient Burp data.",
            "CLI cases establish only the recorded editable source state and launcher; REST cases establish the frozen JAR independently of later CLI edits.",
        ],
    }

    ctx = RunContext(
        run_id=run_id,
        api_url=args.api_url,
        timeout=args.timeout,
        marker=marker,
        expected_hash=args.expected_jar_sha256,
        expected_extension_name=str(fixture["expected_extension_name"]),
        exclusive_extension_custody=args.exclusive_extension_custody,
        versions={},
        expected_version=None,
        binary={},
        repository={},
        targets={
            "target_a": TargetState("target_a", args.target_a_port),
            "target_b": TargetState("target_b", args.target_b_port),
        },
        work_dir=work_dir,
        bp_path=args.bp.resolve(),
        uptime_samples=[],
    )

    try:
        try:
            ctx.repository = git_repository_state()
            document["repository"] = ctx.repository
        except Exception as exc:
            document["repository"] = {"error": json_safe_error(exc)}

        try:
            ctx.versions = derive_versions()
            unique = set(ctx.versions.values())
            ctx.expected_version = next(iter(unique)) if len(unique) == 1 else None
        except Exception as exc:
            document["versions"]["derivation_error"] = json_safe_error(exc)
        document["versions"].update(sources=ctx.versions, consensus=ctx.expected_version)

        try:
            ctx.binary = establish_binary(args.api_url, ctx.expected_extension_name)
            document["binary"].update(ctx.binary)
            if ctx.binary.get("openapi_structurally_aligned") is False:
                for case_id, reason in SOURCE_ALIGNMENT_DEPENDENT_CASES.items():
                    deferred.setdefault(case_id, reason + "; deployed binary predates the change")
                document["invocation"]["deferred_cases"] = deferred
        except Exception as exc:
            document["binary"]["provenance_error"] = json_safe_error(exc)

        if not selected:
            reason = "case selection matched zero behavior cases"
            if unknown_ids:
                reason += f"; unknown IDs: {', '.join(unknown_ids)}"
            document["cases"].append({
                "case_id": "HARNESS-000",
                "group": "harness",
                "layer": "harness",
                "invariant": "A verification run cannot report clean when it selected no behavior cases.",
                "assertion": "Require at least one selected behavior case before any live execution.",
                "outcome": "FAIL",
                "observed_evidence": {"selectedBehaviorCases": 0, "reason": reason},
                "resource_disposition": {},
                "started_at": utc_now(),
                "duration_ms": 0.0,
            })
            ctx.containment_reason = reason
        else:
            # Start targets only after local/process provenance collection. A bind failure is a per-case
            # missing precondition, not permission to use someone else's listener.
            start_target(ctx.targets["target_a"], marker)
            start_target(ctx.targets["target_b"], marker)

            initial_health_error: str | None = None
            try:
                sample_uptime(ctx, "before-system-preflight")
            except Exception as exc:
                initial_health_error = f"initial health/uptime precondition failed: {compact_error(exc)}"

            for case in system_cases:
                result = execute_case(ctx, case)
                document["cases"].append(result)
                if result["outcome"] != "PASS":
                    failure_message = result.get("observed_evidence", {}).get("exception", {}).get("message")
                    ctx.containment_reason = ctx.containment_reason or f"{case.case_id}: {failure_message or 'release preflight failed'}"

            if initial_health_error is not None:
                ctx.containment_reason = ctx.containment_reason or initial_health_error

            for case in selected:
                if ctx.containment_reason is not None:
                    document["cases"].append(could_not_run(case, ctx.containment_reason))
                    continue
                if case.case_id in deferred:
                    document["cases"].append(could_not_run(case, deferred[case.case_id], containment=False))
                    continue
                result = execute_case(ctx, case)
                document["cases"].append(result)
                if ctx.containment_reason is None:
                    try:
                        sample_uptime(ctx, f"after-{case.case_id}")
                    except Exception as exc:
                        ctx.containment_reason = f"after {case.case_id}, uptime continuity failed: {compact_error(exc)}"

            # End attribution is mandatory even after an ordinary product failure.
            continuity_error: str | None = None
            try:
                sample_uptime(ctx, "after-behavior")
                jar_path = Path(str(ctx.binary["deployed_jar_path"]))
                after_snapshot = sha256_file_snapshot(jar_path)
                ctx.binary["jar_sha256_after"] = after_snapshot["sha256"]
                ctx.binary["jar_file_snapshot_after"] = after_snapshot
                document["binary"]["jar_sha256_after"] = ctx.binary["jar_sha256_after"]
                document["binary"]["jar_file_snapshot_after"] = after_snapshot
                require(after_snapshot == ctx.binary["jar_file_snapshot_before"], "configured JAR file identity or bytes changed during run")
                repository_after = git_repository_state()
                document["repository"]["end_release_source_sha256"] = repository_after["release_source_sha256"]
                document["repository"]["end_documentation_sha256"] = repository_after["documentation_sha256"]
                document["repository"]["end_cli_source_sha256"] = repository_after["cli_source_sha256"]
                document["repository"]["end_verifier_sha256"] = repository_after["verifier_sha256"]
                require(
                    repository_after["release_source_sha256"] == ctx.repository["release_source_sha256"],
                    "release source changed during the run",
                )
                require(
                    repository_after["documentation_sha256"] == ctx.repository["documentation_sha256"],
                    "shipped documentation changed during the run",
                )
                require(
                    repository_after["cli_source_sha256"] == ctx.repository["cli_source_sha256"],
                    "CLI source changed during the run",
                )
                require(
                    repository_after["verifier_sha256"] == ctx.repository["verifier_sha256"],
                    "verifier source changed during the run",
                )
            except Exception as exc:
                continuity_error = compact_error(exc)
                ctx.containment_reason = ctx.containment_reason or f"end attribution failed: {continuity_error}"

            if continuity_error is not None or any(
                ctx.uptime_samples[index]["uptime"] < ctx.uptime_samples[index - 1]["uptime"]
                for index in range(1, len(ctx.uptime_samples))
            ):
                reason = continuity_error or "uptime reset detected"
                for item in document["cases"]:
                    if item["group"] in BEHAVIOR_GROUPS and item["outcome"] in {"PASS", "FAIL"}:
                        item["observed_evidence"]["provisional_outcome"] = item["outcome"]
                        item["outcome"] = "COULD_NOT_RUN"
                        item["missing_precondition"] = f"single-binary continuity was not established: {reason}"

        document["binary"]["uptime_samples"] = ctx.uptime_samples
    finally:
        for target in ctx.targets.values():
            stop_target(target)
        try:
            # Remove only this run's isolated, non-evidence CLI state.
            import shutil
            shutil.rmtree(work_dir)
        except Exception as exc:
            document.setdefault("cleanup_errors", []).append({"resource": "isolated_cli_work_dir", "error": json_safe_error(exc)})
        document["targets"] = [
            {"name": target.name, "address": "127.0.0.1", "port": target.actual_port or target.requested_port, "final_disposition": target.disposition, "detail": target.detail, "request_count": (len(target.server.records) if target.server is not None else 0)}  # type: ignore[attr-defined]
            for target in ctx.targets.values()
        ]
        document["resources"] = [
            {"name": "deployed_jar", "final_disposition": "released", "detail": "read only; pre/post hash attempted"},
            {"name": "api_listener", "final_disposition": "held", "detail": "Burp process and listener were not stopped or reconfigured"},
            {"name": "extension_session_state", "final_disposition": ("released" if not any(item.get("resource_disposition", {}).get("extension_session_state", {}).get("status") == "unknown" for item in document["cases"]) else "unknown"), "detail": "clean baseline re-read after every attempted session mutation; see per-case evidence"},
            {"name": "extension_history_state", "final_disposition": ("released" if not any(item.get("resource_disposition", {}).get("extension_history_state", {}).get("status") == "unknown" for item in document["cases"]) else "unknown"), "detail": "empty baseline and owned-entry-only cleanup enforced for every target send; see per-case evidence"},
            {"name": "target_a", "final_disposition": ctx.targets["target_a"].disposition, "detail": ctx.targets["target_a"].detail},
            {"name": "target_b", "final_disposition": ctx.targets["target_b"].disposition, "detail": ctx.targets["target_b"].detail},
            {"name": "isolated_cli_work_dir", "final_disposition": ("unknown" if document.get("cleanup_errors") else "released"), "detail": "removed after subprocesses" if not document.get("cleanup_errors") else "removal unconfirmed"},
            {"name": "Collaborator", "final_disposition": "released", "detail": "not acquired; excluded by lane ceiling"},
            {"name": "Scanner/Intruder jobs", "final_disposition": "released", "detail": "none created"},
        ]
        unknown_final = [item["name"] for item in document["resources"] if item["final_disposition"] in {"unknown", "contaminated"}]
        unknown_final.extend(target.name for target in ctx.targets.values() if target.disposition in {"unknown", "contaminated"})
        if unknown_final:
            ctx.containment_reason = ctx.containment_reason or f"final resource custody unknown: {', '.join(sorted(set(unknown_final)))}"
        document["containment_abort"] = ctx.containment_reason
        document["finished_at"] = utc_now()
        document["summary"] = summarize(document["cases"], len([case for case in all_cases if case.group in BEHAVIOR_GROUPS]), len(selected))
        if ctx.containment_reason is not None:
            document["summary"]["clean"] = False
            document["summary"]["exit_code"] = 1
        result_path = write_result(document, args.result)

    print(str(result_path))
    print(json.dumps(document["summary"], sort_keys=True))
    if document["summary"]["exit_code"] != 0:
        print(
            "LIVE VERIFICATION NOT CLEAN: inspect the recorded FAIL and COULD_NOT_RUN cases",
            file=sys.stderr,
        )
    return int(document["summary"]["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
