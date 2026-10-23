"""Disposable loopback servers and subprocess boundary for CLI audit lanes."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import Final
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class RequestEffect:
    """One request received by a fixture server."""

    method: str
    path: str
    body_sha256: str
    body_length: int
    status: int


@dataclass(frozen=True, slots=True)
class FixtureSnapshot:
    """Immutable pre or post state snapshot for an audit invocation."""

    rest_effects: tuple[RequestEffect, ...]
    target_effects: tuple[RequestEffect, ...]


@dataclass(frozen=True, slots=True)
class FixtureManifest:
    """Concrete addresses and isolated paths supplied to a CLI subprocess."""

    rest_url: str
    target_url: str
    home: Path
    ledger_path: Path
    config_path: Path
    payload_dir: Path


class UnsafeTargetError(ValueError):
    """Raised before a target request when its URL is not the loopback fixture."""


@dataclass(slots=True)
class _ServerState:
    """Mutable request accumulator owned by one fixture server."""

    effects: list[RequestEffect]
    routes: dict[tuple[str, str], tuple[int, bytes, str, bytes | None]]


class _FixtureHandler(BaseHTTPRequestHandler):
    """Strict HTTP handler shared by the REST and target fixture servers."""

    server: _FixtureServer

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def log_message(self, _format: str, *_args: str) -> None:
        """Keep subprocess evidence deterministic and quiet."""

    def _dispatch(self, method: str) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        route = self.server.state.routes.get((method, self.path))
        status, response, content_type, expected_body = route or (
            404,
            b"",
            "application/json",
            None,
        )
        if expected_body is not None and body != expected_body:
            status, response = 400, b'{"error":"unexpected request body"}'
        self.server.state.effects.append(
            RequestEffect(
                method=method,
                path=self.path,
                body_sha256=hashlib.sha256(body).hexdigest(),
                body_length=len(body),
                status=status,
            )
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class _FixtureServer(ThreadingHTTPServer):
    """Threading server with explicit fixture state."""

    def __init__(self, state: _ServerState) -> None:
        super().__init__(("127.0.0.1", 0), _FixtureHandler)
        self.state = state


_DEFAULT_HEALTH: Final[bytes] = json.dumps(
    {
        "success": True,
        "data": {"status": "ok", "version": "fixture", "uptime": 1, "burpVersion": None},
        "error": None,
    },
    separators=(",", ":"),
).encode()


def _loopback_target(url: str) -> bool:
    """Return true only for an explicit HTTP(S) 127.0.0.1 URL."""
    parsed = urlsplit(url)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname == "127.0.0.1"
        and parsed.port is not None
    )


def _origin(url: str) -> tuple[str, str, int | None]:
    """Extract the normalized origin components used by fixture allowlists."""
    parsed = urlsplit(url)
    return parsed.scheme.lower(), parsed.hostname or "", parsed.port


class AuditFixture:
    """Own REST and target servers plus isolated process state for one audit lane."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.home = root / "home"
        self.ledger_path = root / "state" / "ledger.db"
        self.config_path = self.home / ".bp" / "config"
        self.payload_dir = root / "payloads"
        for directory in (
            self.home,
            self.ledger_path.parent,
            self.config_path.parent,
            self.payload_dir,
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._rest = _FixtureServer(
            _ServerState([], {("GET", "/health"): (200, _DEFAULT_HEALTH, "application/json", None)})
        )
        self._target = _FixtureServer(_ServerState([], {}))
        self._threads = (
            threading.Thread(target=self._rest.serve_forever, daemon=True),
            threading.Thread(target=self._target.serve_forever, daemon=True),
        )
        for thread in self._threads:
            thread.start()
        self.manifest = FixtureManifest(
            rest_url=f"http://127.0.0.1:{self._rest.server_address[1]}",
            target_url=f"http://127.0.0.1:{self._target.server_address[1]}",
            home=self.home,
            ledger_path=self.ledger_path,
            config_path=self.config_path,
            payload_dir=self.payload_dir,
        )

    def close(self) -> None:
        """Stop both servers and join their worker threads."""
        for server in (self._rest, self._target):
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)

    def __enter__(self) -> AuditFixture:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        self.close()

    def snapshot(self) -> FixtureSnapshot:
        """Capture REST and target effects at a point in the scenario."""
        return FixtureSnapshot(tuple(self._rest.state.effects), tuple(self._target.state.effects))

    def add_rest_route(
        self, method: str, path: str, *, status: int = 200, body: bytes = _DEFAULT_HEALTH
    ) -> None:
        """Register an exact REST method/path response before invoking the CLI."""
        self._rest.state.routes[(method.upper(), path)] = (status, body, "application/json", None)

    def add_target_route(
        self, method: str, path: str, *, status: int = 200, body: bytes = b""
    ) -> None:
        """Register an exact loopback target method/path response."""
        self._target.state.routes[(method.upper(), path)] = (status, body, "application/json", None)

    def expect_rest_route(
        self,
        method: str,
        path: str,
        *,
        expected_body: bytes,
        status: int = 200,
        body: bytes = _DEFAULT_HEALTH,
    ) -> None:
        """Register an exact route whose request body must match byte-for-byte."""
        self._rest.state.routes[(method.upper(), path)] = (
            status,
            body,
            "application/json",
            expected_body,
        )

    def command(self, executable: str = "burpctl") -> list[str]:
        """Return the installed console-script command executed by tests."""
        project = Path(__file__).resolve().parents[1]
        return ["uv", "run", "--frozen", "--project", str(project), executable]

    def run(
        self, argv: Sequence[str], *, executable: str = "burpctl"
    ) -> subprocess.CompletedProcess[str]:
        """Run an installed CLI with all audit state redirected into this fixture root."""
        allowed_origins = {_origin(self.manifest.rest_url), _origin(self.manifest.target_url)}
        for argument in argv:
            if (
                argument.startswith(("http://", "https://"))
                and _origin(argument) not in allowed_origins
            ):
                raise UnsafeTargetError(f"CLI URL must use a fixture target: {argument}")
        env = dict(os.environ)
        env.update(
            {
                "HOME": str(self.home),
                "BURP_REST_URL": self.manifest.rest_url,
                "BP_LEDGER_PATH": str(self.ledger_path),
                "BP_CONFIG_PATH": str(self.config_path),
                "BP_PAYLOAD_DIR": str(self.payload_dir),
                "BP_AGENT": "1",
                "NO_COLOR": "1",
                "TERM": "dumb",
            }
        )
        return subprocess.run(
            [*self.command(executable), *argv],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def target_request(self, url: str, *, method: str = "GET", body: bytes = b"") -> bytes:
        """Send one target request only after proving the URL is fixture loopback."""
        if not _loopback_target(url) or _origin(url) != _origin(self.manifest.target_url):
            raise UnsafeTargetError(
                f"target URL must use the fixture target origin (127.0.0.1): {url}"
            )
        request = urllib.request.Request(url, data=body or None, method=method.upper())
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return bytes(response.read())
        except urllib.error.HTTPError as error:
            return bytes(error.read())


class FixtureRoot:
    """Convenience context manager that creates and cleans a task-specific root."""

    def __init__(self, parent: Path) -> None:
        self._temporary = TemporaryDirectory(prefix="bp-audit-", dir=parent)
        self.fixture = AuditFixture(Path(self._temporary.name))

    def __enter__(self) -> AuditFixture:
        return self.fixture

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        self.fixture.close()
        self._temporary.cleanup()
