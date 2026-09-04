"""HTTP client for the burp-rest-extension on :8089.

Unwraps the ``ApiResponse{success,data,error}`` envelope and raises typed errors
(``BurpError`` / ``BurpUnreachable``). Inject an ``httpx.Client`` for tests (MockTransport).
When a ``Ledger`` is provided, every HTTP op is recorded (ADR-0005: Run Ledger ON by default)
— sha256 fingerprints only, never raw bodies; the command line is redacted if ``redact`` is set.
"""

from __future__ import annotations

import json as _json
import time
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

import httpx

from bp.config import DEFAULT_BASE_URL as DEFAULT_BASE_URL  # re-exported (single source in config)
from bp.config import redact as _redact_text
from bp.ledger import Ledger, OpRecord
from bp.models import ApiResponse, HealthData, VersionData


def _netloc_no_userinfo(url: str) -> str | None:
    """Return ``host:port`` (or just ``host``) from *url*, stripping any ``user:password@`` userinfo.

    This is used for the ledger ``target`` column so credentials embedded in
    ``BURP_REST_URL`` (e.g. ``http://admin:s3cr3t@host:8089``) are never
    written to ``~/.bp/ledger.db`` at rest.  Only the network address is kept.
    """
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host


def _operation_path(path: str) -> str:
    """Return a query-free, userinfo-free path for ledger/error metadata."""
    parsed = urlsplit(path)
    clean_path = parsed.path or "/"
    return clean_path


class BurpError(Exception):
    """REST API failure with stable code and optional response metadata.

    ``status`` and ``op`` are optional so the established two-argument constructor
    remains valid for command modules and tests that synthesize errors locally.
    """

    def __init__(
        self,
        code: str,
        message: str,
        status: int | None = None,
        op: str | None = None,
        *,
        http_status: int | None = None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        selected_status = status if status is not None else http_status
        self.status = selected_status
        self.http_status = selected_status
        self.status_code = selected_status
        self.op = op
        self.operation = op


class BurpUnreachable(BurpError):
    """Burp / the REST extension is not reachable on the configured URL."""


class BurpClient:
    """Thin typed client over the burp-rest-extension, with optional Run Ledger recording."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
        ledger: Ledger | None = None,
        redact: bool = True,
        command: str | None = None,
    ) -> None:
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout)
        self._ledger = ledger
        self._redact = redact
        self._command = command
        self._op_ids: list[str] = []

    @property
    def op_ids(self) -> list[str]:
        """Ledger ids recorded during this client's lifetime (for exit-code back-fill)."""
        return self._op_ids

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> BurpClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _record(
        self,
        method: str,
        path: str,
        req_identity: Any,
        resp: httpx.Response | None,
        status: str,
        error_code: str | None,
        start: float,
    ) -> None:
        if self._ledger is None:
            return
        cmd = self._command
        if cmd is not None and self._redact:
            cmd = _redact_text(cmd)
        if isinstance(req_identity, (bytes, bytearray)):
            req_body = bytes(req_identity)
        elif req_identity is not None:
            req_body = _json.dumps(req_identity).encode()
        else:
            req_body = None
        op_id = self._ledger.record(
            OpRecord(
                status=status,
                command=cmd,
                burp_op=f"{method} {_operation_path(path)}",
                target=_netloc_no_userinfo(str(self._client.base_url)),
                resp_status=resp.status_code if resp is not None else None,
                resp_len=len(resp.content) if resp is not None else None,
                req_body=req_body,
                resp_body=resp.content if resp is not None else None,
                duration_ms=int((time.monotonic() - start) * 1000),
                error_code=error_code,
            )
        )
        if op_id:
            self._op_ids.append(op_id)

    def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json: Any = None
    ) -> dict[str, Any]:
        start = time.monotonic()
        operation = f"{method} {_operation_path(path)}"
        # A GET has no body, but its exact encoded query bytes are part of
        # transmitted request identity. Build locally to obtain the same httpx
        # encoding even when transport later fails; only their digest persists.
        if method.upper() == "GET":
            prepared = self._client.build_request(method, path, params=params)
            query = prepared.url.query
            req_identity: Any = query if query else None
        else:
            req_identity = json
        try:
            resp = self._client.request(method, path, params=params, json=json)
        except httpx.TransportError as e:
            # ConnectError, timeouts, read/write/protocol errors — all network-level failures.
            code = "CONNECTION_REFUSED" if isinstance(e, httpx.ConnectError) else "TRANSPORT_ERROR"
            self._record(method, path, req_identity, None, "error", code, start)
            raise BurpUnreachable(
                code,
                f"Burp REST unreachable: {e}",
                op=operation,
            ) from e
        try:
            env = ApiResponse[dict[str, Any]].model_validate_json(resp.content)
        except ValueError as e:
            # Non-JSON / empty body (e.g. 404 on an unwired route): a server error, not CLI usage.
            self._record(method, path, req_identity, resp, "error", "INVALID_RESPONSE", start)
            raise BurpError(
                "INVALID_RESPONSE",
                f"server returned non-JSON (HTTP {resp.status_code})",
                status=resp.status_code,
                op=operation,
            ) from e
        if not env.success or env.error is not None:
            err = env.error
            code = err.code if err else "ERROR"
            self._record(method, path, req_identity, resp, "error", code, start)
            raise BurpError(
                code,
                err.message if err else "unknown error",
                status=resp.status_code,
                op=operation,
            )
        self._record(method, path, req_identity, resp, "ok", None, start)
        return env.data if env.data is not None else {}

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        return self._request("GET", path, params=params or None)

    def post(self, path: str, json: Any = None) -> dict[str, Any]:
        return self._request("POST", path, json=json)

    def health(self) -> HealthData:
        return HealthData.model_validate(self.get("/health"))

    def version(self) -> VersionData:
        return VersionData.model_validate(self.get("/version"))
