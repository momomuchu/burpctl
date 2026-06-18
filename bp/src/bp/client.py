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


class BurpError(Exception):
    """The REST API returned an error envelope. ``code`` is the stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


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
        req_json: Any,
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
        req_body = _json.dumps(req_json).encode() if req_json is not None else None
        op_id = self._ledger.record(
            OpRecord(
                status=status,
                command=cmd,
                burp_op=f"{method} {path}",
                target=urlsplit(str(self._client.base_url)).netloc or None,
                resp_status=resp.status_code if resp is not None else None,
                resp_len=len(resp.content) if resp is not None else None,
                req_body=req_body,
                resp_body=resp.content if resp is not None else None,
                duration_ms=int((time.monotonic() - start) * 1000),
                error_code=error_code,
            )
        )
        self._op_ids.append(op_id)

    def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json: Any = None
    ) -> dict[str, Any]:
        start = time.monotonic()
        try:
            resp = self._client.request(method, path, params=params, json=json)
        except httpx.TransportError as e:
            # ConnectError, timeouts, read/write/protocol errors — all network-level failures.
            code = "CONNECTION_REFUSED" if isinstance(e, httpx.ConnectError) else "TRANSPORT_ERROR"
            self._record(method, path, json, None, "error", code, start)
            raise BurpUnreachable(code, f"Burp REST unreachable: {e}") from e
        try:
            env = ApiResponse[dict[str, Any]].model_validate_json(resp.content)
        except ValueError as e:
            # Non-JSON / empty body (e.g. 404 on an unwired route): a server error, not CLI usage.
            self._record(method, path, json, resp, "error", "INVALID_RESPONSE", start)
            raise BurpError(
                "INVALID_RESPONSE", f"server returned non-JSON (HTTP {resp.status_code})"
            ) from e
        if not env.success or env.error is not None:
            err = env.error
            code = err.code if err else "ERROR"
            self._record(method, path, json, resp, "error", code, start)
            raise BurpError(code, err.message if err else "unknown error")
        self._record(method, path, json, resp, "ok", None, start)
        return env.data if env.data is not None else {}

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        return self._request("GET", path, params=params or None)

    def post(self, path: str, json: Any = None) -> dict[str, Any]:
        return self._request("POST", path, json=json)

    def health(self) -> HealthData:
        return HealthData.model_validate(self.get("/health"))

    def version(self) -> VersionData:
        return VersionData.model_validate(self.get("/version"))
