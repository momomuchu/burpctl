"""HTTP client for the burp-rest-extension on :8089.

Unwraps the ``ApiResponse{success,data,error}`` envelope and raises typed errors
(``BurpError`` / ``BurpUnreachable``). Inject an ``httpx.Client`` for tests (MockTransport).
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from bp.models import ApiResponse, HealthData, VersionData

DEFAULT_BASE_URL = "http://127.0.0.1:8089"


class BurpError(Exception):
    """The REST API returned an error envelope. ``code`` is the stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class BurpUnreachable(BurpError):
    """Burp / the REST extension is not reachable on the configured URL."""


class BurpClient:
    """Thin typed client over the burp-rest-extension."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        client: httpx.Client | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._client = client or httpx.Client(base_url=base_url, timeout=timeout)

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

    def _request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, json: Any = None
    ) -> dict[str, Any]:
        try:
            resp = self._client.request(method, path, params=params, json=json)
        except httpx.ConnectError as e:
            raise BurpUnreachable("CONNECTION_REFUSED", f"Burp REST unreachable: {e}") from e
        env = ApiResponse[dict[str, Any]].model_validate_json(resp.content)
        if not env.success or env.error is not None:
            err = env.error
            raise BurpError(
                err.code if err else "ERROR",
                err.message if err else "unknown error",
            )
        return env.data if env.data is not None else {}

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        return self._request("GET", path, params=params or None)

    def post(self, path: str, json: Any = None) -> dict[str, Any]:
        return self._request("POST", path, json=json)

    def health(self) -> HealthData:
        return HealthData.model_validate(self.get("/health"))

    def version(self) -> VersionData:
        return VersionData.model_validate(self.get("/version"))
