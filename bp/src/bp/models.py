"""Typed wire models mirroring the Kotlin DTOs (the serialization contract, docs/SPEC.md §8).

The extension wraps every response in ``ApiResponse{success,data,error}`` with
``encodeDefaults=true`` (null fields are emitted). ``ignoreUnknownKeys=true`` server-side means
we may send a superset; we set ``extra="ignore"`` so we tolerate extra fields on responses too.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class _Wire(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ApiError(_Wire):
    code: str
    message: str


class ApiResponse(_Wire, Generic[T]):
    success: bool
    data: T | None = None
    error: ApiError | None = None


class HealthData(_Wire):
    status: str
    version: str
    uptime: int
    burpVersion: str | None = None


class VersionData(_Wire):
    version: str
    name: str
    burpVersion: str | None = None


class HttpHeader(_Wire):
    name: str
    value: str


class HttpRequestData(_Wire):
    method: str
    url: str
    headers: list[HttpHeader] = []
    body: str | None = None


class HttpResponseData(_Wire):
    statusCode: int
    headers: list[HttpHeader] = []
    body: str | None = None


class ProxyEntry(_Wire):
    """Mirrors the Kotlin ProxyEntry: request/response are NESTED, not flat (SPEC §8)."""

    id: int | None = None
    request: HttpRequestData | None = None
    response: HttpResponseData | None = None
    timestamp: str | None = None
    listenerInterface: str | None = None
    clientIp: str | None = None


class ProxyHistory(_Wire):
    total: int
    entries: list[ProxyEntry] = []
