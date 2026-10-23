"""Typed wire models mirroring the Kotlin DTOs (the serialization contract, docs/SPEC.md §8).

The extension wraps every response in ``ApiResponse{success,data,error}`` with
``encodeDefaults=true`` (null fields are emitted). ``ignoreUnknownKeys=true`` server-side means
we may send a superset; we set ``extra="ignore"`` so we tolerate extra fields on responses too.
"""

from __future__ import annotations

from typing import Annotated, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

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
    """Mirrors the Kotlin ProxyEntry: request/response are NESTED, not flat (SPEC §8).

    Nullability mirrors ProxyModels.kt exactly:
      id: Int            — non-nullable, required
      request: HttpRequestData — non-nullable, required
      response: HttpResponseData? = null — nullable, optional
    """

    id: int
    request: HttpRequestData
    response: HttpResponseData | None = None
    timestamp: str | None = None
    listenerInterface: str | None = None
    clientIp: str | None = None


class ProxyHistory(_Wire):
    total: int
    entries: list[ProxyEntry]


class HistoryEntryResponse(_Wire):
    """Mirrors the Kotlin HistoryEntryResponse: flat shape (no nested request/response).

    Fields taken verbatim from HistoryModels.kt camelCase identifiers.

    Nullability matches HistoryModels.kt exactly:
      reqHeaders: List<HttpHeader>   — non-nullable, no Kotlin default → required, no Python default
      reqBody:    String?            — nullable
      statusCode: Int?               — nullable
      resHeaders: List<HttpHeader>?  — nullable
      resBody:    String?            — nullable
    """

    id: int
    source: str
    method: str
    url: str
    host: str
    reqHeaders: list[HttpHeader]
    reqBody: str | None = None
    statusCode: int | None = None
    resHeaders: list[HttpHeader] | None = None
    resBody: str | None = None
    durationMs: int
    timestamp: str


class HistoryPageResponse(_Wire):
    """Mirrors the Kotlin HistoryPageResponse page-wrapper shape."""

    entries: list[HistoryEntryResponse]
    total: int
    page: int
    pageSize: int


class RepeaterPersistence(_Wire):
    """Replay persistence outcome returned after the target request completes."""

    status: str
    historyPersisted: bool = False
    sitemapPersisted: bool = False
    historyId: int | None = None
    warning: str | None = None


class ReplayResponse(_Wire):
    """Mirrors the Kotlin ReplayResponse shape, including persistence metadata."""

    original: HistoryEntryResponse
    replayed: HistoryEntryResponse
    persistence: RepeaterPersistence = RepeaterPersistence(status="not_configured")


NonNegativeInt = Annotated[int, Field(ge=0)]


class _ScanWire(_Wire):
    """Strict wire types for security-scan responses from the Kotlin extension."""

    model_config = ConfigDict(extra="ignore", strict=True)


class AuthBypassProbeResult(_ScanWire):
    status: int | None
    length: int
    durationMs: int
    error: str | None = None
    inconclusiveReason: str | None = None
    inconclusive: bool = False


class AuthBypassEndpointResult(_ScanWire):
    endpoint: str
    withAuth: AuthBypassProbeResult
    withoutAuth: AuthBypassProbeResult
    cookieOnly: AuthBypassProbeResult
    vulnerable: bool
    inconclusive: bool = False
    errors: list[str] = Field(default_factory=list)


class IdorProbeResult(_ScanWire):
    value: str
    status: int | None
    length: int
    bodyPreview: str | None
    sameAsBaseline: bool
    vulnerable: bool
    inconclusive: bool = False
    error: str | None = None


class HeadersBypassResult(_ScanWire):
    header: str
    value: str
    status: int | None
    length: int
    anomalous: bool
    vulnerable: bool = False
    inconclusive: bool = False
    error: str | None = None


class CorsProbeResult(_ScanWire):
    origin: str
    acao: str | None
    acac: str | None
    vulnerable: bool
    status: int | None = None
    inconclusive: bool = False
    error: str | None = None


class EndpointFinding(_ScanWire):
    endpoint: str
    method: str
    test: str
    detail: str
    severity: str


class EndpointProbeError(_ScanWire):
    endpoint: str
    method: str
    test: str
    probe: str
    status: int | None = None
    error: str


class _ScanResponse(_ScanWire):
    """Typed optional fields tolerated when another scan DTO adds them to a response."""

    vulnerableCount: NonNegativeInt | None = None
    anomalousCount: NonNegativeInt | None = None
    inconclusiveCount: NonNegativeInt | None = None
    findings: list[EndpointFinding] | None = None
    errors: list[EndpointProbeError] | None = None
    note: str | None = None
    ignoredOwnValues: list[str] | None = None


class AuthBypassResponse(_ScanResponse):
    results: list[AuthBypassEndpointResult]
    totalScanned: NonNegativeInt
    vulnerableCount: NonNegativeInt
    inconclusiveCount: NonNegativeInt = 0


class IdorResponse(_ScanResponse):
    baseline: IdorProbeResult
    results: list[IdorProbeResult]
    vulnerableCount: NonNegativeInt
    inconclusiveCount: NonNegativeInt = 0
    ignoredOwnValues: list[str] = Field(default_factory=list)
    note: str | None = None


class HeadersBypassResponse(_ScanResponse):
    baseline: AuthBypassProbeResult
    results: list[HeadersBypassResult]
    anomalousCount: NonNegativeInt
    vulnerableCount: NonNegativeInt = 0
    inconclusiveCount: NonNegativeInt = 0


class CorsResponse(_ScanResponse):
    results: list[CorsProbeResult]
    vulnerableCount: NonNegativeInt
    inconclusiveCount: NonNegativeInt = 0


class EndpointsScanResponse(_ScanResponse):
    scanned: NonNegativeInt
    findings: list[EndpointFinding]
    durationMs: NonNegativeInt
    source: str = "extension-h2-send-history"
    sourceCounts: dict[str, NonNegativeInt] = Field(default_factory=dict)
    errors: list[EndpointProbeError] = Field(default_factory=list)
    inconclusiveCount: NonNegativeInt = 0
