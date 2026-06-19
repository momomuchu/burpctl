"""bp check — custom security-scan probes via /scan/* (SPEC §6.7).

All five sub-commands are Community-compatible and synchronous/blocking.
``bp check endpoints`` additionally requires the SQLite DB to be initialised
inside the extension (503 SERVICE_UNAVAILABLE if absent).

The session must be loaded (``bp session set …``) before auth probes will
carry credentials; otherwise probes run unauthenticated.
"""

from __future__ import annotations

from typing import Any

import typer

from bp.cliutil import EXIT_VULN, parse_headers, run


def _has_findings(data: dict[str, Any]) -> bool:
    """Return True when a security-scan response reports at least one finding.

    Covers:
    - vulnerableCount > 0   (auth-bypass, IDOR, CORS, endpoints)
    - anomalousCount > 0    (headers bypass)
    """
    if data.get("vulnerableCount", 0) > 0:
        return True
    if data.get("anomalousCount", 0) > 0:
        return True
    return False

# ---------------------------------------------------------------------------
# Sub-typer
# ---------------------------------------------------------------------------

sub = typer.Typer(
    name="check",
    no_args_is_help=True,
    help="Security-scan probes: auth-bypass, IDOR, headers, CORS, endpoint sweep.",
)


# ---------------------------------------------------------------------------
# bp check auth <url>
# ---------------------------------------------------------------------------


@sub.command("auth")
def check_auth(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target base URL (e.g. https://example.com)."),
    endpoints: list[str] = typer.Option(
        ["/api/admin"],
        "--endpoint",
        help="Endpoint path(s) to probe for auth-bypass (repeatable).",
    ),
    method: str = typer.Option("GET", "--method", help="HTTP method for each probe."),
) -> None:
    """Triple-probe auth-bypass: with-auth / without-auth / cookie-only.

    Sends AuthBypassRequest { endpoints, baseUrl, method } to POST /scan/auth-bypass.
    A session must be active (bp session set …) for the authenticated leg to carry
    credentials; without one the probe runs fully unauthenticated.
    """
    body: dict[str, Any] = {
        "endpoints": endpoints,
        "baseUrl": url,
        "method": method,
    }
    _result: dict[str, Any] = {}

    def _do(client: Any) -> Any:
        resp = client.post("/scan/auth-bypass", body)
        if isinstance(resp, dict):
            _result.update(resp)
        return resp

    run(ctx, _do)
    if _has_findings(_result):
        raise typer.Exit(EXIT_VULN)


# ---------------------------------------------------------------------------
# bp check idor <url>
# ---------------------------------------------------------------------------


@sub.command("idor")
def check_idor(
    ctx: typer.Context,
    url: str = typer.Argument(
        ...,
        metavar="URL",
        help="Target endpoint URL (may contain {param} placeholder, e.g. https://t/orders/{id}).",
    ),
    param: str = typer.Option(..., "--param", help="Parameter name that carries the object ID."),
    own: list[str] = typer.Option(
        ...,
        "--own",
        help="ID value(s) owned by the authenticated user (repeatable).",
    ),
    target: list[str] = typer.Option(
        ...,
        "--target",
        help="ID value(s) belonging to another account to test for cross-account access (repeatable).",
    ),
    method: str = typer.Option("GET", "--method", help="HTTP method."),
    body: str | None = typer.Option(None, "--body", help="Optional request body string."),
    header: list[str] = typer.Option(
        [],
        "--header",
        help="Extra header as 'Name: Value' (repeatable).",
    ),
) -> None:
    """Cross-account IDOR probe (>5 % delta-length or status 2xx).

    Sends IdorRequest { endpoint, param, ownValues, targetValues, method, body?,
    extraHeaders? } to POST /scan/idor.
    """
    # Shared helper → consistent 'Name: Value' parsing and exit 2 (was a hardcoded literal here).
    extra_headers: dict[str, str] | None = parse_headers(header, "--header") or None

    req_body: dict[str, Any] = {
        "endpoint": url,
        "param": param,
        "ownValues": own,
        "targetValues": target,
        "method": method,
    }
    if body is not None:
        req_body["body"] = body
    if extra_headers is not None:
        req_body["extraHeaders"] = extra_headers

    _result: dict[str, Any] = {}

    def _do(client: Any) -> Any:
        resp = client.post("/scan/idor", req_body)
        if isinstance(resp, dict):
            _result.update(resp)
        return resp

    run(ctx, _do)
    if _has_findings(_result):
        raise typer.Exit(EXIT_VULN)


# ---------------------------------------------------------------------------
# bp check headers <url>
# ---------------------------------------------------------------------------


@sub.command("headers")
def check_headers(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL to test for header-based 403 bypass."),
    method: str = typer.Option("GET", "--method", help="HTTP method."),
    body: str | None = typer.Option(None, "--body", help="Optional request body string."),
) -> None:
    """16 IP-spoof / URL-override headers → 403-bypass probe.

    Sends HeadersBypassRequest { url, method, body? } to POST /scan/headers.
    The extension tries 16 fixed bypass headers (X-Forwarded-For, X-Real-IP,
    X-Original-URL, X-Rewrite-URL, …) and reports which ones alter the response.
    """
    req_body: dict[str, Any] = {
        "url": url,
        "method": method,
    }
    if body is not None:
        req_body["body"] = body

    _result: dict[str, Any] = {}

    def _do(client: Any) -> Any:
        resp = client.post("/scan/headers", req_body)
        if isinstance(resp, dict):
            _result.update(resp)
        return resp

    run(ctx, _do)
    if _has_findings(_result):
        raise typer.Exit(EXIT_VULN)


# ---------------------------------------------------------------------------
# bp check cors <url>
# ---------------------------------------------------------------------------


@sub.command("cors")
def check_cors(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL to test for exploitable CORS."),
    method: str = typer.Option("GET", "--method", help="HTTP method."),
) -> None:
    """8 crafted origins → credentialed CORS-exploit probe.

    Sends CorsRequest { url, method } to POST /scan/cors.
    The extension tries 8 fixed origin variants and flags responses that reflect
    an attacker-controlled origin alongside Access-Control-Allow-Credentials: true.
    """
    req_body: dict[str, Any] = {
        "url": url,
        "method": method,
    }
    _result: dict[str, Any] = {}

    def _do(client: Any) -> Any:
        resp = client.post("/scan/cors", req_body)
        if isinstance(resp, dict):
            _result.update(resp)
        return resp

    run(ctx, _do)
    if _has_findings(_result):
        raise typer.Exit(EXIT_VULN)


# ---------------------------------------------------------------------------
# bp check endpoints <host>
# ---------------------------------------------------------------------------

_DEFAULT_TESTS = ["auth-bypass", "method-switch"]


@sub.command("endpoints")
def check_endpoints(
    ctx: typer.Context,
    host: str = typer.Argument(
        ...,
        metavar="HOST",
        help="Hostname to sweep from the proxy history DB (e.g. example.com).",
    ),
    tests: list[str] = typer.Option(
        _DEFAULT_TESTS,
        "--test",
        help="Test type(s) to run per endpoint (repeatable). Default: auth-bypass method-switch.",
    ),
    limit: int = typer.Option(100, "--limit", help="Maximum number of proxy-history entries to scan."),
) -> None:
    """Bulk-scan proxy-history endpoints for a host.

    Sends EndpointsScanRequest { host, tests, limit } to POST /scan/endpoints.

    CAVEAT: this endpoint requires the SQLite DB to be initialised inside the
    extension (~/.burp-rest/burpdata).  The server returns 503 SERVICE_UNAVAILABLE
    if the DB is absent — bp will surface that as an error rather than silently
    returning empty results.
    """
    req_body: dict[str, Any] = {
        "host": host,
        "tests": tests,
        "limit": limit,
    }
    _result: dict[str, Any] = {}

    def _do(client: Any) -> Any:
        resp = client.post("/scan/endpoints", req_body)
        if isinstance(resp, dict):
            _result.update(resp)
        return resp

    run(ctx, _do)
    if _has_findings(_result):
        raise typer.Exit(EXIT_VULN)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register the ``check`` sub-typer onto the root ``bp`` app."""
    app.add_typer(sub, name="check")
