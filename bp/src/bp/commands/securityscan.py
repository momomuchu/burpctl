"""bp check — custom security-scan probes via /scan/* (SPEC §6.7).

All five sub-commands are Community-compatible and synchronous/blocking.
``bp check endpoints`` reads only extension-owned H2 history produced by
Repeater/session sends; it does not read ordinary Burp proxy-listener history.

The session must be loaded (``bp session set …``) before auth probes will
carry credentials; otherwise probes run unauthenticated.
"""

from __future__ import annotations

from typing import Any, Literal, cast, overload

import typer

from bp.client import BurpError
from bp.cliutil import EXIT_VULN, parse_headers, run


# ---------------------------------------------------------------------------
# Output-hygiene helpers (AX-CAP-BODY / [02] PII-leak / [13] NDJSON pollution)
# ---------------------------------------------------------------------------


def _strip_body_preview(obj: Any) -> Any:
    """Recursively remove every ``bodyPreview`` key from dicts/lists.

    bodyPreview is opt-in per AX-CAP-BODY (OUTPUT.md §4.5); it must never
    appear in default stdout output because it carries raw HTTP response bytes
    that can include victim PII (SSN, email, session tokens).
    """
    if isinstance(obj, dict):
        return {k: _strip_body_preview(v) for k, v in obj.items() if k != "bodyPreview"}
    if isinstance(obj, list):
        return [_strip_body_preview(item) for item in obj]
    return obj


@overload
def _project_for_display(
    data: dict[str, Any], return_note: Literal[False] = ...
) -> dict[str, Any]: ...


@overload
def _project_for_display(
    data: dict[str, Any], return_note: Literal[True]
) -> tuple[dict[str, Any], str]: ...


def _project_for_display(
    data: dict[str, Any],
    return_note: bool = False,
) -> "dict[str, Any] | tuple[dict[str, Any], str]":
    """Project a security-scan response dict for display on stdout.

    Applies three transformations required before the dict is rendered:

    1. Recursively remove every ``bodyPreview`` key (AX-CAP-BODY — opt-in only).
    2. Pop ``note`` from the dict; the caller echoes it to stderr so stdout stays
       clean for NDJSON/machine consumers ([13]).
    3. Drop ``ignoredOwnValues`` when it is an empty list — it clutters output
       without adding information ([13]).  Non-empty values are preserved.

    The critical fields for ``_has_findings`` — ``vulnerableCount`` and
    ``findings`` — are always preserved. ``anomalousCount`` remains an
    observation-only signal and never selects the vulnerability exit code.

    When ``return_note=True`` (used in unit tests), returns ``(projected, note)``
    as a 2-tuple so callers can assert on the extracted note text.
    When ``return_note=False`` (default, used in command ``_do`` wrappers), returns
    only the projected dict.
    """
    projected: dict[str, Any] = cast(dict[str, Any], _strip_body_preview(data))

    note: str = projected.pop("note", "") or ""

    # Drop ignoredOwnValues only when empty — non-empty carries useful context.
    if "ignoredOwnValues" in projected and projected["ignoredOwnValues"] == []:
        del projected["ignoredOwnValues"]

    # [09] Inject one-word verdict for --format quiet (OUTPUT.md §1.5 R-ESSENTIAL).
    # A probe that never completed is neither a finding nor a clean result, so it gets its
    # own verdict rather than being reported as "clean". This is additive — json/table still
    # render the full structured response.
    if _has_findings(projected):
        projected["verdict"] = "vulnerable"
    elif _is_inconclusive(projected):
        projected["verdict"] = "inconclusive"
    else:
        projected["verdict"] = "clean"

    if return_note:
        return projected, note
    return projected


def _has_findings(data: dict[str, Any]) -> bool:
    """Return True when a security-scan response reports at least one finding.

    Covers:
    - vulnerableCount > 0        (auth-bypass, IDOR, CORS, confirmed header bypass)
    - len(findings) > 0          (EndpointsScanResponse shape for check endpoints)

    ``anomalousCount`` is intentionally excluded: a changed response is a
    triage observation, not proof that access improved or a vulnerability exists.
    """
    if data.get("vulnerableCount", 0) > 0:
        return True
    if len(data.get("findings", [])) > 0:
        return True
    return False


def _validate_scan_verdict(
    data: dict[str, Any], finding_field: Literal["vulnerableCount", "findings"]
) -> dict[str, Any]:
    """Reject malformed fields that determine a security-scan verdict.

    Scan responses have two finding indicators: a non-negative ``vulnerableCount``
    for individual probes, or a ``findings`` list for the endpoint sweep. Optional
    inconclusive fields are validated too because they distinguish an uncertain
    scan from a clean one.
    """

    def invalid() -> None:
        raise BurpError(
            "INVALID_RESPONSE",
            "server returned an unexpected response shape",
        )

    if finding_field not in data:
        invalid()

    for field in ("vulnerableCount", "anomalousCount", "inconclusiveCount"):
        if field in data:
            value = data[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                invalid()

    for field in ("findings", "errors"):
        if field in data and not isinstance(data[field], list):
            invalid()

    return data


def _is_inconclusive(data: dict[str, Any]) -> bool:
    """Return True when at least one probe did not complete well enough to judge.

    The extension marks a probe inconclusive when its treatment or control failed —
    transport failure, throttling, a server error, or a missing authenticated baseline.
    Such a scan proves nothing, so it must not be presented as a clean result.
    """
    if data.get("inconclusiveCount", 0) > 0:
        return True
    if len(data.get("errors", [])) > 0:
        return True
    for value in data.values():
        if isinstance(value, list) and any(
            isinstance(item, dict) and item.get("inconclusive") for item in value
        ):
            return True
    if isinstance(data.get("baseline"), dict) and data["baseline"].get("inconclusive"):
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
    url: str = typer.Argument(
        ..., metavar="URL", help="Target base URL (e.g. https://example.com)."
    ),
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

    def _do(client: Any) -> Any:
        return _validate_scan_verdict(client.post("/scan/auth-bypass", body), "vulnerableCount")

    run(ctx, _do, exit_on=lambda d: EXIT_VULN if _has_findings(d) else None)


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
    """Cross-account IDOR probe: flags a target when its full response body differs from the
    own-resource baseline (content-primary, with an empty-vs-non-empty guard) AND both return 2xx
    and the baseline itself succeeded. Catches same-length, different-content records.

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

    def _do(client: Any) -> Any:
        raw = _validate_scan_verdict(client.post("/scan/idor", req_body), "vulnerableCount")
        # [02] Strip bodyPreview (AX-CAP-BODY) and [13] route note to stderr.
        projected, note = _project_for_display(raw, return_note=True)
        if note:
            typer.echo(f"note: {note}", err=True)
        return projected

    run(ctx, _do, exit_on=lambda d: EXIT_VULN if _has_findings(d) else None)


# ---------------------------------------------------------------------------
# bp check headers <url>
# ---------------------------------------------------------------------------


@sub.command("headers")
def check_headers(
    ctx: typer.Context,
    url: str = typer.Argument(
        ..., metavar="URL", help="Target URL to test for header-based 403 bypass."
    ),
    method: str = typer.Option("GET", "--method", help="HTTP method."),
    body: str | None = typer.Option(None, "--body", help="Optional request body string."),
    marker: str | None = typer.Option(
        None,
        "--marker",
        metavar="TEXT",
        help="Protected content that only an authorized response contains; required for a"
        " confirmed bypass verdict rather than an anomaly.",
    ),
) -> None:
    """Probe IP-spoof and URL-override headers against a denial baseline.

    Sends HeadersBypassRequest { url, method, body?, protectedContentMarker? } to
    POST /scan/headers. Without ``--marker`` a changed response is reported as an
    anomaly for triage; the server confirms a bypass only when the marker is absent
    from the denial control and present in the successful treatment.
    """
    req_body: dict[str, Any] = {
        "url": url,
        "method": method,
    }
    if body is not None:
        req_body["body"] = body
    if marker is not None:
        req_body["protectedContentMarker"] = marker

    def _do(client: Any) -> Any:
        return _validate_scan_verdict(client.post("/scan/headers", req_body), "vulnerableCount")

    run(ctx, _do, exit_on=lambda d: EXIT_VULN if _has_findings(d) else None)


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

    def _do(client: Any) -> Any:
        return _validate_scan_verdict(client.post("/scan/cors", req_body), "vulnerableCount")

    run(ctx, _do, exit_on=lambda d: EXIT_VULN if _has_findings(d) else None)


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
        help="Hostname to sweep from extension-owned send history (e.g. example.com).",
    ),
    tests: list[str] = typer.Option(
        _DEFAULT_TESTS,
        "--test",
        help="Test type(s) to run per endpoint (repeatable). Default: auth-bypass method-switch.",
    ),
    limit: int = typer.Option(
        100, "--limit", help="Maximum number of extension-history requests to scan."
    ),
) -> None:
    """Scan requests recorded by extension-driven Repeater/session sends.

    This requires the extension's H2 store. Unavailable storage returns
    ``SERVICE_UNAVAILABLE`` rather than an empty clean result.
    """
    req_body: dict[str, Any] = {
        "host": host,
        "tests": tests,
        "limit": limit,
    }

    def _do(client: Any) -> Any:
        return _validate_scan_verdict(client.post("/scan/endpoints", req_body), "findings")

    run(ctx, _do, exit_on=lambda d: EXIT_VULN if _has_findings(d) else None)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register the ``check`` sub-typer onto the root ``bp`` app."""
    app.add_typer(sub, name="check")
