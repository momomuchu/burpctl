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

from bp.cliutil import (
    EXIT_GENERIC,
    EXIT_VULN,
    emit_error,
    emit_warning,
    parse_headers,
    resolve_redaction,
    run,
)


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


def _is_inconclusive(data: dict[str, Any]) -> bool:
    """Use the server's authoritative top-level count; do not infer probe cardinality."""
    count = data.get("inconclusiveCount", 0)
    return isinstance(count, int) and not isinstance(count, bool) and count > 0


_DEFAULT_PROBE_TIMEOUT_MS = 5_000
_MIN_PROBE_TIMEOUT_MS = 100
_MAX_PROBE_TIMEOUT_MS = 120_000
_MAX_CHECK_PROBES = 8_000
_MAX_PROBE_BUDGET_MS = _MAX_CHECK_PROBES * _MAX_PROBE_TIMEOUT_MS
_MAX_OPERATION_TIMEOUT_MS = _MAX_PROBE_BUDGET_MS + max(5_000, _MAX_PROBE_BUDGET_MS // 10) + 5_000


def _operation_timeout_seconds(
    probe_count: int,
    probe_timeout_ms: int,
    operation_timeout_ms: int | None,
) -> float:
    """Derive a whole-operation deadline from this invocation's maximum sequential probe plan."""
    if operation_timeout_ms is not None:
        return operation_timeout_ms / 1_000
    # Python integers do not wrap.  An adaptive margin (at least five seconds) plus five seconds of
    # fixed overhead admits server work, serialization, and REST transport without applying one
    # enormous timeout to every check.
    probe_budget_ms = max(probe_count, 0) * probe_timeout_ms
    deadline_ms = probe_budget_ms + max(5_000, probe_budget_ms // 10) + 5_000
    return min(deadline_ms, _MAX_OPERATION_TIMEOUT_MS) / 1_000


def _timeout_options(
    probe_count: int,
    probe_timeout_ms: int,
    operation_timeout_ms: int | None,
) -> float:
    # Typer validates normal CLI calls; this guard also protects direct Python callers and makes the
    # domain independent of presentation-library behavior.
    if not _MIN_PROBE_TIMEOUT_MS <= probe_timeout_ms <= _MAX_PROBE_TIMEOUT_MS:
        raise ValueError(
            f"probe timeout must be between {_MIN_PROBE_TIMEOUT_MS} and "
            f"{_MAX_PROBE_TIMEOUT_MS} milliseconds"
        )
    if (
        operation_timeout_ms is not None
        and not 1 <= operation_timeout_ms <= _MAX_OPERATION_TIMEOUT_MS
    ):
        raise ValueError(
            f"operation timeout must be between 1 and {_MAX_OPERATION_TIMEOUT_MS} milliseconds"
        )
    return _operation_timeout_seconds(probe_count, probe_timeout_ms, operation_timeout_ms)


def _scan_exit_code(data: dict[str, Any]) -> int | None:
    """Apply the stable finding > inconclusive > clean process-exit precedence."""
    if _has_findings(data):
        return EXIT_VULN
    count = data.get("inconclusiveCount", 0)
    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        return EXIT_GENERIC
    return None


def _scan_exit(ctx: typer.Context, data: dict[str, Any]) -> int | None:
    exit_code = _scan_exit_code(data)
    if exit_code == EXIT_GENERIC:
        emit_error(
            ctx.obj.fmt,
            "INCONCLUSIVE",
            "one or more probes were inconclusive; no confirmed finding was reported",
            redact_secrets=resolve_redaction(ctx.obj),
        )
    return exit_code


# ---------------------------------------------------------------------------
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
    marker: str | None = typer.Option(
        None,
        "--marker",
        metavar="TEXT",
        help="Server-held content that the unauthenticated probe never supplies; required for a"
        " confirmed protected-read verdict.",
    ),
    probe_timeout_ms: int = typer.Option(
        _DEFAULT_PROBE_TIMEOUT_MS,
        "--probe-timeout-ms",
        min=_MIN_PROBE_TIMEOUT_MS,
        max=_MAX_PROBE_TIMEOUT_MS,
        help="Timeout for one target probe, in milliseconds (default 5000).",
    ),
    operation_timeout_ms: int | None = typer.Option(
        None,
        "--deadline-ms",
        min=1,
        max=_MAX_OPERATION_TIMEOUT_MS,
        help="Override the derived deadline for the entire check command, in milliseconds.",
    ),
) -> None:
    """Three-arm auth probe: FULL, NONE, and COOKIES_ONLY.

    Without a server-held marker, `check auth` cannot distinguish a cookie-only bypass where FULL,
    COOKIES_ONLY, and NONE all return the same representation from an intentionally public route;
    that case is not confirmed. Pass ``--marker`` to require the substantive successful NONE response
    to contain a server-held value that the probe never supplies.
    """
    body: dict[str, Any] = {
        "endpoints": endpoints,
        "baseUrl": url,
        "method": method,
        "probeTimeoutMs": probe_timeout_ms,
    }
    if marker is not None:
        body["protectedContentMarker"] = marker
    timeout = _timeout_options(len(endpoints) * 3, probe_timeout_ms, operation_timeout_ms)

    def _do(client: Any) -> Any:
        return _project_for_display(client.post("/scan/auth-bypass", body))

    run(ctx, _do, exit_on=lambda d: _scan_exit(ctx, d), timeout=timeout)


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
    probe_timeout_ms: int = typer.Option(
        _DEFAULT_PROBE_TIMEOUT_MS,
        "--probe-timeout-ms",
        min=_MIN_PROBE_TIMEOUT_MS,
        max=_MAX_PROBE_TIMEOUT_MS,
        help="Timeout for one target probe, in milliseconds (default 5000).",
    ),
    operation_timeout_ms: int | None = typer.Option(
        None,
        "--deadline-ms",
        min=1,
        max=_MAX_OPERATION_TIMEOUT_MS,
        help="Override the derived deadline for the entire check command, in milliseconds.",
    ),
) -> None:
    """Cross-account IDOR probe: flags a target when its full response body differs from the
    own-resource baseline (content-primary, with an empty-vs-non-empty guard) AND both return 2xx
    and the baseline itself succeeded. Catches same-length, different-content records.

    Sends IdorRequest { endpoint, param, ownValues, targetValues, method, body?,
    extraHeaders? } to POST /scan/idor.
    """
    # Shared helper → consistent 'Name: Value' parsing and exit 2 (was a hardcoded literal here).
    extra_headers: dict[str, str] | None = parse_headers(header, "--header", ctx) or None

    req_body: dict[str, Any] = {
        "endpoint": url,
        "param": param,
        "ownValues": own,
        "targetValues": target,
        "method": method,
        "probeTimeoutMs": probe_timeout_ms,
    }
    if body is not None:
        req_body["body"] = body
    if extra_headers is not None:
        req_body["extraHeaders"] = extra_headers

    def _do(client: Any) -> Any:
        raw = client.post("/scan/idor", req_body)
        # [02] Strip bodyPreview (AX-CAP-BODY) and [13] route note to stderr.
        projected, note = _project_for_display(raw, return_note=True)
        if note:
            emit_warning(
                ctx.obj.fmt,
                "OPERATION_NOTE",
                note,
                redact_secrets=resolve_redaction(ctx.obj),
            )
        return projected

    timeout = _timeout_options(1 + len(target), probe_timeout_ms, operation_timeout_ms)
    run(ctx, _do, exit_on=lambda d: _scan_exit(ctx, d), timeout=timeout)


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
    probe_timeout_ms: int = typer.Option(
        _DEFAULT_PROBE_TIMEOUT_MS,
        "--probe-timeout-ms",
        min=_MIN_PROBE_TIMEOUT_MS,
        max=_MAX_PROBE_TIMEOUT_MS,
        help="Timeout for one target probe, in milliseconds (default 5000).",
    ),
    operation_timeout_ms: int | None = typer.Option(
        None,
        "--deadline-ms",
        min=1,
        max=_MAX_OPERATION_TIMEOUT_MS,
        help="Override the derived deadline for the entire check command, in milliseconds.",
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
        "probeTimeoutMs": probe_timeout_ms,
    }
    if body is not None:
        req_body["body"] = body
    if marker is not None:
        req_body["protectedContentMarker"] = marker

    def _do(client: Any) -> Any:
        return _project_for_display(client.post("/scan/headers", req_body))

    timeout = _timeout_options(17, probe_timeout_ms, operation_timeout_ms)
    run(ctx, _do, exit_on=lambda d: _scan_exit(ctx, d), timeout=timeout)


# ---------------------------------------------------------------------------
# bp check cors <url>
# ---------------------------------------------------------------------------


@sub.command("cors")
def check_cors(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL to test for exploitable CORS."),
    method: str = typer.Option("GET", "--method", help="HTTP method."),
    probe_timeout_ms: int = typer.Option(
        _DEFAULT_PROBE_TIMEOUT_MS,
        "--probe-timeout-ms",
        min=_MIN_PROBE_TIMEOUT_MS,
        max=_MAX_PROBE_TIMEOUT_MS,
        help="Timeout for one target probe, in milliseconds (default 5000).",
    ),
    operation_timeout_ms: int | None = typer.Option(
        None,
        "--deadline-ms",
        min=1,
        max=_MAX_OPERATION_TIMEOUT_MS,
        help="Override the derived deadline for the entire check command, in milliseconds.",
    ),
) -> None:
    """8 crafted origins → credentialed CORS-exploit probe.

    Sends CorsRequest { url, method } to POST /scan/cors.
    The extension tries 8 fixed origin variants and flags responses that reflect
    an attacker-controlled origin alongside Access-Control-Allow-Credentials: true.
    """
    req_body: dict[str, Any] = {
        "url": url,
        "method": method,
        "probeTimeoutMs": probe_timeout_ms,
    }

    def _do(client: Any) -> Any:
        return _project_for_display(client.post("/scan/cors", req_body))

    timeout = _timeout_options(8, probe_timeout_ms, operation_timeout_ms)
    run(ctx, _do, exit_on=lambda d: _scan_exit(ctx, d), timeout=timeout)


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
        100,
        "--limit",
        min=1,
        max=1000,
        help="Maximum number of extension-history requests to scan.",
    ),
    probe_timeout_ms: int = typer.Option(
        _DEFAULT_PROBE_TIMEOUT_MS,
        "--probe-timeout-ms",
        min=_MIN_PROBE_TIMEOUT_MS,
        max=_MAX_PROBE_TIMEOUT_MS,
        help="Timeout for one target probe, in milliseconds (default 5000).",
    ),
    operation_timeout_ms: int | None = typer.Option(
        None,
        "--deadline-ms",
        min=1,
        max=_MAX_OPERATION_TIMEOUT_MS,
        help="Override the derived deadline for the entire check command, in milliseconds.",
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
        "probeTimeoutMs": probe_timeout_ms,
    }

    def _do(client: Any) -> Any:
        return _project_for_display(client.post("/scan/endpoints", req_body))

    probes_per_entry = sum({"auth-bypass": 2, "method-switch": 6}.get(test, 0) for test in tests)
    timeout = _timeout_options(limit * probes_per_entry, probe_timeout_ms, operation_timeout_ms)
    run(ctx, _do, exit_on=lambda d: _scan_exit(ctx, d), timeout=timeout)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register the ``check`` sub-typer onto the root ``bp`` app."""
    app.add_typer(sub, name="check")
