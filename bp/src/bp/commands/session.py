"""bp session command group — session cookie/header management and authenticated requests.

Commands (CLI.md):
  bp session set --json STR          load cookies+headers (POST /session/set, full replace)
  bp session get                     inspect the active session (GET /session/get)
  bp session clear                   reset credentials, origin, and captured jar (DELETE /session/clear)
  bp session send <url>              send an authenticated request (POST /session/send)
  bp session cookies                 show the auto-captured cookie-jar (GET /session/cookie-jar)

Request models (Kotlin source, SPEC §6.11):
  SetSessionRequest      { cookies:Map<String,String> (required), headers:Map?=null,
                           name:String?=null, origin:String?=null }
  AuthenticatedRequest   { method:String="GET", url:String (required), body:String?=null,
                           extraHeaders:Map<String,String>?=null }

SPEC §6.11 caveats surfaced on stderr:
  - POST /session/set is a *full replace* — overwrites all existing cookies and headers.
  - extraHeaders in /session/send *override* session headers (not additive).
  - The cookie-jar is in-memory only (not in DB); 'clear' and extension reload wipe it.
  - DELETE /session/clear atomically resets cookies, headers, origin, and the cookie-jar.
  - The entire /session group is absent from the embedded /docs OpenAPI.
"""

from __future__ import annotations

import json as _json
from typing import Any

import typer

from bp.cliutil import fail_usage, parse_headers, run

# ---------------------------------------------------------------------------
# Sub-application
# ---------------------------------------------------------------------------

sub = typer.Typer(
    no_args_is_help=True, help="Session cookie/header management and authenticated requests."
)


# ---------------------------------------------------------------------------
# bp session set --json STR
# ---------------------------------------------------------------------------


@sub.command("set")
def session_set(
    ctx: typer.Context,
    json_str: str = typer.Option(
        ...,
        "--json",
        metavar="STR",
        help=(
            "JSON string for SetSessionRequest: "
            '{"cookies":{...}, "headers":{...}, "name":"...", "origin":"https://target"} '
            "(cookies required; origin binds credentials to one target origin; full replace)."
        ),
    ),
) -> None:
    """Load session cookies and headers (POST /session/set).

    Sends SetSessionRequest { cookies:Map (required), headers:Map?=null, name:String?=null,
    origin:String?=null }. ``origin`` binds credentials to one exact target origin.
    This is a FULL REPLACE — all existing session cookies and headers are overwritten.

    Example:
      bp session set --json '{"cookies":{"session":"abc123"},"headers":{"X-Role":"admin"},"origin":"https://example.com"}'
    """
    try:
        body: dict[str, Any] = _json.loads(json_str)
    except _json.JSONDecodeError as exc:
        fail_usage(ctx, f"--json is not valid JSON: {exc}")

    if not isinstance(body, dict) or "cookies" not in body:
        fail_usage(ctx, 'SetSessionRequest requires "cookies" key (Map<String,String>).')

    headers = body.get("headers")
    if isinstance(headers, dict):
        for name, value in headers.items():
            if isinstance(value, str) and any(control in value for control in ("\r", "\n", "\x00")):
                fail_usage(
                    ctx,
                    f"session header {name!r} value contains forbidden CR, LF, or NUL",
                )

    typer.echo(
        "note: /session/set is a full replace — existing session cookies and headers are overwritten.",
        err=True,
    )
    run(ctx, lambda c: c.post("/session/set", body))


# ---------------------------------------------------------------------------
# bp session get
# ---------------------------------------------------------------------------


@sub.command("get")
def session_get(ctx: typer.Context) -> None:
    """Inspect the active session (GET /session/get).

    Returns the current session cookies, headers, and name (if set).
    NOTE: reflects the extension's in-memory session, which may differ from the Burp UI state.
    """
    run(ctx, lambda c: c.get("/session/get"))


# ---------------------------------------------------------------------------
# bp session clear
# ---------------------------------------------------------------------------


@sub.command("clear")
def session_clear(ctx: typer.Context) -> None:
    """Atomically clear session credentials, origin binding, and captured cookies.

    DELETE /session/clear resets configured cookies/headers/origin and the auto-captured cookie jar.
    """
    typer.echo(
        "note: /session/clear resets session cookies, headers, origin, and captured cookie-jar.",
        err=True,
    )
    run(ctx, lambda c: c._request("DELETE", "/session/clear"))


# ---------------------------------------------------------------------------
# bp session send <url>
# ---------------------------------------------------------------------------


@sub.command("send")
def session_send(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL for the authenticated request."),
    method: str = typer.Option(
        "GET",
        "--method",
        "-X",
        metavar="M",
        help="HTTP method (default GET).",
    ),
    body: str | None = typer.Option(
        None,
        "--body",
        metavar="STR",
        help="Request body string (optional).",
    ),
    set_header: list[str] = typer.Option(
        [],
        "--set-header",
        metavar="'N: V'",
        help=(
            "Extra header 'Name: Value' (repeatable). These OVERRIDE session headers, not additive."
        ),
    ),
) -> None:
    """Send an authenticated request via the active session (POST /session/send).

    The request is made through the Burp HTTP engine and, when the extension database is available,
    is recorded in its server-side history (`bp history`). It does not traverse the proxy listener
    and therefore does not appear in `bp proxy` history.
    Session cookies and headers are automatically applied.

    Extra headers supplied via --set-header *override* session headers (not additive).

    Example:
      bp session send https://example.com/api/admin --method POST --body '{}'
    """
    # Parse extra headers early (shared helper → consistent exit 2)
    extra_headers = parse_headers(set_header, ctx=ctx)

    def _do(c: Any) -> Any:
        payload: dict[str, Any] = {"method": method, "url": url}
        if body is not None:
            payload["body"] = body
        if extra_headers:
            payload["extraHeaders"] = extra_headers
        return c.post("/session/send", payload)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp session cookies
# ---------------------------------------------------------------------------


@sub.command("cookies")
def session_cookies(ctx: typer.Context) -> None:
    """Show the auto-captured cookie-jar (GET /session/cookie-jar).

    The cookie-jar collects Set-Cookie headers from responses automatically,
    organised by domain. It is distinct from the session cookies set via
    'bp session set'; 'bp session clear' empties both stores and the origin binding.

    NOTE: the cookie-jar is in-memory only (not persisted to DB); extension reload also wipes it.
    """
    run(ctx, lambda c: c.get("/session/cookie-jar"))


# ---------------------------------------------------------------------------
# Registration entry-point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Add the 'session' sub-command group to *app*."""
    app.add_typer(sub, name="session")
