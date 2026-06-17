"""bp session command group — session cookie/header management and authenticated requests.

Commands (CLI.md):
  bp session set --json STR          load cookies+headers (POST /session/set, full replace)
  bp session get                     inspect the active session (GET /session/get)
  bp session clear                   reset session cookies/headers (DELETE /session/clear)
  bp session send <url>              send an authenticated request (POST /session/send)
  bp session cookies                 show the auto-captured cookie-jar (GET /session/cookie-jar)

Request models (Kotlin source, SPEC §6.11):
  SetSessionRequest      { cookies:Map<String,String> (required), headers:Map?=null,
                           name:String?=null }
  AuthenticatedRequest   { method:String="GET", url:String (required), body:String?=null,
                           extraHeaders:Map<String,String>?=null }

SPEC §6.11 caveats surfaced on stderr:
  - POST /session/set is a *full replace* — overwrites all existing cookies and headers.
  - extraHeaders in /session/send *override* session headers (not additive).
  - The cookie-jar is in-memory only (not in DB); it survives 'clear' but is wiped on reload.
  - DELETE /session/clear resets session cookies/headers but does NOT wipe the cookie-jar.
  - The entire /session group is absent from the embedded /docs OpenAPI.
"""

from __future__ import annotations

import json as _json
from typing import Any

import typer

from bp.cliutil import EXIT_USAGE, parse_headers, run

# ---------------------------------------------------------------------------
# Sub-application
# ---------------------------------------------------------------------------

sub = typer.Typer(no_args_is_help=True, help="Session cookie/header management and authenticated requests.")


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
            '{"cookies":{...}, "headers":{...}, "name":"..."} '
            "(cookies required; full replace of active session)."
        ),
    ),
) -> None:
    """Load session cookies and headers (POST /session/set).

    Sends SetSessionRequest { cookies:Map (required), headers:Map?=null, name:String?=null }.
    This is a FULL REPLACE — all existing session cookies and headers are overwritten.

    Example:
      bp session set --json '{"cookies":{"session":"abc123"},"headers":{"X-Role":"admin"}}'
    """
    try:
        body: dict[str, Any] = _json.loads(json_str)
    except _json.JSONDecodeError as exc:
        typer.echo(f"error: --json is not valid JSON: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from None

    if not isinstance(body, dict) or "cookies" not in body:
        typer.echo(
            'error: SetSessionRequest requires "cookies" key (Map<String,String>).',
            err=True,
        )
        raise typer.Exit(EXIT_USAGE) from None

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
    """Reset session cookies and headers (DELETE /session/clear).

    NOTE: this does NOT wipe the auto-captured cookie-jar.
    Use 'bp session cookies' to inspect the cookie-jar (wiped only on extension reload).
    """
    typer.echo(
        "note: /session/clear resets session cookies/headers but leaves the cookie-jar intact.",
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
            "Extra header 'Name: Value' (repeatable). "
            "These OVERRIDE session headers, not additive."
        ),
    ),
) -> None:
    """Send an authenticated request via the active session (POST /session/send).

    The request is made through the Burp HTTP engine and appears in Burp's proxy history.
    Session cookies and headers are automatically applied.

    Extra headers supplied via --set-header *override* session headers (not additive).

    Example:
      bp session send https://example.com/api/admin --method POST --body '{}'
    """
    # Parse extra headers early (shared helper → consistent exit 2)
    extra_headers = parse_headers(set_header)

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
    'bp session set' and survives 'bp session clear'.

    NOTE: the cookie-jar is in-memory only (not persisted to DB); it is wiped
    when the extension is reloaded.
    """
    run(ctx, lambda c: c.get("/session/cookie-jar"))


# ---------------------------------------------------------------------------
# Registration entry-point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Add the 'session' sub-command group to *app*."""
    app.add_typer(sub, name="session")
