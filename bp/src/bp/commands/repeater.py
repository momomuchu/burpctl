"""bp repeater commands — send / tab (docs/CLI.md §repeater, SPEC.md §6.3).

Endpoints:
  POST /repeater/send        — replay a history request with optional modifications.
  POST /repeater/tab/create  — open a Repeater UI tab (no traffic sent).

Request models (Kotlin source, SPEC §6.3):
  SendRequest        { requestId:Int?, modifications:RequestModifications? }
  RequestModifications { headers:Map<String,String>?, body:String?,
                          method:String?, path:String? }
  CreateTabRequest   { name:String?, requestId:Int? }
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer

from bp.cliutil import EXIT_USAGE, parse_headers, run

# ---------------------------------------------------------------------------
# Sub-application
# ---------------------------------------------------------------------------

sub = typer.Typer(no_args_is_help=True, help="Repeater — send / tab commands.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_body(body: str | None) -> str | None:
    """Resolve --body STR or --body @file → string content."""
    if body is None:
        return None
    if body.startswith("@"):
        path = Path(body[1:])
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"cannot read body file {path}: {exc}") from exc
    return body


# ---------------------------------------------------------------------------
# bp send <id>
# ---------------------------------------------------------------------------


@sub.command(name="send")
def send_cmd(
    ctx: typer.Context,
    request_id: int = typer.Argument(..., metavar="ID", help="proxy-history requestId (Int)"),
    set_header: list[str] = typer.Option(
        [],
        "--set-header",
        help="Override / add a header: 'Name: Value' (repeatable).",
        metavar="'N: V'",
    ),
    body: str | None = typer.Option(
        None,
        "--body",
        help="Replace request body: literal string or @file path.",
        metavar="STR|@file",
    ),
    method: str | None = typer.Option(
        None,
        "--method",
        help="Override HTTP method (e.g. POST).",
        metavar="M",
    ),
    path: str | None = typer.Option(
        None,
        "--path",
        help="Override request path (not the full URL).",
        metavar="P",
    ),
) -> None:
    """Replay a proxy-history request via the Repeater engine (POST /repeater/send).

    Modifications (--set-header / --body / --method / --path) are applied
    server-side before sending; only non-null fields are substituted.
    Response includes the replayed request, response, and timing.
    """
    # Resolve body early (may raise ValueError → EXIT_USAGE via run())
    resolved_body: str | None
    try:
        resolved_body = _resolve_body(body)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from None

    # Parse headers early for the same reason (shared helper → consistent exit 2)
    headers = parse_headers(set_header)

    def _do(client: Any) -> Any:
        # Build RequestModifications — only include non-None fields
        mods: dict[str, Any] = {}
        if headers:
            mods["headers"] = headers
        if resolved_body is not None:
            mods["body"] = resolved_body
        if method is not None:
            mods["method"] = method
        if path is not None:
            mods["path"] = path

        payload: dict[str, Any] = {"requestId": request_id}
        if mods:
            payload["modifications"] = mods

        return client.post("/repeater/send", payload)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp tab <id>
# ---------------------------------------------------------------------------


@sub.command(name="tab")
def tab_cmd(
    ctx: typer.Context,
    request_id: int = typer.Argument(..., metavar="ID", help="proxy-history requestId (Int)"),
    name: str | None = typer.Option(
        None,
        "--name",
        help="Label for the new Repeater tab.",
        metavar="N",
    ),
) -> None:
    """Open a Repeater UI tab for a history request (POST /repeater/tab/create).

    No HTTP traffic is sent; the request is loaded into the Repeater UI only.
    If both request and requestId are null the server silently falls back to
    https://example.com — this command always supplies requestId to avoid that.
    """
    def _do(client: Any) -> Any:
        payload: dict[str, Any] = {"requestId": request_id}
        if name is not None:
            payload["name"] = name
        return client.post("/repeater/tab/create", payload)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# Registration entry-point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register send, tab as FLAT top-level commands on *app*."""
    app.command(name="send")(send_cmd)
    app.command(name="tab")(tab_cmd)
