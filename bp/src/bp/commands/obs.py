"""bp obs — observability commands: 'bp log' and 'bp tag' (STATE-AND-CONFIG §1).

Commands
--------
bp log [--since T] [--until T] [--target H] [--tag X] [--status S] [--limit N]
    Query the run ledger and render matching ops rows.

bp tag <opId> <name>
    Set the tag field on a ledger row identified by opId.

These commands operate against the local ledger (~/.bp/ledger.db) and do NOT
require a running Burp instance. They are registered as FLAT top-level commands
(`bp log`, `bp tag`) — a single implementation each, no duplicated sub-Typer.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import typer

from bp.cliutil import (
    EXIT_GENERIC,
    EXIT_USAGE,
    State,
    emit_error,
    emit_warning,
    preflight_output,
    resolve_redaction,
)
from bp.config import ConfigError, load as load_config, redact_data
from bp.ledger import Ledger, QueryFilters
from bp.output import render


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_ledger(ctx: typer.Context) -> Any | None:
    """Resolve local config and return it when ledger operations are enabled."""
    state: State | None = ctx.obj
    ledger_override: bool | None = False if (state is not None and state.no_ledger) else None
    fmt, _fields = _resolve_fmt_fields(ctx)
    warnings: list[str] = []
    redact_secrets = resolve_redaction(state, warn=warnings.append)
    try:
        conf = load_config(
            ledger=ledger_override,
            redact=redact_secrets,
            burp_rest_url=state.url if state is not None else None,
            warn=warnings.append,
        )
    except ConfigError as exc:
        emit_error(
            fmt,
            "INVALID_CONFIG",
            str(exc),
            redact_secrets=redact_secrets,
        )
        raise typer.Exit(EXIT_USAGE) from None
    for warning in warnings:
        emit_warning(
            fmt,
            "INVALID_CONFIG_VALUE",
            warning,
            redact_secrets=conf.redact,
        )
    if not conf.ledger:
        emit_error(
            fmt,
            "LEDGER_DISABLED",
            "ledger is disabled (ledger=off / --no-ledger) — cannot query/tag",
            redact_secrets=conf.redact,
        )
        return None
    return conf


def _resolve_fmt_fields(ctx: typer.Context) -> tuple[str, list[str] | None]:
    """Read fmt/fields off the global State (ctx.obj); fall back to table/all fields."""
    state: State | None = ctx.obj
    if state is None:
        return "table", None
    return state.fmt, state.fields


# ---------------------------------------------------------------------------
# bp log
# ---------------------------------------------------------------------------


def log_cmd(
    ctx: typer.Context,
    since: str | None = typer.Option(
        None, "--since", metavar="T", help="ISO-8601 lower bound for ts (inclusive)."
    ),
    until: str | None = typer.Option(
        None, "--until", metavar="T", help="ISO-8601 upper bound for ts (inclusive)."
    ),
    target: str | None = typer.Option(
        None, "--target", metavar="H", help="Filter by exact Burp REST listener host[:port]."
    ),
    tag: str | None = typer.Option(None, "--tag", metavar="X", help="Filter by exact tag value."),
    status: str | None = typer.Option(
        None, "--status", metavar="S", help="Filter by status: ok | error | refused."
    ),
    limit: int = typer.Option(
        100, "--limit", metavar="N", help="Maximum number of rows to return (default 100)."
    ),
) -> None:
    """Query bp-to-extension REST operations in the local Run Ledger.

    Reads from ~/.bp/ledger.db (or BP_LEDGER_PATH) and does not require Burp. This is not a proxy
    traffic log: curl, xh, browser, and other non-bp traffic never writes it. The `target` field is
    the Burp REST listener host, not the target application's host.
    """
    preflight_output(ctx)
    conf = _require_ledger(ctx)
    if conf is None:
        raise typer.Exit(EXIT_GENERIC)

    filters = QueryFilters(
        since=since, until=until, target=target, tag=tag, status=status, limit=limit
    )
    try:
        ledger_ctx = Ledger()
    except (OSError, sqlite3.Error):
        emit_error(
            _resolve_fmt_fields(ctx)[0],
            "LEDGER_UNAVAILABLE",
            "ledger unavailable",
            redact_secrets=conf.redact,
        )
        raise typer.Exit(EXIT_GENERIC) from None
    try:
        with ledger_ctx as ledger:
            rows = ledger.query(filters)
    except ValueError as exc:
        # Malformed filters are an invocation problem, not a ledger failure.
        emit_error(_resolve_fmt_fields(ctx)[0], "USAGE_ERROR", str(exc), redact_secrets=conf.redact)
        raise typer.Exit(EXIT_USAGE) from None
    except sqlite3.Error:
        emit_error(
            _resolve_fmt_fields(ctx)[0],
            "LEDGER_UNAVAILABLE",
            "ledger unavailable",
            redact_secrets=conf.redact,
        )
        raise typer.Exit(EXIT_GENERIC) from None

    fmt, fields = _resolve_fmt_fields(ctx)
    data: list[dict[str, Any]] = [r.as_dict() for r in rows]
    display_data = redact_data(data) if conf.redact else data
    try:
        out = render(display_data, fmt, fields=fields, command_path=ctx.command_path)
    except (TypeError, ValueError) as exc:
        emit_error(fmt, "USAGE_ERROR", str(exc), redact_secrets=conf.redact)
        raise typer.Exit(EXIT_USAGE) from None
    if out:
        typer.echo(out)


# ---------------------------------------------------------------------------
# bp tag
# ---------------------------------------------------------------------------


def tag_cmd(
    ctx: typer.Context,
    op_id: str = typer.Argument(..., metavar="opId", help="Ledger op id to tag."),
    name: str = typer.Argument(..., metavar="name", help="Tag value to set."),
) -> None:
    """Set a tag on a ledger row: bp tag <opId> <name>.

    Exits 1 if the ledger is disabled or the opId is not found (the tag was not applied).
    """
    preflight_output(ctx)
    conf = _require_ledger(ctx)
    if conf is None:
        raise typer.Exit(EXIT_GENERIC)

    fmt, fields = _resolve_fmt_fields(ctx)
    safe_name = redact_data(name) if conf.redact else name
    data: dict[str, Any] = {"id": op_id, "tag": safe_name, "status": "tagged"}
    render_data: Any
    if fmt == "raw" or (fmt == "table" and fields is None):
        render_data = f"tagged {op_id!r} -> {safe_name!r}"
    else:
        render_data = data
    try:
        out = render(render_data, fmt, fields=fields, command_path=ctx.command_path)
    except (TypeError, ValueError) as exc:
        emit_error(fmt, "USAGE_ERROR", str(exc), redact_secrets=conf.redact)
        raise typer.Exit(EXIT_USAGE) from None

    try:
        ledger_ctx = Ledger()
    except (OSError, sqlite3.Error):
        emit_error(
            fmt,
            "LEDGER_UNAVAILABLE",
            "ledger unavailable",
            redact_secrets=conf.redact,
        )
        raise typer.Exit(EXIT_GENERIC) from None
    try:
        with ledger_ctx as ledger:
            found = ledger.tag(op_id, safe_name)
    except ValueError as exc:
        emit_error(fmt, "USAGE_ERROR", str(exc), redact_secrets=conf.redact)
        raise typer.Exit(EXIT_USAGE) from None
    except sqlite3.Error:
        emit_error(
            fmt,
            "LEDGER_UNAVAILABLE",
            "ledger unavailable",
            redact_secrets=conf.redact,
        )
        raise typer.Exit(EXIT_GENERIC) from None

    if not found:
        emit_error(
            fmt,
            "NOT_FOUND",
            f"op id {op_id!r} not found in ledger.",
            redact_secrets=conf.redact,
        )
        raise typer.Exit(EXIT_GENERIC)

    if out:
        typer.echo(out)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register 'bp log' and 'bp tag' as flat top-level commands on *app*."""
    app.command("log")(log_cmd)
    app.command("tag")(tag_cmd)
