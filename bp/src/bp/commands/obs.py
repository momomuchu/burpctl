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

from typing import Any

import typer

from bp.cliutil import State
from bp.config import load as load_config
from bp.ledger import Ledger, QueryFilters
from bp.output import render


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _require_ledger() -> bool:
    """Return True if the ledger is enabled; otherwise emit a note and return False."""
    if not load_config().ledger:
        typer.echo("note: ledger is disabled (ledger=off in config).", err=True)
        return False
    return True


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
        None, "--target", metavar="H", help="Filter by exact target host/url."
    ),
    tag: str | None = typer.Option(
        None, "--tag", metavar="X", help="Filter by exact tag value."
    ),
    status: str | None = typer.Option(
        None, "--status", metavar="S", help="Filter by status: ok | error | refused."
    ),
    limit: int = typer.Option(
        100, "--limit", metavar="N", help="Maximum number of rows to return (default 100)."
    ),
) -> None:
    """Query the run ledger (bp log [--since --until --target --tag --status --limit]).

    Reads from ~/.bp/ledger.db (or BP_LEDGER_PATH).  Does not require Burp.
    """
    if not _require_ledger():
        return

    filters = QueryFilters(
        since=since, until=until, target=target, tag=tag, status=status, limit=limit
    )
    with Ledger() as ledger:
        rows = ledger.query(filters)

    fmt, fields = _resolve_fmt_fields(ctx)
    data: list[dict[str, Any]] = [r.as_dict() for r in rows]
    typer.echo(render(data, fmt, fields=fields))


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
    if not _require_ledger():
        raise typer.Exit(1)

    with Ledger() as ledger:
        found = ledger.tag(op_id, name)

    if not found:
        typer.echo(f"error: op id {op_id!r} not found in ledger.", err=True)
        raise typer.Exit(1)

    typer.echo(f"tagged {op_id!r} -> {name!r}")


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register 'bp log' and 'bp tag' as flat top-level commands on *app*."""
    app.command("log")(log_cmd)
    app.command("tag")(tag_cmd)
