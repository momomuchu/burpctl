"""bp — Burp Suite REST CLI entry point. See docs/CLI.md.

Global options resolve to a State object on the typer context; each command runs against a
BurpClient and renders via the output layer. Command groups live in ``bp.commands.*`` and are
registered onto ``app`` below. Exit codes follow CLI.md (3=conn, 4=pro).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import typer

from bp.client import DEFAULT_BASE_URL, BurpClient
from bp.cliutil import EXIT_USAGE, State, run
from bp.output import FORMATS
from bp.runner import run_fuzz

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="bp — drive Burp Suite via its REST extension on :8089",
)


@app.callback()
def main(
    ctx: typer.Context,
    url: str = typer.Option(DEFAULT_BASE_URL, "--url", envvar="BURP_REST_URL", help="REST base URL"),
    fmt: str = typer.Option("table", "--format", help="json|table|raw|quiet"),
    fields: str | None = typer.Option(None, "--fields", help="comma-separated fields"),
) -> None:
    if fmt not in FORMATS:
        raise typer.BadParameter(f"must be one of {', '.join(FORMATS)}", param_hint="--format")
    ctx.obj = State(url=url, fmt=fmt, fields=fields.split(",") if fields else None)


@app.command()
def health(ctx: typer.Context) -> None:
    """Liveness + version of the extension."""
    run(ctx, lambda c: c.health().model_dump())


@app.command()
def version(ctx: typer.Context) -> None:
    """Extension version."""
    run(ctx, lambda c: c.version().model_dump())


@app.command()
def proxy(
    ctx: typer.Context,
    host: str | None = typer.Option(None, "--host", help="filter by host substring"),
    limit: int | None = typer.Option(None, "--limit"),
    offset: int | None = typer.Option(None, "--offset"),
) -> None:
    """List proxy HTTP history."""
    params: dict[str, Any] = {
        k: v for k, v in (("host", host), ("limit", limit), ("offset", offset)) if v is not None
    }
    run(ctx, lambda c: c.get("/proxy/history", **params).get("entries", []))


@app.command()
def fuzz(
    ctx: typer.Context,
    request_id: int = typer.Argument(..., metavar="ID", help="proxy-history id of the base request"),
    pos: list[str] = typer.Option([], "--pos", help="position selector, e.g. 'header:Authorization'"),
    payloads: list[str] = typer.Option([], "--payloads", help="NAME=FILE (a payload list per position)"),
    attack_type: str = typer.Option("sniper", "--type", help="sniper|battering-ram|pitchfork|cluster-bomb"),
    anomalous_only: bool = typer.Option(False, "--anomalous-only", help="show only anomalous results"),
) -> None:
    """Fuzz a captured request client-side (all attack types, byte-offset precise)."""
    payload_map: dict[str, list[bytes]] = {}
    for spec in payloads:
        name, sep, path = spec.partition("=")
        if not sep:
            typer.echo(f"error: --payloads must be NAME=FILE, got {spec!r}", err=True)
            raise typer.Exit(EXIT_USAGE)
        with open(path, "rb") as fh:
            payload_map[name] = [ln.rstrip(b"\r\n") for ln in fh if ln.strip()]

    def _do(client: BurpClient) -> Any:
        results = run_fuzz(client, request_id, pos, payload_map, attack_type)
        rows = [asdict(r) for r in results]
        return [r for r in rows if r["anomalous"]] if anomalous_only else rows

    run(ctx, _do)


def _register_command_groups() -> None:
    """Register every bp.commands.* module that exposes register(app)."""
    from importlib import import_module
    from pkgutil import iter_modules

    import bp.commands

    for mod in iter_modules(bp.commands.__path__):
        module = import_module(f"bp.commands.{mod.name}")
        register = getattr(module, "register", None)
        if callable(register):
            register(app)


_register_command_groups()
