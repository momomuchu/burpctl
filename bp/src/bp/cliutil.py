"""Shared CLI helpers: global state, the command runner, and exit codes (docs/CLI.md).

Command modules in ``bp.commands.*`` import from here (not from ``bp.cli``) to avoid circular
imports. Each command resolves its data via a ``BurpClient`` and renders through ``run``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer

from bp.client import BurpClient, BurpError
from bp.output import render
from bp.pos import PosError

EXIT_GENERIC = 1
EXIT_USAGE = 2
EXIT_CONNECTION = 3
EXIT_PRO = 4

_EXIT_BY_CODE: dict[str, int] = {"CONNECTION_REFUSED": EXIT_CONNECTION, "PRO_REQUIRED": EXIT_PRO}


@dataclass
class State:
    url: str
    fmt: str
    fields: list[str] | None


def run(ctx: typer.Context, fn: Callable[[BurpClient], Any]) -> None:
    """Run ``fn`` against a BurpClient from the context state and render the result."""
    state: State = ctx.obj
    try:
        with BurpClient(state.url) as client:
            data = fn(client)
    except BurpError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(_EXIT_BY_CODE.get(e.code, EXIT_GENERIC)) from None
    except (PosError, ValueError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_USAGE) from None
    typer.echo(render(data, state.fmt, fields=state.fields))
