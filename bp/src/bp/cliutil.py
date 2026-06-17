"""Shared CLI helpers: global state, the command runner, and exit codes (docs/CLI.md).

Command modules in ``bp.commands.*`` import from here (not from ``bp.cli``) to avoid circular
imports. Each command resolves its data via a ``BurpClient`` and renders through ``run``.
``run`` is the single chokepoint where the Run Ledger records the op (ADR-0005) and where
secret redaction is applied to displayed output (ADR-0007).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer

from bp import config as _config
from bp.client import BurpClient, BurpError
from bp.config import redact
from bp.ledger import Ledger
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
    """Run ``fn`` against a BurpClient; record to the Run Ledger and render (redacted) output."""
    state: State = ctx.obj
    conf = _config.load(burp_rest_url=state.url)
    ledger = Ledger() if conf.ledger else None
    try:
        with BurpClient(
            state.url, ledger=ledger, redact=conf.redact, command=ctx.command_path
        ) as client:
            data = fn(client)
    except BurpError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(_EXIT_BY_CODE.get(e.code, EXIT_GENERIC)) from None
    except (PosError, ValueError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(EXIT_USAGE) from None
    finally:
        if ledger is not None:
            ledger.close()
    out = render(data, state.fmt, fields=state.fields)
    if conf.redact:
        out = redact(out)
    typer.echo(out)
