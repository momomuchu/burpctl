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
EXIT_VULN = 5  # security-scan finding(s) present (nmap/nuclei convention) — see ADR-0010

_EXIT_BY_CODE: dict[str, int] = {
    "CONNECTION_REFUSED": EXIT_CONNECTION,
    "TRANSPORT_ERROR": EXIT_CONNECTION,
    "PRO_REQUIRED": EXIT_PRO,
    # [15] Community Burp returns SERVICE_UNAVAILABLE for Pro-only scanner surfaces
    # (crawl/audit/all).  Documented contract: exit 4 (EXIT_PRO).
    "SERVICE_UNAVAILABLE": EXIT_PRO,
}


@dataclass
class State:
    url: str
    fmt: str
    fields: list[str] | None
    no_ledger: bool = False
    no_redact: bool = False


def run(ctx: typer.Context, fn: Callable[[BurpClient], Any]) -> None:
    """Run ``fn`` against a BurpClient; record to the Run Ledger and render (redacted) output."""
    state: State = ctx.obj
    conf = _config.load(
        burp_rest_url=state.url,
        ledger=False if state.no_ledger else None,
        redact=False if state.no_redact else None,
    )
    ledger = Ledger() if conf.ledger else None
    client = BurpClient(state.url, ledger=ledger, redact=conf.redact, command=ctx.command_path)
    exit_code = 0
    try:
        try:
            with client:
                data = fn(client)
            out = render(data, state.fmt, fields=state.fields)
        except BurpError as e:
            typer.echo(f"error: {e}", err=True)
            exit_code = _EXIT_BY_CODE.get(e.code, EXIT_GENERIC)
            raise typer.Exit(exit_code) from None
        except (PosError, ValueError) as e:
            typer.echo(f"error: {e}", err=True)
            exit_code = EXIT_USAGE
            raise typer.Exit(exit_code) from None
    finally:
        # Back-fill the actual exit code onto every op recorded during this command (F16).
        if ledger is not None:
            for op_id in client.op_ids:
                ledger.set_exit_code(op_id, exit_code)
            ledger.close()
    if conf.redact:
        out = redact(out)
    # [18] suppress lone '\n' for empty result sets (OUTPUT.md §4.4: empty stdout + exit 0)
    if out:
        typer.echo(out)


def parse_header(raw: str, flag: str = "--set-header") -> tuple[str, str]:
    """Parse a ``'Name: Value'`` header string into ``(name, value)``.

    Shared by the repeater/session/check commands so the parsing, error text, and exit
    code stay consistent. Raises ``ValueError`` (mapped to EXIT_USAGE by callers) on input
    with no colon.
    """
    if ":" not in raw:
        raise ValueError(f"{flag} must be 'Name: Value', got {raw!r}")
    name, _, value = raw.partition(":")
    return name.strip(), value.strip()


def parse_headers(raws: list[str], flag: str = "--set-header") -> dict[str, str]:
    """Parse repeatable ``'Name: Value'`` strings into a dict; clean usage error on malformed.

    Emits the error on stderr and raises ``typer.Exit(EXIT_USAGE)`` so every command surfaces
    the same exit 2 for a bad header (previously one copy used a hardcoded literal ``2``).
    """
    headers: dict[str, str] = {}
    for raw in raws:
        try:
            name, value = parse_header(raw, flag)
        except ValueError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(EXIT_USAGE) from None
        headers[name] = value
    return headers
