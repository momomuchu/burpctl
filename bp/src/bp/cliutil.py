"""Shared CLI helpers: global state, command execution, and stable exits."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import typer
from pydantic import ValidationError

from bp import config as _config
from bp.client import BurpClient, BurpError
from bp.config import ConfigError, redact, redact_data
from bp.ledger import Ledger
from bp.output import render
from bp.pos import PosError

EXIT_GENERIC = 1
EXIT_USAGE = 2
EXIT_CONNECTION = 3
EXIT_PRO = 4
EXIT_VULN = 5

_EXIT_BY_CODE: dict[str, int] = {
    "CONNECTION_REFUSED": EXIT_CONNECTION,
    "TRANSPORT_ERROR": EXIT_CONNECTION,
    "PRO_REQUIRED": EXIT_PRO,
    "SERVICE_UNAVAILABLE": EXIT_GENERIC,
}


def exit_code_for_error_code(code: str) -> int:
    """Map a Burp error code to the stable CLI exit contract."""
    return _EXIT_BY_CODE.get(code, EXIT_GENERIC)


@dataclass
class State:
    # None means --url was omitted; config.load then applies env/file/default.
    url: str | None
    fmt: str
    fields: list[str] | None
    no_ledger: bool = False
    no_redact: bool = False


def _safe_message(message: str, *, redact_secrets: bool) -> str:
    return redact(message) if redact_secrets else message


def emit_error(
    fmt: str,
    code: str,
    message: str,
    *,
    status: int | None = None,
    op: str | None = None,
    redact_secrets: bool = True,
) -> None:
    """Emit one machine record in JSON mode, or the established human line."""
    safe_message = _safe_message(message, redact_secrets=redact_secrets)
    if fmt == "json":
        detail: dict[str, Any] = {"code": code, "message": safe_message}
        if status is not None:
            detail["status"] = status
            detail["http_status"] = status
        if op is not None:
            detail["op"] = _safe_message(op, redact_secrets=redact_secrets)
        typer.echo(json.dumps({"error": detail}, separators=(",", ":")), err=True)
    else:
        typer.echo(f"error: {safe_message}", err=True)


def emit_warning(
    fmt: str,
    code: str,
    message: str,
    *,
    redact_secrets: bool,
) -> None:
    safe_message = _safe_message(message, redact_secrets=redact_secrets)
    if fmt == "json":
        typer.echo(
            json.dumps(
                {"warning": {"code": code, "message": safe_message}},
                separators=(",", ":"),
            ),
            err=True,
        )
    else:
        typer.echo(f"warning: {safe_message}", err=True)


def run(
    ctx: typer.Context,
    fn: Callable[[BurpClient], Any],
    *,
    exit_on: Callable[[Any], "int | None"] | None = None,
) -> None:
    """Execute one command, structurally redact its result, render, and audit it."""
    state: State = ctx.obj
    redact_secrets = not state.no_redact
    config_warnings: list[str] = []
    try:
        conf = _config.load(
            burp_rest_url=state.url,
            ledger=False if state.no_ledger else None,
            redact=False if state.no_redact else None,
            warn=config_warnings.append,
        )
    except ConfigError as exc:
        emit_error(
            state.fmt,
            "INVALID_CONFIG",
            str(exc),
            redact_secrets=redact_secrets,
        )
        raise typer.Exit(EXIT_USAGE) from None

    runtime_warnings = [("INVALID_CONFIG_VALUE", warning) for warning in config_warnings]

    ledger: Ledger | None = None
    if conf.ledger:
        try:
            ledger = Ledger()
        except (PermissionError, OSError, sqlite3.Error):
            runtime_warnings.append(
                ("LEDGER_UNAVAILABLE", "ledger unavailable, proceeding without it")
            )

    client = BurpClient(
        conf.burp_rest_url,
        ledger=ledger,
        redact=conf.redact,
        command=ctx.command_path,
    )
    # Failure is the initial audit state. Only a fully processed and emitted
    # result can change it to zero, so an unexpected exception never records
    # success merely because it missed a known except branch.
    exit_code = EXIT_GENERIC
    try:
        try:
            with client:
                data = fn(client)
            render_data = redact_data(data) if conf.redact else data
            out = render(render_data, state.fmt, fields=state.fields)
        except BurpError as exc:
            exit_code = exit_code_for_error_code(exc.code)
            emit_error(
                state.fmt,
                exc.code,
                exc.message,
                status=exc.status,
                op=exc.op,
                redact_secrets=conf.redact,
            )
            raise typer.Exit(exit_code) from None
        except ValidationError:
            exit_code = EXIT_GENERIC
            emit_error(
                state.fmt,
                "INVALID_RESPONSE",
                "server returned an unexpected response shape",
                redact_secrets=conf.redact,
            )
            raise typer.Exit(exit_code) from None
        except (PosError, ValueError) as exc:
            exit_code = EXIT_USAGE
            emit_error(
                state.fmt,
                "USAGE_ERROR",
                str(exc),
                redact_secrets=conf.redact,
            )
            raise typer.Exit(exit_code) from None
        except TypeError:
            exit_code = EXIT_GENERIC
            emit_error(
                state.fmt,
                "RENDER_ERROR",
                "could not render command result",
                redact_secrets=conf.redact,
            )
            raise typer.Exit(exit_code) from None

        desired_exit = 0
        if exit_on is not None:
            desired_exit = exit_on(data) or 0
        for warning_code, warning_message in runtime_warnings:
            emit_warning(
                state.fmt,
                warning_code,
                warning_message,
                redact_secrets=conf.redact,
            )
        if out:
            typer.echo(out)
        exit_code = desired_exit
    finally:
        if ledger is not None:
            for op_id in client.op_ids:
                if op_id:
                    ledger.set_exit_code(op_id, exit_code)
            ledger.close()

    if exit_code != 0:
        raise typer.Exit(exit_code)


def parse_header(raw: str, flag: str = "--set-header") -> tuple[str, str]:
    """Parse a ``Name: Value`` header string."""
    if ":" not in raw:
        raise ValueError(f"{flag} must be 'Name: Value', got {raw!r}")
    name, _, value = raw.partition(":")
    return name.strip(), value.strip()


def parse_headers(raws: list[str], flag: str = "--set-header") -> dict[str, str]:
    """Parse repeatable header flags with a stable usage exit."""
    headers: dict[str, str] = {}
    for raw in raws:
        try:
            name, value = parse_header(raw, flag)
        except ValueError as exc:
            typer.echo(f"error: {redact(str(exc))}", err=True)
            raise typer.Exit(EXIT_USAGE) from None
        headers[name] = value
    return headers
