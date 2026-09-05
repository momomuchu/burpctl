"""Shared CLI helpers: global state, command execution, and stable exits."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn

import typer
from pydantic import ValidationError

from bp import config as _config
from bp.client import BurpClient, BurpError
from bp.config import ConfigError, redact, redact_data
from bp.ledger import Ledger
from bp.output import escape_terminal_controls, render, validate_output_options
from bp.pos import PosError

EXIT_GENERIC = 1
EXIT_USAGE = 2
EXIT_CONNECTION = 3
EXIT_PRO = 4
EXIT_VULN = 5

_EXIT_BY_CODE: dict[str, int] = {
    "CONNECTION_REFUSED": EXIT_CONNECTION,
    "TRANSPORT_ERROR": EXIT_CONNECTION,
    "NO_RESPONSE": EXIT_CONNECTION,
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


def resolve_redaction(
    state: State | None = None,
    *,
    no_redact: bool = False,
    warn: Callable[[str], None] | None = None,
) -> bool:
    """Resolve redaction once from CLI flag, environment, config file, and default.

    Configuration read failures fail closed here. The normal command path still reports
    the underlying invalid configuration when it subsequently loads the full config.
    """
    selected_no_redact = no_redact or (state is not None and state.no_redact)
    warning_sink = warn if warn is not None else lambda _message: None
    try:
        return _config.resolve_redaction(
            redact=False if selected_no_redact else None,
            warn=warning_sink,
        )
    except ConfigError:
        return not selected_no_redact


def _safe_message(message: str, *, redact_secrets: bool) -> str:
    safe = redact(message) if redact_secrets else message
    return escape_terminal_controls(safe)


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


def fail_usage(ctx: typer.Context, message: str) -> "NoReturn":
    """Emit one usage diagnostic in the invocation's selected format, then exit 2."""
    state: State = ctx.obj
    emit_error(
        state.fmt,
        "USAGE_ERROR",
        message,
        redact_secrets=resolve_redaction(state),
    )
    raise typer.Exit(EXIT_USAGE)


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


def _emit_response_warning(data: Any, state: State, *, redact_secrets: bool) -> None:
    """Route a response's top-level warning to stderr before output can narrow it away."""
    if not isinstance(data, dict):
        return
    warning = data.get("warning")
    if isinstance(warning, str) and warning:
        emit_warning(
            state.fmt,
            "OPERATION_WARNING",
            warning,
            redact_secrets=redact_secrets,
        )


def preflight_output(ctx: typer.Context) -> None:
    """Resolve output compatibility before a command can observe or change external state."""
    state: State = ctx.obj
    try:
        validate_output_options(ctx.command_path, state.fmt, state.fields)
    except ValueError as exc:
        emit_error(
            state.fmt,
            "USAGE_ERROR",
            str(exc),
            redact_secrets=resolve_redaction(state),
        )
        raise typer.Exit(EXIT_USAGE) from None


def run(
    ctx: typer.Context,
    fn: Callable[[BurpClient], Any],
    *,
    exit_on: Callable[[Any], "int | None"] | None = None,
    timeout: float | None = None,
) -> None:
    """Execute one command, structurally redact its result, render, and audit it."""
    state: State = ctx.obj
    preflight_output(ctx)

    config_warnings: list[str] = []
    redact_secrets = resolve_redaction(state, warn=config_warnings.append)
    try:
        conf = _config.load(
            burp_rest_url=state.url,
            ledger=False if state.no_ledger else None,
            redact=redact_secrets,
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

    client_options: dict[str, Any] = {
        "ledger": ledger,
        "redact": conf.redact,
        "command": ctx.command_path,
    }
    if timeout is not None:
        client_options["timeout"] = timeout
    client = BurpClient(conf.burp_rest_url, **client_options)
    # Failure is the initial audit state. Only a fully processed and emitted
    # result can change it to zero, so an unexpected exception never records
    # success merely because it missed a known except branch.
    exit_code = EXIT_GENERIC
    try:
        try:
            with client:
                data = fn(client)
            _emit_response_warning(data, state, redact_secrets=conf.redact)
            render_data = redact_data(data) if conf.redact else data
            out = render(
                render_data,
                state.fmt,
                fields=state.fields,
                command_path=ctx.command_path,
            )
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
            if isinstance(out, bytes):
                sys.stdout.buffer.write(out)
                sys.stdout.buffer.flush()
            else:
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


def _process_error_format() -> str:
    explicit: str | None = None
    index = 1
    while index < len(sys.argv):
        token = sys.argv[index]
        if token == "--":
            break
        if token == "--format" and index + 1 < len(sys.argv):
            explicit = sys.argv[index + 1]
            index += 2
            continue
        if token.startswith("--format="):
            explicit = token.partition("=")[2]
        index += 1
    if explicit is not None:
        return explicit
    return "json" if os.environ.get("BP_AGENT") == "1" else "table"


def parse_headers(
    raws: list[str], flag: str = "--set-header", ctx: typer.Context | None = None
) -> dict[str, str]:
    """Parse repeatable header flags with a stable usage exit."""
    headers: dict[str, str] = {}
    for raw in raws:
        try:
            name, value = parse_header(raw, flag)
        except ValueError as exc:
            if ctx is not None:
                fail_usage(ctx, str(exc))
            emit_error(
                _process_error_format(),
                "USAGE_ERROR",
                str(exc),
                redact_secrets=True,
            )
            raise typer.Exit(EXIT_USAGE) from None
        headers[name] = value
    return headers
