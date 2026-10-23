"""bp — Burp Suite REST CLI entry point. See docs/CLI.md.

Global options resolve to a State object on the typer context; each command runs against a
BurpClient and renders via the output layer. Command groups live in ``bp.commands.*`` and are
registered onto ``app`` below. Exit codes follow CLI.md (3=conn, 4=pro).
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from importlib import import_module
from importlib.metadata import version as distribution_version
from typing import TYPE_CHECKING, Any

import typer

if TYPE_CHECKING:
    from typer._click.exceptions import ClickException
else:
    _click_exceptions_module = (
        "typer._click.exceptions"
        if tuple(int(part) for part in distribution_version("typer").split(".")[:2]) >= (0, 26)
        else "click.exceptions"
    )
    ClickException = getattr(import_module(_click_exceptions_module), "ClickException")

from bp import __version__
from bp.client import BurpClient, BurpError
from bp.cliutil import EXIT_USAGE, State, emit_error, exit_code_for_error_code, run
from bp.models import ProxyEntry
from bp.output import FORMATS
from bp.runner import FuzzResult, run_fuzz

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="bp — drive Burp Suite via its REST extension on :8089 (alias: burpctl)",
)


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    url: str | None = typer.Option(
        None,
        "--url",
        envvar="BURP_REST_URL",
        help="REST base URL (env/config/default when omitted)",
    ),
    fmt: str | None = typer.Option(
        None,
        "--format",
        help="json (NDJSON for lists)|table|raw|quiet",
        show_default="table; json when BP_AGENT=1",
    ),
    fields: str | None = typer.Option(
        None, "--fields", help="comma-separated fields; all or * for all"
    ),
    no_ledger: bool = typer.Option(
        False, "--no-ledger", help="Skip the Run Ledger for this invocation (ADR-0005)."
    ),
    no_redact: bool = typer.Option(
        False, "--no-redact", help="Do not mask secrets in output (e.g. to read a JWT you decode)."
    ),
    version: bool = typer.Option(
        False, "--version", help="Show bp version and exit.", is_eager=True, callback=_version_cb
    ),
) -> None:
    selected_format = (
        fmt if fmt is not None else ("json" if os.environ.get("BP_AGENT") == "1" else "table")
    )
    if selected_format not in FORMATS:
        raise typer.BadParameter(f"must be one of {', '.join(FORMATS)}", param_hint="--format")
    selected_fields = [item.strip() for item in fields.split(",")] if fields else None
    ctx.obj = State(
        url=url,
        fmt=selected_format,
        fields=selected_fields,
        no_ledger=no_ledger,
        no_redact=no_redact,
    )


@app.command()
def health(ctx: typer.Context) -> None:
    """Liveness + version of the extension."""
    run(ctx, lambda c: c.health().model_dump())


@app.command()
def version(ctx: typer.Context) -> None:
    """Extension version."""
    run(ctx, lambda c: c.version().model_dump())


def _proxy_rows(entries: object) -> list[dict[str, Any]]:
    """Flatten the server's nested ProxyEntry (request/response) into display rows.

    The extension returns ``{id, request:{method,url,...}, response:{statusCode,...}}``; for the
    list view we project the essentials so the table shows id/method/url/status, not raw JSON blobs.
    """
    if not isinstance(entries, list):
        raise BurpError("INVALID_RESPONSE", "server returned an unexpected response shape")

    rows: list[dict[str, Any]] = []
    for e in entries:
        pe = ProxyEntry.model_validate(e)
        rows.append(
            {
                "id": pe.id,
                "method": pe.request.method,
                "url": pe.request.url,
                "status": pe.response.statusCode if pe.response else None,
            }
        )
    return rows


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
    run(ctx, lambda c: _proxy_rows(c.get("/proxy/history", **params).get("entries", [])))


def _fuzz_rows(results: list[FuzzResult], anomalous_only: bool) -> list[dict[str, Any]]:
    """Renderable fuzz rows, retaining the fresh control even in anomaly-only output."""
    rows = [asdict(result) for result in results]
    if not anomalous_only:
        return rows
    return [row for row in rows if row["baseline"] or row["anomalous"] or row["error"] is not None]


def _fuzz_exit(rows: list[dict[str, Any]], fmt: str = "table") -> int | None:
    """Fail after rendering if a shot has an error row, preserving partial evidence."""
    failures = [row for row in rows if row["error"] is not None]
    if not failures:
        return None
    message = f"{len(failures)} fuzz send(s) failed; attempted-shot rows remain on stdout"
    if fmt == "json":
        typer.echo(
            json.dumps(
                {"error": {"code": "FUZZ_PARTIAL_FAILURE", "message": message}},
                separators=(",", ":"),
            ),
            err=True,
        )
    else:
        typer.echo(f"error: {message}", err=True)
    return max(exit_code_for_error_code(row["error_code"]) for row in failures)


@app.command()
def fuzz(
    ctx: typer.Context,
    request_id: int = typer.Argument(
        ..., metavar="ID", help="proxy-history id of the base request"
    ),
    pos: list[str] = typer.Option(
        [], "--pos", help="position selector, e.g. 'header:Authorization'"
    ),
    payloads: list[str] = typer.Option(
        [], "--payloads", help="NAME=FILE (a payload list per position)"
    ),
    attack_type: str = typer.Option(
        "sniper", "--type", help="sniper|battering-ram|pitchfork|cluster-bomb"
    ),
    anomalous_only: bool = typer.Option(
        False, "--anomalous-only", help="show the fresh baseline plus anomalous payload results"
    ),
) -> None:
    """Fuzz a captured request client-side (all attack types, byte-offset precise).

    \b
    Framing limit: not a raw-framing transport; recomputes Content-Length.
    """
    payload_map: dict[str, list[bytes]] = {}
    for spec in payloads:
        name, sep, path = spec.partition("=")
        if not sep:
            emit_error(
                ctx.obj.fmt,
                "USAGE_ERROR",
                f"--payloads must be NAME=FILE, got {spec!r}",
                redact_secrets=not ctx.obj.no_redact,
            )
            raise typer.Exit(EXIT_USAGE)
        try:
            with open(path, "rb") as fh:
                payload_map[name] = [ln.rstrip(b"\r\n") for ln in fh if ln.strip()]
        except OSError as exc:
            emit_error(
                ctx.obj.fmt,
                "USAGE_ERROR",
                f"cannot read payload file {path}: {exc}",
                redact_secrets=not ctx.obj.no_redact,
            )
            raise typer.Exit(EXIT_USAGE) from None

    def _do(client: BurpClient) -> Any:
        results = run_fuzz(client, request_id, pos, payload_map, attack_type)
        return _fuzz_rows(results, anomalous_only)

    run(ctx, _do, exit_on=lambda rows: _fuzz_exit(rows, ctx.obj.fmt))


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


_GLOBAL_VALUE_OPTS = ("--url", "--format", "--fields")
_GLOBAL_FLAG_OPTS = ("--no-ledger", "--no-redact")


def _find_subcommand(argv: list[str]) -> int | None:
    """Index of the subcommand token, skipping leading global options and their values."""
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return None
        if not tok.startswith("-"):
            return i
        name = tok.partition("=")[0]
        if name in _GLOBAL_VALUE_OPTS and "=" not in tok:
            i += 2  # skip the option AND its value
        else:
            i += 1  # a flag, or --opt=value
    return None


def _hoist_global_opts(argv: list[str]) -> list[str]:
    """Move global value-taking options (and their values) ahead of the subcommand.

    Makes ``bp <cmd> --format json`` behave like ``bp --format json <cmd>`` (ADR-0009).
    Only the three known options in ``_GLOBAL_VALUE_OPTS`` are moved, and only when they
    appear after the subcommand; everything else is left untouched for Typer to parse or
    reject exactly as before.
    """
    sub_idx = _find_subcommand(argv)
    if sub_idx is None:
        return argv
    head = argv[:sub_idx]
    tail = argv[sub_idx:]
    hoisted: list[str] = []
    rest: list[str] = [tail[0]]  # the subcommand token stays put
    i = 1
    while i < len(tail):
        tok = tail[i]
        if tok == "--":
            # Everything after the delimiter is command payload, even when it
            # happens to spell a global option.
            rest.extend(tail[i:])
            break
        name = tok.partition("=")[0]
        if name in _GLOBAL_VALUE_OPTS:
            if "=" in tok:  # --opt=value
                hoisted.append(tok)
                i += 1
            elif i + 1 < len(tail) and tail[i + 1] != "--":  # --opt value
                hoisted.extend((tok, tail[i + 1]))
                i += 2
            else:  # dangling --opt with no value: leave for Typer to error on
                rest.append(tok)
                i += 1
        elif name in _GLOBAL_FLAG_OPTS:  # value-less global flag (e.g. --no-ledger)
            hoisted.append(tok)
            i += 1
        else:
            rest.append(tok)
            i += 1
    return head + hoisted + rest


def cli_main() -> None:
    """Console entrypoint (bp / burpctl). Applies ADR-0009 option hoisting, then dispatches.

    ``prog_name`` reflects the command the user actually invoked, so ``bp --help`` and
    ``burpctl --help`` each show their own name in usage/error output (both are installed;
    ADR-0012: ``bp`` is primary, ``burpctl`` is the alias).
    """
    prog = os.path.basename(sys.argv[0]) or "bp"
    args = _hoist_global_opts(sys.argv[1:])
    boundary = args.index("--") if "--" in args else len(args)
    parser_args = args[:boundary]
    formats: list[str] = []
    i = 0
    while i < len(parser_args):
        arg = parser_args[i]
        if arg == "--format" and i + 1 < len(parser_args):
            formats.append(parser_args[i + 1])
            i += 2
        elif arg.startswith("--format="):
            formats.append(arg.partition("=")[2])
            i += 1
        else:
            i += 1
    error_format = (
        formats[-1]
        if formats and formats[-1] in FORMATS
        else ("json" if os.environ.get("BP_AGENT") == "1" else "table")
    )
    if error_format != "json":
        app(args=args, prog_name=prog)
        return
    try:
        exit_code = app(args=args, prog_name=prog, standalone_mode=False)
    except ClickException as exc:
        emit_error("json", "USAGE_ERROR", exc.format_message(), redact_secrets=True)
        raise SystemExit(exc.exit_code) from None
    if exit_code is not None:
        raise SystemExit(exit_code)
