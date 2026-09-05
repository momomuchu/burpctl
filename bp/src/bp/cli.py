"""bp — Burp Suite REST CLI entry point. See docs/CLI.md.

Global options resolve to a State object on the typer context; each command runs against a
BurpClient and renders via the output layer. Command groups live in ``bp.commands.*`` and are
registered onto ``app`` below. Exit codes follow CLI.md (3=conn, 4=pro).
"""

from __future__ import annotations

import io
import json
import os
import sys
from dataclasses import asdict
from typing import Any

import typer
from typer import Abort, Exit as ClickExit

# Typer 0.26 vendors Click and does not publicly re-export ClickException.  Keep this sole private
# compatibility import at the entrypoint boundary; no command module may depend on typer._click.
from typer._click import ClickException

from bp import __version__
from bp.client import BurpClient
from bp.cliutil import (
    State,
    emit_error,
    exit_code_for_error_code,
    fail_usage,
    resolve_redaction,
    run,
)
from bp.fuzz import load_payload_file
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


def _proxy_rows(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten the server's nested ProxyEntry (request/response) into display rows.

    The extension returns ``{id, request:{method,url,...}, response:{statusCode,...}}``; for the
    list view we project the essentials so the table shows id/method/url/status, not raw JSON blobs.
    """
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
            fail_usage(ctx, f"--payloads must be NAME=FILE, got {spec!r}")
        try:
            payload_map[name] = load_payload_file(path)
        except OSError as exc:
            fail_usage(ctx, f"cannot read payload file {path}: {exc}")
        except ValueError as exc:
            fail_usage(ctx, f"invalid payload file {path}: {exc}")

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


def _json_error_mode(argv: list[str]) -> bool:
    """Resolve error rendering before Click has successfully built a context.

    An explicit format wins over BP_AGENT just as it does in ``main``.  This deliberately scans only
    the three spellings the argv hoister supports and never interprets tokens after ``--``.
    """
    explicit: str | None = None
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--":
            break
        if token == "--format" and index + 1 < len(argv):
            explicit = argv[index + 1]
            index += 2
            continue
        if token.startswith("--format="):
            explicit = token.partition("=")[2]
        index += 1
    if explicit is not None:
        return explicit == "json"
    return os.environ.get("BP_AGENT") == "1"


def _redaction_enabled(argv: list[str]) -> bool:
    """Resolve redaction for errors raised before Typer constructs the root context."""
    no_redact = False
    for token in argv:
        if token == "--":
            break
        if token == "--no-redact":
            no_redact = True
    return resolve_redaction(no_redact=no_redact)


def _emit_click_error(
    exc: ClickException,
    *,
    json_mode: bool,
    redact_secrets: bool,
) -> None:
    if json_mode:
        message = exc.format_message()
        if redact_secrets:
            from bp.config import redact

            message = redact(message)
        detail = {"error": {"code": "USAGE_ERROR", "message": message}}
        typer.echo(json.dumps(detail, separators=(",", ":")), err=True)
    elif redact_secrets:
        from bp.config import redact

        stream = io.StringIO()
        exc.show(file=stream)
        typer.echo(redact(stream.getvalue()), nl=False, err=True)
    else:
        exc.show(file=sys.stderr)


def cli_main() -> None:
    """Console entrypoint (bp / burpctl). Applies ADR-0009 option hoisting, then dispatches.

    ``prog_name`` reflects the command the user actually invoked, so ``bp --help`` and
    ``burpctl --help`` each show their own name in usage/error output (both are installed;
    ADR-0012: ``bp`` is primary, ``burpctl`` is the alias).
    """
    prog = os.path.basename(sys.argv[0]) or "bp"
    args = _hoist_global_opts(sys.argv[1:])
    try:
        result = app(args=args, prog_name=prog, standalone_mode=False)
        if isinstance(result, int) and result != 0:
            raise SystemExit(result)
    except ClickException as exc:
        _emit_click_error(
            exc,
            json_mode=_json_error_mode(args),
            redact_secrets=_redaction_enabled(args),
        )
        raise SystemExit(exc.exit_code) from None
    except ClickExit as exc:
        raise SystemExit(exc.exit_code) from None
    except Abort:
        if _json_error_mode(args):
            typer.echo(
                json.dumps(
                    {"error": {"code": "USAGE_ERROR", "message": "Aborted"}},
                    separators=(",", ":"),
                ),
                err=True,
            )
        else:
            typer.echo("Aborted!", err=True)
        raise SystemExit(1) from None
    except Exception:
        # This is the final output boundary: never let Python print an exception
        # traceback whose message can quote attacker-controlled or credential data.
        fmt = "json" if _json_error_mode(args) else "table"
        emit_error(
            fmt,
            "INTERNAL_ERROR",
            "unexpected internal error",
            redact_secrets=_redaction_enabled(args),
        )
        raise SystemExit(1) from None
