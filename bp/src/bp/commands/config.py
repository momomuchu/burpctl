"""Read and update real Burp project/user configuration through Montoya.

Configuration values retain their nested JSON types. ``bp ext`` remains a
self-only view because Montoya exposes metadata for the current extension only.
"""

from __future__ import annotations

import json as _json
from typing import Annotated, Any

import typer

from bp.cliutil import EXIT_USAGE, run

# ---------------------------------------------------------------------------
# config sub-typer  (bp config get … / bp config set …)
# ---------------------------------------------------------------------------

sub = typer.Typer(
    no_args_is_help=True,
    help="Read or update Burp project and user configuration.",
)

# -- bp config get -----------------------------------------------------------

config_get = typer.Typer(
    no_args_is_help=True,
    help="Export current project or user configuration.",
)
sub.add_typer(config_get, name="get")


@config_get.command("project")
def config_get_project(ctx: typer.Context) -> None:
    """Export the current Burp project options as nested JSON."""
    run(ctx, lambda c: c.get("/config/project"))


@config_get.command("user")
def config_get_user(ctx: typer.Context) -> None:
    """Export the current Burp user options as nested JSON."""
    run(ctx, lambda c: c.get("/config/user"))


# -- bp config set -----------------------------------------------------------

config_set = typer.Typer(
    no_args_is_help=True,
    help="Import a complete project or user JSON configuration object.",
)
sub.add_typer(config_set, name="set")


def _parse_config_json(raw: str) -> dict[str, Any]:
    """Parse --json as an object while preserving nested JSON value types."""
    try:
        parsed = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        typer.echo(f"error: --json is not valid JSON: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc
    if not isinstance(parsed, dict):
        typer.echo("error: --json must be a JSON object.", err=True)
        raise typer.Exit(EXIT_USAGE)
    return parsed


@config_set.command("project")
def config_set_project(
    ctx: typer.Context,
    json_str: Annotated[
        str,
        typer.Option(
            "--json",
            metavar="STR",
            help='JSON object to PUT as ConfigUpdateRequest.config, e.g. \'{"key":"value"}\'.',
        ),
    ],
) -> None:
    """Import a complete Burp project configuration object."""
    config_map = _parse_config_json(json_str)
    body: dict[str, Any] = {"config": config_map}

    def _do(c: Any) -> Any:
        return c._request("PUT", "/config/project", json=body)

    run(ctx, _do)


@config_set.command("user")
def config_set_user(
    ctx: typer.Context,
    json_str: Annotated[
        str,
        typer.Option(
            "--json",
            metavar="STR",
            help='JSON object to PUT as ConfigUpdateRequest.config, e.g. \'{"key":"value"}\'.',
        ),
    ],
) -> None:
    """Import a complete Burp user configuration object."""
    config_map = _parse_config_json(json_str)
    body: dict[str, Any] = {"config": config_map}

    def _do(c: Any) -> Any:
        return c._request("PUT", "/config/user", json=body)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register the 'config' group and the flat 'ext' command onto *app*."""
    app.add_typer(sub, name="config")

    # bp ext — mounted at root /extensions (not /config/extensions per SPEC §6.10)
    @app.command("ext")
    def ext(ctx: typer.Context) -> None:
        """List loaded Burp extensions (self-metadata only; total is always 1).

        GET /extensions — mounted at the root path, not under /config.
        Montoya only allows inspection of the currently-active extension, so
        'total' is always 1 regardless of how many extensions are loaded in Burp.
        """
        typer.echo(
            "note: /extensions only reports the active extension; total is always 1.",
            err=True,
        )
        run(ctx, lambda c: c.get("/extensions"))
