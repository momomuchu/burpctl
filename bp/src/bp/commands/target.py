"""bp target — scope management and sitemap commands. See docs/CLI.md + SPEC.md §6.8.

Endpoints (all Community, scope tracked in-memory on the JVM heap):
  GET  /target/scope          — read extension-managed scope changes (≠ Burp UI scope)
  POST /target/scope          — replace the extension-managed list, then add its entries to Burp
  POST /target/scope/add      — add one URL (AddScopeRequest)
  POST /target/scope/remove   — remove/exclude one URL (same DTO as add)
  GET  /target/scope/check    — authoritative scope verdict (delegates to Burp engine)
  GET  /target/sitemap        — dump Burp sitemap, optional prefix filter

CLI.md grammar:
  bp scope show|set|add|remove|check [url]   — sub-Typer named "scope"
  bp sitemap [prefix]                        — FLAT top-level command on app

Caveats surfaced per SPEC:
  - GET /target/scope reflects the extension-managed list, NOT the complete Burp UI scope.
    Use /scope/check for the authoritative Burp-engine verdict.
  - POST /target/scope replaces only that extension-managed list. Montoya has no scope-list or
    remove-rule API, so earlier Burp/UI rules remain active.
  - Scope classifies traffic for Burp features; it does not block proxy forwarding.
  - /scope/check without url query param returns INVALID_PARAM inside an HTTP 200
    envelope (Burp extension early-return quirk).
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from bp.cliutil import EXIT_USAGE, run

# ---------------------------------------------------------------------------
# "scope" sub-Typer — registered as app.add_typer(scope, name="scope")
# ---------------------------------------------------------------------------

scope = typer.Typer(
    no_args_is_help=True,
    help="Classify Burp target scope; this does not block proxy traffic.",
)


@scope.command("show")
def scope_show(ctx: typer.Context) -> None:
    """Show scope entries changed through this extension process.

    NOTE: this is not a complete Burp UI scope listing. Use
    'bp scope check <url>' for the authoritative Burp-engine verdict.
    """
    run(ctx, lambda c: c.get("/target/scope"))


@scope.command("set")
def scope_set(
    ctx: typer.Context,
    includes: Annotated[
        list[str],
        typer.Option("--include", help="URL pattern to include (repeat for multiple)."),
    ] = [],
    excludes: Annotated[
        list[str],
        typer.Option("--exclude", help="URL pattern to exclude (repeat for multiple)."),
    ] = [],
    confirm: Annotated[
        bool,
        typer.Option(
            "--confirm/--no-confirm", help="Confirm replacing the extension-managed list."
        ),
    ] = False,
) -> None:
    """Replace entries tracked by this extension process, then add them to Burp.

    Earlier entries added through Burp or this extension remain active in the Burp engine because
    Montoya does not expose a scope-list or remove-rule API. Use 'bp scope add' for one new entry.
    """
    if not confirm:
        typer.echo(
            "warning: 'bp scope set' replaces the extension-managed scope list, but cannot remove\n"
            "         earlier Burp-engine rules. Pass --confirm, or use 'bp scope add'.",
            err=True,
        )
        raise typer.Exit(EXIT_USAGE)

    body: dict[str, Any] = {"includes": includes, "excludes": excludes}
    run(ctx, lambda c: c.post("/target/scope", body))


@scope.command("add")
def scope_add(
    ctx: typer.Context,
    url: Annotated[str, typer.Argument(metavar="URL", help="URL to add to scope.")],
) -> None:
    """Add a URL to the in-memory scope."""
    body: dict[str, Any] = {"url": url}
    run(ctx, lambda c: c.post("/target/scope/add", body))


@scope.command("remove")
def scope_remove(
    ctx: typer.Context,
    url: Annotated[str, typer.Argument(metavar="URL", help="URL to remove from scope.")],
) -> None:
    """Remove/exclude a URL from the in-memory scope."""
    body: dict[str, Any] = {"url": url}
    run(ctx, lambda c: c.post("/target/scope/remove", body))


@scope.command("check")
def scope_check(
    ctx: typer.Context,
    url: Annotated[str, typer.Argument(metavar="URL", help="URL to check against scope.")],
) -> None:
    """Check whether a URL is in scope (authoritative Burp-engine verdict).

    Unlike 'bp scope show', this delegates to the Burp engine and reflects the
    scope configured in the Burp UI as well as the in-memory scope.
    """
    run(ctx, lambda c: c.get("/target/scope/check", url=url))


# ---------------------------------------------------------------------------
# bp sitemap — FLAT top-level command registered directly on app
# ---------------------------------------------------------------------------


def sitemap(
    ctx: typer.Context,
    prefix: Annotated[
        str | None,
        typer.Argument(metavar="PREFIX", help="Optional URL prefix to filter sitemap entries."),
    ] = None,
) -> None:
    """Dump the Burp sitemap, optionally filtered by URL prefix.

    Useful for wordlist generation and discovering cached endpoints.
    SitemapEntry fields: url, method, statusCode (nullable), mimeType (nullable).
    """

    def _do(c: Any) -> Any:
        params: dict[str, Any] = {}
        if prefix is not None:
            params["url"] = prefix
        return c.get("/target/sitemap", **params)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register scope sub-Typer and flat sitemap command onto *app*."""
    app.add_typer(scope, name="scope")
    app.command(name="sitemap")(sitemap)
