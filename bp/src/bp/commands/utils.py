"""bp utils — HTTP diff and endpoint extraction commands. See docs/CLI.md + SPEC.md §6.12.

Endpoints (all Community, backed by SessionService HTTP engine — no DB required):
  POST /utils/diff               — fire two live requests and diff status/length/headers
  POST /utils/extract-endpoints  — fetch a URL + up to 10 JS bundles, extract API endpoints

SPEC §6.12 flags surfaced per contract:
  - diff body-diff is *set-based* (not a unified diff); only status/length/header deltas
    are returned, not a line-by-line body comparison.
  - extract-endpoints fetches up to 10 JS bundles (hard cap); per-bundle errors are
    silently swallowed by the extension. Static assets and w3.org URLs are filtered out.
  - Both endpoints are absent from the embedded /docs OpenAPI; SPEC.md is the authority.
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from bp.cliutil import run

sub = typer.Typer(no_args_is_help=True, help="HTTP diff and endpoint extraction utilities.")


# ---------------------------------------------------------------------------
# bp utils diff <a> <b>
# ---------------------------------------------------------------------------


@sub.command("diff")
def diff(
    ctx: typer.Context,
    a: Annotated[str, typer.Argument(metavar="A", help="URL of the first request target.")],
    b: Annotated[str, typer.Argument(metavar="B", help="URL of the second request target.")],
    method_a: Annotated[
        str,
        typer.Option("--method-a", help="HTTP method for request A (default GET)."),
    ] = "GET",
    method_b: Annotated[
        str,
        typer.Option("--method-b", help="HTTP method for request B (default GET)."),
    ] = "GET",
    body_a: Annotated[
        str | None,
        typer.Option("--body-a", help="Request body for A (optional)."),
    ] = None,
    body_b: Annotated[
        str | None,
        typer.Option("--body-b", help="Request body for B (optional)."),
    ] = None,
) -> None:
    """Fire two live requests and diff their status/length/headers.

    Sends POST /utils/diff with a DiffRequest containing two DiffTarget shapes:
      DiffTarget { url:String (required), method="GET", body:String?, extraHeaders:Map? }

    NOTE: body diff is *set-based*, not a unified line diff — only status code,
    response length, and header deltas are compared, not a line-by-line body diff.

    Example:
      bp diff https://api.example.com/v1/resource https://api.example.com/v2/resource
    """
    typer.echo(
        "note: /utils/diff body comparison is set-based (not unified diff);"
        " only status/length/header deltas are returned.",
        err=True,
    )

    target_a: dict[str, Any] = {"url": a, "method": method_a}
    if body_a is not None:
        target_a["body"] = body_a

    target_b: dict[str, Any] = {"url": b, "method": method_b}
    if body_b is not None:
        target_b["body"] = body_b

    body: dict[str, Any] = {"a": target_a, "b": target_b}
    run(ctx, lambda c: c.post("/utils/diff", body))


# ---------------------------------------------------------------------------
# bp utils endpoints <data>
# ---------------------------------------------------------------------------


@sub.command("endpoints")
def endpoints(
    ctx: typer.Context,
    data: Annotated[
        str,
        typer.Argument(metavar="data", help="URL to fetch and extract API endpoints from."),
    ],
) -> None:
    """Extract API endpoints from a URL's HTML and linked JS bundles.

    Sends POST /utils/extract-endpoints with ExtractEndpointsRequest { url:String }.

    The extension fetches the page and up to 10 JS bundles (hard cap), applies regex
    extraction, then filters out static assets and w3.org URLs.

    NOTE: per-bundle fetch errors are silently swallowed by the extension — a partial
    result (or empty list) does not indicate a failure, only that some bundles were
    unreachable or contained no recognisable endpoint patterns.

    Example:
      bp endpoints https://app.example.com
    """
    typer.echo(
        "note: /utils/extract-endpoints fetches up to 10 JS bundles (hard cap);"
        " per-bundle errors are silently swallowed.",
        err=True,
    )

    request_body: dict[str, Any] = {"url": data}
    run(ctx, lambda c: c.post("/utils/extract-endpoints", request_body))


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register diff, endpoints as FLAT top-level commands on *app*."""
    app.command(name="diff")(diff)
    app.command(name="endpoints")(endpoints)
