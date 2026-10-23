"""Commands for extension-owned H2 request history and sitemap state.

The five routes remain mounted when storage is unavailable and then return a
typed ``SERVICE_UNAVAILABLE`` response. History IDs are durable database keys,
not ephemeral proxy-history indexes. Clearing history and sitemap is one
transaction and remains guarded by ``--confirm``.
"""

from __future__ import annotations

from typing import Any

import typer

from bp.client import BurpError
from bp.cliutil import EXIT_USAGE, run
from bp.models import HistoryEntryResponse, ReplayResponse


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _history_rows(entries: object) -> list[dict[str, Any]]:
    """Flatten HistoryEntryResponse dicts into compact display rows for list view.

    The server returns a flat HistoryEntryResponse shape (not nested like ProxyEntry).
    We project the four essential columns so the table shows id/method/url/statusCode
    without any reqHeaders/resHeaders blob cells.  Analogous to _proxy_rows() in cli.py.
    """
    if not isinstance(entries, list):
        raise BurpError("INVALID_RESPONSE", "server returned an unexpected response shape")

    rows: list[dict[str, Any]] = []
    for e in entries:
        he = HistoryEntryResponse.model_validate(e)
        rows.append(
            {
                "id": he.id,
                "method": he.method,
                "url": he.url,
                "statusCode": he.statusCode,
            }
        )
    return rows


def _history_entry_display(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a single HistoryEntryResponse dict to a clean display dict.

    Omits reqHeaders, resHeaders, reqBody, resBody (blobs) for default table/quiet output.
    Used by 'history get' and 'history replay'; --format json bypasses this and returns the full record.
    """
    he = HistoryEntryResponse.model_validate(entry)
    return {
        "id": he.id,
        "source": he.source,
        "method": he.method,
        "url": he.url,
        "host": he.host,
        "statusCode": he.statusCode,
        "durationMs": he.durationMs,
        "timestamp": he.timestamp,
    }


def _replay_display(response: dict[str, Any]) -> dict[str, Any]:
    """Project a ReplayResponse {original, replayed} to a clean display dict.

    Validates the response through the ReplayResponse pydantic model first so that
    a missing or malformed shape raises pydantic.ValidationError — which cliutil.run()
    already catches and renders as a clean 'unexpected response shape' message (exit 1),
    with no bare KeyError / raw traceback leaking file paths or class names.

    Applies _history_entry_display to both the 'original' and 'replayed' entries,
    stripping reqHeaders, resHeaders, reqBody, resBody (blobs) so that cookies and
    API keys embedded in header arrays are never emitted to default table/quiet output.
    --format json bypasses this via history_replay and returns the full raw response.
    """
    rr = ReplayResponse.model_validate(response)
    return {
        "original": _history_entry_display(rr.original.model_dump()),
        "replayed": _history_entry_display(rr.replayed.model_dump()),
    }


# ---------------------------------------------------------------------------
# Sub-application
# ---------------------------------------------------------------------------

sub = typer.Typer(no_args_is_help=True, help="Extension-owned H2 request history and sitemap.")


# ---------------------------------------------------------------------------
# bp history [--host H --method M --status N --page P]
# ---------------------------------------------------------------------------


@sub.command(name="list")
def history_list(
    ctx: typer.Context,
    host: str | None = typer.Option(
        None,
        "--host",
        help="Filter by host substring.",
        metavar="H",
    ),
    method: str | None = typer.Option(
        None,
        "--method",
        help="Filter by HTTP method (e.g. GET, POST).",
        metavar="M",
    ),
    status: int | None = typer.Option(
        None,
        "--status",
        help="Filter by HTTP status code (Int).",
        metavar="N",
    ),
    page: int | None = typer.Option(
        None,
        "--page",
        help="Page number (0-based, server default 0).",
        metavar="P",
    ),
) -> None:
    """List paginated request history from the server DB (GET /history).

    Applies HistoryFilter query params: host, method, statusCode, page.
    Entries are sorted id DESC (newest first).  Bodies are truncated at 1 MB
    at insert time.

    NOTE: returns 404 if the Burp extension DB failed to initialise.
    """

    def _do(c: Any) -> Any:
        params: dict[str, Any] = {}
        if host is not None:
            params["host"] = host
        if method is not None:
            params["method"] = method
        if status is not None:
            params["statusCode"] = status
        if page is not None:
            params["page"] = page
        page_data = c.get("/history", **params)
        return _history_rows(page_data.get("entries", []))

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp history get <id>
# ---------------------------------------------------------------------------


@sub.command(name="get")
def history_get(
    ctx: typer.Context,
    id: int = typer.Argument(..., metavar="ID", help="History entry id (Long / DB primary key)."),
) -> None:
    """Fetch a single history entry by id (GET /history/{id}).

    Returns the full entry including request and response bodies.
    id must be a Long (DB primary key) — not the proxy history Int index.

    For table/quiet/raw output the entry is projected to the core fields
    (id, source, method, url, host, statusCode, durationMs, timestamp),
    suppressing the raw header/body blobs.  Use --format json to get the
    full record including reqHeaders, reqBody, resHeaders, resBody.

    NOTE: returns 404 if the Burp extension DB failed to initialise.
    """

    def _do(c: Any) -> Any:
        entry = c.get(f"/history/{id}")
        if ctx.obj.fmt == "json":
            return entry
        return _history_entry_display(entry)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp history sitemap
# ---------------------------------------------------------------------------


@sub.command(name="sitemap")
def history_sitemap(
    ctx: typer.Context,
    host: str | None = typer.Option(
        None,
        "--host",
        help="Filter sitemap by host.",
        metavar="H",
    ),
) -> None:
    """List unique host+path+method tuples from the history DB (GET /history/sitemap).

    Each entry includes a hitCount reflecting how many times that combination
    was seen.  Useful for endpoint discovery and wordlist generation.

    NOTE: returns 404 if the Burp extension DB failed to initialise.
    """

    def _do(c: Any) -> Any:
        params: dict[str, Any] = {}
        if host is not None:
            params["host"] = host
        return c.get("/history/sitemap", **params)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp history replay <id>
# ---------------------------------------------------------------------------


@sub.command(name="replay")
def history_replay(
    ctx: typer.Context,
    id: int = typer.Argument(..., metavar="ID", help="History entry id (Long / DB primary key)."),
) -> None:
    """Replay a history entry verbatim via Burp (POST /history/{id}/replay).

    The request is re-sent live through the Burp HTTP engine.  The replayed
    entry is NOT persisted with a real id (id=0, source='replay'); the
    RepeaterService may re-insert it as a separate row.

    For table/quiet/raw output the response {original, replayed} is projected
    to the core fields (id, source, method, url, host, statusCode, durationMs,
    timestamp), suppressing raw header/body blobs so that cookies and API keys
    embedded in header arrays are never emitted to stdout.  Use --format json
    to get the full record including reqHeaders, reqBody, resHeaders, resBody.

    NOTE: returns 404 if the Burp extension DB failed to initialise.
    """

    def _do(c: Any) -> Any:
        response = c.post(f"/history/{id}/replay")
        if ctx.obj.fmt == "json":
            return response
        return _replay_display(response)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp history clear --confirm
# ---------------------------------------------------------------------------


@sub.command(name="clear")
def history_clear(
    ctx: typer.Context,
    confirm: bool = typer.Option(
        False,
        "--confirm/--no-confirm",
        help="Confirm irreversible wipe of history + sitemap tables.",
    ),
) -> None:
    """DESTRUCTIVE: delete all history and sitemap entries (DELETE /history).

    This operation is irreversible and non-transactional between the two
    tables — history and sitemap are wiped separately.  Pass --confirm to
    proceed.

    NOTE: returns 404 if the Burp extension DB failed to initialise.
    """
    if not confirm:
        typer.echo(
            "warning: 'bp history clear' irreversibly wipes the history and sitemap tables.\n"
            "         Pass --confirm to proceed.",
            err=True,
        )
        raise typer.Exit(EXIT_USAGE)

    def _do(c: Any) -> Any:
        return c._request("DELETE", "/history")

    run(ctx, _do)


# ---------------------------------------------------------------------------
# Registration entry-point
# ---------------------------------------------------------------------------


def register(app: typer.Typer) -> None:
    """Register the 'history' command group onto the root app.

    The default sub-command (bare 'bp history') maps to 'list'.
    """
    # Make bare 'bp history' invoke the list command by registering it both
    # as a sub-command and as the callback via invoke_without_command.
    app.add_typer(sub, name="history")
