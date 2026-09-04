"""Flat CLI commands for proxy history and interception.

``forward`` and ``drop`` remain discoverable for route compatibility, but pinned
Montoya 2025.3 cannot perform either operation. The server returns a typed
``UNSUPPORTED`` failure rather than a successful no-op.
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from bp.cliutil import fail_usage, run
from bp.models import ProxyEntry, WebSocketHistoryResponse


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def _proxy_entry_display(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a single ProxyEntry dict to safe core display fields (AX-CAP-BODY).

    Mirrors the _proxy_rows() projection in bp.cli so that 'bp req <id>' and
    'bp proxy' are consistent: id/method/url/status only.  Request/response
    header and body blobs are suppressed in default output to prevent PII,
    cookie, JWT, and credential leakage to stdout.

    Also includes host/timestamp when present in the entry (same information
    density as 'history get' safe projection).

    For --format json, the caller bypasses this and returns the raw entry.
    """
    pe = ProxyEntry.model_validate(entry)
    row: dict[str, Any] = {
        "id": pe.id,
        "method": pe.request.method,
        "url": pe.request.url,
        "status": pe.response.statusCode if pe.response else None,
    }
    if pe.timestamp is not None:
        row["timestamp"] = pe.timestamp
    if pe.listenerInterface is not None:
        row["listenerInterface"] = pe.listenerInterface
    return row


# ---------------------------------------------------------------------------
# bp req <id>   →   GET /proxy/history/{id}
# ---------------------------------------------------------------------------
def req(
    ctx: typer.Context,
    id: Annotated[int, typer.Argument(metavar="ID", help="Absolute proxy-history index.")],
) -> None:
    """Fetch a single proxy-history entry by its absolute index.

    Table/quiet project the core safe fields (id, method, url, status, and optional
    timestamp/listenerInterface). JSON returns the complete structured entry. Raw emits the captured
    request and response as HTTP/1.1 bytes separated by an ASCII record-separator line.
    """

    def _do(c: Any) -> Any:
        entry = c.get(f"/proxy/history/{id}")
        if ctx.obj.fmt in {"json", "raw"}:
            return entry
        return _proxy_entry_display(entry)

    run(ctx, _do)


# ---------------------------------------------------------------------------
# bp ws   →   GET /proxy/websocket/history
# ---------------------------------------------------------------------------
def _websocket_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    history = WebSocketHistoryResponse.model_validate(data)
    return [entry.model_dump() for entry in history.entries]


def ws(ctx: typer.Context) -> None:
    """List captured WebSocket messages with original identity and nullable projections."""
    run(ctx, lambda c: _websocket_rows(c.get("/proxy/websocket/history")))


# ---------------------------------------------------------------------------
# bp intercept on|off|forward|drop   →   POST /proxy/intercept/{action}
# ---------------------------------------------------------------------------
_INTERCEPT_ACTIONS = ("on", "off", "forward", "drop")
_UNSUPPORTED_ACTIONS = {"forward", "drop"}
_ACTION_TO_PATH = {
    "on": "/proxy/intercept/enable",
    "off": "/proxy/intercept/disable",
    "forward": "/proxy/intercept/forward",
    "drop": "/proxy/intercept/drop",
}


def intercept(
    ctx: typer.Context,
    action: Annotated[
        str,
        typer.Argument(
            metavar="on|off|forward|drop",
            help="on=enable, off=disable; forward/drop report unsupported on Montoya 2025.3.",
        ),
    ],
) -> None:
    """Control interception; unsupported actions fail with a typed runtime error."""
    if action not in _INTERCEPT_ACTIONS:
        fail_usage(ctx, f"intercept action must be one of {_INTERCEPT_ACTIONS!r}, got {action!r}")

    if action in _UNSUPPORTED_ACTIONS:
        typer.echo(
            f"note: '{action}' is unavailable in pinned Montoya 2025.3; "
            "the server will return UNSUPPORTED without acting.",
            err=True,
        )

    path = _ACTION_TO_PATH[action]
    run(ctx, lambda c: c.post(path))


# ---------------------------------------------------------------------------
# Registration hook — called by bp.cli._register_command_groups()
# ---------------------------------------------------------------------------
def register(app: typer.Typer) -> None:
    """Register req, ws, intercept as FLAT top-level commands on *app*."""
    app.command(name="req")(req)
    app.command(name="ws")(ws)
    app.command(name="intercept")(intercept)
