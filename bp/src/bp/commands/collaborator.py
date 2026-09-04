"""Burp Collaborator OAST payload generation and authoritative polling.

Capability failures map to ``PRO_REQUIRED``/exit 4. Provider failures remain
runtime errors, unknown payload IDs are ``NOT_FOUND``, and successful interaction
rows carry Montoya capture identity, time, address, port, and protocol details.
"""

from __future__ import annotations

from typing import Any, Optional

import typer

from bp.cliutil import run

sub = typer.Typer(no_args_is_help=True, help="Burp Collaborator OAST payloads (Pro only).")


@sub.command("new")
def new(
    ctx: typer.Context,
    count: Optional[int] = typer.Option(
        None, "--count", min=1, help="Number of payloads to generate (default 1)."
    ),
) -> None:
    """Generate one or more Burp Collaborator OAST payloads.

    Uses POST /collaborator/generate for a single payload and
    POST /collaborator/generate/batch (BatchGenerateRequest { count:Int }) when --count > 1.

    Requires Burp Suite Professional — exits 4 (PRO_REQUIRED) on Community.
    """
    if count is not None and count > 1:
        # Batch path: POST /collaborator/generate/batch with { "count": N }
        body: dict[str, Any] = {"count": count}

        def _batch(c: Any) -> Any:
            return c.post("/collaborator/generate/batch", body)

        run(ctx, _batch)
    else:
        # Single path: POST /collaborator/generate (no body)
        def _single(c: Any) -> Any:
            return c.post("/collaborator/generate")

        run(ctx, _single)


@sub.command("poll")
def poll(
    ctx: typer.Context,
    collab_id: Optional[str] = typer.Argument(
        None, metavar="id", help="Collaborator payload id to scope the poll (optional)."
    ),
) -> None:
    """Poll all interactions or one authoritative generated payload ID."""
    if collab_id is not None:

        def _poll_id(c: Any) -> Any:
            return c.get(f"/collaborator/poll/{collab_id}")

        run(ctx, _poll_id)
    else:

        def _poll_all(c: Any) -> Any:
            return c.get("/collaborator/poll")

        run(ctx, _poll_all)


def register(app: typer.Typer) -> None:
    """Register the 'collab' sub-command group onto *app*."""
    app.add_typer(sub, name="collab")
