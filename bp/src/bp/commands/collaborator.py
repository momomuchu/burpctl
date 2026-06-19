"""bp collaborator command group — Burp Collaborator OAST payload management.

Commands (CLI.md):
  bp collab new [--count N]   generate 1 or N Collaborator payloads (Pro only)
  bp collab poll [id]         poll interactions for all payloads or a specific id (Pro only)

All endpoints require Burp Suite Professional; on Community the routes return the error code
``PRO_REQUIRED`` (HTTP 503), which the shared ``run`` runner maps to exit-code 4 (EXIT_PRO).
(Note: ``SERVICE_UNAVAILABLE`` is a distinct code reserved for infra failures and maps to exit 1.)

SPEC §6.5 flags surfaced on stderr:
  - ``interactionId == id`` is a local key, not a real Burp UUID.
  - ``timestamp`` on poll responses is set to ``Instant.now()`` at poll time, not capture time.
  - Poll errors are silently swallowed by the extension → ``found=false`` (HTTP 200); it is
    impossible to distinguish "unknown id" from "no interaction yet".
  - ``/collaborator/generate/batch`` and ``/collaborator/poll/{id}`` are absent from the
    embedded ``/docs`` OpenAPI; the SPEC is the authority.
"""

from __future__ import annotations

from typing import Any, Optional

import typer

from bp.cliutil import run

sub = typer.Typer(no_args_is_help=True, help="Burp Collaborator OAST payloads (Pro only).")


@sub.command("new")
def new(
    ctx: typer.Context,
    count: Optional[int] = typer.Option(None, "--count", min=1, help="Number of payloads to generate (default 1)."),
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
    collab_id: Optional[str] = typer.Argument(None, metavar="id", help="Collaborator payload id to scope the poll (optional)."),
) -> None:
    """Poll for Collaborator interactions.

    Without an id: GET /collaborator/poll — returns all interactions for the session.
    With an id:    GET /collaborator/poll/{id} — scoped to that specific payload.

    Requires Burp Suite Professional — exits 4 (PRO_REQUIRED) on Community.

    NOTE: poll errors are silently swallowed by the extension (returns found=false on HTTP 200),
    so an unknown id is indistinguishable from a payload with no interaction yet.
    """
    if collab_id is not None:

        def _poll_id(c: Any) -> Any:
            result = c.get(f"/collaborator/poll/{collab_id}")
            typer.echo(
                "note: Collaborator poll timestamps reflect poll time (Instant.now()), not capture time.",
                err=True,
            )
            return result

        run(ctx, _poll_id)
    else:

        def _poll_all(c: Any) -> Any:
            result = c.get("/collaborator/poll")
            typer.echo(
                "note: Collaborator poll timestamps reflect poll time (Instant.now()), not capture time.",
                err=True,
            )
            return result

        run(ctx, _poll_all)


def register(app: typer.Typer) -> None:
    """Register the 'collab' sub-command group onto *app*."""
    app.add_typer(sub, name="collab")
