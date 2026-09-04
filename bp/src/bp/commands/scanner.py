"""Burp Scanner commands.

Crawl and target-seeded audit require Burp Professional. Montoya 2025.3 has
no linked crawl-and-audit or pause/resume primitive; those discoverable REST
operations return a typed ``UNSUPPORTED`` result rather than false success.
"""

from __future__ import annotations

import typer

from bp.cliutil import run

sub = typer.Typer(
    name="scan",
    no_args_is_help=True,
    help="Scanner commands (Pro-only for crawl/audit/start). See §6.6.",
)


@sub.command("crawl")
def scan_crawl(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL to crawl."),
) -> None:
    """Spider the target app and map its endpoints (Pro-only).

    Returns a scanId (String). Poll with 'bp scan status <id>'.
    Requires Burp Suite Professional; exits with code 4 on Community.
    """
    run(ctx, lambda c: c.post("/scanner/crawl", {"url": url, "config": {}}))


@sub.command("audit")
def scan_audit(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Exact HTTP(S) URL to audit."),
) -> None:
    """Start active checks seeded with the supplied target URL (Pro-only)."""

    run(ctx, lambda c: c.post("/scanner/audit", {"url": url, "config": {}}))


@sub.command("all")
def scan_all(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL to crawl and audit."),
) -> None:
    """Request linked crawl+audit; Montoya 2025.3 reports this unsupported."""
    run(ctx, lambda c: c.post("/scanner/crawl-and-audit", {"url": url, "config": {}}))


@sub.command("status")
def scan_status(
    ctx: typer.Context,
    scan_id: str = typer.Argument(
        ..., metavar="SCAN_ID", help="Scan ID returned by crawl/audit/all."
    ),
) -> None:
    """Show authoritative task status, request/error counts, and issue count."""

    run(ctx, lambda client: client.get(f"/scanner/{scan_id}/status"))


@sub.command("issues")
def scan_issues(
    ctx: typer.Context,
    scan_id: str = typer.Argument(
        ..., metavar="SCAN_ID", help="Scan ID returned by crawl/audit/all."
    ),
) -> None:
    """List vulnerabilities found by a scan (Pro-only).

    Each issue has: name, url, severity (HIGH/MEDIUM/LOW/INFORMATION/FALSE_POSITIVE),
    confidence (CERTAIN/FIRM/TENTATIVE).
    """
    run(ctx, lambda c: c.get(f"/scanner/{scan_id}/issues"))


@sub.command("defs")
def scan_defs(
    ctx: typer.Context,
) -> None:
    """List issue definitions from the Burp sitemap.

    Degrades gracefully on Community (returns empty list if unavailable).
    This is the only scanner endpoint available without Pro.
    """
    run(ctx, lambda c: c.get("/scanner/issue-definitions"))


def register(app: typer.Typer) -> None:
    """Register the 'scan' sub-command group onto *app*."""
    app.add_typer(sub, name="scan")
