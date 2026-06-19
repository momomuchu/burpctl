"""bp scan — Scanner group (§6.6 SPEC.md). Pro-only for crawl/audit/start endpoints.

Commands
--------
bp scan crawl <url>   POST /scanner/crawl          {url, config:{}}
bp scan audit <url>   POST /scanner/audit          {url, config:{}} — url IGNORED by server
bp scan all   <url>   POST /scanner/crawl-and-audit {url, config:{}}
bp scan status <id>   GET  /scanner/{id}/status
bp scan issues <id>   GET  /scanner/{id}/issues
bp scan defs          GET  /scanner/issue-definitions

Kotlin DTOs (§6.6):
  ScanRequest    { url:String, config:ScanConfig={} }
  ScanConfig     {} (empty, accepted for forward-compat)
  scanId         String (8-char UUID prefix)

Caveats (surfaced to stderr where relevant):
  - crawl/audit/crawl-and-audit → PRO_REQUIRED (500) on Community.
  - audit ignores the <url> argument server-side; scope = Burp UI scope.
  - pause / resume are stubs (not implemented here — not in CLI.md scope).
  - stop removes from tracking map but does NOT stop the Burp task.
  - crawlProgress / auditProgress always 0 (server stub).
  - Entire group absent from /docs (OpenAPI).
  - issue-definitions degrades gracefully on Community (empty list).
"""

from __future__ import annotations

from typing import Any

import typer

from bp.client import BurpClient
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
    url: str = typer.Argument(..., metavar="URL", help="URL argument (ignored server-side)."),
) -> None:
    """Run active checks against the current Burp scope (Pro-only).

    WARNING: the <url> argument is accepted but IGNORED by the server.
    Scope is determined by the Burp UI scope, not this argument.
    Requires Burp Suite Professional; exits with code 4 on Community.
    """
    typer.echo(
        "warning: audit ignores <url>; scope is the Burp UI scope, not this argument.",
        err=True,
    )
    run(ctx, lambda c: c.post("/scanner/audit", {"url": url, "config": {}}))


@sub.command("all")
def scan_all(
    ctx: typer.Context,
    url: str = typer.Argument(..., metavar="URL", help="Target URL to crawl and audit."),
) -> None:
    """Full scan: crawl then audit in one call (Pro-only).

    Returns a scanId (String). Poll with 'bp scan status <id>'.
    Requires Burp Suite Professional; exits with code 4 on Community.
    """
    run(ctx, lambda c: c.post("/scanner/crawl-and-audit", {"url": url, "config": {}}))


@sub.command("status")
def scan_status(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., metavar="SCAN_ID", help="Scan ID returned by crawl/audit/all."),
) -> None:
    """Show scan progress and issue count for a running scan (Pro-only).

    Note: crawlProgress and auditProgress are always 0 (server stub).
    issueCount reflects issues found so far.
    """

    def _do(client: BurpClient) -> Any:
        result = client.get(f"/scanner/{scan_id}/status")
        typer.echo(
            "note: crawlProgress/auditProgress are always 0 (server stub).",
            err=True,
        )
        return result

    run(ctx, _do)


@sub.command("issues")
def scan_issues(
    ctx: typer.Context,
    scan_id: str = typer.Argument(..., metavar="SCAN_ID", help="Scan ID returned by crawl/audit/all."),
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
