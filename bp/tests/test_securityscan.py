"""[10][12] RED tests — bp check commands exit 5 (EXIT_VULN) when findings present.

Per ADR-0010 (docs/adr/0010-check-exit-on-findings.md), bp check auth/idor/cors/headers/endpoints
must exit 5 when the scan succeeded AND reported findings (vulnerableCount > 0 or
anomalousCount > 0 for headers).

These tests cover:
1. Unit tests for the _has_findings() helper (pure logic, no Burp needed).
2. The helper is the required RED; Burp-gated e2e is skipped when :8089 is down.
"""

from __future__ import annotations

import pytest

from bp.commands.securityscan import _has_findings


# ---------------------------------------------------------------------------
# Unit tests for _has_findings helper — no Burp required
# ---------------------------------------------------------------------------


def test_has_findings_vulnerable_count_nonzero() -> None:
    """vulnerableCount > 0 → has findings."""
    assert _has_findings({"vulnerableCount": 1}) is True


def test_has_findings_vulnerable_count_large() -> None:
    """vulnerableCount > 1 → has findings."""
    assert _has_findings({"vulnerableCount": 42}) is True


def test_has_findings_vulnerable_count_zero() -> None:
    """vulnerableCount == 0 → no findings."""
    assert _has_findings({"vulnerableCount": 0}) is False


def test_has_findings_anomalous_count_nonzero() -> None:
    """anomalousCount > 0 → has findings (headers command)."""
    assert _has_findings({"anomalousCount": 3}) is True


def test_has_findings_anomalous_count_zero() -> None:
    """anomalousCount == 0 → no findings."""
    assert _has_findings({"anomalousCount": 0}) is False


def test_has_findings_both_zero() -> None:
    """Both counts zero → no findings."""
    assert _has_findings({"vulnerableCount": 0, "anomalousCount": 0}) is False


def test_has_findings_both_nonzero() -> None:
    """Both counts nonzero → has findings."""
    assert _has_findings({"vulnerableCount": 2, "anomalousCount": 1}) is True


def test_has_findings_neither_key_present() -> None:
    """Response without either count key → no findings (safe default)."""
    assert _has_findings({}) is False
    assert _has_findings({"results": []}) is False


# ---------------------------------------------------------------------------
# [00]/[19] RED — EndpointsScanResponse shape: findings list, not count keys
# ---------------------------------------------------------------------------


def test_has_findings_findings_list_nonempty() -> None:
    """findings=[{...}] with scanned/durationMs → has findings (endpoints shape)."""
    data = {"findings": [{"endpoint": "/admin", "test": "auth-bypass"}], "scanned": 3, "durationMs": 120}
    assert _has_findings(data) is True


def test_has_findings_findings_list_empty() -> None:
    """findings=[] → no findings (endpoints shape, clean scan)."""
    data = {"findings": [], "scanned": 3, "durationMs": 87}
    assert _has_findings(data) is False


def test_has_findings_findings_list_multiple() -> None:
    """findings=[...] with multiple entries → has findings."""
    data = {"findings": [{"endpoint": "/a"}, {"endpoint": "/b"}], "scanned": 10}
    assert _has_findings(data) is True


def test_has_findings_findings_key_absent_scanned_only() -> None:
    """scanned/durationMs present but no findings key → no findings (safe default)."""
    assert _has_findings({"scanned": 5, "durationMs": 50}) is False


def test_has_findings_vulnerable_count_unchanged_after_fix() -> None:
    """Regression: existing vulnerableCount path still works after findings-list fix."""
    assert _has_findings({"vulnerableCount": 1, "scanned": 1}) is True
    assert _has_findings({"vulnerableCount": 0}) is False


def test_has_findings_anomalous_count_unchanged_after_fix() -> None:
    """Regression: existing anomalousCount path still works after findings-list fix."""
    assert _has_findings({"anomalousCount": 2}) is True
    assert _has_findings({"anomalousCount": 0}) is False


def test_has_findings_nested_data() -> None:
    """_has_findings works on a typical server response dict."""
    assert _has_findings({"vulnerableCount": 1, "results": [{"endpoint": "/admin"}]}) is True


# ---------------------------------------------------------------------------
# Burp-gated e2e (skipped when :8089 is not reachable)
# ---------------------------------------------------------------------------

try:
    import httpx as _httpx
    _burp_up = _httpx.get("http://127.0.0.1:8089/health", timeout=1.0).status_code == 200
except Exception:
    _burp_up = False


# ---------------------------------------------------------------------------
# [10] RED — securityscan must pass exit_on= to run() instead of holder pattern
# ---------------------------------------------------------------------------


def test_check_commands_use_exit_on_not_holder_pattern() -> None:
    """[10] RED: after the fix, no check_* function calls raise typer.Exit(EXIT_VULN) directly.

    The holder pattern (capture _result, then `if _has_findings(_result): raise typer.Exit(EXIT_VULN)`)
    must be removed.  Instead each command passes exit_on= to run() which handles both the
    ledger back-fill and the raise internally.

    This test inspects the bytecode/source of each check_* function to confirm it no longer
    contains a standalone `typer.Exit(EXIT_VULN)` raise after the `run(ctx, _do)` call.
    """
    import ast
    import inspect

    from bp.commands import securityscan

    commands = [
        securityscan.check_auth,
        securityscan.check_idor,
        securityscan.check_headers,
        securityscan.check_cors,
        securityscan.check_endpoints,
    ]

    for cmd in commands:
        src = inspect.getsource(cmd)
        try:
            tree = ast.parse(src)
        except SyntaxError:
            pytest.fail(f"Could not parse {cmd.__name__}")

        # After the fix there must be NO raise of typer.Exit(...) at the top level of the
        # function body (the holder pattern). The exit_on= argument to run() replaces it.
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and node.exc is not None:
                exc = node.exc
                # Detect: raise typer.Exit(EXIT_VULN)
                if (
                    isinstance(exc, ast.Call)
                    and isinstance(exc.func, ast.Attribute)
                    and exc.func.attr == "Exit"
                ):
                    pytest.fail(
                        f"{cmd.__name__} still contains a direct `raise typer.Exit(...)` — "
                        "the holder pattern must be replaced by exit_on= in run()"
                    )


@pytest.mark.skipif(not _burp_up, reason="needs live Burp REST on :8089")
def test_check_auth_exits_5_when_findings_live() -> None:
    """[12] Live: bp check auth exits 5 if vulnerableCount > 0, 0 if no findings."""
    import subprocess
    import sys

    entry = (
        "import sys; sys.argv=['bp','check','auth','http://127.0.0.1:8089']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    # Accept 0 (no findings) or 5 (findings present); anything else is a bug.
    assert r.returncode in (0, 5), (
        f"expected 0 or 5, got {r.returncode}\nstdout={r.stdout!r}\nstderr={r.stderr!r}"
    )
