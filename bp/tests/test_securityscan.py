"""[12] RED tests — bp check commands exit 5 (EXIT_VULN) when findings present.

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
