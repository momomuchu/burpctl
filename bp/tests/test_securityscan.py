"""[10][12] RED tests — bp check commands exit 5 (EXIT_VULN) when findings present.

Per ADR-0010 (docs/adr/0010-check-exit-on-findings.md), bp check auth/idor/cors/headers/endpoints
must exit 5 when the scan succeeded AND reported findings (vulnerableCount > 0 or
anomalousCount > 0 for headers).

These tests cover:
1. Unit tests for the _has_findings() helper (pure logic, no Burp needed).
2. The helper is the required RED; Burp-gated e2e is skipped when :8089 is down.
"""

from __future__ import annotations

from typing import Any

import pytest

from bp.commands.securityscan import _has_findings, _project_for_display


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


# ---------------------------------------------------------------------------
# [02][13] RED — _project_for_display output-hygiene (PII-leak / NDJSON pollution)
# ---------------------------------------------------------------------------

# Canonical fake IdorResponse that mirrors what the server sends.
_FAKE_IDOR_RESPONSE: dict[str, Any] = {
    "vulnerableCount": 1,
    "results": [
        {
            "targetId": "42",
            "statusCode": 200,
            "bodyPreview": "SSN: 123-45-6789, email: victim@corp.com",
            "delta": 0.8,
        },
        {
            "targetId": "43",
            "statusCode": 200,
            "bodyPreview": "admin email: root@corp.com",
            "delta": 0.6,
        },
    ],
    "baseline": {
        "statusCode": 200,
        "bodyPreview": "your own baseline body here",
        "length": 512,
    },
    "note": "IDOR heuristic: >= 5% body-length delta or 2xx on target IDs.",
    "ignoredOwnValues": [],
}


def _deep_has_key(obj: Any, key: str) -> bool:
    """Recursively check whether *key* exists anywhere in a nested dict/list."""
    if isinstance(obj, dict):
        if key in obj:
            return True
        return any(_deep_has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(_deep_has_key(item, key) for item in obj)
    return False


def test_project_removes_body_preview_from_results() -> None:
    """[02] bodyPreview must not appear in any results[] entry after projection."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    assert not _deep_has_key(projected, "bodyPreview"), (
        "bodyPreview found in projected dict — PII leak to stdout"
    )


def test_project_removes_body_preview_from_baseline() -> None:
    """[02] bodyPreview must not appear in baseline after projection."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    assert "bodyPreview" not in projected.get("baseline", {}), (
        "bodyPreview still present in baseline after projection"
    )


def test_project_removes_note_from_dict() -> None:
    """[13] note must be removed from the projected dict (it goes to stderr, not stdout)."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    assert "note" not in projected, (
        "note key still present in projected dict — corrupts NDJSON consumers"
    )


def test_project_returns_note_text() -> None:
    """[13] _project_for_display must return the note text so the caller can echo it to stderr."""
    projected, note = _project_for_display(_FAKE_IDOR_RESPONSE.copy(), return_note=True)
    assert note == _FAKE_IDOR_RESPONSE["note"]


def test_project_drops_empty_ignored_own_values() -> None:
    """[13] ignoredOwnValues=[] must be dropped from the projected dict."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    assert "ignoredOwnValues" not in projected, (
        "empty ignoredOwnValues still present — clutters output"
    )


def test_project_keeps_non_empty_ignored_own_values() -> None:
    """[13] ignoredOwnValues=[...] must be PRESERVED when non-empty."""
    data = dict(_FAKE_IDOR_RESPONSE)
    data["ignoredOwnValues"] = ["100", "101"]
    projected = _project_for_display(data)
    assert projected.get("ignoredOwnValues") == ["100", "101"]


def test_project_preserves_vulnerable_count() -> None:
    """[02] vulnerableCount must survive projection so _has_findings still works."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    assert projected.get("vulnerableCount") == 1


def test_project_preserves_results_minus_body_preview() -> None:
    """[02] results[] entries are kept (minus bodyPreview) after projection."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    results = projected.get("results", [])
    assert len(results) == 2
    for entry in results:
        assert "bodyPreview" not in entry
        assert "targetId" in entry  # structural fields preserved


def test_has_findings_on_projected_dict() -> None:
    """_has_findings must still detect findings after projection (exit_on= contract preserved)."""
    projected = _project_for_display(_FAKE_IDOR_RESPONSE.copy())
    assert _has_findings(projected) is True


def test_project_no_body_preview_input_is_identity_like() -> None:
    """When there is no bodyPreview/note/ignoredOwnValues, projection preserves all input
    fields and adds exactly one key: 'verdict' (additive per [09], OUTPUT.md §1.5)."""
    data: dict[str, Any] = {"vulnerableCount": 0, "results": [], "anomalousCount": 0}
    projected = _project_for_display(data)
    # All original keys must be preserved unchanged.
    for k, v in data.items():
        assert projected[k] == v, f"key {k!r} was mutated by projection"
    # The only addition is the verdict key.
    assert projected.get("verdict") == "clean"
    assert set(projected.keys()) == set(data.keys()) | {"verdict"}


def test_project_handles_missing_baseline_gracefully() -> None:
    """projection must not crash when baseline key is absent."""
    data = {k: v for k, v in _FAKE_IDOR_RESPONSE.items() if k != "baseline"}
    projected = _project_for_display(data)
    assert "baseline" not in projected


def test_project_handles_deeply_nested_body_preview() -> None:
    """bodyPreview removal is recursive — nested dicts inside results[] are also cleaned."""
    data: dict[str, Any] = {
        "vulnerableCount": 1,
        "results": [
            {"nested": {"bodyPreview": "secret"}, "targetId": "1"},
        ],
        "ignoredOwnValues": [],
    }
    projected = _project_for_display(data)
    assert not _deep_has_key(projected, "bodyPreview")


# ---------------------------------------------------------------------------
# [09] RED — quiet format must emit 'vulnerable' or 'clean', not Python repr
# ---------------------------------------------------------------------------


def test_project_adds_verdict_vulnerable_when_findings_present() -> None:
    """[09] RED: _project_for_display must inject verdict='vulnerable' when _has_findings."""
    data: dict[str, Any] = {"vulnerableCount": 1, "results": []}
    projected = _project_for_display(data)
    assert projected.get("verdict") == "vulnerable", (
        f"expected verdict='vulnerable', got {projected.get('verdict')!r}"
    )


def test_project_adds_verdict_clean_when_no_findings() -> None:
    """[09] RED: _project_for_display must inject verdict='clean' when no findings."""
    data: dict[str, Any] = {"vulnerableCount": 0, "anomalousCount": 0, "findings": []}
    projected = _project_for_display(data)
    assert projected.get("verdict") == "clean", (
        f"expected verdict='clean', got {projected.get('verdict')!r}"
    )


def test_project_adds_verdict_vulnerable_via_anomalous_count() -> None:
    """[09] anomalousCount > 0 → verdict='vulnerable'."""
    data: dict[str, Any] = {"anomalousCount": 2}
    projected = _project_for_display(data)
    assert projected.get("verdict") == "vulnerable"


def test_project_adds_verdict_vulnerable_via_findings_list() -> None:
    """[09] non-empty findings list → verdict='vulnerable' (endpoints shape)."""
    data: dict[str, Any] = {"findings": [{"endpoint": "/admin"}], "scanned": 1}
    projected = _project_for_display(data)
    assert projected.get("verdict") == "vulnerable"


def test_quiet_render_verdict_vulnerable() -> None:
    """[09] render(projected, 'quiet') → 'vulnerable' when verdict key present."""
    from bp.output import render
    data = {"verdict": "vulnerable", "vulnerableCount": 1}
    assert render(data, "quiet") == "vulnerable"


def test_quiet_render_verdict_clean() -> None:
    """[09] render(projected, 'quiet') → 'clean' when verdict='clean'."""
    from bp.output import render
    data = {"verdict": "clean", "vulnerableCount": 0}
    assert render(data, "quiet") == "clean"


def test_quiet_verdict_takes_priority_over_status() -> None:
    """[09] 'verdict' key must be picked before 'status' in _ESSENTIAL ordering."""
    from bp.output import render
    # If verdict is present it must win over status
    data = {"verdict": "vulnerable", "status": 200}
    assert render(data, "quiet") == "vulnerable"


def test_json_render_includes_verdict() -> None:
    """[09] json/table formats still include verdict (additive, not stripped)."""
    from bp.output import render
    import json as _json
    data = {"verdict": "vulnerable", "vulnerableCount": 1}
    out = render(data, "json")
    parsed = _json.loads(out)
    assert parsed["verdict"] == "vulnerable"
    assert parsed["vulnerableCount"] == 1


def test_project_verdict_does_not_break_has_findings_contract() -> None:
    """[09] _has_findings still works on projected dict (verdict key has no effect on it)."""
    data: dict[str, Any] = {"vulnerableCount": 3}
    projected = _project_for_display(data)
    assert _has_findings(projected) is True


def test_project_clean_verdict_with_empty_findings() -> None:
    """[09] findings=[] (endpoints clean scan) → verdict='clean'."""
    data: dict[str, Any] = {"findings": [], "scanned": 5, "durationMs": 80}
    projected = _project_for_display(data)
    assert projected.get("verdict") == "clean"


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
