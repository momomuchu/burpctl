"""[10][12] RED tests — bp check commands exit 5 (EXIT_VULN) when findings present.

Per ADR-0010 and ADR-0013, bp check auth/idor/cors/headers/endpoints must exit 5 when
the scan succeeded and reported a confirmed finding (``vulnerableCount > 0`` or a nonempty
``findings`` list). A response delta reported only through ``anomalousCount`` is triage evidence,
not a vulnerability verdict.

These tests cover:
1. Unit tests for the _has_findings() helper (pure logic, no Burp needed).
2. The helper is the required RED; Burp-gated e2e is skipped when :8089 is down.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from bp.commands.securityscan import (
    _has_findings,
    _project_for_display,
    _scan_exit_code,
)
from bp.cliutil import EXIT_GENERIC, EXIT_VULN


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
    """An anomaly alone is not a confirmed finding."""
    assert _has_findings({"anomalousCount": 3}) is False


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
    data = {
        "findings": [{"endpoint": "/admin", "test": "auth-bypass"}],
        "scanned": 3,
        "durationMs": 120,
    }
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


def test_has_findings_anomalous_count_does_not_override_zero_verdict() -> None:
    """Regression: an observation count cannot independently select exit 5."""
    assert _has_findings({"anomalousCount": 2}) is False
    assert _has_findings({"vulnerableCount": 0, "anomalousCount": 2}) is False


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
        src = inspect.getsource(cmd)  # type: ignore[arg-type]
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
# C3 — every check command must project the same verdict before rendering
# ---------------------------------------------------------------------------


def test_all_check_commands_apply_shared_output_projection() -> None:
    import inspect

    from bp.commands import securityscan

    for command in (
        securityscan.check_auth,
        securityscan.check_idor,
        securityscan.check_headers,
        securityscan.check_cors,
        securityscan.check_endpoints,
    ):
        source = inspect.getsource(command)
        assert "_project_for_display" in source, f"{command.__name__} bypasses verdict projection"
        assert "_scan_exit" in source, f"{command.__name__} bypasses shared exit precedence"


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


def test_project_adds_verdict_clean_for_anomaly_only() -> None:
    """Anomaly-only output remains visible but its quiet verdict is clean."""
    data: dict[str, Any] = {"anomalousCount": 2, "vulnerableCount": 0}
    projected = _project_for_display(data)
    assert projected.get("verdict") == "clean"


def test_project_reports_inconclusive_instead_of_clean() -> None:
    """Only the authoritative top-level count drives the inconclusive verdict."""
    data: dict[str, Any] = {"vulnerableCount": 0, "inconclusiveCount": 1}
    assert _project_for_display(data).get("verdict") == "inconclusive"
    assert _has_findings(data) is False


def test_project_does_not_infer_inconclusive_from_nested_shapes() -> None:
    for data in (
        {"vulnerableCount": 0, "results": [{"inconclusive": True}]},
        {"findings": [], "errors": [{"endpoint": "/a"}]},
        {"vulnerableCount": 0, "baseline": {"inconclusive": True}},
    ):
        assert _project_for_display(data).get("verdict") == "clean"


def test_confirmed_finding_outranks_inconclusive_probes() -> None:
    data: dict[str, Any] = {"vulnerableCount": 1, "inconclusiveCount": 3}
    assert _project_for_display(data).get("verdict") == "vulnerable"


def test_scan_exit_precedence_is_finding_then_inconclusive_then_clean() -> None:
    """C8: mixed results stay exit 5; inconclusive-only uses existing runtime exit 1."""
    assert _scan_exit_code({"vulnerableCount": 1, "inconclusiveCount": 2}) == EXIT_VULN
    assert _scan_exit_code({"findings": [{"id": 1}], "inconclusiveCount": 2}) == EXIT_VULN
    assert _scan_exit_code({"vulnerableCount": 0, "inconclusiveCount": 1}) == EXIT_GENERIC
    assert _scan_exit_code({"findings": [], "inconclusiveCount": 0}) is None


def test_scan_exit_does_not_infer_inconclusive_from_anomaly_count() -> None:
    assert _scan_exit_code({"vulnerableCount": 0, "anomalousCount": 9}) is None


def test_check_operation_deadline_is_derived_from_actual_probe_plan() -> None:
    from bp.commands.securityscan import _operation_timeout_seconds

    small_auth = _operation_timeout_seconds(3, 5_000, None)
    headers = _operation_timeout_seconds(17, 5_000, None)
    large_endpoints = _operation_timeout_seconds(8_000, 120_000, None)

    assert 15 < small_auth < 30
    assert headers > 85
    assert large_endpoints > 8_000 * 120
    assert small_auth < headers < large_endpoints


def test_check_operation_deadline_override_is_exact() -> None:
    from bp.commands.securityscan import _operation_timeout_seconds

    assert _operation_timeout_seconds(8_000, 120_000, 1_234) == 1.234


def test_headers_cli_sends_probe_budget_and_uses_deadline_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    from bp.cli import app

    posted: list[dict[str, Any]] = []
    deadlines: list[float | None] = []

    class StubClient:
        def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
            assert path == "/scan/headers"
            posted.append(body)
            return {"vulnerableCount": 0, "inconclusiveCount": 0, "results": []}

    def fake_run(
        _ctx: Any,
        fn: Any,
        *,
        exit_on: Any = None,
        timeout: float | None = None,
    ) -> None:
        deadlines.append(timeout)
        fn(StubClient())

    monkeypatch.setattr("bp.commands.securityscan.run", fake_run)
    result = CliRunner().invoke(
        app,
        [
            "check",
            "headers",
            "https://example.test",
            "--probe-timeout-ms",
            "1234",
            "--deadline-ms",
            "9000",
        ],
    )

    assert result.exit_code == 0, result.stderr
    assert posted[0]["probeTimeoutMs"] == 1234
    assert deadlines == [9.0]


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
def test_check_auth_live_has_a_valid_scan_outcome() -> None:
    """Live matched pair returns clean (0), inconclusive (1), or confirmed finding (5)."""
    import subprocess
    import sys

    entry = (
        "import sys; sys.argv=['bp','check','auth','http://127.0.0.1:8089']; "
        "from bp.cli import cli_main; cli_main()"
    )
    result = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert result.returncode in (0, 1, 5), (
        f"expected 0, 1, or 5, got {result.returncode}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    if result.returncode == 1:
        # Runtime exit 1 is valid here only for the structured inconclusive outcome. A stale-extension
        # compatibility refusal deliberately remains a failing live gate until the JAR is hot-swapped.
        assert "inconclusive" in result.stderr.lower(), result.stderr
        assert result.stdout, "an inconclusive scan must retain its structured result"


def _invoke_auth_check(
    monkeypatch: pytest.MonkeyPatch,
    response_data: dict[str, Any],
    *auth_args: str,
) -> tuple[Any, list[dict[str, Any]]]:
    """Invoke the real CLI/client path while capturing the exact JSON transport receives."""
    from typer.testing import CliRunner

    from bp.cli import app
    from bp.client import BurpClient

    received: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/scan/auth-bypass"
        request_data = json.loads(request.content)
        assert isinstance(request_data, dict)
        received.append(request_data)
        return httpx.Response(
            200,
            json={"success": True, "data": response_data, "error": None},
        )

    def client_factory(
        _base_url: str,
        *,
        ledger: Any = None,
        redact: bool = True,
        command: str | None = None,
        timeout: float = 30.0,
    ) -> BurpClient:
        return BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(handler),
                base_url="http://mock-extension",
                timeout=timeout,
            ),
            ledger=ledger,
            redact=redact,
            command=command,
        )

    monkeypatch.setattr("bp.cliutil.BurpClient", client_factory)
    result = CliRunner().invoke(
        app,
        [
            "--no-ledger",
            "--format",
            "quiet",
            "check",
            "auth",
            "https://target.test",
            *auth_args,
        ],
    )
    return result, received


@pytest.mark.parametrize(
    ("auth_args", "expected_marker"),
    [
        pytest.param(("--marker", "/api/élèves"), "/api/élèves", id="present-lossless"),
        pytest.param((), None, id="omitted"),
    ],
)
def test_check_auth_marker_wire_contract(
    monkeypatch: pytest.MonkeyPatch,
    auth_args: tuple[str, ...],
    expected_marker: str | None,
) -> None:
    """The transport sees an exact optional marker, not a CLI-side projection or null default."""
    result, received = _invoke_auth_check(
        monkeypatch,
        {"vulnerableCount": 0, "inconclusiveCount": 0, "results": []},
        *auth_args,
    )

    assert result.exit_code == 0, result.stderr
    assert len(received) == 1
    if expected_marker is None:
        assert "protectedContentMarker" not in received[0]
    else:
        assert received[0]["protectedContentMarker"] == expected_marker


def test_check_auth_omitted_marker_preserves_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An omitted marker remains absent and does not turn server uncertainty into a clean exit."""
    result, received = _invoke_auth_check(
        monkeypatch,
        {"vulnerableCount": 0, "inconclusiveCount": 1, "results": []},
    )

    assert "protectedContentMarker" not in received[0]
    assert result.exit_code == EXIT_GENERIC
    assert "inconclusive" in result.stderr.lower()


def test_check_auth_marker_response_exit_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Marker-backed vulnerable, clean, and inconclusive responses remain three distinct outcomes."""
    marker = "/api/élèves"
    cases = [
        ({"vulnerableCount": 1, "inconclusiveCount": 0, "results": []}, EXIT_VULN),
        ({"vulnerableCount": 0, "inconclusiveCount": 0, "results": []}, 0),
        ({"vulnerableCount": 0, "inconclusiveCount": 1, "results": []}, EXIT_GENERIC),
    ]
    observed: list[int] = []

    for response_data, expected_exit in cases:
        result, received = _invoke_auth_check(
            monkeypatch,
            response_data,
            "--marker",
            marker,
        )
        assert received == [
            {
                "endpoints": ["/api/admin"],
                "baseUrl": "https://target.test",
                "method": "GET",
                "probeTimeoutMs": 5_000,
                "protectedContentMarker": marker,
            }
        ]
        assert result.exit_code == expected_exit, result.stderr
        observed.append(result.exit_code)

    assert observed == [EXIT_VULN, 0, EXIT_GENERIC]
    assert len(set(observed)) == 3
