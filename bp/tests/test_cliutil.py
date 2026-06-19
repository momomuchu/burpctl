"""Guards on the cliutil.run chokepoint via the real CLI app.

These exercise the parts of the chokepoint that need no running Burp: option validation that
must fail fast with a clean usage error (exit 2) instead of leaking a Python traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import typer
from typer.testing import CliRunner

from bp.cli import app
from bp.client import BurpClient
from bp.cliutil import EXIT_VULN, parse_header, parse_headers, run
from bp.ledger import Ledger
from bp.output import render

runner = CliRunner()


# ---------------------------------------------------------------------------
# [18] — empty render output must produce zero bytes on stdout (no lone '\n')
# ---------------------------------------------------------------------------


def test_empty_render_produces_no_output(capsys: pytest.CaptureFixture[str]) -> None:
    """[18] render([]) returns '' and echo must be suppressed so stdout is zero bytes.

    This test invokes render() directly (the guard lives in cliutil.run before typer.echo).
    The contract: if render returns '', no echo call happens → stdout stays empty.
    We verify the render contract here; the cliutil guard is what makes it work end-to-end.
    """
    result = render([], "json")
    assert result == "", f"render([]) should be '' but got {result!r}"


def test_empty_table_render_produces_no_output() -> None:
    """[18] render([], 'table') must also return '' so the empty-output guard triggers."""
    assert render([], "table") == ""


def test_invalid_format_is_usage_error_not_traceback() -> None:
    """``--format bogus`` must be rejected before any server call, as a clean usage error.

    Regression: previously the bad format reached render() after the command ran, raising an
    uncaught ValueError that printed a Rich traceback and exited 1. It is now validated in the
    callback, so it fails with exit 2 and never contacts Burp.
    """
    result = runner.invoke(app, ["--format", "bogus", "health"])
    assert result.exit_code == 2


def test_parse_header_splits_name_value() -> None:
    assert parse_header("X-Role: admin") == ("X-Role", "admin")


def test_parse_header_strips_surrounding_whitespace() -> None:
    assert parse_header("  A :  b ") == ("A", "b")


def test_parse_header_missing_colon_raises_with_flag_name() -> None:
    """The shared helper names the offending flag (--set-header vs --header) in the error."""
    with pytest.raises(ValueError, match="--header"):
        parse_header("nocolon", "--header")


def test_parse_headers_builds_dict() -> None:
    assert parse_headers(["A: 1", "B: 2"]) == {"A": "1", "B": "2"}


def test_parse_headers_bad_input_is_usage_exit() -> None:
    """All three call sites now share exit 2 (one previously used a hardcoded literal)."""
    with pytest.raises(typer.Exit) as ei:
        parse_headers(["nocolon"])
    assert ei.value.exit_code == 2


# ---------------------------------------------------------------------------
# [15] — SERVICE_UNAVAILABLE BurpError code must map to EXIT_PRO (exit 4)
# ---------------------------------------------------------------------------


def test_service_unavailable_maps_to_exit_pro() -> None:
    """[15] _EXIT_BY_CODE['SERVICE_UNAVAILABLE'] must equal EXIT_PRO (4).

    Community Burp returns SERVICE_UNAVAILABLE for Pro-only scanner surfaces.
    The docs contract is exit 4; the map previously fell through to EXIT_GENERIC=1.
    """
    from bp.cliutil import EXIT_PRO, _EXIT_BY_CODE  # type: ignore[attr-defined]

    assert "SERVICE_UNAVAILABLE" in _EXIT_BY_CODE, (
        "_EXIT_BY_CODE missing SERVICE_UNAVAILABLE key"
    )
    assert _EXIT_BY_CODE["SERVICE_UNAVAILABLE"] == EXIT_PRO, (
        f"expected EXIT_PRO={EXIT_PRO}, got {_EXIT_BY_CODE['SERVICE_UNAVAILABLE']}"
    )


# ---------------------------------------------------------------------------
# Helpers shared by [10] and [12] cliutil tests
# ---------------------------------------------------------------------------


def _make_mock_client(ledger: Ledger | None, response_data: Any = None) -> BurpClient:
    """Return a BurpClient backed by a MockTransport; no real Burp needed."""
    data = response_data if response_data is not None else {"status": "ok"}

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "data": data, "error": None})

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test"),
        ledger=ledger,
    )


def _make_ctx(no_ledger: bool = False) -> typer.Context:
    """Build a minimal typer.Context with a State object."""
    from bp.cliutil import State

    ctx = MagicMock(spec=typer.Context)
    ctx.obj = State(
        url="http://127.0.0.1:8089",
        fmt="json",
        fields=None,
        no_ledger=no_ledger,
        no_redact=True,
    )
    ctx.command_path = "bp test"
    return ctx


# ---------------------------------------------------------------------------
# [10] RED — exit_on callback: check with findings records exit_code=5 in ledger
# ---------------------------------------------------------------------------


def _make_mock_burp_client(ledger: Ledger | None, response_data: Any = None) -> BurpClient:
    """BurpClient backed by a MockTransport — no real Burp needed."""
    data = response_data if response_data is not None else {"status": "ok"}

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "data": data, "error": None})

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test"),
        ledger=ledger,
    )


def test_run_exit_on_vuln_records_exit5_in_ledger(tmp_path: Path) -> None:
    """[10] GREEN: when exit_on returns EXIT_VULN, the ledger row must have exit_code=5.

    Before the fix, run()'s finally backfills 0 and then securityscan raises Exit(5)
    after run() returns — ledger already recorded 0.  After the fix, run() calls
    exit_on, sets exit_code=5 internally before finally runs, and raises Exit(5) itself.

    We patch both Ledger() and BurpClient() inside run() so fn() is called through a
    mock transport.  run() calls ledger.close() in its finally, so we open a fresh
    Ledger on the same db file to read back the persisted row.
    """
    db = tmp_path / "ledger.db"
    # Pre-create the db file so the mock-patched Ledger() returns it correctly.
    # We pass the db path via a factory so the patched Ledger() uses the same file.
    findings_data: dict[str, Any] = {"vulnerableCount": 1}

    captured_ledger: list[Ledger] = []

    def _ledger_factory() -> Ledger:
        ledger_inst = Ledger(db_path=db)
        captured_ledger.append(ledger_inst)
        return ledger_inst

    def _fn(client: BurpClient) -> Any:
        # Simulate a Burp HTTP call so a ledger row is inserted via the real client path.
        client.get("/health")
        return findings_data

    ctx = _make_ctx(no_ledger=False)

    def _client_factory(url: str, *, ledger: Ledger | None = None, redact: bool = True, command: str = "") -> BurpClient:
        return _make_mock_burp_client(ledger, {"status": "ok"})

    with patch("bp.cliutil.Ledger", side_effect=_ledger_factory), \
         patch("bp.cliutil.BurpClient", side_effect=_client_factory):
        with pytest.raises(typer.Exit) as exc_info:
            run(ctx, _fn, exit_on=lambda d: EXIT_VULN if d.get("vulnerableCount", 0) > 0 else None)

    assert exc_info.value.exit_code == EXIT_VULN, (
        f"process must exit {EXIT_VULN}, got {exc_info.value.exit_code}"
    )
    # Open a fresh connection to read back the persisted row (run() already closed the ledger).
    with Ledger(db_path=db) as verify_ledger:
        rows = verify_ledger.query()
    assert len(rows) == 1, f"expected 1 ledger row, got {len(rows)}"
    assert rows[0].exit_code == EXIT_VULN, (
        f"ledger must record exit_code={EXIT_VULN}, got {rows[0].exit_code}"
    )


def test_run_exit_on_none_does_not_raise(tmp_path: Path) -> None:
    """[10] GREEN (backward-compat): when exit_on returns None, run() behaves exactly as before."""
    db = tmp_path / "ledger.db"

    def _fn(client: BurpClient) -> Any:
        client.get("/health")
        return {"status": "ok"}

    ctx = _make_ctx(no_ledger=False)

    def _ledger_factory() -> Ledger:
        return Ledger(db_path=db)

    def _client_factory(url: str, *, ledger: Ledger | None = None, redact: bool = True, command: str = "") -> BurpClient:
        return _make_mock_burp_client(ledger, {"status": "ok"})

    with patch("bp.cliutil.Ledger", side_effect=_ledger_factory), \
         patch("bp.cliutil.BurpClient", side_effect=_client_factory):
        # Must NOT raise; run() returns normally
        run(ctx, _fn, exit_on=lambda d: None)

    with Ledger(db_path=db) as verify_ledger:
        rows = verify_ledger.query()
    assert len(rows) == 1
    assert rows[0].exit_code == 0, (
        f"clean run must record exit_code=0, got {rows[0].exit_code}"
    )


def test_run_no_exit_on_default_behavior(tmp_path: Path) -> None:
    """[10] GREEN (backward-compat): omitting exit_on keeps existing behavior (no raise, exit_code=0)."""
    db = tmp_path / "ledger.db"

    def _fn(client: BurpClient) -> Any:
        client.get("/health")
        return {"status": "ok"}

    ctx = _make_ctx(no_ledger=False)

    def _ledger_factory() -> Ledger:
        return Ledger(db_path=db)

    def _client_factory(url: str, *, ledger: Ledger | None = None, redact: bool = True, command: str = "") -> BurpClient:
        return _make_mock_burp_client(ledger, {"status": "ok"})

    with patch("bp.cliutil.Ledger", side_effect=_ledger_factory), \
         patch("bp.cliutil.BurpClient", side_effect=_client_factory):
        run(ctx, _fn)  # no exit_on — must not raise

    with Ledger(db_path=db) as verify_ledger:
        rows = verify_ledger.query()
    assert len(rows) == 1
    assert rows[0].exit_code == 0


# ---------------------------------------------------------------------------
# [12] RED — Ledger() construction failure must not crash run(); op still executes
# ---------------------------------------------------------------------------


def test_run_ledger_ctor_permission_error_op_proceeds(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """[12] RED: when Ledger() raises PermissionError, run() warns on stderr and executes fn().

    Before the fix, a PermissionError from Ledger() propagates out of run() and the Burp
    call never happens.  After the fix, ledger=None and the operation succeeds.
    """
    fn_called = False

    def _fn(client: BurpClient) -> Any:
        nonlocal fn_called
        fn_called = True
        return {"status": "ok"}

    ctx = _make_ctx(no_ledger=False)

    with patch("bp.cliutil.Ledger", side_effect=PermissionError("no write permission")):
        run(ctx, _fn)  # must NOT raise

    assert fn_called, "fn(client) must be called even when Ledger() construction fails"
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower(), (
        f"stderr must contain a warning line, got {captured.err!r}"
    )


def test_run_ledger_ctor_sqlite_error_op_proceeds(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """[12] RED: when Ledger() raises sqlite3.OperationalError, run() warns and proceeds."""
    import sqlite3

    fn_called = False

    def _fn(client: BurpClient) -> Any:
        nonlocal fn_called
        fn_called = True
        return {"status": "ok"}

    ctx = _make_ctx(no_ledger=False)

    with patch("bp.cliutil.Ledger", side_effect=sqlite3.OperationalError("unable to open")):
        run(ctx, _fn)

    assert fn_called
    captured = capsys.readouterr()
    assert "warning" in captured.err.lower()
