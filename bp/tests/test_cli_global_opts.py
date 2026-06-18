"""F1 / ADR-0009 — global output options must be position-tolerant.

`bp <cmd> --format json` must behave like `bp --format json <cmd>`. The fix is a
conservative argv pre-processor (`_hoist_global_opts`) in the console entrypoint;
these unit tests lock its token-rewriting rules, and one Burp-gated subprocess
test proves the real binary round-trips.
"""

from __future__ import annotations

import subprocess
import sys

import httpx
import pytest

from bp.cli import _hoist_global_opts


def test_hoist_format_after_subcommand() -> None:
    assert _hoist_global_opts(["health", "--format", "json"]) == ["--format", "json", "health"]


def test_hoist_fields_after_subcommand() -> None:
    assert _hoist_global_opts(["health", "--fields", "status"]) == ["--fields", "status", "health"]


def test_hoist_is_noop_when_already_global() -> None:
    assert _hoist_global_opts(["--format", "json", "health"]) == ["--format", "json", "health"]


def test_hoist_handles_equals_form() -> None:
    assert _hoist_global_opts(["health", "--fields=status"]) == ["--fields=status", "health"]


def test_hoist_preserves_url_and_command_args() -> None:
    assert _hoist_global_opts(
        ["--url", "http://x", "proxy", "--host", "h", "--format", "json"]
    ) == ["--url", "http://x", "--format", "json", "proxy", "--host", "h"]


def test_hoist_no_subcommand_is_noop() -> None:
    assert _hoist_global_opts(["--help"]) == ["--help"]
    assert _hoist_global_opts([]) == []


def test_hoist_dangling_option_left_for_typer() -> None:
    # A trailing global option with no value is left in place for Typer to reject.
    assert _hoist_global_opts(["health", "--format"]) == ["health", "--format"]


def test_hoist_does_not_touch_non_global_options() -> None:
    assert _hoist_global_opts(["fuzz", "5", "--pos", "header:X"]) == ["fuzz", "5", "--pos", "header:X"]


def test_hoist_no_ledger_flag_after_subcommand() -> None:
    assert _hoist_global_opts(["health", "--no-ledger"]) == ["--no-ledger", "health"]


# --- Burp-gated end-to-end: the real binary must accept the option after the subcommand ---

def _burp_up() -> bool:
    try:
        return httpx.get("http://127.0.0.1:8089/health", timeout=1.0).status_code == 200
    except Exception:
        return False


# Invoke the real entrypoint (cli_main → hoist → dispatch) end-to-end, independent of
# whether the console script has been (re)installed in this venv.
_ENTRY = "import sys; sys.argv=['bp','health','--format','json']; from bp.cli import cli_main; cli_main()"


@pytest.mark.skipif(not _burp_up(), reason="needs live Burp REST on :8089")
def test_format_after_subcommand_exits_zero_live() -> None:
    r = subprocess.run([sys.executable, "-c", _ENTRY], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().startswith("{")


def test_no_ledger_flag_is_accepted_globally() -> None:
    """ADR-0005 H7: --no-ledger must be a real global flag. Pointed at a dead port it should
    reach the connection layer (exit 3) — proving it parsed — not bounce as 'No such option'
    (exit 2). No live Burp needed."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','--no-ledger','health']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 3, f"expected exit 3 (conn refused), got {r.returncode}: {r.stderr}"
