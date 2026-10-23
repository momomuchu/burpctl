"""A partial fuzz run emits attempted-shot evidence before its summary."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


_PARTIAL_FUZZ = """
import sys
from unittest.mock import patch

from bp.cli import cli_main
from bp.runner import FuzzResult

rows = [
    FuzzResult(-1, (), 200, 8, 1, False, True, None, None),
    FuzzResult(
        0, ("one",), 0, 0, 0, False, False,
        "TRANSPORT_ERROR: transport stopped", "TRANSPORT_ERROR",
    ),
]
sys.argv = [
    "bp", "--format", "json", "--no-ledger", "fuzz", "1",
    "--pos", "query:q", "--payloads", "q=" + sys.argv[1],
]
with patch("bp.cli.run_fuzz", return_value=rows):
    cli_main()
"""


def test_fuzz_partial_evidence_precedes_summary_in_merged_stream(tmp_path: Path) -> None:
    payloads = tmp_path / "payloads.txt"
    payloads.write_text("one\n", encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "HOME": str(tmp_path),
            "BP_CONFIG_PATH": str(tmp_path / "config"),
            "BP_LEDGER_PATH": str(tmp_path / "ledger.db"),
            "BURP_REST_URL": "http://127.0.0.1:9",
            "BP_AGENT": "1",
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
    )

    result = subprocess.run(
        [sys.executable, "-c", _PARTIAL_FUZZ, str(payloads)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    lines: list[dict[str, Any]] = [json.loads(line) for line in result.stdout.splitlines()]
    assert result.returncode == 3
    assert len(lines) == 3
    assert lines[0]["baseline"] is True
    assert lines[1]["error_code"] == "TRANSPORT_ERROR"
    assert lines[2]["error"]["code"] == "FUZZ_PARTIAL_FAILURE"
    assert not (tmp_path / "ledger.db").exists()
