"""[04/27/29] RED tests — --payloads NAME=FILE missing-file guard.

bp fuzz <id> --payloads x=/nonexistent/file must exit 2 with a clean stderr
message and NO traceback instead of a raw FileNotFoundError (exit 1 + traceback).
No Burp required: the file-open happens before any network call.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bp.cli import app


def test_payloads_missing_file_exits_usage() -> None:
    """[04/27/29] Missing payload file → exit 2, no traceback."""
    entry = (
        "import sys; sys.argv=['bp','fuzz','1','--payloads','x=/nonexistent/does-not-exist.txt']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 2, (
        f"expected exit 2 (EXIT_USAGE), got {r.returncode}\nstdout={r.stdout!r}\nstderr={r.stderr!r}"
    )


def test_payloads_missing_file_no_traceback() -> None:
    """[04/27/29] Missing payload file stderr must NOT contain 'Traceback'."""
    entry = (
        "import sys; sys.argv=['bp','fuzz','1','--payloads','x=/nonexistent/does-not-exist.txt']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert "Traceback" not in r.stderr, f"got a traceback:\n{r.stderr}"
    assert "Traceback" not in r.stdout, f"got a traceback in stdout:\n{r.stdout}"


def test_payloads_missing_file_clean_error_message() -> None:
    """[04/27/29] Missing payload file stderr contains 'cannot read payload file'."""
    entry = (
        "import sys; sys.argv=['bp','fuzz','1','--payloads','x=/nonexistent/does-not-exist.txt']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert "cannot read payload file" in r.stderr, (
        f"expected 'cannot read payload file' in stderr:\n{r.stderr!r}"
    )


def test_versioned_payload_file_reaches_fuzz_with_exact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C17: magic JSON payloads are not filtered or split again at the CLI boundary."""
    payload_file = tmp_path / "payloads"
    payload_file.write_bytes(b'#!bp-payloads-json-v1\n[""," ","A\\nB",{"b64":"/wA="}]')
    seen: list[list[bytes]] = []

    def capture(
        _client: object,
        _request_id: int,
        _selectors: object,
        payload_map: dict[str, list[bytes]],
        _attack_type: str,
    ) -> list[object]:
        seen.append(payload_map["u"])
        return []

    monkeypatch.setattr("bp.cli.run_fuzz", capture)
    result = CliRunner().invoke(
        app,
        [
            "--no-ledger",
            "--url",
            "http://127.0.0.1:1",
            "fuzz",
            "1",
            "--pos",
            "query:u",
            "--payloads",
            f"u={payload_file}",
        ],
    )

    assert result.exit_code == 0, result.stderr
    assert seen == [[b"", b" ", b"A\nB", b"\xff\x00"]]


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"not-json", "valid UTF-8 JSON"),
        (b"{}", "JSON array"),
        (b"[7]", "payload[0]"),
        (b'[{"b64":"***"}]', "payload[0].b64"),
    ],
)
def test_versioned_payload_errors_are_usage_before_fuzz_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes, message: str
) -> None:
    """C17: the CLI consumes the magic JSON loader and rejects bad corpora before run_fuzz."""
    payload_file = tmp_path / "payloads"
    payload_file.write_bytes(b"#!bp-payloads-json-v1\n" + body)
    called = False

    def forbidden_send(*_args: object, **_kwargs: object) -> object:
        nonlocal called
        called = True
        raise AssertionError("run_fuzz must not run for an invalid payload file")

    monkeypatch.setattr("bp.cli.run_fuzz", forbidden_send)
    result = CliRunner().invoke(
        app,
        [
            "--format",
            "json",
            "fuzz",
            "1",
            "--pos",
            "query:u",
            "--payloads",
            f"u={payload_file}",
        ],
    )

    assert result.exit_code == 2
    assert message in result.stderr
    assert called is False
