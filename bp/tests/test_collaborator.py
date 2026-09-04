"""[16] RED tests — bp collab poll caveat note must not appear on error path.

bp collab poll (with or without id) should only print the caveat note AFTER a
successful API response, not before the call.  On a PRO_REQUIRED failure or a
connection-refused error the note must be absent from stderr.

No Burp required: pointing at a dead port (9999) produces a connection-refused
error (exit 3), which is sufficient to prove the note is emitted before the call.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

from typer.testing import CliRunner

from bp.cli import app


def test_collab_new_count_above_documented_max_is_local_usage() -> None:
    """C9: the documented/server maximum of 100 is enforced before REST dispatch."""
    result = CliRunner().invoke(app, ["--format", "json", "collab", "new", "--count", "101"])
    assert result.exit_code == 2
    assert result.stdout == ""


def test_collaborator_leaf_fields_survive_effectful_cli_boundary(monkeypatch: Any) -> None:
    """D34: valid payload/interaction leaves render after exactly one mocked operation."""
    responses: dict[str, dict[str, Any]] = {
        "/collaborator/generate": {
            "payloads": [
                {
                    "id": "payload-7",
                    "payload": "payload-7.oastify.test",
                    "interactionId": "payload-7",
                }
            ]
        },
        "/collaborator/poll/payload-7": {
            "found": True,
            "interactions": [
                {
                    "id": "interaction-8",
                    "type": "DNS",
                    "clientIp": "192.0.2.8",
                    "timestamp": "2026-09-04T00:00:00Z",
                }
            ],
            "queriedPayloadId": "payload-7",
        },
    }
    calls: list[tuple[str, str]] = []

    def fake_request(self: Any, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        calls.append((method, path))
        return responses[path]

    monkeypatch.setattr("bp.client.BurpClient._request", fake_request)
    monkeypatch.setenv("BP_NO_LEDGER", "1")
    cli = CliRunner()

    generated = cli.invoke(
        app,
        ["--format", "json", "--fields", "payload", "collab", "new"],
    )
    polled = cli.invoke(
        app,
        [
            "--format",
            "json",
            "--fields",
            "interactionId,type,clientIp,timestamp,clientPort",
            "collab",
            "poll",
            "payload-7",
        ],
    )

    assert generated.exit_code == 0, generated.output
    assert json.loads(generated.stdout) == {"payload": "payload-7.oastify.test"}
    assert polled.exit_code == 0, polled.output
    assert json.loads(polled.stdout) == {
        "interactionId": "interaction-8",
        "type": "DNS",
        "clientIp": "192.0.2.8",
        "timestamp": "2026-09-04T00:00:00Z",
        "clientPort": None,
    }
    assert calls == [
        ("POST", "/collaborator/generate"),
        ("GET", "/collaborator/poll/payload-7"),
    ]


def test_collab_poll_error_no_caveat_note() -> None:
    """[16] When collab poll fails (conn refused), the caveat note must NOT appear in stderr."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','collab','poll']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    # Connection refused → exit 3 (EXIT_CONNECTION)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused), got {r.returncode}\nstderr={r.stderr!r}"
    )
    assert "timestamp" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"
    assert "poll time" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"


def test_collab_poll_id_error_no_caveat_note() -> None:
    """[16] When collab poll <id> fails (conn refused), the caveat note must NOT appear in stderr."""
    entry = (
        "import os; os.environ['BURP_REST_URL']='http://127.0.0.1:9999'; "
        "import sys; sys.argv=['bp','collab','poll','abc123']; "
        "from bp.cli import cli_main; cli_main()"
    )
    r = subprocess.run([sys.executable, "-c", entry], capture_output=True, text=True)
    assert r.returncode == 3, (
        f"expected exit 3 (conn refused), got {r.returncode}\nstderr={r.stderr!r}"
    )
    assert "timestamp" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"
    assert "poll time" not in r.stderr, f"caveat note must not appear on error path:\n{r.stderr!r}"
