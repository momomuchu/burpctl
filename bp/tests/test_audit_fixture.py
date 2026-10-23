"""Boundary checks for the disposable loopback CLI audit fixture."""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path

import pytest

from audit_fixture import AuditFixture, FixtureRoot, UnsafeTargetError


def test_loopback_health(tmp_path: Path) -> None:
    """The installed alias reaches exactly one strict local GET and isolates state."""
    with FixtureRoot(tmp_path) as fixture:
        before = fixture.snapshot()
        result = fixture.run(["--format", "json", "health"])
        after = fixture.snapshot()

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["status"] == "ok"
        assert before.rest_effects == ()
        assert [(item.method, item.path) for item in after.rest_effects] == [("GET", "/health")]
        assert after.target_effects == ()
        assert fixture.manifest.rest_url.startswith("http://127.0.0.1:")
        assert fixture.manifest.home != Path.home()
        assert fixture.manifest.ledger_path.is_file()


def test_rejects_non_loopback(tmp_path: Path) -> None:
    """Unsafe target URLs fail before urllib can create any target effect."""
    with FixtureRoot(tmp_path) as fixture:
        before = fixture.snapshot()
        with pytest.raises(UnsafeTargetError, match="127.0.0.1"):
            fixture.target_request("http://example.com/private")
        after = fixture.snapshot()

        assert before.target_effects == after.target_effects == ()
        assert before.rest_effects == after.rest_effects == ()


def test_rejects_other_loopback_port(tmp_path: Path) -> None:
    """A loopback URL is safe only when it is this fixture's target origin."""
    with FixtureRoot(tmp_path) as fixture:
        with pytest.raises(UnsafeTargetError, match="fixture target origin"):
            fixture.target_request("http://127.0.0.1:9/private")
        assert fixture.snapshot().target_effects == ()


def test_run_rejects_remote_url_before_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A remote URL operand is rejected before process creation or fixture traffic."""
    with FixtureRoot(tmp_path) as fixture:

        def fail_if_spawned(*_args: tuple[str, ...], **_kwargs: str) -> None:
            raise AssertionError("subprocess must not be spawned")

        monkeypatch.setattr("audit_fixture.subprocess.run", fail_if_spawned)
        with pytest.raises(UnsafeTargetError, match="fixture target"):
            fixture.run(["check", "http://example.com/private"])
        assert fixture.snapshot().rest_effects == ()
        assert fixture.snapshot().target_effects == ()


def test_api_manifest_and_route_contract(tmp_path: Path) -> None:
    """The later audit lanes can add an exact route and inspect body identity."""
    with FixtureRoot(tmp_path) as fixture:
        fixture.expect_rest_route(
            "POST",
            "/owned",
            expected_body=b'{"request":true}',
            body=b'{"success":true}',
        )
        assert fixture.manifest.config_path.parent == fixture.manifest.home / ".bp"
        assert fixture.manifest.payload_dir.is_dir()
        assert fixture.command("bp")[-1] == "bp"


@pytest.fixture
def fixture(tmp_path: Path) -> Generator[AuditFixture, None, None]:
    """Provide a disposable fixture to future audit lanes."""
    with FixtureRoot(tmp_path) as instance:
        yield instance
