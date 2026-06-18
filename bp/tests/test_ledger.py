"""Tests for ledger.py and config.py (STATE-AND-CONFIG §3 RED cases).

All tests use a real SQLite DB in a tmp directory — no mocks, no Burp required.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from bp.client import BurpClient
from bp.config import load, redact
from bp.ledger import Ledger, OpRecord, QueryFilters


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_ledger(tmp_path: Path) -> Ledger:
    """Return an open Ledger backed by a temp SQLite file."""
    return Ledger(db_path=tmp_path / "ledger.db")


# ---------------------------------------------------------------------------
# Ledger: record + query roundtrip
# ---------------------------------------------------------------------------


def test_record_returns_id(tmp_ledger: Ledger) -> None:
    op = OpRecord(status="ok", target="example.com", burp_op="GET /proxy/history")
    op_id = tmp_ledger.record(op)
    assert isinstance(op_id, str)
    assert len(op_id) > 0


def test_record_query_roundtrip(tmp_ledger: Ledger) -> None:
    op = OpRecord(
        status="ok",
        command="bp proxy --host example.com",
        burp_op="GET /proxy/history",
        target="example.com",
        resp_status=200,
        resp_len=1024,
        duration_ms=42,
    )
    op_id = tmp_ledger.record(op)
    rows = tmp_ledger.query()
    assert len(rows) == 1
    row = rows[0]
    assert row.id == op_id
    assert row.status == "ok"
    assert row.target == "example.com"
    assert row.burp_op == "GET /proxy/history"
    assert row.resp_status == 200
    assert row.resp_len == 1024
    assert row.duration_ms == 42


def test_multiple_records_ordered_newest_first(tmp_ledger: Ledger) -> None:
    id1 = tmp_ledger.record(OpRecord(status="ok", target="a.com"))
    tmp_ledger.record(OpRecord(status="error", target="b.com"))
    id3 = tmp_ledger.record(OpRecord(status="ok", target="c.com"))
    rows = tmp_ledger.query()
    assert len(rows) == 3
    # newest first (ORDER BY ts DESC)
    assert rows[0].id == id3
    assert rows[2].id == id1


# ---------------------------------------------------------------------------
# Ledger: no raw body stored
# ---------------------------------------------------------------------------


def test_no_raw_body_stored(tmp_ledger: Ledger) -> None:
    """req_body and resp_body must NEVER be persisted; only sha256 fingerprints."""
    raw_req = b"GET / HTTP/1.1\r\nHost: secret.internal\r\n\r\n"
    raw_resp = b"HTTP/1.1 200 OK\r\n\r\nSecret body"

    tmp_ledger.record(
        OpRecord(
            status="ok",
            req_body=raw_req,
            resp_body=raw_resp,
        )
    )

    rows = tmp_ledger.query()
    assert len(rows) == 1
    row = rows[0]

    # sha256 fingerprints must be present
    assert row.req_sha256 is not None
    assert len(row.req_sha256) == 64  # hex sha256
    assert row.resp_sha256 is not None
    assert len(row.resp_sha256) == 64

    # Raw body must NOT appear in any string column
    row_dict = row.as_dict()
    for key, val in row_dict.items():
        if key in ("req_sha256", "resp_sha256"):
            continue
        if isinstance(val, str):
            assert "Secret body" not in val, f"raw resp body text leaked into column {key!r}"
            assert "secret.internal" not in val, (
                f"raw req host leaked into column {key!r}"
            )


def test_sha256_correct(tmp_ledger: Ledger) -> None:
    import hashlib

    body = b"hello world"
    expected = hashlib.sha256(body).hexdigest()
    tmp_ledger.record(OpRecord(status="ok", req_body=body))
    rows = tmp_ledger.query()
    assert rows[0].req_sha256 == expected


def test_no_body_gives_null_sha(tmp_ledger: Ledger) -> None:
    tmp_ledger.record(OpRecord(status="ok"))
    rows = tmp_ledger.query()
    assert rows[0].req_sha256 is None
    assert rows[0].resp_sha256 is None


# ---------------------------------------------------------------------------
# Ledger: tag updates
# ---------------------------------------------------------------------------


def test_tag_updates_row(tmp_ledger: Ledger) -> None:
    op_id = tmp_ledger.record(OpRecord(status="ok"))
    result = tmp_ledger.tag(op_id, "interesting")
    assert result is True
    rows = tmp_ledger.query()
    assert rows[0].tag == "interesting"


def test_tag_returns_false_for_unknown_id(tmp_ledger: Ledger) -> None:
    result = tmp_ledger.tag("nonexistent-id", "whatever")
    assert result is False


def test_tag_overwrite(tmp_ledger: Ledger) -> None:
    op_id = tmp_ledger.record(OpRecord(status="ok", tag="first"))
    tmp_ledger.tag(op_id, "second")
    rows = tmp_ledger.query()
    assert rows[0].tag == "second"


# ---------------------------------------------------------------------------
# Ledger: query filters
# ---------------------------------------------------------------------------


def test_filter_by_status(tmp_ledger: Ledger) -> None:
    tmp_ledger.record(OpRecord(status="ok"))
    tmp_ledger.record(OpRecord(status="error"))
    tmp_ledger.record(OpRecord(status="ok"))

    ok_rows = tmp_ledger.query(QueryFilters(status="ok"))
    assert len(ok_rows) == 2
    assert all(r.status == "ok" for r in ok_rows)

    err_rows = tmp_ledger.query(QueryFilters(status="error"))
    assert len(err_rows) == 1


def test_filter_by_target(tmp_ledger: Ledger) -> None:
    tmp_ledger.record(OpRecord(status="ok", target="alpha.com"))
    tmp_ledger.record(OpRecord(status="ok", target="beta.com"))

    rows = tmp_ledger.query(QueryFilters(target="alpha.com"))
    assert len(rows) == 1
    assert rows[0].target == "alpha.com"


def test_filter_by_tag(tmp_ledger: Ledger) -> None:
    id1 = tmp_ledger.record(OpRecord(status="ok"))
    tmp_ledger.record(OpRecord(status="ok"))
    tmp_ledger.tag(id1, "vuln")

    rows = tmp_ledger.query(QueryFilters(tag="vuln"))
    assert len(rows) == 1
    assert rows[0].id == id1


def test_filter_limit(tmp_ledger: Ledger) -> None:
    for _ in range(10):
        tmp_ledger.record(OpRecord(status="ok"))
    rows = tmp_ledger.query(QueryFilters(limit=3))
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# Ledger: --no-ledger suppression (config.ledger=False -> 0 rows inserted)
# ---------------------------------------------------------------------------


def _mock_health_client(ledger: Ledger | None) -> BurpClient:
    """A BurpClient wired to a MockTransport that returns a valid /health envelope."""

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "data": {"status": "ok"}, "error": None})

    return BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://test"),
        ledger=ledger,
    )


def test_ledger_suppressed_when_client_ledger_is_none() -> None:
    """The real --no-ledger path: BurpClient(ledger=None) records nothing (client.py:80 guard).

    Exercises the ``if self._ledger is None: return`` short-circuit; the op must still succeed.
    The previous version of this test put the guard inside the test body, so record() never ran
    and the assertion was trivially true regardless of production code.
    """
    with _mock_health_client(None) as client:
        client.get("/health")  # must not raise


def test_ledger_records_one_row_when_enabled(tmp_path: Path) -> None:
    """Positive control: with a Ledger attached, exactly one row is written per op."""
    with Ledger(db_path=tmp_path / "ledger.db") as ledger:
        with _mock_health_client(ledger) as client:
            client.get("/health")
        assert len(ledger.query()) == 1


# ---------------------------------------------------------------------------
# Ledger: exit_code populated after the command resolves (F16)
# ---------------------------------------------------------------------------


def test_set_exit_code_updates_row(tmp_ledger: Ledger) -> None:
    op_id = tmp_ledger.record(OpRecord(status="ok"))
    assert tmp_ledger.set_exit_code(op_id, 3) is True
    assert tmp_ledger.query()[0].exit_code == 3


def test_set_exit_code_unknown_id_returns_false(tmp_ledger: Ledger) -> None:
    assert tmp_ledger.set_exit_code("nonexistent", 1) is False


def test_client_tracks_op_ids_per_call(tmp_path: Path) -> None:
    """F16: the client exposes the ids it recorded so run() can backfill the exit code."""
    with Ledger(db_path=tmp_path / "ledger.db") as ledger:
        with _mock_health_client(ledger) as client:
            client.get("/health")
            client.get("/health")
        assert len(client.op_ids) == 2


# ---------------------------------------------------------------------------
# Config: precedence flag > env > file > default
# ---------------------------------------------------------------------------


def test_default_values() -> None:
    cfg = load(config_path=Path("/nonexistent/path/config"))
    assert cfg.burp_rest_url == "http://127.0.0.1:8089"
    assert cfg.enforce_scope == "warn"
    assert cfg.envelope is False
    assert cfg.redact is True
    assert cfg.ledger is True
    assert cfg.throttle_ms == 0
    assert cfg.anomaly_pct == 5


def test_flag_overrides_default() -> None:
    cfg = load(
        burp_rest_url="http://localhost:9999",
        redact=False,
        ledger=False,
        throttle_ms=500,
        config_path=Path("/nonexistent/path/config"),
    )
    assert cfg.burp_rest_url == "http://localhost:9999"
    assert cfg.redact is False
    assert cfg.ledger is False
    assert cfg.throttle_ms == 500


def test_env_overrides_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BURP_REST_URL", "http://env-host:1234")
    monkeypatch.setenv("BP_REDACT", "off")
    monkeypatch.setenv("BP_THROTTLE_MS", "250")
    cfg = load(config_path=Path("/nonexistent/path/config"))
    assert cfg.burp_rest_url == "http://env-host:1234"
    assert cfg.redact is False
    assert cfg.throttle_ms == 250


def test_flag_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BURP_REST_URL", "http://env-host:1234")
    cfg = load(
        burp_rest_url="http://flag-host:5678",
        config_path=Path("/nonexistent/path/config"),
    )
    assert cfg.burp_rest_url == "http://flag-host:5678"


def test_file_overrides_default(tmp_path: Path) -> None:
    config_file = tmp_path / "config"
    config_file.write_text(
        "burp_rest_url = http://file-host:7777\nenforce_scope = block\n",
        encoding="utf-8",
    )
    cfg = load(config_path=config_file)
    assert cfg.burp_rest_url == "http://file-host:7777"
    assert cfg.enforce_scope == "block"


def test_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "config"
    config_file.write_text("burp_rest_url = http://file-host:7777\n", encoding="utf-8")
    monkeypatch.setenv("BURP_REST_URL", "http://env-host:8888")
    cfg = load(config_path=config_file)
    assert cfg.burp_rest_url == "http://env-host:8888"


def test_bp_no_ledger_disables_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    """BP_NO_LEDGER=1 is the inverted env var that sets ledger=False."""
    monkeypatch.setenv("BP_NO_LEDGER", "1")
    cfg = load(config_path=Path("/nonexistent/path/config"))
    assert cfg.ledger is False


def test_bp_no_ledger_zero_keeps_ledger(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BP_NO_LEDGER", "0")
    cfg = load(config_path=Path("/nonexistent/path/config"))
    assert cfg.ledger is True


def test_file_ledger_on_keeps_ledger_enabled(tmp_path: Path) -> None:
    """Regression: positive-sense ``ledger=on`` in the config FILE must ENABLE the ledger.

    The invert flag exists only for the negatively-named BP_NO_LEDGER env var; it must not
    invert the positively-named ``ledger`` config-file key (which silently disabled it).
    """
    config_file = tmp_path / "config"
    config_file.write_text("ledger = on\n", encoding="utf-8")
    assert load(config_path=config_file).ledger is True


def test_file_ledger_off_disables_ledger(tmp_path: Path) -> None:
    config_file = tmp_path / "config"
    config_file.write_text("ledger = off\n", encoding="utf-8")
    assert load(config_path=config_file).ledger is False


def test_file_redact_off_read_literally(tmp_path: Path) -> None:
    """Guard: a positive-sense boolean file key (redact) is read literally, never inverted."""
    config_file = tmp_path / "config"
    config_file.write_text("redact = off\n", encoding="utf-8")
    assert load(config_path=config_file).redact is False


def test_empty_redact_env_keeps_redaction_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """SECURITY: BP_REDACT='' (e.g. `export BP_REDACT=` in a script) must NOT disable redaction."""
    monkeypatch.setenv("BP_REDACT", "")
    assert load(config_path=Path("/nonexistent/path/config")).redact is True


def test_empty_url_env_falls_back_to_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty env var is treated as unset, not as an empty URL."""
    monkeypatch.setenv("BURP_REST_URL", "")
    assert load(config_path=Path("/nonexistent/path/config")).burp_rest_url == "http://127.0.0.1:8089"


def test_invalid_bool_token_in_file_keeps_safe_default(tmp_path: Path) -> None:
    """A typo'd boolean (redact = ye) must not silently flip a security control off."""
    config_file = tmp_path / "config"
    config_file.write_text("redact = ye\n", encoding="utf-8")
    assert load(config_path=config_file).redact is True


def test_invalid_bool_env_keeps_safe_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BP_REDACT", "maybe")
    assert load(config_path=Path("/nonexistent/path/config")).redact is True


def test_empty_no_ledger_env_keeps_ledger_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BP_NO_LEDGER", "")
    assert load(config_path=Path("/nonexistent/path/config")).ledger is True


# ---------------------------------------------------------------------------
# Config: redact() masks Bearer token
# ---------------------------------------------------------------------------


def test_redact_masks_bearer_token() -> None:
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    result = redact(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result
    assert "***" in result


def test_redact_masks_basic_auth() -> None:
    text = "Authorization: Basic dXNlcjpwYXNz"
    result = redact(text)
    assert "dXNlcjpwYXNz" not in result
    assert "***" in result


def test_redact_masks_cookie() -> None:
    text = "Cookie: session=abc123; token=xyz"
    result = redact(text)
    assert "abc123" not in result
    assert "***" in result


def test_redact_leaves_non_sensitive_intact() -> None:
    text = "Content-Type: application/json"
    result = redact(text)
    assert result == text


def test_redact_masks_jwt_in_value() -> None:
    """A JWT appearing inline (e.g. JSON value) must be masked."""
    text = 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SIGNATURE'
    result = redact(text)
    assert "eyJzdWIiOiJ1c2VyIn0" not in result


def test_redact_empty_string() -> None:
    assert redact("") == ""
