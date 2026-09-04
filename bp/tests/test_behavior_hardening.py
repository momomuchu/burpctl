"""Security, output, config, and ledger hardening regression tests."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch

import httpx
import pytest
import typer
from pydantic import BaseModel, ValidationError
from typer.testing import CliRunner

from bp.cli import _hoist_global_opts, app
from bp.client import BurpClient, BurpError
from bp.cliutil import EXIT_GENERIC, EXIT_USAGE, State, run
from bp.config import ConfigError, load, redact_data
from bp.ledger import Ledger, OpRecord
from bp.output import render


@pytest.mark.parametrize(
    ("payload", "secrets"),
    [
        (
            {"outer": [{"password": "pw-sentinel", "ok": 3}]},
            ["pw-sentinel"],
        ),
        (
            {"headers": {"Authorization": "Bearer auth-sentinel", "X-Test": "safe"}},
            ["auth-sentinel"],
        ),
        (
            {"headers": {"Proxy-Authorization": "Basic proxy-sentinel"}},
            ["proxy-sentinel"],
        ),
        (
            {"headers": {"Cookie": "sid=cookie-sentinel", "Set-Cookie": "s=set-sentinel"}},
            ["cookie-sentinel", "set-sentinel"],
        ),
        (
            {"headers": [{"name": "Authorization", "value": "Digest digest-sentinel"}]},
            ["digest-sentinel"],
        ),
        (
            {"headers": [{"value": "sid=list-cookie-sentinel", "name": "Cookie"}]},
            ["list-cookie-sentinel"],
        ),
        (
            {
                "api_key": "api-sentinel",
                "accessToken": "token-sentinel",
                "db_password": "db-sentinel",
                "clientSecret": "client-sentinel",
            },
            ["api-sentinel", "token-sentinel", "db-sentinel", "client-sentinel"],
        ),
        (
            {
                "url": (
                    "https://url-user:url-pass@localhost/cb?state=ok&"
                    "access_token=query-sentinel&x=1#frag"
                )
            },
            ["url-user", "url-pass", "query-sentinel"],
        ),
        ({"url": "/relative?api_key=relative-sentinel&ok=1"}, ["relative-sentinel"]),
        ({"url": "https://localhost/cb#access_token=fragment-sentinel"}, ["fragment-sentinel"]),
        ({"url": "//proto-user:proto-pass@localhost/path"}, ["proto-user", "proto-pass"]),
    ],
)
def test_recursive_structural_redaction_masks_sensitive_values(
    payload: dict[str, Any], secrets: list[str]
) -> None:
    result = redact_data(payload)
    encoded = json.dumps(result)
    for secret in secrets:
        assert secret not in encoded
    assert result is not payload


def test_structural_redaction_preserves_container_types_order_and_input() -> None:
    payload: OrderedDict[str, Any] = OrderedDict(
        [("safe", [1, True, None]), ("password", "secret-value"), ("tail", {"x": 2})]
    )
    result = redact_data(payload)

    assert isinstance(result, OrderedDict)
    assert list(result) == ["safe", "password", "tail"]
    assert result["safe"] == [1, True, None]
    assert result["tail"] == {"x": 2}
    assert payload["password"] == "secret-value"
    assert result["password"] == "***"


def test_sensitive_container_values_keep_their_container_types() -> None:
    payload = {
        "Authorization": ["Bearer one", "Bearer two"],
        "tokens": {"primary": "one", "backup": "two"},
    }
    result = redact_data(payload)
    assert result == {
        "Authorization": ["***", "***"],
        "tokens": {"primary": "***", "backup": "***"},
    }
    assert isinstance(result["Authorization"], list)
    assert isinstance(result["tokens"], dict)


def test_structural_redaction_keeps_json_list_as_parseable_ndjson() -> None:
    payload = [
        {"id": 1, "password": "first-sentinel"},
        {"id": 2, "headers": [{"name": "Cookie", "value": "sid=second-sentinel"}]},
    ]
    output = render(redact_data(payload), "json")

    records = [json.loads(line) for line in output.splitlines()]
    assert [record["id"] for record in records] == [1, 2]
    assert "first-sentinel" not in output
    assert "second-sentinel" not in output


def _ctx(*, fmt: str = "json", fields: list[str] | None = None, no_redact: bool = False) -> Any:
    ctx = MagicMock(spec=typer.Context)
    ctx.obj = State(
        url="http://127.0.0.1:8089",
        fmt=fmt,
        fields=fields,
        no_ledger=True,
        no_redact=no_redact,
    )
    ctx.command_path = "bp test"
    return ctx


def test_run_redacts_structure_before_json_render(capsys: pytest.CaptureFixture[str]) -> None:
    run(
        _ctx(),
        lambda _client: {
            "password": "stdout-sentinel",
            "nested": [{"name": "Authorization", "value": "Bearer nested-sentinel"}],
        },
    )

    captured = capsys.readouterr()
    record = json.loads(captured.out)
    assert record["password"] == "***"
    assert record["nested"][0]["value"] == "***"
    assert "stdout-sentinel" not in captured.out + captured.err
    assert "nested-sentinel" not in captured.out + captured.err


def _json_stderr(capsys: pytest.CaptureFixture[str]) -> dict[str, Any]:
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1, captured.err
    return cast(dict[str, Any], json.loads(lines[0]))


def test_json_burp_error_is_one_redacted_record(capsys: pytest.CaptureFixture[str]) -> None:
    error = BurpError(
        "INVALID_REQUEST",
        "Authorization: Bearer stderr-sentinel",
        status=400,
        op="GET /thing",
    )
    with pytest.raises(typer.Exit) as exc_info:
        run(_ctx(), lambda _client: (_ for _ in ()).throw(error))

    assert exc_info.value.exit_code == EXIT_GENERIC
    diagnostic = _json_stderr(capsys)
    assert diagnostic["error"]["code"] == "INVALID_REQUEST"
    assert diagnostic["error"]["status"] == 400
    assert diagnostic["error"]["op"] == "GET /thing"
    assert "stderr-sentinel" not in json.dumps(diagnostic)


def _validation_error() -> ValidationError:
    class Model(BaseModel):
        number: int

    try:
        Model.model_validate({"number": "bad"})
    except ValidationError as exc:
        return exc
    raise AssertionError("validation unexpectedly succeeded")


def test_json_validation_error_is_one_record(capsys: pytest.CaptureFixture[str]) -> None:
    error = _validation_error()
    with pytest.raises(typer.Exit) as exc_info:
        run(_ctx(), lambda _client: (_ for _ in ()).throw(error))

    assert exc_info.value.exit_code == EXIT_GENERIC
    diagnostic = _json_stderr(capsys)
    assert diagnostic == {
        "error": {
            "code": "INVALID_RESPONSE",
            "message": "server returned an unexpected response shape",
        }
    }


def test_json_render_error_is_one_record(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(typer.Exit) as exc_info:
        run(_ctx(fields=["missing"]), lambda _client: {"present": 1})

    assert exc_info.value.exit_code == EXIT_USAGE
    diagnostic = _json_stderr(capsys)
    assert diagnostic["error"]["code"] == "USAGE_ERROR"
    assert "unknown field" in diagnostic["error"]["message"]


def test_json_internal_render_error_is_one_record(capsys: pytest.CaptureFixture[str]) -> None:
    with patch("bp.cliutil.render", side_effect=TypeError("object sentinel-secret is not JSON")):
        with pytest.raises(typer.Exit) as exc_info:
            run(_ctx(), lambda _client: {"present": 1})

    assert exc_info.value.exit_code == EXIT_GENERIC
    diagnostic = _json_stderr(capsys)
    assert diagnostic == {
        "error": {"code": "RENDER_ERROR", "message": "could not render command result"}
    }
    assert "sentinel-secret" not in json.dumps(diagnostic)


def test_burp_error_retains_old_signature_and_exposes_metadata() -> None:
    old = BurpError("OLD", "message")
    assert old.code == "OLD"
    assert old.status is None
    assert old.http_status is None
    assert old.op is None

    rich = BurpError("NEW", "message", status=503, op="POST /scan")
    assert rich.status == 503
    assert rich.http_status == 503
    assert rich.op == "POST /scan"
    assert str(rich) == "NEW: message"


def _ok_response(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "data": {"ok": True}, "error": None})


def test_client_burp_error_has_http_status_and_operation() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "success": False,
                "data": None,
                "error": {"code": "DENIED", "message": "no"},
            },
        )

    client = BurpClient(
        client=httpx.Client(transport=httpx.MockTransport(handler), base_url="http://localhost")
    )
    with pytest.raises(BurpError) as exc_info:
        client.get("/target", token="secret-query")
    assert exc_info.value.status == 403
    assert exc_info.value.op == "GET /target"
    assert "secret-query" not in (exc_info.value.op or "")


def test_get_query_changes_ledger_fingerprint_without_raw_storage(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"
    with Ledger(db_path=db_path) as ledger:
        client = BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(_ok_response),
                base_url="http://user:password@localhost:8089",
            ),
            ledger=ledger,
        )
        client.get("/history", token="query-secret-one", page=1)
        client.get("/history", token="query-secret-two", page=1)
        rows = ledger.query()

    assert len(rows) == 2
    assert all(row.req_sha256 is not None for row in rows)
    assert rows[0].req_sha256 != rows[1].req_sha256
    assert all(row.burp_op == "GET /history" for row in rows)
    assert all(row.target == "localhost:8089" for row in rows)
    database_bytes = db_path.read_bytes()
    for secret in (b"query-secret-one", b"query-secret-two", b"user", b"password"):
        assert secret not in database_bytes


def test_ledger_boundary_never_persists_recognizable_secret_text(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"
    secrets = ["command-sentinel", "query-sentinel", "url-user", "url-pass", "ref-sentinel"]
    with Ledger(db_path=db_path) as ledger:
        ledger.record(
            OpRecord(
                status="ok",
                command="bp send --access-token command-sentinel",
                burp_op="GET /history?access_token=query-sentinel&safe=1",
                target="https://url-user:url-pass@burp.internal:9443/?safe=1",
                req_ref="https://localhost/blob?signature=ref-sentinel",
            )
        )
        row = ledger.query()[0]

    serialized = json.dumps(row.as_dict())
    database_bytes = db_path.read_bytes()
    for secret in secrets:
        assert secret not in serialized
        assert secret.encode() not in database_bytes
    assert row.burp_op == "GET /history"
    assert row.target == "burp.internal:9443"


def test_get_fingerprint_tracks_exact_transmitted_query_bytes(tmp_path: Path) -> None:
    with Ledger(db_path=tmp_path / "ledger.db") as ledger:
        client = BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(_ok_response), base_url="http://localhost"
            ),
            ledger=ledger,
        )
        client.get("/history", b=2, a=1)
        client.get("/history", a=1, b=2)
        rows = ledger.query()
    assert rows[0].req_sha256 != rows[1].req_sha256
    assert rows[0].req_sha256 == hashlib.sha256(b"a=1&b=2").hexdigest()
    assert rows[1].req_sha256 == hashlib.sha256(b"b=2&a=1").hexdigest()


def test_get_path_query_is_hashed_but_never_persisted(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"
    with Ledger(db_path=db_path) as ledger:
        client = BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(_ok_response), base_url="http://localhost"
            ),
            ledger=ledger,
        )
        client.get("/history?access_token=embedded-sentinel&safe=1")
        row = ledger.query()[0]
    assert row.req_sha256 == hashlib.sha256(b"access_token=embedded-sentinel&safe=1").hexdigest()
    assert row.burp_op == "GET /history"
    assert b"embedded-sentinel" not in db_path.read_bytes()


def test_unexpected_failure_backfills_pessimistic_exit(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"

    def ledger_factory() -> Ledger:
        return Ledger(db_path=db_path)

    def client_factory(
        url: str, *, ledger: Ledger | None = None, redact: bool = True, command: str = ""
    ) -> BurpClient:
        return BurpClient(
            client=httpx.Client(
                transport=httpx.MockTransport(_ok_response), base_url="http://localhost"
            ),
            ledger=ledger,
            redact=redact,
            command=command,
        )

    def crash(client: BurpClient) -> Any:
        client.get("/health")
        raise RuntimeError("unexpected")

    ctx = _ctx()
    ctx.obj.no_ledger = False
    with (
        patch("bp.cliutil.Ledger", side_effect=ledger_factory),
        patch("bp.cliutil.BurpClient", side_effect=client_factory),
    ):
        with pytest.raises(RuntimeError, match="unexpected"):
            run(ctx, crash)

    with Ledger(db_path=db_path) as ledger:
        assert ledger.query()[0].exit_code == EXIT_GENERIC


def test_default_config_path_is_resolved_at_call_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "isolated-home"
    config = home / ".bp" / "config"
    config.parent.mkdir(parents=True)
    config.write_text("burp_rest_url=http://localhost:9123\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("BURP_REST_URL", raising=False)

    assert load().burp_rest_url == "http://localhost:9123"


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"burp_rest_url": "ftp://localhost:8089"}, "http"),
        ({"burp_rest_url": "http://user:pass@localhost:8089"}, "userinfo"),
        ({"burp_rest_url": "http://localhost:8089?token=secret"}, "query"),
        ({"burp_rest_url": "http://localhost:8089?"}, "query"),
        ({"burp_rest_url": "http://localhost:8089#"}, "fragment"),
        ({"enforce_scope": "sometimes"}, "enforce_scope"),
        ({"throttle_ms": -1}, "throttle_ms"),
        ({"anomaly_pct": -1}, "anomaly_pct"),
        ({"anomaly_pct": 101}, "anomaly_pct"),
    ],
)
def test_config_rejects_invalid_selected_values(
    kwargs: dict[str, Any], match: str, tmp_path: Path
) -> None:
    with pytest.raises(ConfigError, match=match):
        load(config_path=tmp_path / "absent", **kwargs)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8089",
        "https://localhost:8089/",
        "http://[::1]:8089",
        "http://127.4.5.6",
        "https://burp.internal:9443",
    ],
)
def test_config_accepts_http_rest_origins(url: str, tmp_path: Path) -> None:
    assert load(burp_rest_url=url, config_path=tmp_path / "absent").burp_rest_url == url


def test_non_utf8_config_is_clean_config_error(tmp_path: Path) -> None:
    path = tmp_path / "config"
    path.write_bytes(b"burp_rest_url=http://localhost:8089\n\xff")
    with pytest.raises(ConfigError, match="UTF-8"):
        load(config_path=path)


def test_unreadable_config_is_clean_config_error(tmp_path: Path) -> None:
    path = tmp_path / "config"
    path.write_text("", encoding="utf-8")
    with patch.object(Path, "read_text", side_effect=PermissionError("denied")):
        with pytest.raises(ConfigError, match="cannot read config"):
            load(config_path=path)


def test_cli_invalid_config_is_clean_human_usage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    config = home / ".bp" / "config"
    config.parent.mkdir(parents=True)
    config.write_text("throttle_ms=-1\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    result = CliRunner().invoke(app, ["health"])
    assert result.exit_code == EXIT_USAGE
    assert "error:" in result.stderr
    assert "Traceback" not in result.output + result.stderr


def test_omitted_cli_url_allows_config_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    config = home / ".bp" / "config"
    config.parent.mkdir(parents=True)
    config.write_text("burp_rest_url=http://localhost:9234\nledger=off\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("BURP_REST_URL", raising=False)
    seen: list[str] = []

    class FakeClient:
        op_ids: list[str] = []

        def __init__(self, url: str, **_kwargs: Any) -> None:
            seen.append(url)

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def health(self) -> Any:
            class Health:
                def model_dump(self) -> dict[str, Any]:
                    return {"status": "ok"}

            return Health()

    with patch("bp.cliutil.BurpClient", FakeClient):
        result = CliRunner().invoke(app, ["health"])
    assert result.exit_code == 0, result.stderr
    assert seen == ["http://localhost:9234"]


def test_bp_agent_sets_json_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BP_AGENT", "1")
    observed: list[str] = []

    def fake_run(ctx: typer.Context, _fn: Any) -> None:
        observed.append(ctx.obj.fmt)

    with patch("bp.cli.run", side_effect=fake_run):
        result = CliRunner().invoke(app, ["health"])
    assert result.exit_code == 0
    assert observed == ["json"]


def test_explicit_format_beats_bp_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BP_AGENT", "1")
    observed: list[str] = []

    def fake_run(ctx: typer.Context, _fn: Any) -> None:
        observed.append(ctx.obj.fmt)

    with patch("bp.cli.run", side_effect=fake_run):
        result = CliRunner().invoke(app, ["--format", "table", "health"])
    assert result.exit_code == 0
    assert observed == ["table"]


def test_short_help_is_supported() -> None:
    result = CliRunner().invoke(app, ["-h"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout


def test_option_hoisting_stops_at_double_dash() -> None:
    argv = ["encode", "--", "--format", "json", "--no-ledger"]
    assert _hoist_global_opts(argv) == argv


def test_option_hoisting_does_not_consume_double_dash_as_a_value() -> None:
    argv = ["health", "--format", "--", "json", "--no-ledger"]
    assert _hoist_global_opts(argv) == argv


def test_option_hoisting_stops_at_leading_double_dash() -> None:
    argv = ["--", "health", "--format", "json"]
    assert _hoist_global_opts(argv) == argv


@pytest.mark.parametrize("selector", [["all"], ["*"]])
@pytest.mark.parametrize("fmt", ["json", "table"])
def test_fields_all_and_star_mean_all_fields(selector: list[str], fmt: str) -> None:
    output = render({"first": 1, "second": 2}, fmt, fields=selector)
    assert "first" in output.lower()
    assert "second" in output.lower()


@pytest.mark.parametrize("structured", [{"x": 1}])
def test_raw_rejects_structured_values(structured: Any) -> None:
    with pytest.raises(ValueError, match="raw requires an unstructured value"):
        render(structured, "raw")


def test_tag_honors_json_renderer_and_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "ledger.db"
    with Ledger(db_path=db_path) as ledger:
        actual_id = ledger.record(OpRecord(status="ok"))
    monkeypatch.setenv("BP_LEDGER_PATH", str(db_path))

    result = CliRunner().invoke(
        app, ["--format", "json", "--fields", "tag,id", "tag", actual_id, "reviewed"]
    )
    assert result.exit_code == 0, result.stderr
    assert json.loads(result.stdout) == {"tag": "reviewed", "id": actual_id}
