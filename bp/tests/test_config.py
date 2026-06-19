"""Tests for bp.config — load() precedence and redact() masking.

TDD protocol: RED tests are committed first; GREEN follows in config.py.
"""

from __future__ import annotations

import json as _json
from pathlib import Path

import pytest

from bp.config import load, redact


# ---------------------------------------------------------------------------
# redact() — existing coverage (regression lock)
# ---------------------------------------------------------------------------


class TestRedactBearer:
    """Bearer token redaction — header-line and JSON-embedded forms."""

    def test_bearer_header_line(self) -> None:
        line = "Authorization: Bearer eyABCDEFGHIJKLMN"
        result = redact(line)
        assert "eyABCDEFGHIJKLMN" not in result
        assert "***" in result

    def test_bearer_json_embedded(self) -> None:
        blob = '{"name":"Authorization","value":"Bearer eyABCDEFGHIJKLMN"}'
        result = redact(blob)
        assert "eyABCDEFGHIJKLMN" not in result
        assert "***" in result

    def test_jwt_segments_masked(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact(jwt)
        # The payload and signature segments should be masked
        assert "eyJzdWIiOiJ1c2VyIn0" not in result


class TestRedactCookieHeaderLine:
    """Cookie header-line form — existing pattern regression lock."""

    def test_cookie_header_line_masked(self) -> None:
        line = "Cookie: session=SECRETSESSIONTOKEN; path=/"
        result = redact(line)
        assert "SECRETSESSIONTOKEN" not in result
        assert "***" in result

    def test_set_cookie_header_line(self) -> None:
        line = "Set-Cookie: session=SECRETSESSIONTOKEN; HttpOnly"
        result = redact(line)
        assert "SECRETSESSIONTOKEN" not in result
        assert "***" in result


# ---------------------------------------------------------------------------
# [10] Cookie JSON-embedded form — NEW RED TESTS
# ---------------------------------------------------------------------------


class TestRedactCookieJsonEmbedded:
    """Cookie values embedded in JSON must be masked.

    When headers are serialized to JSON (e.g. --format json), a Cookie header
    appears as {"name":"Cookie","value":"session=SECRETSESSIONTOKEN"}.
    The value field must be masked; the key 'Cookie' may remain visible.
    """

    def test_cookie_json_value_masked(self) -> None:
        blob = '{"name":"Cookie","value":"session=SECRETSESSIONTOKEN"}'
        result = redact(blob)
        assert "SECRETSESSIONTOKEN" not in result, (
            "Cookie value in JSON blob must be masked"
        )
        assert "***" in result

    def test_set_cookie_json_value_masked(self) -> None:
        blob = '{"name":"Set-Cookie","value":"session=SECRETSESSIONTOKEN; HttpOnly; Path=/"}'
        result = redact(blob)
        assert "SECRETSESSIONTOKEN" not in result, (
            "Set-Cookie value in JSON blob must be masked"
        )
        assert "***" in result

    def test_cookie_json_name_preserved(self) -> None:
        """The cookie NAME (key before '=') may be preserved; value must be masked."""
        blob = '{"name":"Cookie","value":"session=SECRETSESSIONTOKEN"}'
        result = redact(blob)
        # The word 'Cookie' (field name) and 'session' (cookie name) may survive —
        # what must NOT survive is the secret value.
        assert "SECRETSESSIONTOKEN" not in result

    def test_cookie_json_multiple_cookies(self) -> None:
        blob = '{"name":"Cookie","value":"a=FIRST_SECRET; b=SECOND_SECRET"}'
        result = redact(blob)
        assert "FIRST_SECRET" not in result
        assert "SECOND_SECRET" not in result

    def test_cookie_json_authorization_key_form(self) -> None:
        """Flat JSON where Cookie is a key: {"Cookie":"session=SECRET"}."""
        blob = '{"Cookie":"session=SECRETSESSIONTOKEN"}'
        result = redact(blob)
        assert "SECRETSESSIONTOKEN" not in result

    def test_cookie_non_secret_text_unaffected(self) -> None:
        """Plain text without credential patterns is untouched."""
        plain = "no secrets here, just regular text"
        assert redact(plain) == plain


# ---------------------------------------------------------------------------
# [11] Authorization Basic / Token / Digest — NEW RED TESTS
# ---------------------------------------------------------------------------


class TestRedactAuthBasicTokenDigest:
    """Basic, Token and Digest credentials must be masked in both forms.

    Header-line form:   Authorization: Basic dXNlcjpwYXNzd29yZA==
    JSON-embedded form: {"name":"Authorization","value":"Basic dXNlcjpwYXNzd29yZA=="}
                        {"Authorization":"Basic dXNlcjpwYXNzd29yZA=="}
    """

    BASIC_TOKEN = "dXNlcjpwYXNzd29yZA=="   # base64("user:password")
    TOKEN_VALUE = "myapitokenvalue123"
    DIGEST_CRED = 'username="user", realm="example", nonce="abc123", uri="/", response="deadbeef"'

    # --- Basic ---

    def test_basic_header_line_masked(self) -> None:
        line = f"Authorization: Basic {self.BASIC_TOKEN}"
        result = redact(line)
        assert self.BASIC_TOKEN not in result, "Basic token in header line must be masked"
        assert "***" in result

    def test_basic_json_value_field_masked(self) -> None:
        blob = f'{{"name":"Authorization","value":"Basic {self.BASIC_TOKEN}"}}'
        result = redact(blob)
        assert self.BASIC_TOKEN not in result, (
            "Basic token in JSON value field must be masked"
        )
        assert "***" in result

    def test_basic_json_flat_key_masked(self) -> None:
        blob = f'{{"Authorization":"Basic {self.BASIC_TOKEN}"}}'
        result = redact(blob)
        assert self.BASIC_TOKEN not in result, (
            "Basic token in flat JSON key must be masked"
        )
        assert "***" in result

    def test_basic_standalone_masked(self) -> None:
        """'Basic <token>' appearing anywhere (not just as a header line) is masked."""
        text = f"creds: Basic {self.BASIC_TOKEN}"
        result = redact(text)
        assert self.BASIC_TOKEN not in result

    # --- Token ---

    def test_token_header_line_masked(self) -> None:
        line = f"Authorization: Token {self.TOKEN_VALUE}"
        result = redact(line)
        assert self.TOKEN_VALUE not in result, "Token in header line must be masked"
        assert "***" in result

    def test_token_json_value_field_masked(self) -> None:
        blob = f'{{"name":"Authorization","value":"Token {self.TOKEN_VALUE}"}}'
        result = redact(blob)
        assert self.TOKEN_VALUE not in result, (
            "Token credential in JSON value field must be masked"
        )
        assert "***" in result

    def test_token_standalone_masked(self) -> None:
        text = f"Token {self.TOKEN_VALUE}"
        result = redact(text)
        assert self.TOKEN_VALUE not in result

    # --- Digest ---

    def test_digest_header_line_masked(self) -> None:
        line = f"Authorization: Digest {self.DIGEST_CRED}"
        result = redact(line)
        assert "response=\"deadbeef\"" not in result, "Digest cred in header line must be masked"
        assert "***" in result

    def test_digest_json_value_field_masked(self) -> None:
        # In real NDJSON output the JSON encoder escapes inner quotes as \".
        # DIGEST_CRED contains bare " so we JSON-encode it first to get the
        # realistic wire form that redact() actually receives.
        import json as _json_mod
        encoded_cred = _json_mod.dumps(f"Digest {self.DIGEST_CRED}")[1:-1]  # strip outer quotes
        blob = f'{{"name":"Authorization","value":"{encoded_cred}"}}'
        result = redact(blob)
        assert "deadbeef" not in result, (
            "Digest credential in JSON value field must be masked"
        )
        assert "***" in result

    # --- Regression: Bearer still works after adding Basic/Token/Digest ---

    def test_bearer_unaffected_by_new_patterns(self) -> None:
        line = "Authorization: Bearer supersecretbearertokenXYZ"
        result = redact(line)
        assert "supersecretbearertokenXYZ" not in result
        assert "***" in result


# ---------------------------------------------------------------------------
# load() — precedence and boolean parsing
# ---------------------------------------------------------------------------


class TestLoadDefaults:
    def test_default_url(self) -> None:
        cfg = load()
        assert cfg.burp_rest_url == "http://127.0.0.1:8089"

    def test_redact_on_by_default(self) -> None:
        cfg = load()
        assert cfg.redact is True

    def test_ledger_on_by_default(self) -> None:
        cfg = load()
        assert cfg.ledger is True


class TestLoadFlagPrecedence:
    def test_flag_overrides_default_url(self) -> None:
        cfg = load(burp_rest_url="http://example.com:9999")
        assert cfg.burp_rest_url == "http://example.com:9999"

    def test_flag_disables_redact(self) -> None:
        cfg = load(redact=False)
        assert cfg.redact is False

    def test_flag_disables_ledger(self) -> None:
        cfg = load(ledger=False)
        assert cfg.ledger is False


class TestLoadEnvPrecedence:
    def test_env_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BURP_REST_URL", "http://env-host:1234")
        cfg = load()
        assert cfg.burp_rest_url == "http://env-host:1234"

    def test_bp_no_ledger_disables_ledger(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BP_NO_LEDGER", "1")
        cfg = load()
        assert cfg.ledger is False

    def test_invalid_bool_env_falls_through_to_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BP_REDACT=junk should not silently disable redact — default (on) wins."""
        monkeypatch.setenv("BP_REDACT", "junk")
        cfg = load()
        assert cfg.redact is True


class TestLoadConfigFile:
    def test_file_sets_url(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config"
        cfg_file.write_text("burp_rest_url=http://file-host:8000\n")
        cfg = load(config_path=cfg_file)
        assert cfg.burp_rest_url == "http://file-host:8000"

    def test_ledger_on_in_file(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "config"
        cfg_file.write_text("ledger=on\n")
        cfg = load(config_path=cfg_file)
        assert cfg.ledger is True

    def test_invalid_bool_in_file_keeps_default(self, tmp_path: Path) -> None:
        """ledger=ye in config file must not silently disable ledger."""
        cfg_file = tmp_path / "config"
        cfg_file.write_text("ledger=ye\n")
        cfg = load(config_path=cfg_file)
        assert cfg.ledger is True


# ---------------------------------------------------------------------------
# [B] Invalid numeric env vars must keep the default AND warn to stderr
# ---------------------------------------------------------------------------


class TestLoadInvalidNumericEnv:
    """BP_THROTTLE_MS / BP_ANOMALY_PCT with non-numeric values must:
    - keep the built-in default (not crash, not silently return 0)
    - emit a warning to stderr (mirrors the invalid-boolean behaviour)
    """

    def test_invalid_throttle_ms_keeps_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BP_THROTTLE_MS=abc must keep the default (0), not crash."""
        monkeypatch.setenv("BP_THROTTLE_MS", "abc")
        cfg = load()
        assert cfg.throttle_ms == 0

    def test_invalid_throttle_ms_emits_warning(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """BP_THROTTLE_MS=abc must emit a warning to stderr."""
        monkeypatch.setenv("BP_THROTTLE_MS", "abc")
        load()
        err = capsys.readouterr().err
        assert "BP_THROTTLE_MS" in err or "throttle_ms" in err, (
            f"expected a warning mentioning throttle_ms or BP_THROTTLE_MS in stderr, got: {err!r}"
        )
        assert "warning" in err.lower()

    def test_invalid_anomaly_pct_keeps_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BP_ANOMALY_PCT=xyz must keep the default (5), not crash."""
        monkeypatch.setenv("BP_ANOMALY_PCT", "xyz")
        cfg = load()
        assert cfg.anomaly_pct == 5

    def test_invalid_anomaly_pct_emits_warning(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """BP_ANOMALY_PCT=xyz must emit a warning to stderr."""
        monkeypatch.setenv("BP_ANOMALY_PCT", "xyz")
        load()
        err = capsys.readouterr().err
        assert "BP_ANOMALY_PCT" in err or "anomaly_pct" in err, (
            f"expected a warning mentioning anomaly_pct or BP_ANOMALY_PCT in stderr, got: {err!r}"
        )
        assert "warning" in err.lower()

    def test_valid_throttle_ms_no_warning(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A valid BP_THROTTLE_MS value must be used without any warning."""
        monkeypatch.setenv("BP_THROTTLE_MS", "250")
        cfg = load()
        assert cfg.throttle_ms == 250
        err = capsys.readouterr().err
        assert "throttle" not in err.lower()

    def test_valid_anomaly_pct_no_warning(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A valid BP_ANOMALY_PCT value must be used without any warning."""
        monkeypatch.setenv("BP_ANOMALY_PCT", "10")
        cfg = load()
        assert cfg.anomaly_pct == 10
        err = capsys.readouterr().err
        assert "anomaly" not in err.lower()

    def test_unset_throttle_ms_uses_default_silently(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unset BP_THROTTLE_MS must use default (0) with no warning."""
        monkeypatch.delenv("BP_THROTTLE_MS", raising=False)
        cfg = load()
        assert cfg.throttle_ms == 0
        err = capsys.readouterr().err
        assert "throttle" not in err.lower()

    def test_unset_anomaly_pct_uses_default_silently(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unset BP_ANOMALY_PCT must use default (5) with no warning."""
        monkeypatch.delenv("BP_ANOMALY_PCT", raising=False)
        cfg = load()
        assert cfg.anomaly_pct == 5
        err = capsys.readouterr().err
        assert "anomaly" not in err.lower()


# ---------------------------------------------------------------------------
# [06] HIGH — redact() must NOT break NDJSON structural validity (F-JSON / A3)
# ---------------------------------------------------------------------------
# CRITICAL invariant: redact() is applied to rendered --format json output.
# Every NDJSON line must remain independently parseable after redaction.
# The greedy patterns (\S.*, \S[^\r\n]*) STOP at newline but NOT at the
# closing JSON quote, so they consume the `"` and everything after it,
# producing invalid JSON.  These RED tests prove the regression and lock the fix.
# ---------------------------------------------------------------------------


class TestRedactNdjsonValidity:
    """After redaction every single-object NDJSON line must still parse with json.loads()."""

    # --- Cookie in JSON value field ---

    def test_cookie_ndjson_reparseable(self) -> None:
        """Cookie secret inside a JSON object: redacted line must still parse."""
        line = '{"name":"Cookie","value":"session=SECRETTOK","x":1}'
        result = redact(line)
        parsed = _json.loads(result)          # must not raise
        assert "SECRETTOK" not in result, "secret must be masked"
        assert parsed.get("x") == 1, "sibling field 'x' must survive intact"

    def test_set_cookie_ndjson_reparseable(self) -> None:
        """Set-Cookie in JSON: redacted line must still parse; sibling field intact."""
        line = '{"name":"Set-Cookie","value":"sid=SETSECRET; HttpOnly","extra":"ok"}'
        result = redact(line)
        parsed = _json.loads(result)
        assert "SETSECRET" not in result
        assert parsed.get("extra") == "ok"

    # --- Authorization Bearer in JSON value field ---

    def test_bearer_ndjson_reparseable(self) -> None:
        """Bearer token in JSON value: redacted line must still parse."""
        line = '{"name":"Authorization","value":"Bearer eyABCDEFGHIJKLMN","z":99}'
        result = redact(line)
        parsed = _json.loads(result)
        assert "eyABCDEFGHIJKLMN" not in result
        assert parsed.get("z") == 99

    # --- Authorization Basic in JSON value field ---

    def test_basic_ndjson_reparseable(self) -> None:
        """Basic credential in JSON value: redacted line must still parse."""
        line = '{"name":"Authorization","value":"Basic dXNlcjpwYXNzd29yZA==","z":2}'
        result = redact(line)
        parsed = _json.loads(result)
        assert "dXNlcjpwYXNzd29yZA==" not in result
        assert parsed.get("z") == 2

    # --- Authorization Digest in JSON value field ---

    def test_digest_ndjson_reparseable(self) -> None:
        """Digest credential in JSON value: redacted line must still parse."""
        line = '{"name":"Authorization","value":"Digest username=\\"u\\", response=\\"deadbeef\\"","z":3}'
        result = redact(line)
        parsed = _json.loads(result)
        assert "deadbeef" not in result
        assert parsed.get("z") == 3

    # --- Authorization header-line value embedded inside a JSON string ---

    def test_auth_header_line_in_json_string_reparseable(self) -> None:
        """Header-line form stored as a JSON string value: sibling fields survive."""
        # e.g. a request dump that stores the raw header line as a JSON value
        line = '{"raw":"Authorization: Bearer SUPERSECRETXYZ","id":42}'
        result = redact(line)
        parsed = _json.loads(result)
        assert "SUPERSECRETXYZ" not in result
        assert parsed.get("id") == 42

    # --- Cookie header-line value embedded inside a JSON string ---

    def test_cookie_header_line_in_json_string_reparseable(self) -> None:
        """Cookie header-line stored as JSON string value: sibling fields survive."""
        line = '{"raw":"Cookie: session=RAWSECRET; path=/","id":7}'
        result = redact(line)
        parsed = _json.loads(result)
        assert "RAWSECRET" not in result
        assert parsed.get("id") == 7

    # --- Plain header-line forms still work (non-regression) ---

    def test_cookie_header_line_still_masked(self) -> None:
        """Plain Cookie: header line (not inside JSON) must still be masked."""
        line = "Cookie: session=SECRETSESSIONTOKEN; path=/"
        result = redact(line)
        assert "SECRETSESSIONTOKEN" not in result
        assert "***" in result

    def test_auth_digest_header_line_still_masked(self) -> None:
        """Plain Authorization: Digest header line must still be masked."""
        line = 'Authorization: Digest username="u", realm="r", response="deadbeef"'
        result = redact(line)
        assert "deadbeef" not in result
        assert "***" in result
