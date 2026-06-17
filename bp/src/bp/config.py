"""bp configuration loader (STATE-AND-CONFIG §2, ADR-0005/0007).

Precedence (highest wins): flag > env > ~/.bp/config > built-in default.

Keys
----
burp_rest_url   http://127.0.0.1:8089
enforce_scope   warn | block | off
envelope        on | off
redact          on | off
ledger          on | off
throttle_ms     int >= 0
anomaly_pct     int 0-100

Public API
----------
load(**flag_overrides) -> BpConfig
redact(text)           -> str   (masks JWT/Authorization/Cookie values)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# Single source of truth for the REST base URL (re-exported by bp.client).
DEFAULT_BASE_URL = "http://127.0.0.1:8089"

_DEFAULTS: dict[str, str] = {
    "burp_rest_url": DEFAULT_BASE_URL,
    "enforce_scope": "warn",
    "envelope": "off",
    "redact": "on",
    "ledger": "on",
    "throttle_ms": "0",
    "anomaly_pct": "5",
}

# Env-var name mapping  (config key -> env var name)
_ENV_MAP: dict[str, str] = {
    "burp_rest_url": "BURP_REST_URL",
    "enforce_scope": "BP_ENFORCE_SCOPE",
    "envelope": "BP_ENVELOPE",
    "redact": "BP_REDACT",
    "ledger": "BP_NO_LEDGER",       # inverted: BP_NO_LEDGER=1 -> ledger=off
    "throttle_ms": "BP_THROTTLE_MS",
    "anomaly_pct": "BP_ANOMALY_PCT",
}

_DEFAULT_CONFIG_PATH = Path("~/.bp/config").expanduser()


# ---------------------------------------------------------------------------
# Config file parser  (KEY = value  or  KEY=value, shell-sourceable)
# ---------------------------------------------------------------------------

def _parse_config_file(path: Path) -> dict[str, str]:
    """Parse a KEY=value (or KEY = value) file; skip comments and blanks."""
    result: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return result
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        result[key.strip().lower()] = val.strip()
    return result


# ---------------------------------------------------------------------------
# BpConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class BpConfig:
    burp_rest_url: str = DEFAULT_BASE_URL
    enforce_scope: str = "warn"      # warn | block | off
    envelope: bool = False
    redact: bool = True
    ledger: bool = True
    throttle_ms: int = 0
    anomaly_pct: int = 5


def _to_bool(val: str) -> bool:
    return val.lower() in ("1", "true", "on", "yes")


def _to_bool_inv(val: str) -> bool:
    """Inverted: BP_NO_LEDGER=1 means ledger=False."""
    return not _to_bool(val)


# ---------------------------------------------------------------------------
# load()
# ---------------------------------------------------------------------------

def load(
    *,
    burp_rest_url: str | None = None,
    enforce_scope: str | None = None,
    envelope: bool | None = None,
    redact: bool | None = None,
    ledger: bool | None = None,
    throttle_ms: int | None = None,
    anomaly_pct: int | None = None,
    config_path: Path | None = None,
) -> BpConfig:
    """Build a BpConfig applying precedence: flag > env > file > default.

    Pass keyword args for CLI flag overrides.  None means "not set by flag".
    """
    cfg_path = config_path or _DEFAULT_CONFIG_PATH
    file_vals = _parse_config_file(cfg_path)

    def _resolve_str(key: str, flag_val: str | None, env_key: str) -> str:
        if flag_val is not None:
            return flag_val
        ev = os.environ.get(env_key)
        if ev is not None:
            return ev
        if key in file_vals:
            return file_vals[key]
        return _DEFAULTS[key]

    def _resolve_bool(key: str, flag_val: bool | None, env_key: str, invert: bool = False) -> bool:
        # ``invert`` applies ONLY to the negatively-named env var (e.g. BP_NO_LEDGER=1 -> off).
        # The config-file key and the built-in default are positive-sense and read literally;
        # inverting them silently flipped ``ledger=on`` to disabled (regression test in test_ledger).
        if flag_val is not None:
            return flag_val
        ev = os.environ.get(env_key)
        if ev is not None:
            return _to_bool_inv(ev) if invert else _to_bool(ev)
        if key in file_vals:
            return _to_bool(file_vals[key])
        return _to_bool(_DEFAULTS[key])

    def _resolve_int(key: str, flag_val: int | None, env_key: str) -> int:
        raw = _resolve_str(key, str(flag_val) if flag_val is not None else None, env_key)
        try:
            return int(raw)
        except ValueError:
            return int(_DEFAULTS[key])

    url_flag = burp_rest_url  # may be None or explicit str

    return BpConfig(
        burp_rest_url=_resolve_str("burp_rest_url", url_flag, _ENV_MAP["burp_rest_url"]),
        enforce_scope=_resolve_str("enforce_scope", enforce_scope, _ENV_MAP["enforce_scope"]),
        envelope=_resolve_bool("envelope", envelope, _ENV_MAP["envelope"]),
        redact=_resolve_bool("redact", redact, _ENV_MAP["redact"]),
        # BP_NO_LEDGER is inverted: BP_NO_LEDGER=1 -> ledger=False
        ledger=_resolve_bool("ledger", ledger, _ENV_MAP["ledger"], invert=True),
        throttle_ms=_resolve_int("throttle_ms", throttle_ms, _ENV_MAP["throttle_ms"]),
        anomaly_pct=_resolve_int("anomaly_pct", anomaly_pct, _ENV_MAP["anomaly_pct"]),
    )


# ---------------------------------------------------------------------------
# redact()
# ---------------------------------------------------------------------------

# Patterns to mask.  Each pattern captures a "prefix" group and a "secret" group.
# The secret group is replaced with *** .
_REDACT_PATTERNS: list[re.Pattern[str]] = [
    # Authorization: Bearer <token>  or  Authorization: Basic <creds>
    re.compile(r"(Authorization:\s*(?:Bearer|Basic|Token)\s+)\S+", re.IGNORECASE),
    # Bearer token anywhere (e.g. in JSON values)
    re.compile(r"(Bearer\s+)[A-Za-z0-9\-_=.+/]{8,}", re.IGNORECASE),
    # Cookie: name=value pairs
    re.compile(r"(Cookie:\s*)\S.*", re.IGNORECASE),
    # JWT: three base64url segments separated by dots (eyJ...)
    re.compile(r"(eyJ[A-Za-z0-9\-_]+\.)([A-Za-z0-9\-_.]+)"),
]

_REDACT_PLACEHOLDER = "***"


def redact(text: str) -> str:
    """Mask JWT/Authorization/Cookie values in *text*.

    Applies all _REDACT_PATTERNS; replaces the secret portion with ***.
    If the config has redact=off this function should not be called by the
    caller — but it is always safe to call.
    """
    for pattern in _REDACT_PATTERNS:
        # Replace group(0) keeping group(1) (prefix), replacing rest with ***
        def _replace(m: re.Match[str]) -> str:
            prefix = m.group(1)
            return f"{prefix}{_REDACT_PLACEHOLDER}"

        text = pattern.sub(_replace, text)
    return text
