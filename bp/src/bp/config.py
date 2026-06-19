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
import sys
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


_TRUE_TOKENS = ("1", "true", "on", "yes")
_FALSE_TOKENS = ("0", "false", "off", "no")


def _parse_bool(val: str) -> bool | None:
    """Return True/False for a recognised token, or None if *val* is not a valid boolean.

    A ``None`` result means "unrecognised" (typo, empty, junk) — callers fall back to the
    next precedence layer rather than silently treating it as False, which previously turned
    a security control (redact) off on ``BP_REDACT=`` or ``redact = ye``.
    """
    v = val.strip().lower()
    if v in _TRUE_TOKENS:
        return True
    if v in _FALSE_TOKENS:
        return False
    return None


def _warn_invalid(source: str, val: str) -> None:
    print(f"warning: invalid boolean for {source}={val!r}; keeping default", file=sys.stderr)


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
        if ev:  # an empty env var (BURP_REST_URL=) is treated as unset, not as an empty URL
            return ev
        if key in file_vals:
            return file_vals[key]
        return _DEFAULTS[key]

    def _resolve_bool(key: str, flag_val: bool | None, env_key: str, invert: bool = False) -> bool:
        # ``invert`` applies ONLY to the negatively-named env var (e.g. BP_NO_LEDGER=1 -> off).
        # An empty or unrecognised value (BP_REDACT=, redact=ye) is NOT treated as False — it
        # falls through to the next layer, so a typo never silently disables a security control.
        if flag_val is not None:
            return flag_val
        ev = os.environ.get(env_key)
        if ev and ev.strip():
            parsed = _parse_bool(ev)
            if parsed is not None:
                return (not parsed) if invert else parsed
            _warn_invalid(env_key, ev)
        if key in file_vals:
            parsed = _parse_bool(file_vals[key])
            if parsed is not None:
                return parsed
            _warn_invalid(key, file_vals[key])
        default = _parse_bool(_DEFAULTS[key])
        return default if default is not None else False

    def _resolve_int(key: str, flag_val: int | None, env_key: str) -> int:
        raw = _resolve_str(key, str(flag_val) if flag_val is not None else None, env_key)
        try:
            return int(raw)
        except ValueError:
            # Warn only when the invalid value came from env/config, not from a CLI flag
            # (a flag value is always pre-validated as int by the CLI layer).
            if flag_val is None:
                print(
                    f"warning: invalid int for {env_key}={raw!r}; keeping default",
                    file=sys.stderr,
                )
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

# Patterns to mask.  Each pattern must use a named group ``secret`` for the
# portion to redact.  Everything else in the match (prefix/context captured by
# other groups or plain match text) is preserved verbatim.
#
# Two forms are covered for each credential class:
#   (A) Header-line form:  "Authorization: Basic <cred>"
#   (B) JSON-embedded form: "Basic <cred>" inside a JSON string value, or a
#       Cookie "value" field in {"name":"Cookie","value":"..."} blobs.
_REDACT_PATTERNS: list[re.Pattern[str]] = [
    # [A] Authorization header line — Bearer / Basic / Token (NOT Digest).
    # Value match uses [^"\r\n]+ so the pattern is JSON-safe: it stops at the
    # closing double-quote when the header line is embedded inside a JSON string
    # value (NDJSON output), leaving the line independently parseable.
    # Bearer/Basic/Token credentials never contain bare `"` so this is lossless.
    re.compile(
        r'(Authorization:\s*(?:Bearer|Basic|Token)\s+)(?P<secret>[^"\r\n]+)',
        re.IGNORECASE,
    ),
    # [A-Digest] Authorization: Digest header line — plain/raw form.
    # RFC 7235 Digest credentials contain bare `"` (quoted-string parameters
    # like username="u", response="deadbeef") so we must NOT stop at `"`.
    # We stop at CR/LF only, which is correct for a raw header line.
    # Note: this pattern is NOT JSON-safe for a Digest header embedded inside a
    # JSON string value ("raw":"Authorization: Digest ...").  That case is rare
    # in bp output (burp serialises headers as structured {name, value} objects);
    # the structured form is covered by [B-Digest] below.
    re.compile(
        r"(Authorization:\s*Digest\s+)(?P<secret>[^\r\n]+)",
        re.IGNORECASE,
    ),
    # [B] Credential scheme keyword anywhere (JSON-embedded or standalone).
    #     Covers Bearer, Basic, Token — masks the credential that follows.
    #     Min 4 chars to avoid false positives on short words after "Token".
    re.compile(
        r"((?:Bearer|Basic|Token)\s+)(?P<secret>[A-Za-z0-9\-_=.+/]{4,})",
        re.IGNORECASE,
    ),
    # [B-Digest] Digest credential value anywhere — JSON-embedded form.
    # In JSON, inner quotes in the Digest value are escaped as \" in the raw
    # Python string.  The alternation (?:\\"|[^"\r\n])+ tries the two-char
    # sequence \" FIRST so that \ and " are consumed together as a unit; the
    # fallback [^"\r\n] then handles every other non-quote character.  The
    # combined effect: passes through \"-sequences (escaped inner quotes) and
    # stops only at a bare " (the JSON closing delimiter), keeping the NDJSON
    # line parseable after redaction.
    # For the plain Authorization: Digest header-line form, [A-Digest] fires
    # first and the Digest keyword is consumed into the replacement, so this
    # pattern does not double-fire on already-redacted output.
    re.compile(r'(Digest\s+)(?P<secret>(?:\\"|[^"\r\n])+)', re.IGNORECASE),
    # [A] Cookie / Set-Cookie header line.
    # Cookie values do not contain bare `"` so [^"\r\n]+ is both lossless for
    # plain header lines and JSON-safe when embedded in a JSON string value.
    re.compile(r'((?:Set-)?Cookie:\s*)(?P<secret>[^"\r\n]+)', re.IGNORECASE),
    # [B] Cookie value in JSON flat-key form: {"Cookie":"session=SECRET"}
    re.compile(r'("(?:Set-)?Cookie"\s*:\s*")(?P<secret>[^"]+)', re.IGNORECASE),
    # [B] Cookie value in {"name":"Cookie","value":"session=SECRET"} blob.
    #     Non-capturing context (Cookie name field) precedes the value field.
    re.compile(
        r'(?:"(?:Set-)?Cookie"[^}]{0,200}"value"\s*:\s*")(?P<secret>[^"]+)',
        re.IGNORECASE | re.DOTALL,
    ),
    # JWT: three base64url segments — keep header, mask payload+signature.
    re.compile(r"(eyJ[A-Za-z0-9\-_]+\.)(?P<secret>[A-Za-z0-9\-_.]+)"),
]

_REDACT_PLACEHOLDER = "***"


def redact(text: str) -> str:
    """Mask JWT/Authorization/Cookie values in *text*.

    Applies all _REDACT_PATTERNS.  Each pattern uses a named group ``secret``
    for the portion to replace; everything else in the match is kept verbatim.
    If the config has redact=off this function should not be called by the
    caller — but it is always safe to call.
    """
    for pattern in _REDACT_PATTERNS:
        def _replace(m: re.Match[str]) -> str:
            full = m.group(0)
            # Keep everything in the match before the secret group.
            prefix = full[: m.start("secret") - m.start(0)]
            return f"{prefix}{_REDACT_PLACEHOLDER}"

        text = pattern.sub(_replace, text)
    return text
