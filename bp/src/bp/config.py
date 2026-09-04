"""Configuration loading and secret redaction for ``bp``.

Configuration precedence is flag > environment > ``~/.bp/config`` > built-in
values. Structured command results are redacted recursively before rendering;
``redact()`` remains a conservative text fallback for diagnostics and command
text that have no reliable structure.
"""

from __future__ import annotations

import copy
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit

DEFAULT_BASE_URL = "http://127.0.0.1:8089"
REDACTED = "***"

_DEFAULTS: dict[str, str] = {
    "burp_rest_url": DEFAULT_BASE_URL,
    "enforce_scope": "warn",
    "envelope": "off",
    "redact": "on",
    "ledger": "on",
    "throttle_ms": "0",
    "anomaly_pct": "5",
}

_ENV_MAP: dict[str, str] = {
    "burp_rest_url": "BURP_REST_URL",
    "enforce_scope": "BP_ENFORCE_SCOPE",
    "envelope": "BP_ENVELOPE",
    "redact": "BP_REDACT",
    "ledger": "BP_NO_LEDGER",
    "throttle_ms": "BP_THROTTLE_MS",
    "anomaly_pct": "BP_ANOMALY_PCT",
}

_TRUE_TOKENS = ("1", "true", "on", "yes")
_FALSE_TOKENS = ("0", "false", "off", "no")
_SCOPE_VALUES = ("warn", "block", "off")


class ConfigError(ValueError):
    """A selected configuration value or configuration input is invalid."""


@dataclass
class BpConfig:
    burp_rest_url: str = DEFAULT_BASE_URL
    enforce_scope: str = "warn"
    envelope: bool = False
    redact: bool = True
    ledger: bool = True
    throttle_ms: int = 0
    anomaly_pct: int = 5


def _default_config_path() -> Path:
    """Resolve HOME for every load, which keeps isolated invocations isolated."""
    return Path("~/.bp/config").expanduser()


def _parse_config_file(path: Path) -> dict[str, str]:
    """Parse a simple KEY=value file, ignoring comments, blanks, and unknown lines."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config file {path} is not valid UTF-8") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}") from exc

    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        result[key.strip().lower()] = value.strip()
    return result


def _parse_bool(value: str) -> bool | None:
    token = value.strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    return None


def _warn_invalid(source: str, value: str, kind: str = "boolean") -> None:
    safe_value = _redact_text_fallback(value)
    print(
        f"warning: invalid {kind} for {source}={safe_value!r}; keeping default",
        file=sys.stderr,
    )


def _validate_rest_url(value: str) -> str:
    value = value.strip()
    if any(char.isspace() or ord(char) < 0x20 for char in value):
        raise ConfigError("burp_rest_url must be a valid http(s) REST URL")
    try:
        parsed = urlsplit(value)
        # Accessing .port performs the URL parser's port validation.
        _ = parsed.port
    except ValueError as exc:
        raise ConfigError("burp_rest_url must be a valid http(s) REST URL") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ConfigError("burp_rest_url must use http or https")
    if not parsed.hostname:
        raise ConfigError("burp_rest_url must name a host")
    if parsed.hostname != parsed.hostname.strip() or any(
        char.isspace() for char in parsed.hostname
    ):
        raise ConfigError("burp_rest_url must name a valid host")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("burp_rest_url must not contain URL userinfo")
    if "?" in value:
        raise ConfigError("burp_rest_url must not contain a query")
    if "#" in value:
        raise ConfigError("burp_rest_url must not contain a fragment")
    if parsed.path not in {"", "/"}:
        raise ConfigError("burp_rest_url must be a REST origin without a path")

    return value


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
    warn: Callable[[str], None] | None = None,
) -> BpConfig:
    """Resolve and validate configuration using flag > env > file > default precedence."""
    path = Path(config_path) if config_path is not None else _default_config_path()
    file_values = _parse_config_file(path)
    warn_invalid = (
        _warn_invalid
        if warn is None
        else lambda source, value, kind="boolean": warn(
            f"invalid {kind} for {source}={_redact_text_fallback(value)!r}; keeping default"
        )
    )

    def resolve_str(key: str, flag_value: str | None) -> str:
        if flag_value is not None:
            return flag_value.strip()
        env_value = os.environ.get(_ENV_MAP[key])
        if env_value is not None and env_value.strip():
            return env_value.strip()
        if key in file_values:
            return file_values[key]
        return _DEFAULTS[key]

    def resolve_bool(
        key: str, flag_value: bool | None, *, invert_environment: bool = False
    ) -> bool:
        if flag_value is not None:
            return flag_value
        env_name = _ENV_MAP[key]
        env_value = os.environ.get(env_name)
        if env_value is not None and env_value.strip():
            parsed = _parse_bool(env_value)
            if parsed is not None:
                return not parsed if invert_environment else parsed
            warn_invalid(env_name, env_value)
        if key in file_values:
            parsed = _parse_bool(file_values[key])
            if parsed is not None:
                return parsed
            warn_invalid(key, file_values[key])
        parsed_default = _parse_bool(_DEFAULTS[key])
        assert parsed_default is not None
        return parsed_default

    def resolve_int(key: str, flag_value: int | None) -> int:
        if flag_value is not None:
            return flag_value
        raw = resolve_str(key, None)
        try:
            return int(raw)
        except ValueError:
            warn_invalid(_ENV_MAP[key], raw, "integer")
            return int(_DEFAULTS[key])

    selected_url = _validate_rest_url(resolve_str("burp_rest_url", burp_rest_url))
    selected_scope = resolve_str("enforce_scope", enforce_scope).lower()
    if selected_scope not in _SCOPE_VALUES:
        raise ConfigError(f"enforce_scope must be one of {', '.join(_SCOPE_VALUES)}")

    selected_throttle = resolve_int("throttle_ms", throttle_ms)
    if selected_throttle < 0:
        raise ConfigError("throttle_ms must be greater than or equal to 0")
    selected_anomaly = resolve_int("anomaly_pct", anomaly_pct)
    if not 0 <= selected_anomaly <= 100:
        raise ConfigError("anomaly_pct must be between 0 and 100")

    return BpConfig(
        burp_rest_url=selected_url,
        enforce_scope=selected_scope,
        envelope=resolve_bool("envelope", envelope),
        redact=resolve_bool("redact", redact),
        ledger=resolve_bool("ledger", ledger, invert_environment=True),
        throttle_ms=selected_throttle,
        anomaly_pct=selected_anomaly,
    )


# Exact canonical names plus deliberately narrow suffixes. ``key`` alone is
# sensitive, but arbitrary words ending in "key" (for example "monkey") are not.
_SENSITIVE_NAMES = {
    "authorization",
    "proxyauthorization",
    "cookie",
    "cookies",
    "setcookie",
    "apikey",
    "apikeys",
    "apiaccesskey",
    "accesskey",
    "secretkey",
    "privatekey",
    "key",
    "token",
    "tokens",
    "accesstoken",
    "authtoken",
    "bearertoken",
    "idtoken",
    "refreshtoken",
    "sessiontoken",
    "password",
    "passwords",
    "passwd",
    "pwd",
    "secret",
    "secrets",
    "clientsecret",
    "credential",
    "credentials",
}
_SENSITIVE_SUFFIXES = (
    "apikey",
    "accesskey",
    "secretkey",
    "privatekey",
    "secretaccesskey",
    "token",
    "tokenhash",
    "tokenvalue",
    "password",
    "passwordhash",
    "passwordvalue",
    "passwd",
    "secret",
    "secretvalue",
    "credential",
    "credentials",
)
_SENSITIVE_QUERY_NAMES = _SENSITIVE_NAMES | {
    "auth",
    "code",
    "csrf",
    "xsrf",
    "jwt",
    "session",
    "sessionid",
    "sig",
    "xamzcredential",
    "xamzsignature",
    "xgoogcredential",
    "xgoogsignature",
    "awsaccesskeyid",
    "googleaccessid",
    "signature",
}


def _canonical_name(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _is_sensitive_name(value: Any) -> bool:
    name = _canonical_name(value)
    return bool(name) and (name in _SENSITIVE_NAMES or name.endswith(_SENSITIVE_SUFFIXES))


def _is_sensitive_query_name(value: str) -> bool:
    decoded = unquote_plus(value)
    name = _canonical_name(decoded)
    return (
        _is_sensitive_name(decoded)
        or bool(name)
        and (name in _SENSITIVE_QUERY_NAMES or name.endswith(_SENSITIVE_SUFFIXES))
    )


def _redact_query(query: str) -> str:
    if not query:
        return query
    parts = re.split(r"([&;])", query)
    for index in range(0, len(parts), 2):
        item = parts[index]
        key, separator, _value = item.partition("=")
        if separator and _is_sensitive_query_name(key):
            parts[index] = f"{key}={REDACTED}"
    return "".join(parts)


def _redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError:
        return url
    if parsed.scheme:
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return url
    elif parsed.netloc:
        pass
    elif not parsed.query or not url.startswith(("/", "?")):
        return url

    netloc = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[-1]}"
    query = _redact_query(parsed.query)
    fragment = _redact_query(parsed.fragment)
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


_URL_IN_TEXT = re.compile(r"(?:https?:)?//[^\s<>\"']+", re.IGNORECASE)

# Text fallback patterns intentionally need recognizable credential context.
# Structured output takes the recursive path below and never relies on these.
_TEXT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"((?:Proxy-)?Authorization:\s*)(?P<secret>[^\r\n]+)",
        re.IGNORECASE,
    ),
    re.compile(r"((?:Set-)?Cookie:\s*)(?P<secret>[^\r\n]+)", re.IGNORECASE),
    re.compile(
        r"((?:Bearer|Basic|Token|Digest)\s+)(?P<secret>[A-Za-z0-9_\-=.+/, :\\\"]{4,})",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<prefix>\b(?:(?:proxy[_-]?)?authorization|api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd|client[_-]?secret|secret|(?:set[_-]?)?cookie)\b[\"']?\s*[=:]\s*[\"']?)(?P<secret>[^\s,;&\"']+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?P<prefix>--(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd|client[_-]?secret|secret)(?:=|\s+)[\"']?)(?P<secret>[^\s\"']+)",
        re.IGNORECASE,
    ),
    re.compile(r"(eyJ[A-Za-z0-9_-]+\.)(?P<secret>[A-Za-z0-9_.-]+)"),
)


def _redact_text_fallback(text: str) -> str:
    text = _redact_url(text)
    text = _URL_IN_TEXT.sub(lambda match: _redact_url(match.group(0)), text)
    for pattern in _TEXT_PATTERNS:

        def replace(match: re.Match[str]) -> str:
            full = match.group(0)
            prefix_length = match.start("secret") - match.start(0)
            return f"{full[:prefix_length]}{REDACTED}"

        text = pattern.sub(replace, text)
    return text


def redact(text: str) -> str:
    """Conservatively redact credentials from unstructured text.

    Older callers sometimes pass already serialized JSON/NDJSON. Parse those
    records first so compatibility never comes at the cost of broken JSON; new
    output paths call :func:`redact_data` before serialization instead.
    """
    sentinel = object()
    parsed: Any = sentinel
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    if parsed is not sentinel:
        return json.dumps(redact_data(parsed), separators=(",", ":"), ensure_ascii=False)

    lines = text.splitlines()
    if len(lines) > 1:
        parsed_lines: list[Any] = []
        try:
            parsed_lines = [json.loads(line) for line in lines]
        except json.JSONDecodeError:
            parsed_lines = []
        if parsed_lines:
            return "\n".join(
                json.dumps(redact_data(record), separators=(",", ":"), ensure_ascii=False)
                for record in parsed_lines
            )
    return _redact_text_fallback(text)


def _copy_mapping(value: Mapping[Any, Any]) -> Any:
    try:
        result: Any = copy.copy(value)
        for key in value:
            result[key] = value[key]
        return result
    except (AttributeError, TypeError):
        return dict(value)


def _mask_sensitive_value(value: Any) -> Any:
    """Mask every scalar while retaining the value's structural shape and types."""
    if isinstance(value, Mapping):
        result = _copy_mapping(value)
        for key, item in value.items():
            result[key] = _mask_sensitive_value(item)
        return result
    if isinstance(value, list):
        return [_mask_sensitive_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_mask_sensitive_value(item) for item in value)
    if isinstance(value, bytes):
        return REDACTED.encode()
    if isinstance(value, bytearray):
        return bytearray(REDACTED, "utf-8")
    if isinstance(value, str):
        return REDACTED
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return 0
    if isinstance(value, float):
        return 0.0
    return REDACTED


def redact_data(value: Any) -> Any:
    """Return a recursively redacted copy while retaining structure and key order.

    Nested mappings and lists are handled before serialization. Header maps,
    ``{name, value}`` header records, credential-named fields, URL userinfo, and
    common credential query parameters are recognized case-insensitively.
    """
    if isinstance(value, Mapping):
        result = _copy_mapping(value)
        header_name: Any = None
        value_key: Any = None
        for key, item in value.items():
            canonical = _canonical_name(key)
            if canonical == "name":
                header_name = item
            elif canonical == "value":
                value_key = key
        header_record = _is_sensitive_name(header_name)

        for key, item in value.items():
            if header_record and key == value_key:
                result[key] = _mask_sensitive_value(item)
            elif _is_sensitive_name(key):
                result[key] = _mask_sensitive_value(item)
            else:
                result[key] = redact_data(item)
        return result
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    if isinstance(value, bytes):
        return _redact_text_fallback(value.decode("utf-8", "replace")).encode("utf-8")
    if isinstance(value, bytearray):
        return bytearray(_redact_text_fallback(value.decode("utf-8", "replace")), "utf-8")
    if isinstance(value, str):
        return _redact_text_fallback(value)
    return value


# Descriptive aliases for callers migrating from serialized redaction.
redact_structure = redact_data
redact_value = redact_data
