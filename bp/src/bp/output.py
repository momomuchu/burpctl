"""Output rendering — json | table | raw | quiet (+ --fields). See docs/OUTPUT.md.

``json`` = compact NDJSON (one record per line) for AI-agent consumption; ``table`` = aligned
human view; ``quiet`` = the single most essential value; ``raw`` = the value as-is.
"""

from __future__ import annotations

import base64
import binascii
import json as _json
from http import HTTPStatus
from typing import Any, Literal, overload
from urllib.parse import urlsplit

FORMATS = ("json", "table", "raw", "quiet")

_COLLAB_PAYLOAD_FIELDS = ("id", "payload", "interactionId")
_COLLAB_INTERACTION_FIELDS = (
    "id",
    "interactionId",
    "type",
    "clientIp",
    "timestamp",
    "details",
    "clientPort",
)

# Commands whose single essential value is explicitly defined by OUTPUT.md §1.5. A command outside
# this set emits no quiet stdout rather than inferring a meaning from response key order.
_QUIET_ESSENTIAL_COMMANDS = frozenset(
    {
        "health",
        "proxy",
        "req",
        "fuzz",
        "send",
        "collab new",
        "collab poll",
        "scan issues",
        "scope check",
        "history list",
        "history get",
        "log",
        "tag",
        "check auth",
        "check idor",
        "check headers",
        "check cors",
        "check endpoints",
    }
)

# Static command contracts let the execution chokepoint reject output mistakes before invoking a
# command callback.  A response-derived schema is too late for mutating calls: the target may already
# have changed, a one-use poll may already have been consumed, or an opaque task id may already be
# lost.  Catalogs intentionally include both full JSON fields and safe table projections where those
# views differ.
_COMMAND_FIELDS: dict[str, tuple[str, ...]] = {
    # Synthetic command path used by direct cliutil.run regression tests.
    "test": ("present", "password", "nested", "status"),
    "health": ("status", "version", "uptime", "burpVersion"),
    "version": ("version", "name", "burpVersion"),
    "proxy": ("id", "method", "url", "status"),
    "log": (
        "id",
        "ts",
        "command",
        "burp_op",
        "target",
        "program",
        "tag",
        "status",
        "exit_code",
        "req_sha256",
        "resp_sha256",
        "resp_status",
        "resp_len",
        "duration_ms",
        "error_code",
        "req_ref",
        "resp_ref",
    ),
    "tag": ("id", "tag", "status"),
    "fuzz": (
        "index",
        "payloads",
        "status",
        "length",
        "duration_ms",
        "anomalous",
        "baseline",
        "error",
        "error_code",
    ),
    "req": (
        "id",
        "request",
        "response",
        "timestamp",
        "listenerInterface",
        "clientIp",
        "listenerPort",
        "method",
        "url",
        "status",
    ),
    "ws": (
        "id",
        "url",
        "direction",
        "payload",
        "timestamp",
        "webSocketId",
        "payloadBase64",
        "editedPayloadBase64",
        "time",
        "listenerPort",
    ),
    "intercept": ("enabled",),
    "send": ("request", "response", "durationMs", "hasResponse", "persistence"),
    "tab": ("name", "created"),
    "collab new": ("payloads", *_COLLAB_PAYLOAD_FIELDS),
    "collab poll": ("found", "interactions", "queriedPayloadId", *_COLLAB_INTERACTION_FIELDS),
    "scan crawl": ("scanId", "status"),
    "scan audit": ("scanId", "status"),
    "scan all": ("scanId", "status"),
    "scan status": (
        "scanId",
        "status",
        "crawlProgress",
        "auditProgress",
        "issueCount",
        "statusMessage",
        "requestCount",
        "errorCount",
    ),
    "scan issues": (
        "scanId",
        "issues",
        "total",
        "name",
        "url",
        "severity",
        "confidence",
        "detail",
        "remediation",
    ),
    "scan defs": ("definitions", "total"),
    "scope show": ("include", "exclude", "includes", "excludes"),
    "scope set": ("include", "exclude", "includes", "excludes"),
    "scope add": ("url", "inScope"),
    "scope remove": ("url", "inScope"),
    "scope check": ("url", "inScope"),
    "sitemap": ("entries", "total", "url", "method", "statusCode", "mimeType"),
    "encode": ("result", "encoding"),
    "decode": ("result", "encoding", "final", "steps"),
    "hash": ("result", "algorithm"),
    "config get project": ("config", "excludedPaths"),
    "config get user": ("config", "excludedPaths"),
    "config set project": ("applied", "config", "excludedPaths", "warning"),
    "config set user": ("applied", "config", "excludedPaths", "warning"),
    "ext": ("extensions", "total", "scope"),
    "session set": ("name", "cookieCount", "headerCount", "cookies", "headers", "origin"),
    "session get": ("name", "cookieCount", "headerCount", "cookies", "headers", "origin"),
    "session clear": ("name", "cookieCount", "headerCount", "cookies", "headers", "origin"),
    "session send": (
        "durationMs",
        "hasResponse",
        "persistence",
        "statusCode",
        "headers",
        "body",
    ),
    "session cookies": ("cookies", "total"),
    "diff": (
        "statusMatch",
        "statusA",
        "statusB",
        "lengthA",
        "lengthB",
        "lengthDiff",
        "headerDiffs",
        "bodyDiff",
    ),
    "endpoints": (
        "endpoints",
        "total",
        "bundlesDiscovered",
        "bundlesAttempted",
        "bundlesFetched",
        "bundlesFailed",
        "failures",
    ),
    "history list": ("id", "method", "url", "statusCode"),
    "history get": (
        "id",
        "source",
        "method",
        "url",
        "host",
        "reqHeaders",
        "reqBody",
        "statusCode",
        "resHeaders",
        "resBody",
        "durationMs",
        "timestamp",
    ),
    "history sitemap": ("entries", "total"),
    "history replay": ("original", "replayed"),
    "history clear": ("cleared",),
}

# These commands have a documented, unambiguous single-entry HTTP byte representation.  Every other
# run()-based command is structured, so raw must fail before its callback runs.
_RAW_HTTP_COMMANDS = frozenset({"req", "send", "history get", "history replay"})

# Security checks are target-effecting, so each command needs its exact top-level response catalog;
# a family-wide union would merely move invalid-field detection back after the probes.
_COMMAND_FIELDS.update(
    {
        "check auth": (
            "results",
            "totalScanned",
            "vulnerableCount",
            "inconclusiveCount",
            "verdict",
        ),
        "check idor": (
            "baseline",
            "results",
            "ignoredOwnValues",
            "vulnerableCount",
            "inconclusiveCount",
            "verdict",
        ),
        "check headers": (
            "baseline",
            "results",
            "anomalousCount",
            "vulnerableCount",
            "inconclusiveCount",
            "verdict",
        ),
        "check cors": ("results", "vulnerableCount", "inconclusiveCount", "verdict"),
        "check endpoints": (
            "scanned",
            "findings",
            "durationMs",
            "source",
            "sourceCounts",
            "errors",
            "inconclusiveCount",
            "verdict",
        ),
    }
)


def _command_name(command_path: str) -> str:
    """Drop the executable name from Click's command path."""
    return " ".join(command_path.split()[1:])


def validate_output_options(command_path: str, fmt: str, fields: list[str] | None) -> None:
    """Validate format/field compatibility without observing a command response."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r} (want one of {FORMATS})")
    if fields is not None and fmt == "raw":
        raise ValueError("--fields is not valid with --format raw")
    if fields is not None and fmt == "quiet":
        raise ValueError("--fields is not valid with --format quiet")

    command = _command_name(command_path)
    if fmt == "raw" and command not in _RAW_HTTP_COMMANDS:
        raise ValueError(
            "raw requires an unstructured value, not a dict or list; "
            "use --format json for structured records"
        )

    if fields is None or (len(fields) == 1 and fields[0].lower() in {"all", "*"}):
        return
    if command == "collab new":
        wrapper = {"payloads"}
        leaves = {field.lower() for field in _COLLAB_PAYLOAD_FIELDS}
        requested = {field.lower() for field in fields}
        if requested & wrapper and requested & leaves:
            raise ValueError("collaborator payload wrapper and record fields cannot be mixed")
    if command == "collab poll":
        wrapper = {"found", "interactions", "queriedpayloadid"}
        leaves = {field.lower() for field in _COLLAB_INTERACTION_FIELDS}
        requested = {field.lower() for field in fields}
        if requested & wrapper and requested & leaves:
            raise ValueError("collaborator poll wrapper and interaction fields cannot be mixed")
    catalog = _COMMAND_FIELDS.get(command)
    if catalog is None:
        # A new command must declare its output contract before it can safely honor --fields.  Failing
        # closed here prevents a future effectful command from reintroducing post-effect validation.
        raise ValueError(f"--fields is unavailable: no output contract for command {command!r}")
    canonical = {field.lower(): field for field in catalog}
    unknown = [field for field in fields if field.lower() not in canonical]
    if unknown:
        valid = ", ".join(sorted(catalog)) or "(none)"
        raise ValueError(f"unknown field(s): {', '.join(unknown)}; valid: {valid}")


# Keys tried, in order, when --quiet must pick the one essential value of a record.
# "verdict" leads so that bp check * --format quiet emits 'vulnerable'/'clean' first
# (OUTPUT.md §1.5 R-ESSENTIAL — bp scan * quiet value).
_ESSENTIAL = ("verdict", "status", "statusCode", "id", "attackId", "payload", "result", "value")


def _collaborator_records(data: Any, command: str) -> Any:
    if not isinstance(data, dict):
        return data
    key = "payloads" if command == "collab new" else "interactions"
    records = data.get(key)
    if not isinstance(records, list):
        return data
    fields = _COLLAB_PAYLOAD_FIELDS if command == "collab new" else _COLLAB_INTERACTION_FIELDS
    normalized: list[Any] = []
    for record in records:
        if not isinstance(record, dict):
            normalized.append(record)
            continue
        item = dict(record)
        if command == "collab poll" and "interactionId" not in item and "id" in item:
            item["interactionId"] = item["id"]
        for field in fields:
            item.setdefault(field, None)
        normalized.append(item)
    return normalized


def _field_data(data: Any, command: str, fields: list[str] | None) -> Any:
    if not fields or (len(fields) == 1 and fields[0].lower() in {"all", "*"}):
        return data
    requested = {field.lower() for field in fields}
    if command == "collab new" and requested <= {field.lower() for field in _COLLAB_PAYLOAD_FIELDS}:
        return _collaborator_records(data, command)
    if command == "collab poll" and requested <= {
        field.lower() for field in _COLLAB_INTERACTION_FIELDS
    }:
        return _collaborator_records(data, command)
    return data


def _body_bytes(record: dict[str, Any], text_key: str, base64_key: str) -> bytes:
    encoded = record.get(base64_key)
    if encoded is not None:
        if not isinstance(encoded, str):
            raise TypeError(f"{base64_key} must be text or null")
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError(f"{base64_key} is not valid base64") from None
    body = record.get(text_key)
    if body is None:
        return b""
    if not isinstance(body, str):
        raise TypeError(f"{text_key} must be text or null")
    return body.encode("utf-8")


def _body_is_present(record: dict[str, Any], text_key: str, base64_key: str) -> bool:
    return record.get(base64_key) is not None or record.get(text_key) is not None


def _header_lines(
    headers: Any,
    *,
    body_present: bool,
    body_length: int,
) -> tuple[list[bytes], set[str]]:
    if headers is None:
        headers = []
    if not isinstance(headers, list):
        raise TypeError("HTTP headers must be a list")
    parsed: list[tuple[str, str]] = []
    trailer_names: set[str] = set()
    for header in headers:
        if not isinstance(header, dict):
            raise TypeError("each HTTP header must be an object")
        name = header.get("name")
        value = header.get("value")
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("HTTP header names and values must be text")
        if any(character in name + value for character in "\r\n\0"):
            raise ValueError("HTTP header contains CR, LF, or NUL")
        parsed.append((name, value))
        if name.lower() == "trailer":
            trailer_names.update(item.strip().lower() for item in value.split(",") if item.strip())

    lines: list[bytes] = []
    names: set[str] = set()
    has_transfer_encoding = any(name.lower() == "transfer-encoding" for name, _ in parsed)
    captured_lengths = [(name, value) for name, value in parsed if name.lower() == "content-length"]
    framing_names = {"content-length", "transfer-encoding", "trailer", *trailer_names}
    for name, value in parsed:
        lowered = name.lower()
        if lowered in framing_names:
            continue
        lines.append(f"{name}: {value}".encode("utf-8"))
        names.add(lowered)

    if has_transfer_encoding:
        selected_lengths = [("Content-Length", str(body_length))]
    elif body_present:
        matching_length = len(captured_lengths) == 1 and captured_lengths[0][1].strip() == str(
            body_length
        )
        selected_lengths = (
            captured_lengths if matching_length else [("Content-Length", str(body_length))]
        )
    else:
        # A bodyless HEAD/304 response may truthfully carry the length of the
        # selected representation. Preserve that metadata when no conversion is needed.
        selected_lengths = captured_lengths
    for name, value in selected_lengths:
        lines.append(f"{name}: {value}".encode("utf-8"))
        names.add("content-length")
    return lines, names


def _raw_request(record: dict[str, Any]) -> bytes:
    method = record.get("method")
    url = record.get("url")
    if not isinstance(method, str) or not isinstance(url, str):
        raise TypeError("raw HTTP request requires text method and url")
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise ValueError("raw HTTP request requires an absolute URL")
    target = parts.path or "/"
    before_fragment = url.split("#", 1)[0]
    if "?" in before_fragment:
        target = f"{target}?{parts.query}"
    lines = [f"{method} {target} HTTP/1.1".encode("utf-8")]
    body = _body_bytes(record, "body", "bodyBase64")
    headers, names = _header_lines(
        record.get("headers"),
        body_present=_body_is_present(record, "body", "bodyBase64"),
        body_length=len(body),
    )
    if "host" not in names:
        lines.append(f"Host: {parts.netloc}".encode("utf-8"))
    lines.extend(headers)
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


def _raw_response(record: dict[str, Any]) -> bytes:
    status = record.get("statusCode")
    if not isinstance(status, int) or isinstance(status, bool):
        raise TypeError("raw HTTP response requires an integer statusCode")
    try:
        phrase = HTTPStatus(status).phrase
    except ValueError:
        phrase = ""
    status_line = f"HTTP/1.1 {status}{f' {phrase}' if phrase else ''}".encode("ascii")
    body = _body_bytes(record, "body", "bodyBase64")
    headers, _names = _header_lines(
        record.get("headers"),
        body_present=_body_is_present(record, "body", "bodyBase64"),
        body_length=len(body),
    )
    return b"\r\n".join([status_line, *headers]) + b"\r\n\r\n" + body


def _history_http(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    request = {
        "method": record.get("method"),
        "url": record.get("url"),
        "headers": record.get("reqHeaders"),
        "body": record.get("reqBody"),
    }
    response: dict[str, Any] | None = None
    if record.get("statusCode") is not None:
        response = {
            "statusCode": record.get("statusCode"),
            "headers": record.get("resHeaders"),
            "body": record.get("resBody"),
        }
    return request, response


def _join_http(request: dict[str, Any] | None, response: dict[str, Any] | None) -> bytes:
    parts: list[bytes] = []
    if request is not None:
        parts.append(_raw_request(request))
    if response is not None:
        parts.append(_raw_response(response))
    return b"\r\n\x1e\r\n".join(parts)


def _render_raw_http(data: Any, command: str) -> bytes:
    if not isinstance(data, dict):
        raise TypeError("raw HTTP output requires one record")
    if command == "send":
        response = data.get("response")
        if not isinstance(response, dict):
            raise TypeError("send result has no response record")
        return _raw_response(response)
    if command == "req":
        request = data.get("request")
        response = data.get("response")
        if not isinstance(request, dict):
            raise TypeError("proxy entry has no request record")
        if response is not None and not isinstance(response, dict):
            raise TypeError("proxy entry response must be an object or null")
        return _join_http(request, response)
    if command == "history replay":
        data = data.get("replayed")
        if not isinstance(data, dict):
            raise TypeError("history replay result has no replayed record")
    request, response = _history_http(data)
    return _join_http(request, response)


@overload
def render(
    data: Any,
    fmt: Literal["raw"],
    *,
    fields: list[str] | None = None,
    command_path: str,
) -> bytes: ...


@overload
def render(
    data: Any,
    fmt: Literal["json", "table", "quiet"] = "table",
    *,
    fields: list[str] | None = None,
    command_path: str | None = None,
) -> str: ...


@overload
def render(
    data: Any,
    fmt: str,
    *,
    fields: list[str] | None = None,
    command_path: None = None,
) -> str: ...


@overload
def render(
    data: Any,
    fmt: str,
    *,
    fields: list[str] | None = None,
    command_path: str | None = None,
) -> str | bytes: ...


def render(
    data: Any,
    fmt: str = "table",
    *,
    fields: list[str] | None = None,
    command_path: str | None = None,
) -> str | bytes:
    command = _command_name(command_path) if command_path else ""
    data = _field_data(data, command, fields)
    if fmt == "raw" and command in _RAW_HTTP_COMMANDS:
        if fields is not None:
            raise ValueError("--fields is not valid with --format raw")
        return _render_raw_http(data, command)
    if fmt == "raw" and isinstance(data, list):
        # Preserve the established list diagnostic while refusing every
        # structured value (dict is handled below) instead of JSON-masquerading.
        raise ValueError(
            "raw requires a single record and an unstructured value; "
            "use --format json for structured records"
        )
    if fmt == "raw" and fields is not None:
        raise ValueError("--fields is not valid with --format raw")
    if fmt == "quiet" and fields is not None:
        raise ValueError("--fields is not valid with --format quiet")
    if fmt == "raw" and isinstance(data, dict):
        raise ValueError(
            "raw requires an unstructured value, not a dict or list; "
            "use --format json for structured records"
        )
    if fields is not None and len(fields) == 1 and fields[0].strip().lower() in {"all", "*"}:
        fields = None
    if fmt == "json":
        return _render_json(data, fields)
    if fmt == "table":
        return _render_table(data, fields)
    if fmt == "quiet":
        return _render_quiet(data, command)
    if fmt == "raw":
        return _render_raw(data)
    raise ValueError(f"unknown format {fmt!r} (want one of {FORMATS})")


def _canonical_map(record: dict[str, Any]) -> dict[str, str]:
    """Return a lowercase-key → canonical-key mapping for a single record.

    When the same lowercase key would map to multiple canonical keys (e.g. ``Foo``
    and ``foo`` both present), the first one wins — a degenerate case that should
    not arise in real Burp records.
    """
    result: dict[str, str] = {}
    for k in record:
        lk = k.lower()
        if lk not in result:
            result[lk] = k
    return result


def _resolve_fields(fields: list[str], union_map: dict[str, str]) -> tuple[list[str], list[str]]:
    """Resolve requested field names against a union canonical map.

    Returns (canonical_fields, unknown_fields).
    canonical_fields preserves the requested order, using canonical (actual record)
    key casing.  unknown_fields contains requested names that are absent from the
    union at all.

    OUTPUT.md §2.1 R-FIELDS: "Case-insensitive match, canonical-cased on output."
    """
    canonical: list[str] = []
    unknown: list[str] = []
    for f in fields:
        canon = union_map.get(f.lower())
        if canon is None:
            unknown.append(f)
        else:
            canonical.append(canon)
    return canonical, unknown


def _select(record: dict[str, Any], fields: list[str] | None) -> dict[str, Any]:
    """Select and reorder fields from a single record using case-insensitive matching.

    OUTPUT.md §2.1 R-FIELDS:
    - Case-insensitive match against this record's keys.
    - Unknown (from this record only) → ValueError.
    - Canonical (actual record) key casing used in output.

    Note: for list contexts, use _select_list_rows which performs union-based
    validation instead of per-row validation.
    """
    if fields is None:
        return record
    cmap = _canonical_map(record)
    canonical, unknown = _resolve_fields(fields, cmap)
    if unknown:
        valid = ", ".join(sorted(record)) or "(none)"
        raise ValueError(f"unknown field(s): {', '.join(unknown)}; valid: {valid}")
    return {k: record[k] for k in canonical}


def _select_list_rows(rows: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    """Select fields from a list of rows using union-based validation.

    OUTPUT.md §2.1 R-FIELDS:
    - A field is "unknown" only if it is absent from EVERY row (union check).
    - Rows that lack a requested field get None (blank cell / null JSON value).
    - canonical casing comes from the first row that contains each key.

    This replaces the old per-row _select call which raised when a field was
    absent from ANY row (over-strict, contra spec).
    """
    # An empty result set has no rows to validate --fields against; return empty
    # (exit 0) rather than raising "unknown field" — mirrors the _render_table
    # `if not rows: return ""` guard so json and table agree (OUTPUT.md A1).
    if not rows:
        return []
    # Build union map: lowercase → canonical key (first occurrence wins)
    union_map: dict[str, str] = {}
    for row in rows:
        for k in row:
            lk = k.lower()
            if lk not in union_map:
                union_map[lk] = k

    canonical_fields, unknown = _resolve_fields(fields, union_map)
    if unknown:
        valid = ", ".join(sorted(union_map.values())) or "(none)"
        raise ValueError(f"unknown field(s): {', '.join(unknown)}; valid: {valid}")

    result: list[dict[str, Any]] = []
    for row in rows:
        # Build a lowercase lookup for this row so we can fetch by canonical name
        row_lmap = {k.lower(): v for k, v in row.items()}
        result.append({cf: row_lmap.get(cf.lower()) for cf in canonical_fields})
    return result


def _render_json(data: Any, fields: list[str] | None) -> str:
    if isinstance(data, list):
        if fields is not None:
            dicts = [r for r in data if isinstance(r, dict)]
            # [07] Distinguish genuinely empty input (return empty, exit 0 — round-8
            # parity) from a non-empty list that contains NO dict rows at all.
            # In the latter case --fields cannot be honoured: raise a usage error
            # instead of silently ignoring the flag (OUTPUT.md §2.1 R-FIELDS).
            if data and not dicts:
                raise ValueError(
                    "--fields requires dict records; "
                    "the input list contains no dict rows to select fields from"
                )
            selected = _select_list_rows(dicts, fields)
            # interleave in original order
            it_sel = iter(selected)
            rows: list[Any] = [next(it_sel) if isinstance(r, dict) else r for r in data]
        else:
            rows = data
        return "\n".join(_json.dumps(r, separators=(",", ":")) for r in rows)
    if isinstance(data, dict):
        data = _select(data, fields)
    return _json.dumps(data, separators=(",", ":"))


def escape_terminal_controls(text: str) -> str:
    """Render untrusted controls visibly instead of executing them in a terminal.

    Raw output is intentionally exempt: it is an exact byte artifact and must not be
    directed to a terminal. JSON already escapes controls during serialization.
    """
    parts: list[str] = []
    for character in text:
        codepoint = ord(character)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            parts.append(f"\\x{codepoint:02x}")
        elif 0xD800 <= codepoint <= 0xDFFF:
            parts.append(f"\\u{codepoint:04x}")
        else:
            parts.append(character)
    return "".join(parts)


def _cell(value: Any) -> str:
    """Render one table cell: null -> blank, nested dict/list -> compact JSON, else str.

    Avoids leaking Python ``repr`` (``None``, ``{'k': 'v'}``) into the human table view.
    Booleans render as JSON-style ``true``/``false`` (not Python ``True``/``False``).
    Note: ``bool`` is a subclass of ``int`` in Python, so this check must come before
    the generic ``str()`` fallback to prevent ``True`` → ``'True'`` leaking.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return _json.dumps(value, separators=(",", ":"))
    return escape_terminal_controls(str(value))


def _render_table(data: Any, fields: list[str] | None) -> str:
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
        if not rows:
            return ""

        # [08-NEW] validate fields against the UNION of all row keys (spec-correct)
        # and render None for rows that lack a field (no error for partial absence).
        if fields is not None:
            selected_rows = _select_list_rows(rows, fields)
            # cols uses canonical keys from the selected rows
            cols = list(selected_rows[0].keys()) if selected_rows else list(fields)
            rows = selected_rows
        else:
            # [22] union of keys across all rows (first-appearance order)
            cols = list(dict.fromkeys(k for r in rows for k in r))

        # Width: computed from the uppercase header label and cell values
        widths = {c: max(len(c.upper()), *(len(_cell(r.get(c))) for r in rows)) for c in cols}
        # [06-NEW] Header uses UPPERCASE field names (OUTPUT.md §1.2 F-TABLE)
        header = "  ".join(c.upper().ljust(widths[c]) for c in cols)
        body = "\n".join("  ".join(_cell(r.get(c)).ljust(widths[c]) for c in cols) for r in rows)
        return f"{header}\n{body}"

    if isinstance(data, dict):
        record = _select(data, fields)
        width = max((len(k) for k in record), default=0)
        # [06-NEW] Key column is UPPERCASE (OUTPUT.md §1.2 F-TABLE)
        return "\n".join(f"{k.upper().ljust(width)}  {_cell(v)}" for k, v in record.items())
    return str(data)


def _render_quiet(data: Any, command: str = "") -> str:
    if command and command not in _QUIET_ESSENTIAL_COMMANDS:
        return ""
    if command in {"proxy", "req", "history list", "history get", "log", "tag"}:
        records = data if isinstance(data, list) else [data]
        return "\n".join(
            _scalar_text(record.get("id")) for record in records if isinstance(record, dict)
        )
    if command == "scope check" and isinstance(data, dict):
        in_scope = data.get("inScope")
        if isinstance(in_scope, bool):
            return "in-scope" if in_scope else "out-of-scope"
    if command == "collab new":
        records = _collaborator_records(data, command)
        if isinstance(records, list):
            return "\n".join(
                _scalar_text(record.get("payload"))
                for record in records
                if isinstance(record, dict)
            )
    if command == "collab poll":
        records = _collaborator_records(data, command)
        if isinstance(records, list):
            if not records:
                return "none"
            return "\n".join(
                _scalar_text(record.get("interactionId"))
                for record in records
                if isinstance(record, dict)
            )
    if command == "scan issues" and isinstance(data, dict):
        issues = data.get("issues")
        if issues is None:
            return ""
        if isinstance(issues, list):
            return "\n".join(
                _scalar_text(issue.get("severity")) for issue in issues if isinstance(issue, dict)
            )
    if command == "send" and isinstance(data, dict):
        response = data.get("response")
        if isinstance(response, dict):
            return _scalar_text(response.get("statusCode"))
    if isinstance(data, list):
        joined = "\n".join(_essential(r) for r in data)
        # [06] when every essential value is empty the join produces only '\n'
        # characters; suppress entirely so the empty-output guard in cliutil.run
        # can silence stdout (OUTPUT.md §4.4).  Interior blank lines between
        # real values (e.g. 'a\n\nb') are preserved because strip('\n') is non-empty.
        return "" if joined.strip("\n") == "" else joined
    return _essential(data)


def _scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return _json.dumps(value, separators=(",", ":"))
    return escape_terminal_controls(str(value))


def _essential(record: Any) -> str:
    if record is None:
        return ""
    if isinstance(record, dict):
        for key in _ESSENTIAL:
            if key in record:
                return _scalar_text(record[key])
        first = next(iter(record.values()), None)
        return _scalar_text(first)
    return _scalar_text(record)


def _render_raw(data: Any) -> str:
    if isinstance(data, (bytes, bytearray)):
        return data.decode("utf-8", "replace")
    if isinstance(data, str):
        return data
    return _json.dumps(data, separators=(",", ":"))
