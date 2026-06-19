"""Output rendering — json | table | raw | quiet (+ --fields). See docs/OUTPUT.md.

``json`` = compact NDJSON (one record per line) for AI-agent consumption; ``table`` = aligned
human view; ``quiet`` = the single most essential value; ``raw`` = the value as-is.
"""

from __future__ import annotations

import json as _json
from typing import Any

FORMATS = ("json", "table", "raw", "quiet")

# Keys tried, in order, when --quiet must pick the one essential value of a record.
_ESSENTIAL = ("status", "statusCode", "id", "attackId", "payload", "result", "value")


def render(data: Any, fmt: str = "table", *, fields: list[str] | None = None) -> str:
    # [23] raw requires a single record (OUTPUT.md §1.3 R-RAW-SINGLE)
    if fmt == "raw" and isinstance(data, list):
        raise ValueError("raw requires a single record; use --format json for multiple records")
    if fmt == "raw" and fields is not None:
        raise ValueError("--fields is not valid with --format raw")
    if fmt == "quiet" and fields is not None:
        raise ValueError("--fields is not valid with --format quiet")
    if fmt == "json":
        return _render_json(data, fields)
    if fmt == "table":
        return _render_table(data, fields)
    if fmt == "quiet":
        return _render_quiet(data)
    if fmt == "raw":
        return _render_raw(data)
    raise ValueError(f"unknown format {fmt!r} (want one of {FORMATS})")


def _select(record: dict[str, Any], fields: list[str] | None) -> dict[str, Any]:
    if fields is None:
        return record
    unknown = [f for f in fields if f not in record]
    if unknown:
        valid = ", ".join(record) or "(none)"
        raise ValueError(f"unknown field(s): {', '.join(unknown)}; valid: {valid}")
    return {k: record[k] for k in fields}


def _render_json(data: Any, fields: list[str] | None) -> str:
    if isinstance(data, list):
        rows = [_select(r, fields) if isinstance(r, dict) else r for r in data]
        return "\n".join(_json.dumps(r, separators=(",", ":")) for r in rows)
    if isinstance(data, dict):
        data = _select(data, fields)
    return _json.dumps(data, separators=(",", ":"))


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
    return str(value)


def _render_table(data: Any, fields: list[str] | None) -> str:
    if isinstance(data, list):
        rows = [r for r in data if isinstance(r, dict)]
        if not rows:
            return ""
        # [19][20] validate fields against every row (match _render_json/_select behaviour)
        if fields is not None:
            for row in rows:
                _select(row, fields)  # raises ValueError on unknown/absent field
            cols = fields
        else:
            # [22] union of keys across all rows (first-appearance order)
            cols = list(dict.fromkeys(k for r in rows for k in r))
        widths = {c: max(len(c), *(len(_cell(r.get(c))) for r in rows)) for c in cols}
        header = "  ".join(c.ljust(widths[c]) for c in cols)
        body = "\n".join("  ".join(_cell(r.get(c)).ljust(widths[c]) for c in cols) for r in rows)
        return f"{header}\n{body}"
    if isinstance(data, dict):
        record = _select(data, fields)
        width = max((len(k) for k in record), default=0)
        return "\n".join(f"{k.ljust(width)}  {_cell(v)}" for k, v in record.items())
    return str(data)


def _render_quiet(data: Any) -> str:
    if isinstance(data, list):
        joined = "\n".join(_essential(r) for r in data)
        # [06] when every essential value is empty the join produces only '\n'
        # characters; suppress entirely so the empty-output guard in cliutil.run
        # can silence stdout (OUTPUT.md §4.4).  Interior blank lines between
        # real values (e.g. 'a\n\nb') are preserved because strip('\n') is non-empty.
        return "" if joined.strip("\n") == "" else joined
    return _essential(data)


def _essential(record: Any) -> str:
    if record is None:
        return ""
    if isinstance(record, dict):
        for key in _ESSENTIAL:
            if key in record:
                v = record[key]
                return "" if v is None else str(v)
        first = next(iter(record.values()), None)
        return "" if first is None else str(first)
    return str(record)


def _render_raw(data: Any) -> str:
    if isinstance(data, (bytes, bytearray)):
        return data.decode("utf-8", "replace")
    if isinstance(data, str):
        return data
    return _json.dumps(data, separators=(",", ":"))
