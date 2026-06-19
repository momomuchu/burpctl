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


def _resolve_fields(
    fields: list[str], union_map: dict[str, str]
) -> tuple[list[str], list[str]]:
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


def _select_list_rows(
    rows: list[dict[str, Any]], fields: list[str]
) -> list[dict[str, Any]]:
    """Select fields from a list of rows using union-based validation.

    OUTPUT.md §2.1 R-FIELDS:
    - A field is "unknown" only if it is absent from EVERY row (union check).
    - Rows that lack a requested field get None (blank cell / null JSON value).
    - canonical casing comes from the first row that contains each key.

    This replaces the old per-row _select call which raised when a field was
    absent from ANY row (over-strict, contra spec).
    """
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
        widths = {
            c: max(len(c.upper()), *(len(_cell(r.get(c))) for r in rows))
            for c in cols
        }
        # [06-NEW] Header uses UPPERCASE field names (OUTPUT.md §1.2 F-TABLE)
        header = "  ".join(c.upper().ljust(widths[c]) for c in cols)
        body = "\n".join(
            "  ".join(_cell(r.get(c)).ljust(widths[c]) for c in cols) for r in rows
        )
        return f"{header}\n{body}"

    if isinstance(data, dict):
        record = _select(data, fields)
        width = max((len(k) for k in record), default=0)
        # [06-NEW] Key column is UPPERCASE (OUTPUT.md §1.2 F-TABLE)
        return "\n".join(
            f"{k.upper().ljust(width)}  {_cell(v)}" for k, v in record.items()
        )
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
