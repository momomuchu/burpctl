"""A1 — resolve a ``--pos`` selector to a byte-offset Position in a raw HTTP request.

See ``docs/ALGORITHMS.md`` §A1. The byte range ``raw[pos.start:pos.end]`` is the value to fuzz.
Selectors: ``header:NAME`` ``cookie:NAME`` ``body:FIELD`` ``query:NAME`` ``path:INDEX``
``offset:START-END``. Offsets are byte offsets (HTTP/1.1, CRLF; LF-only tolerated).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Position:
    """A byte range in a raw request, plus the originating selector name."""

    start: int
    end: int
    name: str


class PosError(Exception):
    """A --pos selector could not be resolved. ``code`` is a stable machine code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def resolve_pos(raw: bytes, selector: str) -> Position:
    """Resolve ``selector`` against ``raw`` → Position. Raises PosError on failure."""
    kind, sep, arg = selector.partition(":")
    if not sep:
        raise PosError("BAD_SELECTOR", f"expected kind:arg, got {selector!r}")
    resolver = _RESOLVERS.get(kind)
    if resolver is None:
        raise PosError("BAD_SELECTOR", f"unknown selector kind {kind!r}")
    return resolver(raw, arg, selector)


# --- structural parsing -------------------------------------------------------


def _line_end(raw: bytes, start: int, limit: int) -> tuple[int, int]:
    """Return (line_end_index, newline_len) for the line at ``start`` within ``limit``."""
    i = raw.find(b"\r\n", start, limit)
    if i != -1:
        return i, 2
    i = raw.find(b"\n", start, limit)
    if i != -1:
        return i, 1
    return limit, 0


def _request_target_span(raw: bytes) -> tuple[int, int]:
    """Byte span of the request-target (2nd token of the request line)."""
    line_end, _ = _line_end(raw, 0, len(raw))
    sp1 = raw.find(b" ", 0, line_end)
    if sp1 == -1:
        raise PosError("BAD_SELECTOR", "malformed request line")
    sp2 = raw.find(b" ", sp1 + 1, line_end)
    if sp2 == -1:
        raise PosError("BAD_SELECTOR", "malformed request line")
    return sp1 + 1, sp2


def _header_region(raw: bytes) -> tuple[int, int]:
    """Byte span covering the header lines (after the request line, before blank line)."""
    line_end, nl = _line_end(raw, 0, len(raw))
    start = line_end + nl
    b = raw.find(b"\r\n\r\n")
    if b != -1:
        return start, b
    b = raw.find(b"\n\n")
    if b != -1:
        return start, b
    return start, len(raw)


def _iter_headers(raw: bytes) -> Iterator[tuple[bytes, int, int]]:
    """Yield (name, value_start, value_end) for each header (value OWS-trimmed)."""
    start, end = _header_region(raw)
    i = start
    while i < end:
        line_end, nl = _line_end(raw, i, end)
        colon = raw.find(b":", i, line_end)
        if colon != -1:
            name = raw[i:colon]
            v_start = colon + 1
            while v_start < line_end and raw[v_start] in (0x20, 0x09):
                v_start += 1
            v_end = line_end
            while v_end > v_start and raw[v_end - 1] in (0x20, 0x09):
                v_end -= 1
            yield name, v_start, v_end
        i = line_end + nl if nl else end


def _body_start(raw: bytes) -> int:
    b = raw.find(b"\r\n\r\n")
    if b != -1:
        return b + 4
    b = raw.find(b"\n\n")
    if b != -1:
        return b + 2
    return len(raw)


def _content_type(raw: bytes) -> bytes:
    for name, v_start, v_end in _iter_headers(raw):
        if name.lower() == b"content-type":
            return raw[v_start:v_end].lower()
    return b""


# --- per-selector resolvers ---------------------------------------------------


def _resolve_offset(raw: bytes, arg: str, selector: str) -> Position:
    a_str, dash, b_str = arg.partition("-")
    if not dash:
        raise PosError("BAD_SELECTOR", f"offset must be A-B, got {arg!r}")
    try:
        a, b = int(a_str), int(b_str)
    except ValueError:
        raise PosError("BAD_SELECTOR", f"offset must be integers, got {arg!r}") from None
    if not 0 <= a < b <= len(raw):
        raise PosError("POS_NOT_FOUND", f"offset {a}-{b} out of range (len {len(raw)})")
    return Position(a, b, selector)


def _resolve_header(raw: bytes, arg: str, selector: str) -> Position:
    want = arg.lower().encode()
    for name, v_start, v_end in _iter_headers(raw):
        if name.lower() == want:
            return Position(v_start, v_end, selector)
    raise PosError("POS_NOT_FOUND", f"header {arg!r} not found")


def _resolve_cookie(raw: bytes, arg: str, selector: str) -> Position:
    key = arg.encode()
    for name, v_start, v_end in _iter_headers(raw):
        if name.lower() != b"cookie":
            continue
        val = raw[v_start:v_end]
        pos = 0
        while pos <= len(val):
            semi = val.find(b";", pos)
            seg_end = semi if semi != -1 else len(val)
            seg = val[pos:seg_end]
            lead = 0
            while lead < len(seg) and seg[lead] == 0x20:
                lead += 1
            eq = seg.find(b"=")
            if eq != -1 and seg[lead:eq] == key:
                return Position(v_start + pos + eq + 1, v_start + seg_end, selector)
            if semi == -1:
                break
            pos = semi + 1
        raise PosError("POS_NOT_FOUND", f"cookie {arg!r} not found")
    raise PosError("POS_NOT_FOUND", "no Cookie header")


def _resolve_query(raw: bytes, arg: str, selector: str) -> Position:
    t_start, t_end = _request_target_span(raw)
    target = raw[t_start:t_end]
    q = target.find(b"?")
    if q == -1:
        raise PosError("POS_NOT_FOUND", "no query string")
    key = arg.encode()
    pos = q + 1
    while pos <= len(target):
        amp = target.find(b"&", pos)
        seg_end = amp if amp != -1 else len(target)
        seg = target[pos:seg_end]
        eq = seg.find(b"=")
        if eq != -1 and seg[:eq] == key:
            return Position(t_start + pos + eq + 1, t_start + seg_end, selector)
        if amp == -1:
            break
        pos = amp + 1
    raise PosError("POS_NOT_FOUND", f"query param {arg!r} not found")


def _resolve_path(raw: bytes, arg: str, selector: str) -> Position:
    try:
        idx = int(arg)
    except ValueError:
        raise PosError("BAD_SELECTOR", f"path index must be int, got {arg!r}") from None
    t_start, t_end = _request_target_span(raw)
    target = raw[t_start:t_end]
    q = target.find(b"?")
    path = target[: q if q != -1 else len(target)]
    seg_no = 0
    i = 0
    n = len(path)
    while i < n:
        if path[i] == 0x2F:  # '/'
            i += 1
            continue
        j = i
        while j < n and path[j] != 0x2F:
            j += 1
        seg_no += 1
        if seg_no == idx:
            return Position(t_start + i, t_start + j, selector)
        i = j
    raise PosError("POS_NOT_FOUND", f"path segment {idx} not found")


def _resolve_body(raw: bytes, arg: str, selector: str) -> Position:
    ct = _content_type(raw)
    b0 = _body_start(raw)
    body = raw[b0:]
    if b"application/json" in ct:
        return _resolve_json(body, b0, arg, selector)
    if b"x-www-form-urlencoded" in ct or (not ct and b"=" in body):
        return _resolve_form(body, b0, arg, selector)
    raise PosError("UNSUPPORTED_BODY", f"content-type {ct!r} unsupported for body:{arg}")


def _resolve_json(body: bytes, b0: int, field: str, selector: str) -> Position:
    pattern = b'"' + re.escape(field).encode() + b'"\\s*:\\s*'
    m = re.search(pattern, body)
    if m is None:
        raise PosError("POS_NOT_FOUND", f'json key "{field}" not found')
    v0 = m.end()
    if v0 < len(body) and body[v0] == 0x22:  # '"' → string value
        end = body.find(b'"', v0 + 1)
        if end == -1:
            raise PosError("POS_NOT_FOUND", "unterminated json string")
        return Position(b0 + v0 + 1, b0 + end, selector)
    j = v0  # literal value
    terminators = (0x2C, 0x7D, 0x5D, 0x20, 0x0D, 0x0A, 0x09)  # , } ] sp cr lf tab
    while j < len(body) and body[j] not in terminators:
        j += 1
    return Position(b0 + v0, b0 + j, selector)


def _resolve_form(body: bytes, b0: int, field: str, selector: str) -> Position:
    key = field.encode()
    pos = 0
    while pos <= len(body):
        amp = body.find(b"&", pos)
        seg_end = amp if amp != -1 else len(body)
        seg = body[pos:seg_end]
        eq = seg.find(b"=")
        if eq != -1 and seg[:eq] == key:
            return Position(b0 + pos + eq + 1, b0 + seg_end, selector)
        if amp == -1:
            break
        pos = amp + 1
    raise PosError("POS_NOT_FOUND", f"form field {field!r} not found")


_RESOLVERS: dict[str, "Resolver"] = {
    "offset": _resolve_offset,
    "header": _resolve_header,
    "cookie": _resolve_cookie,
    "query": _resolve_query,
    "path": _resolve_path,
    "body": _resolve_body,
}

# Defined after the functions so the annotation resolves cleanly under strict mypy.
from collections.abc import Callable  # noqa: E402

Resolver = Callable[[bytes, str, str], Position]
