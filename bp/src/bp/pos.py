"""A1 — resolve a ``--pos`` selector to a byte-offset Position in a raw HTTP request.

See ``docs/ALGORITHMS.md`` §A1. The byte range ``raw[pos.start:pos.end]`` is the value to fuzz.
Selectors: ``header:NAME`` ``cookie:NAME`` ``body:FIELD`` ``query:NAME`` ``path:INDEX``
``offset:START-END``. Offsets are byte offsets (HTTP/1.1, CRLF; LF-only tolerated).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from bp.rawhttp import body_start, content_type, iter_headers, request_target_span


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


Resolver = Callable[[bytes, str, str], Position]


def resolve_pos(raw: bytes, selector: str) -> Position:
    """Resolve ``selector`` against ``raw`` → Position. Raises PosError on failure."""
    kind, sep, arg = selector.partition(":")
    if not sep:
        raise PosError("BAD_SELECTOR", f"expected kind:arg, got {selector!r}")
    resolver = _RESOLVERS.get(kind)
    if resolver is None:
        raise PosError("BAD_SELECTOR", f"unknown selector kind {kind!r}")
    return resolver(raw, arg, selector)


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
    for name, v_start, v_end in iter_headers(raw):
        if name.lower() == want:
            return Position(v_start, v_end, selector)
    raise PosError("POS_NOT_FOUND", f"header {arg!r} not found")


def _resolve_cookie(raw: bytes, arg: str, selector: str) -> Position:
    key = arg.encode()
    for name, v_start, v_end in iter_headers(raw):
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


def _scan_kv(buf: bytes, key: bytes, start: int) -> tuple[int, int] | None:
    """Scan ``&``-separated ``key=value`` pairs in ``buf`` from offset ``start``.

    Returns the ``(value_start, value_end)`` byte span of the matching value relative to
    ``buf``, or None if ``key`` is absent. Shared by the query-string and form-body resolvers.
    """
    pos = start
    while pos <= len(buf):
        amp = buf.find(b"&", pos)
        seg_end = amp if amp != -1 else len(buf)
        seg = buf[pos:seg_end]
        eq = seg.find(b"=")
        if eq != -1 and seg[:eq] == key:
            return pos + eq + 1, seg_end
        if amp == -1:
            break
        pos = amp + 1
    return None


def _resolve_query(raw: bytes, arg: str, selector: str) -> Position:
    t_start, t_end = request_target_span(raw)
    target = raw[t_start:t_end]
    q = target.find(b"?")
    if q == -1:
        raise PosError("POS_NOT_FOUND", "no query string")
    span = _scan_kv(target, arg.encode(), q + 1)
    if span is None:
        raise PosError("POS_NOT_FOUND", f"query param {arg!r} not found")
    return Position(t_start + span[0], t_start + span[1], selector)


def _resolve_path(raw: bytes, arg: str, selector: str) -> Position:
    try:
        idx = int(arg)
    except ValueError:
        raise PosError("BAD_SELECTOR", f"path index must be int, got {arg!r}") from None
    t_start, t_end = request_target_span(raw)
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
    ct = content_type(raw)
    b0 = body_start(raw)
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
    span = _scan_kv(body, field.encode(), 0)
    if span is None:
        raise PosError("POS_NOT_FOUND", f"form field {field!r} not found")
    return Position(b0 + span[0], b0 + span[1], selector)


_RESOLVERS: dict[str, Resolver] = {
    "offset": _resolve_offset,
    "header": _resolve_header,
    "cookie": _resolve_cookie,
    "query": _resolve_query,
    "path": _resolve_path,
    "body": _resolve_body,
}
