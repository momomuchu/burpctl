"""A1 — resolve a ``--pos`` selector to a byte-offset Position in a raw HTTP request.

See ``docs/ALGORITHMS.md`` §A1. The byte range ``raw[pos.start:pos.end]`` is the value to fuzz.
Selectors: ``header:NAME`` ``cookie:NAME`` ``body:FIELD`` ``query:NAME`` ``path:INDEX``
``offset:START-END``. Offsets are byte offsets (HTTP/1.1, CRLF; LF-only tolerated).
"""

from __future__ import annotations

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
    if a < 0 or b < 0 or a >= b:
        raise PosError("BAD_SELECTOR", f"offset {a}-{b} is not a valid range")
    if b > len(raw):
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
    seen_cookie = False
    for name, v_start, v_end in iter_headers(raw):
        if name.lower() != b"cookie":
            continue
        seen_cookie = True
        val = raw[v_start:v_end]
        pos = 0
        while pos <= len(val):
            semi = val.find(b";", pos)
            seg_end = semi if semi != -1 else len(val)
            seg = val[pos:seg_end]
            lead = 0
            while lead < len(seg) and seg[lead] in (0x20, 0x09):
                lead += 1
            eq = seg.find(b"=")
            if eq != -1 and seg[lead:eq] == key:
                return Position(v_start + pos + eq + 1, v_start + seg_end, selector)
            if semi == -1:
                break
            pos = semi + 1
        # key not in this Cookie header — keep scanning any subsequent Cookie headers
    if seen_cookie:
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
    # Strip the fragment (everything from the first '#') — query string ends at '#'.
    frag = target.find(b"#", q + 1)
    qs_end = frag if frag != -1 else len(target)
    span = _scan_kv(target[:qs_end], arg.encode(), q + 1)
    if span is None:
        raise PosError("POS_NOT_FOUND", f"query param {arg!r} not found")
    return Position(t_start + span[0], t_start + span[1], selector)


def _resolve_path(raw: bytes, arg: str, selector: str) -> Position:
    try:
        idx = int(arg)
    except ValueError:
        raise PosError("BAD_SELECTOR", f"path index must be int, got {arg!r}") from None
    if idx <= 0:
        raise PosError("BAD_SELECTOR", f"path index must be >= 1, got {idx}")
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
        return _resolve_json_or_reclassify(body, b0, arg, selector)
    if b"x-www-form-urlencoded" in ct:
        return _resolve_form(body, b0, arg, selector)
    if not ct:
        # JSON-first: if body (stripped) starts with '{' or '[', treat as JSON.
        stripped = body.lstrip()
        if stripped and stripped[0] in (0x7B, 0x5B):  # '{' or '['
            return _resolve_json_or_reclassify(body, b0, arg, selector)
        if b"=" in body:
            return _resolve_form(body, b0, arg, selector)
    raise PosError("UNSUPPORTED_BODY", f"content-type {ct!r} unsupported for body:{arg}")


def _resolve_json_or_reclassify(body: bytes, b0: int, arg: str, selector: str) -> Position:
    """Call ``_resolve_json``; if the body is a JSON array (not an object), re-raise
    the POS_NOT_FOUND as UNSUPPORTED_BODY so callers get the right diagnostic.

    Only reclassifies as UNSUPPORTED_BODY with an "array" message when the body
    actually starts with ``[`` (after stripping whitespace).  Empty bodies, scalars,
    and other non-object shapes propagate the original POS_NOT_FOUND unchanged.
    """
    try:
        return _resolve_json(body, b0, arg, selector)
    except PosError as exc:
        if exc.code == "POS_NOT_FOUND" and "body is not a JSON object" in str(exc):
            stripped = body.lstrip()
            if stripped and stripped[0:1] == b"[":
                raise PosError(
                    "UNSUPPORTED_BODY",
                    f"body:{arg} is not supported on a top-level JSON array",
                ) from None
            # Empty body, scalar, or other non-object/non-array shape:
            # propagate the original POS_NOT_FOUND so the caller gets an accurate error.
        raise


def _unescape_json_string(raw_key: bytes) -> bytes:
    """Return the logical (decoded) bytes for a JSON string key (excluding surrounding quotes).

    Handles the standard JSON escape sequences: \\\" \\\\ \\/ \\b \\f \\n \\r \\t and \\uXXXX.
    Unknown escapes are passed through as-is (lenient).
    """
    out = bytearray()
    i = 0
    n = len(raw_key)
    while i < n:
        c = raw_key[i]
        if c != 0x5C:  # not backslash
            out.append(c)
            i += 1
            continue
        # backslash escape
        i += 1
        if i >= n:
            out.append(0x5C)
            break
        esc = raw_key[i]
        i += 1
        if esc == 0x22:    # \"
            out.append(0x22)
        elif esc == 0x5C:  # \\
            out.append(0x5C)
        elif esc == 0x2F:  # \/
            out.append(0x2F)
        elif esc == 0x62:  # \b
            out.append(0x08)
        elif esc == 0x66:  # \f
            out.append(0x0C)
        elif esc == 0x6E:  # \n
            out.append(0x0A)
        elif esc == 0x72:  # \r
            out.append(0x0D)
        elif esc == 0x74:  # \t
            out.append(0x09)
        elif esc == 0x75:  # \uXXXX
            hex_part = raw_key[i : i + 4]
            i += 4
            try:
                codepoint = int(hex_part, 16)
                out.extend(chr(codepoint).encode("utf-8"))
            except (ValueError, UnicodeEncodeError):
                out.append(0x5C)
                out.append(0x75)
                out.extend(hex_part)
        else:
            # Unknown escape — pass through both bytes
            out.append(0x5C)
            out.append(esc)
    return bytes(out)


def _resolve_json(body: bytes, b0: int, field: str, selector: str) -> Position:
    """Resolve ``field`` to its value span at the TOP LEVEL of the JSON object in ``body``.

    Scans character by character with bracket/brace depth tracking so that:
    - Keys inside nested objects/arrays are skipped ([01]).
    - Array and object values are captured in full by matching their open/close
      delimiter using a depth counter that respects string literals ([00]).
    - Primitive values use terminator scanning (unchanged behaviour).
    - JSON key escapes are decoded before comparison so logical names match [00].
    """
    n = len(body)
    i = 0

    # Skip leading whitespace and the opening '{' of the top-level object.
    while i < n and body[i] in (0x20, 0x09, 0x0D, 0x0A):
        i += 1
    if i >= n or body[i] != 0x7B:  # must start with '{'
        raise PosError("POS_NOT_FOUND", f'json key "{field}" not found (body is not a JSON object)')
    i += 1  # consume '{'

    target = field.encode("utf-8")

    # Iterate over top-level key-value pairs.
    while i < n:
        # Skip whitespace and commas between pairs.
        while i < n and body[i] in (0x20, 0x09, 0x0D, 0x0A, 0x2C):
            i += 1
        if i >= n:
            break
        if body[i] == 0x7D:  # closing '}' of the top-level object
            break

        # Expect a quoted key.
        if body[i] != 0x22:  # '"'
            raise PosError("POS_NOT_FOUND", f'json key "{field}" not found (unexpected byte at key position)')
        i += 1  # consume opening '"'
        key_start = i
        while i < n:
            c = body[i]
            if c == 0x5C:  # backslash escape
                i += 2
                continue
            if c == 0x22:  # closing '"'
                break
            i += 1
        key_bytes = body[key_start:i]
        i += 1  # consume closing '"'

        # Skip whitespace then ':'
        while i < n and body[i] in (0x20, 0x09, 0x0D, 0x0A):
            i += 1
        if i >= n or body[i] != 0x3A:  # ':'
            raise PosError("POS_NOT_FOUND", f'json key "{field}" not found (missing colon)')
        i += 1  # consume ':'

        # Skip whitespace before value.
        while i < n and body[i] in (0x20, 0x09, 0x0D, 0x0A):
            i += 1

        v_start = i  # value starts here

        if _unescape_json_string(key_bytes) == target:
            # Found the top-level key — now locate the full value extent.
            if i >= n:
                raise PosError("POS_NOT_FOUND", f'json key "{field}" has no value')
            first = body[i]
            if first == 0x22:  # '"' → string value
                i += 1
                while i < n:
                    c = body[i]
                    if c == 0x5C:
                        i += 2
                        continue
                    if c == 0x22:
                        return Position(b0 + v_start + 1, b0 + i, selector)
                    i += 1
                raise PosError("POS_NOT_FOUND", "unterminated json string")
            if first in (0x5B, 0x7B):  # '[' or '{' → array/object value
                # Use depth counting to find the matching close delimiter.
                open_ch = first
                close_ch = 0x5D if open_ch == 0x5B else 0x7D
                depth = 0
                while i < n:
                    c = body[i]
                    if c == 0x22:  # string — skip its contents
                        i += 1
                        while i < n:
                            sc = body[i]
                            if sc == 0x5C:
                                i += 2
                                continue
                            if sc == 0x22:
                                break
                            i += 1
                    elif c == open_ch:
                        depth += 1
                    elif c == close_ch:
                        depth -= 1
                        if depth == 0:
                            return Position(b0 + v_start, b0 + i + 1, selector)
                    i += 1
                raise PosError("POS_NOT_FOUND", f'json key "{field}" value is unterminated')
            # Primitive literal (number, true, false, null).
            terminators = (0x2C, 0x7D, 0x5D, 0x20, 0x0D, 0x0A, 0x09)
            while i < n and body[i] not in terminators:
                i += 1
            return Position(b0 + v_start, b0 + i, selector)

        else:
            # Not the target key — skip the value entirely (depth-aware) to stay at depth 0.
            if i >= n:
                break
            first = body[i]
            if first == 0x22:  # string
                i += 1
                while i < n:
                    c = body[i]
                    if c == 0x5C:
                        i += 2
                        continue
                    if c == 0x22:
                        i += 1
                        break
                    i += 1
            elif first in (0x5B, 0x7B):  # array or object
                open_ch = first
                close_ch = 0x5D if open_ch == 0x5B else 0x7D
                depth = 0
                while i < n:
                    c = body[i]
                    if c == 0x22:
                        i += 1
                        while i < n:
                            sc = body[i]
                            if sc == 0x5C:
                                i += 2
                                continue
                            if sc == 0x22:
                                break
                            i += 1
                    elif c == open_ch:
                        depth += 1
                    elif c == close_ch:
                        depth -= 1
                        if depth == 0:
                            i += 1
                            break
                    i += 1
            else:
                # Primitive literal
                terminators = (0x2C, 0x7D, 0x5D, 0x20, 0x0D, 0x0A, 0x09)
                while i < n and body[i] not in terminators:
                    i += 1

    raise PosError("POS_NOT_FOUND", f'json key "{field}" not found')


def _resolve_form(body: bytes, b0: int, field: str, selector: str) -> Position:
    # Strip leading whitespace before key scanning (mirrors the JSON branch in _resolve_body).
    # The stripped byte count is added back to all offsets so Position values remain
    # relative to the original raw request, not to the stripped body.
    stripped = body.lstrip()
    lead = len(body) - len(stripped)
    span = _scan_kv(stripped, field.encode(), 0)
    if span is None:
        raise PosError("POS_NOT_FOUND", f"form field {field!r} not found")
    return Position(b0 + lead + span[0], b0 + lead + span[1], selector)


_RESOLVERS: dict[str, Resolver] = {
    "offset": _resolve_offset,
    "header": _resolve_header,
    "cookie": _resolve_cookie,
    "query": _resolve_query,
    "path": _resolve_path,
    "body": _resolve_body,
}
