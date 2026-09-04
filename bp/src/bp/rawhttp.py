"""Raw HTTP/1.1 request parsing helpers (byte-offset based).

The low-level offset helpers remain lenient for byte-splicing callers.  ``parse_request`` is the
strict grammar boundary used before a request is resolved or crosses the structured REST bridge.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

# RFC 9110 ``tchar``.  Header names and methods are deliberately ASCII-only.
_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


@dataclass(frozen=True)
class ParsedHeader:
    """A validated header and its byte spans in the original request."""

    name: bytes
    name_start: int
    name_end: int
    value_start: int
    value_end: int
    line_start: int
    line_end: int


@dataclass(frozen=True)
class ParsedRequest:
    """Validated HTTP/1.1 request grammar and byte coordinates."""

    method: bytes
    method_start: int
    method_end: int
    target: bytes
    target_start: int
    target_end: int
    newline: bytes
    headers: tuple[ParsedHeader, ...]
    body_start: int


def line_end(raw: bytes, start: int, limit: int) -> tuple[int, int]:
    """Return (index_of_line_terminator, terminator_len) for the line at ``start``."""
    i = raw.find(b"\r\n", start, limit)
    if i != -1:
        return i, 2
    i = raw.find(b"\n", start, limit)
    if i != -1:
        return i, 1
    return limit, 0


def parse_request(raw: bytes) -> ParsedRequest:
    """Validate and index one HTTP/1.1 request.

    CRLF and LF-only messages are accepted, but the request line, every header line, and the blank
    separator must all use one convention.  Framing semantics are checked by ``wire`` because the
    low-level position resolver only needs unambiguous grammar and offsets.
    """
    if not isinstance(raw, bytes):
        raise TypeError("raw request must be bytes")

    first_lf = raw.find(b"\n")
    if first_lf == -1:
        raise ValueError("HTTP request has no request-line terminator")
    newline = b"\r\n" if first_lf > 0 and raw[first_lf - 1] == 0x0D else b"\n"
    separator = newline + newline
    separator_at = raw.find(separator)
    if separator_at == -1:
        raise ValueError("HTTP request has no matching header/body separator")
    body_at = separator_at + len(separator)

    framed_head = raw[:body_at]
    if b"\x00" in framed_head:
        raise ValueError("NUL is not allowed in an HTTP request line or header")
    if newline == b"\r\n":
        residue = framed_head.replace(b"\r\n", b"")
        if b"\r" in residue or b"\n" in residue:
            raise ValueError("mixed or malformed HTTP line endings")
    elif b"\r" in framed_head:
        raise ValueError("mixed or malformed HTTP line endings")

    lines = raw[:separator_at].split(newline)
    if not lines or not lines[0]:
        raise ValueError("malformed request line")
    request_line = lines[0]
    tokens = request_line.split(b" ")
    if len(tokens) != 3 or any(not token for token in tokens):
        raise ValueError("malformed request line (expected METHOD SP target SP HTTP/1.1)")
    method, target, version = tokens
    if any(byte not in _TCHAR for byte in method):
        raise ValueError("malformed HTTP method")
    if version != b"HTTP/1.1":
        raise ValueError("structured REST bridge supports only HTTP/1.1 requests")
    if any(byte <= 0x20 or byte == 0x7F for byte in target):
        raise ValueError("request target contains whitespace or a control byte")

    method_start = 0
    method_end = len(method)
    target_start = method_end + 1
    target_end = target_start + len(target)

    headers: list[ParsedHeader] = []
    cursor = len(request_line) + len(newline)
    for line in lines[1:]:
        line_start = cursor
        line_end_at = line_start + len(line)
        cursor = line_end_at + len(newline)
        if not line:
            raise ValueError("ambiguous empty line inside HTTP header block")
        if line[0] in (0x20, 0x09):
            raise ValueError("obsolete folded HTTP headers are not supported")
        colon = line.find(b":")
        if colon <= 0:
            if colon == 0:
                raise ValueError("HTTP pseudo-headers are not supported")
            raise ValueError("malformed HTTP header (missing colon)")
        name = line[:colon]
        if any(byte not in _TCHAR for byte in name):
            raise ValueError("malformed HTTP header name")
        raw_value = line[colon + 1 :]
        if any((byte < 0x20 and byte != 0x09) or byte == 0x7F for byte in raw_value):
            raise ValueError("HTTP header value contains a control byte")
        left = 0
        while left < len(raw_value) and raw_value[left] in (0x20, 0x09):
            left += 1
        right = len(raw_value)
        while right > left and raw_value[right - 1] in (0x20, 0x09):
            right -= 1
        name_start = line_start
        name_end = line_start + colon
        value_start = line_start + colon + 1 + left
        value_end = line_start + colon + 1 + right
        headers.append(
            ParsedHeader(
                name=name,
                name_start=name_start,
                name_end=name_end,
                value_start=value_start,
                value_end=value_end,
                line_start=line_start,
                line_end=line_end_at,
            )
        )

    return ParsedRequest(
        method=method,
        method_start=method_start,
        method_end=method_end,
        target=target,
        target_start=target_start,
        target_end=target_end,
        newline=newline,
        headers=tuple(headers),
        body_start=body_at,
    )


def request_target_span(raw: bytes) -> tuple[int, int]:
    """Byte span of the request-target (2nd token of a valid request line)."""
    parsed = parse_request(raw)
    return parsed.target_start, parsed.target_end


def header_region(raw: bytes) -> tuple[int, int]:
    """Byte span of the header block (after the request line, before the blank line)."""
    end, nl = line_end(raw, 0, len(raw))
    start = end + nl
    b = raw.find(b"\r\n\r\n")
    if b != -1:
        return start, b
    b = raw.find(b"\n\n")
    if b != -1:
        return start, b
    return start, len(raw)


def iter_headers(raw: bytes) -> Iterator[tuple[bytes, int, int]]:
    """Yield (name, value_start, value_end) per header; value is OWS-trimmed.

    This helper intentionally retains its lenient historical behavior.  Security-sensitive callers
    first call ``parse_request`` and then consume its indexed headers.
    """
    start, end = header_region(raw)
    i = start
    while i < end:
        le, nl = line_end(raw, i, end)
        colon = raw.find(b":", i, le)
        if colon != -1:
            name = raw[i:colon]
            v_start = colon + 1
            while v_start < le and raw[v_start] in (0x20, 0x09):
                v_start += 1
            v_end = le
            while v_end > v_start and raw[v_end - 1] in (0x20, 0x09):
                v_end -= 1
            yield name, v_start, v_end
        i = le + nl if nl else end


def body_start(raw: bytes) -> int:
    """Byte offset where the body begins (after the blank line); ``len(raw)`` if none."""
    b = raw.find(b"\r\n\r\n")
    if b != -1:
        return b + 4
    b = raw.find(b"\n\n")
    if b != -1:
        return b + 2
    return len(raw)


def content_type(raw: bytes) -> bytes:
    """Lowercased Content-Type header value, or empty bytes if absent."""
    for name, v_start, v_end in iter_headers(raw):
        if name.lower() == b"content-type":
            return raw[v_start:v_end].lower()
    return b""
