"""Strict bridge between raw HTTP/1.1 bytes and structured ``HttpRequestData``."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

from bp.rawhttp import ParsedRequest, parse_request

_SUPPORTED_SCHEMES = {"http", "https"}
_FORBIDDEN_STRUCTURED = frozenset({"\x00", "\r", "\n"})


@dataclass(frozen=True)
class _BridgeRequest:
    parsed: ParsedRequest
    method: str
    url: str
    headers: list[dict[str, str]]
    body_bytes: bytes | None


def _contains_forbidden(value: str) -> bool:
    return any(character in value for character in _FORBIDDEN_STRUCTURED)


def _url_parts(url: str, *, allow_fragment: bool = False) -> SplitResult:
    if not isinstance(url, str):
        raise TypeError("request URL must be text")
    if _contains_forbidden(url):
        raise ValueError("request URL contains CR, LF, or NUL injection")
    try:
        parts = urlsplit(url)
        # Accessors perform additional bracket and port validation.
        hostname = parts.hostname
        _ = parts.port
    except ValueError as exc:
        raise ValueError(f"malformed request URL: {exc}") from None
    if parts.scheme.lower() not in _SUPPORTED_SCHEMES:
        raise ValueError("structured REST bridge supports only http and https URLs")
    if not parts.netloc or not hostname:
        raise ValueError("request URL must contain an authority")
    if parts.username is not None or parts.password is not None:
        raise ValueError("request URL userinfo is not supported")
    if parts.fragment and not allow_fragment:
        raise ValueError("HTTP request targets cannot contain URL fragments")
    return parts


def _normalise_authority(authority: str, scheme: str) -> tuple[str, int]:
    if not isinstance(authority, str):
        raise TypeError("HTTP authority must be text")
    if not authority or _contains_forbidden(authority):
        raise ValueError("HTTP authority is empty or contains a control byte")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in authority):
        raise ValueError("HTTP authority contains whitespace or a control byte")
    if any(character in authority for character in "/?#,\\"):
        raise ValueError("malformed HTTP authority")
    try:
        parts = urlsplit(f"{scheme}://{authority}")
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"malformed HTTP authority: {exc}") from None
    if not hostname or parts.username is not None or parts.password is not None:
        raise ValueError("malformed HTTP authority")
    default_port = 443 if scheme == "https" else 80
    return hostname.rstrip(".").casefold(), port if port is not None else default_port


def _authorities_match(left: str, right: str, scheme: str) -> bool:
    return _normalise_authority(left, scheme) == _normalise_authority(right, scheme)


def _validate_framing(raw: bytes, parsed: ParsedRequest) -> None:
    body_length = len(raw) - parsed.body_start
    content_lengths: list[bytes] = []
    for header in parsed.headers:
        lower = header.name.lower()
        value = raw[header.value_start : header.value_end]
        if lower == b"transfer-encoding":
            raise ValueError("Transfer-Encoding cannot cross the structured REST bridge")
        if lower == b"trailer":
            raise ValueError("trailer framing cannot cross the structured REST bridge")
        if lower == b"content-length":
            content_lengths.append(value)
    if len(content_lengths) > 1:
        raise ValueError("duplicate Content-Length fields are ambiguous")
    if content_lengths:
        value = content_lengths[0]
        if not value or any(byte < 0x30 or byte > 0x39 for byte in value):
            raise ValueError("Content-Length must contain one decimal byte length")
        if int(value) != body_length:
            raise ValueError(
                f"Content-Length {int(value)} does not match the {body_length}-byte body"
            )


def _bridge_request(raw: bytes, scheme: str, authority: str) -> _BridgeRequest:
    if not isinstance(scheme, str) or scheme.lower() not in _SUPPORTED_SCHEMES:
        raise ValueError("structured REST bridge scheme must be http or https")
    scheme = scheme.lower()
    fallback_authority = _normalise_authority(authority, scheme)
    parsed = parse_request(raw)
    _validate_framing(raw, parsed)

    try:
        method = parsed.method.decode("ascii")
        target = parsed.target.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"request line is not lossless UTF-8: {exc}") from None

    headers: list[dict[str, str]] = []
    host_values: list[str] = []
    for header in parsed.headers:
        # ``build_raw`` contributes one conventional SP after the colon.  Remove that one byte but
        # retain every byte supplied as the structured value, including empty/whitespace-only fuzz
        # payloads and trailing whitespace.
        bridge_value_start = header.name_end + 1
        if bridge_value_start < header.line_end and raw[bridge_value_start] == 0x20:
            bridge_value_start += 1
        try:
            name = header.name.decode("ascii")
            value = raw[bridge_value_start : header.line_end].decode("utf-8")
            semantic_value = raw[header.value_start : header.value_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"HTTP header cannot be preserved as UTF-8: {exc}") from None
        headers.append({"name": name, "value": value})
        if header.name.lower() == b"host":
            host_values.append(semantic_value)

    if len(host_values) > 1:
        raise ValueError("duplicate Host fields are ambiguous")
    host_value = host_values[0] if host_values else authority
    host_authority = _normalise_authority(host_value, scheme)
    if host_authority != fallback_authority:
        raise ValueError("Host header is inconsistent with the structured request authority")

    if target.startswith("/"):
        # A proxy capture can retain browser-only fragment metadata even though fragments never cross
        # the HTTP wire.  Query/path selectors already exclude it, so replay must do the same.
        wire_target = target.partition("#")[0]
        url = f"{scheme}://{host_value}{wire_target}"
    elif target.lower().startswith(("http://", "https://")):
        absolute = _url_parts(target, allow_fragment=True)
        target_scheme = absolute.scheme.lower()
        if target_scheme != scheme:
            raise ValueError("absolute-form request target scheme is inconsistent")
        if not _authorities_match(absolute.netloc, host_value, scheme):
            raise ValueError("absolute-form authority is inconsistent with Host")
        if not _authorities_match(absolute.netloc, authority, scheme):
            raise ValueError("absolute-form authority is inconsistent with the base request")
        # Preserve the validated spelling byte-for-byte; rebuilding a SplitResult would erase a
        # significant empty query delimiter (``/a?``) while removing the fragment.
        url = target.partition("#")[0]
    else:
        raise ValueError("unsupported request target form for the structured REST bridge")

    body_bytes = raw[parsed.body_start :]
    has_explicit_length = any(header.name.lower() == b"content-length" for header in parsed.headers)
    structured_body = body_bytes if body_bytes or has_explicit_length else None
    return _BridgeRequest(parsed, method, url, headers, structured_body)


def build_raw(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    body: str | bytes | None,
) -> bytes:
    """Build validated raw HTTP/1.1 bytes from structured request parts."""
    if not isinstance(method, str):
        raise TypeError("request method must be text")
    if _contains_forbidden(method):
        raise ValueError("request method contains CR, LF, or NUL injection")
    parts = _url_parts(url, allow_fragment=True)
    scheme = parts.scheme.lower()
    authority = parts.netloc
    fragmentless_url = url.partition("#")[0]
    target = parts.path or "/"
    if "?" in fragmentless_url:
        target = f"{target}?{parts.query}"

    checked_headers: list[tuple[str, str]] = []
    host_count = 0
    for item in headers:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("each structured header must be a (name, value) pair")
        name, value = item
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("structured header names and values must be text")
        if _contains_forbidden(name) or _contains_forbidden(value):
            raise ValueError("structured HTTP header contains CR, LF, or NUL injection")
        if name.startswith(":"):
            raise ValueError("HTTP pseudo-headers are not supported")
        if name.lower() == "host":
            host_count += 1
            if not _authorities_match(value.strip(" \t"), authority, scheme):
                raise ValueError("Host header is inconsistent with the request URL authority")
        checked_headers.append((name, value))
    if host_count > 1:
        raise ValueError("duplicate Host fields are ambiguous")

    if body is not None and not isinstance(body, (str, bytes)):
        raise TypeError("structured request body must be text, bytes, or None")
    try:
        body_bytes = body if isinstance(body, bytes) else (body or "").encode("utf-8")
        effective_headers = checked_headers
        has_explicit_length = any(name.lower() == "content-length" for name, _ in checked_headers)
        if body is not None and not has_explicit_length:
            # Preserve the structured model's empty-body state.  Without an explicit zero length,
            # the raw separator alone is indistinguishable from a request with no body at all.
            effective_headers = [*checked_headers, ("Content-Length", str(len(body_bytes)))]
        lines = [f"{method} {target} HTTP/1.1"]
        if host_count == 0:
            lines.append(f"Host: {authority}")
        lines.extend(f"{name}: {value}" for name, value in effective_headers)
        raw = "\r\n".join(lines).encode("utf-8") + b"\r\n\r\n" + body_bytes
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"structured request contains text that is not UTF-8 encodable: {exc}"
        ) from None

    # Validate the exact bytes, including duplicate/framing fields and method/header token grammar.
    _bridge_request(raw, scheme, authority)
    return raw


def to_send_request(raw: bytes, scheme: str, host: str) -> dict[str, Any]:
    """Parse raw bytes into a lossless, framing-safe ``/repeater/send`` request payload."""
    request = _bridge_request(raw, scheme, host)
    result: dict[str, Any] = {
        "method": request.method,
        "url": request.url,
        "headers": request.headers,
    }
    if request.body_bytes is not None:
        # The live bridge proved that Montoya's String overload narrows UTF-16 code units, turning
        # 25 intended UTF-8 bytes into 19.  One base64 path preserves empty, Unicode, NUL, and
        # arbitrary binary bodies without a text branch that can silently re-encode them.
        result["bodyBase64"] = base64.b64encode(request.body_bytes).decode("ascii")
    return result
