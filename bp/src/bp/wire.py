"""Bridge between raw HTTP/1.1 bytes (A1/A2 work here) and structured HttpRequestData.

The extension's /repeater/send wants ``{method, url, headers, body}`` and rebuilds the request
from the URL; A1/A2 need raw bytes for byte-offset-precise substitution. ``build_raw`` goes
structured→raw (to run A1/A2), ``to_send_request`` goes raw→structured (to fire the result).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from bp.rawhttp import body_start, iter_headers, line_end


def build_raw(method: str, url: str, headers: list[tuple[str, str]], body: str | None) -> bytes:
    """Build a raw HTTP/1.1 request from structured parts (Host injected if absent)."""
    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    lines = [f"{method} {target} HTTP/1.1"]
    if not any(n.lower() == "host" for n, _ in headers) and parts.hostname:
        host = parts.hostname + (f":{parts.port}" if parts.port else "")
        lines.append(f"Host: {host}")
    lines.extend(f"{n}: {v}" for n, v in headers)
    head = "\r\n".join(lines).encode()
    return head + b"\r\n\r\n" + (body or "").encode()


def to_send_request(raw: bytes, scheme: str, host: str) -> dict[str, Any]:
    """Parse modified raw bytes back into a /repeater/send ``request`` payload.

    ``scheme`` (http/https) and ``host`` come from the base request; a Host header in ``raw``
    overrides ``host``. The URL is reconstructed as ``scheme://host<request-target>``.
    """
    end, _ = line_end(raw, 0, len(raw))
    tokens = raw[:end].split(b" ")
    method = tokens[0].decode() if tokens else "GET"
    target = tokens[1].decode() if len(tokens) > 1 else "/"

    headers: list[dict[str, str]] = []
    host_header: str | None = None
    for name, v_start, v_end in iter_headers(raw):
        nm = name.decode()
        val = raw[v_start:v_end].decode("utf-8", "replace")
        headers.append({"name": nm, "value": val})
        if nm.lower() == "host":
            host_header = val

    final_host = host_header or host
    if not target.startswith("/"):
        target = f"/{target}"
    url = f"{scheme}://{final_host}{target}"
    body_bytes = raw[body_start(raw) :]
    body = body_bytes.decode("utf-8", "replace") if body_bytes else None
    return {"method": method, "url": url, "headers": headers, "body": body}
