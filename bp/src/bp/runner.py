"""bp fuzz orchestration (docs/ALGORITHMS.md A2 + the firing flow).

Fetch the base request by id → build raw → resolve --pos (A1) → expand combinations (A2) →
fire each via /repeater/send (structured, via the wire bridge) → explicit-baseline anomaly flagging.
The Burp Intruder is sniper/by-name only, so bp owns all of this.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from bp.client import BurpClient, BurpError
from bp.fuzz import expand
from bp.pos import Position, resolve_pos
from bp.wire import build_raw, to_send_request


@dataclass(frozen=True)
class FuzzResult:
    index: int
    payloads: tuple[str, ...]
    status: int
    length: int
    duration_ms: int
    anomalous: bool
    baseline: bool
    error: str | None


def _base_raw(entry: Mapping[str, Any]) -> tuple[bytes, str, str]:
    if "request" not in entry:
        raise BurpError("INVALID_RESPONSE", "history entry missing 'request' field")
    req = entry["request"]
    headers = [(h["name"], h["value"]) for h in req.get("headers", [])]
    raw = build_raw(req["method"], req["url"], headers, req.get("body"))
    parts = urlsplit(req["url"])
    return raw, (parts.scheme or "https"), parts.netloc


def _short(name: str) -> str:
    """Short payload key of a position: the selector arg (``query:u`` -> ``u``)."""
    return name.split(":", 1)[1] if ":" in name else name


def _payload_lists(
    positions: Sequence[Position], payload_map: Mapping[str, list[bytes]], attack_type: str
) -> list[list[bytes]]:
    _KNOWN_ATTACK_TYPES = ("sniper", "battering-ram", "pitchfork", "cluster-bomb")
    if attack_type not in _KNOWN_ATTACK_TYPES:
        raise ValueError(
            f"unknown attack type {attack_type!r} (want one of {', '.join(_KNOWN_ATTACK_TYPES)})"
        )
    if attack_type in ("sniper", "battering-ram"):
        if not payload_map:
            raise ValueError("at least one --payloads list is required")
        return [next(iter(payload_map.values()))]
    lists: list[list[bytes]] = []
    missing: list[str] = []
    for p in positions:
        short = _short(p.name)
        if short in payload_map:
            lists.append(payload_map[short])
        elif p.name in payload_map:
            lists.append(payload_map[p.name])
        else:
            missing.append(short)
    if missing:
        raise ValueError(f"{attack_type} needs a --payloads list per position; missing: {missing}")
    return lists


def _send(client: BurpClient, raw: bytes, scheme: str, host: str) -> tuple[int, int, int]:
    data = client.post("/repeater/send", {"request": to_send_request(raw, scheme, host)})
    if "response" not in data:
        raise BurpError("INVALID_RESPONSE", "repeater/send reply missing 'response' field")
    resp = data["response"]
    if "statusCode" not in resp:
        raise BurpError("INVALID_RESPONSE", "repeater/send reply missing 'statusCode' field")
    try:
        status = int(resp["statusCode"])
    except (TypeError, ValueError):
        raise BurpError("INVALID_RESPONSE", "repeater/send reply has a non-integer 'statusCode'") from None
    body = resp.get("body") or ""
    if not isinstance(body, str):
        raise BurpError("INVALID_RESPONSE", "repeater/send response body is not text")
    length = len(body.encode("utf-8"))
    duration = int(data.get("durationMs", 0))
    return status, length, duration


def run_fuzz(
    client: BurpClient,
    request_id: int,
    selectors: Sequence[str],
    payload_map: Mapping[str, list[bytes]],
    attack_type: str,
    *,
    anomaly_pct: int = 5,
) -> list[FuzzResult]:
    """Run the full client-side fuzz against ``request_id`` and return per-request results."""
    if not selectors:
        raise ValueError("fuzz requires at least one --pos position")
    entry = client.get(f"/proxy/history/{request_id}")
    raw, scheme, host = _base_raw(entry)
    positions = [resolve_pos(raw, s) for s in selectors]
    lists = _payload_lists(positions, payload_map, attack_type)
    concrete = expand(raw, positions, lists, attack_type)
    if not concrete:
        raise ValueError("fuzz requires at least one concrete request")

    try:
        base_status, base_len, base_duration = _send(client, raw, scheme, host)
    except BurpError as exc:
        return [
            FuzzResult(
                index=-1,
                payloads=(),
                status=0,
                length=0,
                duration_ms=0,
                anomalous=False,
                baseline=True,
                error=str(exc),
            )
        ]
    threshold = max(base_len * anomaly_pct // 100, 20)

    results: list[FuzzResult] = [
        FuzzResult(
            index=-1,
            payloads=(),
            status=base_status,
            length=base_len,
            duration_ms=base_duration,
            anomalous=False,
            baseline=True,
            error=None,
        )
    ]
    for i, cr in enumerate(concrete):
        payloads = tuple(payload.decode("utf-8", "replace") for payload in cr.payloads)
        try:
            status, length, duration = _send(client, cr.raw, scheme, host)
        except BurpError as exc:
            results.append(
                FuzzResult(
                    index=i,
                    payloads=payloads,
                    status=0,
                    length=0,
                    duration_ms=0,
                    anomalous=True,
                    baseline=False,
                    error=str(exc),
                )
            )
            continue
        anomalous = status != base_status or abs(length - base_len) > threshold
        results.append(
            FuzzResult(
                index=i,
                payloads=payloads,
                status=status,
                length=length,
                duration_ms=duration,
                anomalous=anomalous,
                baseline=False,
                error=None,
            )
        )
    return results
