"""bp fuzz orchestration (docs/ALGORITHMS.md A2 + the firing flow).

Fetch the base request by id → build raw → resolve --pos (A1) → expand combinations (A2) →
fire each via /repeater/send (structured, via the wire bridge) → explicit-baseline anomaly flagging.
The Burp Intruder is sniper/by-name only, so bp owns all of this.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from bp.client import BurpClient, BurpError
from bp.fuzz import ATTACK_TYPES, expand
from bp.pos import Position, resolve_pos
from bp.wire import build_raw, to_send_request


@dataclass(frozen=True)
class FuzzResult:
    index: int
    payloads: tuple[str | dict[str, str], ...]
    status: int
    length: int
    duration_ms: int
    anomalous: bool
    baseline: bool
    error: str | None
    error_code: str | None


def _request_body(entry: Mapping[str, Any]) -> str | bytes | None:
    encoded = entry.get("bodyBase64")
    if encoded is None:
        body = entry.get("body")
        if body is not None and not isinstance(body, str):
            raise BurpError("INVALID_RESPONSE", "history request body is not text")
        return body
    if not isinstance(encoded, str):
        raise BurpError("INVALID_RESPONSE", "history request bodyBase64 is not text")
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise BurpError(
            "INVALID_RESPONSE", "history request bodyBase64 is not valid base64"
        ) from None


def _base_raw(entry: Mapping[str, Any]) -> tuple[bytes, str, str]:
    if "request" not in entry:
        raise BurpError("INVALID_RESPONSE", "history entry missing 'request' field")
    req = entry["request"]
    headers = [(h["name"], h["value"]) for h in req.get("headers", [])]
    raw = build_raw(req["method"], req["url"], headers, _request_body(req))
    parts = urlsplit(req["url"])
    return raw, (parts.scheme or "https"), parts.netloc


def _short(name: str) -> str:
    """Short payload key of a position: the selector arg (``query:u`` -> ``u``)."""
    return name.split(":", 1)[1] if ":" in name else name


def _position_payload_lists(
    positions: Sequence[Position], payload_map: Mapping[str, list[bytes]], attack_type: str
) -> list[list[bytes]]:
    lists: list[list[bytes]] = []
    missing: list[str] = []
    used: set[str] = set()
    for position in positions:
        short = _short(position.name)
        if short in payload_map:
            key = short
        elif position.name in payload_map:
            key = position.name
        else:
            missing.append(short)
            continue
        lists.append(payload_map[key])
        used.add(key)
    if missing:
        raise ValueError(f"{attack_type} needs a --payloads list per position; missing: {missing}")
    extra = [key for key in payload_map if key not in used]
    if extra:
        raise ValueError(f"{attack_type} got unused --payloads list(s): {extra}")
    return lists


def _payload_lists(
    positions: Sequence[Position], payload_map: Mapping[str, list[bytes]], attack_type: str
) -> list[list[bytes]]:
    if attack_type not in ATTACK_TYPES:
        raise ValueError(
            f"unknown attack type {attack_type!r} (want one of {', '.join(ATTACK_TYPES)})"
        )
    if not payload_map:
        raise ValueError("at least one --payloads list is required")
    if attack_type == "battering-ram":
        # One set S is the definition of battering-ram.  Combining several named sets would silently
        # invent a corpus the caller did not request; require another attack type instead.
        if len(payload_map) != 1:
            raise ValueError("battering-ram requires exactly one shared --payloads list")
        return [next(iter(payload_map.values()))]
    if attack_type == "sniper" and len(payload_map) == 1:
        return [next(iter(payload_map.values()))]
    return _position_payload_lists(positions, payload_map, attack_type)


def _response_body_bytes(response: Mapping[str, Any]) -> bytes:
    """Return response bytes; bodyBase64 is a K33 path the current extension does not emit."""
    encoded = response.get("bodyBase64")
    if encoded is not None:
        if not isinstance(encoded, str):
            raise BurpError("INVALID_RESPONSE", "repeater/send response bodyBase64 is not text")
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BurpError(
                "INVALID_RESPONSE", "repeater/send response bodyBase64 is not valid base64"
            ) from None
    body = response.get("body")
    if body is None:
        return b""
    if not isinstance(body, str):
        raise BurpError("INVALID_RESPONSE", "repeater/send response body is not text")
    return body.encode("utf-8")


def _payload_for_output(payload: bytes) -> str | dict[str, str]:
    """Represent text directly and arbitrary bytes reversibly, without replacement characters."""
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return {"b64": base64.b64encode(payload).decode("ascii")}


def _send_request(client: BurpClient, request: Mapping[str, Any]) -> tuple[int, int, int]:
    data = client.post("/repeater/send", {"request": request})
    if "response" not in data or not isinstance(data["response"], Mapping):
        raise BurpError("INVALID_RESPONSE", "repeater/send reply missing 'response' object")
    resp = data["response"]
    if "statusCode" not in resp:
        raise BurpError("INVALID_RESPONSE", "repeater/send reply missing 'statusCode' field")
    try:
        status = int(resp["statusCode"])
    except (TypeError, ValueError):
        raise BurpError(
            "INVALID_RESPONSE", "repeater/send reply has a non-integer 'statusCode'"
        ) from None
    body_bytes = _response_body_bytes(resp)
    length = len(body_bytes)
    try:
        duration = int(data.get("durationMs", 0))
    except (TypeError, ValueError):
        raise BurpError(
            "INVALID_RESPONSE", "repeater/send reply has invalid 'durationMs'"
        ) from None
    return status, length, duration


def _prepare_send(raw: bytes, scheme: str, host: str) -> Mapping[str, Any]:
    try:
        return to_send_request(raw, scheme, host)
    except (IndexError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"fuzz request cannot cross the structured REST bridge: {exc}") from None


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
    if attack_type not in ATTACK_TYPES:
        raise ValueError(
            f"unknown attack type {attack_type!r} (want one of {', '.join(ATTACK_TYPES)})"
        )
    entry = client.get(f"/proxy/history/{request_id}")
    raw, scheme, host = _base_raw(entry)
    positions = [resolve_pos(raw, s) for s in selectors]
    lists = _payload_lists(positions, payload_map, attack_type)
    plan = expand(raw, positions, lists, attack_type)
    base_request = _prepare_send(raw, scheme, host)

    # Validate the complete corpus before the baseline reaches the target, but retain no prepared
    # request list.  FuzzPlan is restartable, so the second pass constructs and sends one shot at a
    # time while the first pass guarantees an invalid late payload cannot cause a partial campaign.
    for item in plan:
        _prepare_send(item.raw, scheme, host)

    try:
        base_status, base_len, base_duration = _send_request(client, base_request)
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
                error_code=exc.code,
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
            error_code=None,
        )
    ]
    for i, cr in enumerate(plan):
        request = _prepare_send(cr.raw, scheme, host)
        payloads = tuple(_payload_for_output(payload) for payload in cr.payloads)
        try:
            status, length, duration = _send_request(client, request)
        except BurpError as exc:
            results.append(
                FuzzResult(
                    index=i,
                    payloads=payloads,
                    status=0,
                    length=0,
                    duration_ms=0,
                    anomalous=False,
                    baseline=False,
                    error=str(exc),
                    error_code=exc.code,
                )
            )
            if exc.code in {
                "CONNECTION_REFUSED",
                "TRANSPORT_ERROR",
                "NO_RESPONSE",
                "INVALID_RESPONSE",
            }:
                break
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
                error_code=None,
            )
        )
    return results
