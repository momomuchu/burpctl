"""A2 — client-side fuzz engine: byte substitution + the 4 attack-type generators.

See ``docs/ALGORITHMS.md`` §A2. The Burp extension only does sniper/by-name, so ``bp`` does
all fuzzing itself: A1 resolves positions, A2 expands the combinations and substitutes payloads
(byte-offset precise, right-to-left), then each concrete request is fired via /repeater/send.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from dataclasses import dataclass

from bp.pos import Position
from bp.rawhttp import body_start, iter_headers

ATTACK_TYPES = ("sniper", "battering-ram", "pitchfork", "cluster-bomb")


@dataclass(frozen=True)
class Sub:
    """Replace ``pos``'s byte range with ``payload``."""

    pos: Position
    payload: bytes


@dataclass(frozen=True)
class ConcreteRequest:
    """One fully-substituted request ready to fire, plus the payload(s) applied."""

    raw: bytes
    payloads: tuple[bytes, ...]
    position_index: int | None = None  # for sniper: which position was fuzzed


def apply_subs(base: bytes, subs: Sequence[Sub]) -> bytes:
    """Apply non-overlapping ``subs`` to ``base`` (right-to-left), recomputing Content-Length."""
    body0 = body_start(base)
    body_touched = any(s.pos.start >= body0 for s in subs)
    out = base
    for s in sorted(subs, key=lambda x: x.pos.start, reverse=True):
        out = out[: s.pos.start] + s.payload + out[s.pos.end :]
    if body_touched:
        out = _recompute_content_length(out)
    return out


def _recompute_content_length(raw: bytes) -> bytes:
    new_len = len(raw) - body_start(raw)
    for name, v_start, v_end in iter_headers(raw):
        if name.lower() == b"content-length":
            return raw[:v_start] + str(new_len).encode() + raw[v_end:]
    # No Content-Length header present — insert one just before the blank-line separator.
    # Find the end of the header block (the \r\n\r\n or \n\n separator).
    sep = raw.find(b"\r\n\r\n")
    if sep != -1:
        insert_at = sep + 2  # after the first \r\n, before the final \r\n
        return raw[:insert_at] + b"Content-Length: " + str(new_len).encode() + b"\r\n" + raw[insert_at:]
    sep = raw.find(b"\n\n")
    if sep != -1:
        insert_at = sep + 1
        return raw[:insert_at] + b"Content-Length: " + str(new_len).encode() + b"\n" + raw[insert_at:]
    return raw


def expand(
    base: bytes,
    positions: Sequence[Position],
    payload_lists: Sequence[Sequence[bytes]],
    attack_type: str,
) -> list[ConcreteRequest]:
    """Generate the concrete requests for ``attack_type``.

    For sniper/battering-ram, ``payload_lists`` holds one list (used for all positions);
    for pitchfork/cluster-bomb, one list per position (aligned with ``positions``).
    """
    if not positions:
        # Without positions, apply_subs() returns the base unchanged — battering-ram and
        # cluster-bomb would silently fire N identical, unmodified requests. Refuse instead.
        raise ValueError("fuzz requires at least one --pos position")
    if attack_type == "sniper":
        single = payload_lists[0]
        return [
            ConcreteRequest(apply_subs(base, [Sub(p, v)]), (v,), position_index=k)
            for k, p in enumerate(positions)
            for v in single
        ]
    if attack_type == "battering-ram":
        single = payload_lists[0]
        return [
            ConcreteRequest(apply_subs(base, [Sub(p, v) for p in positions]), (v,))
            for v in single
        ]
    if attack_type == "pitchfork":
        m = min(len(lst) for lst in payload_lists)
        out: list[ConcreteRequest] = []
        for i in range(m):
            combo = tuple(payload_lists[k][i] for k in range(len(positions)))
            subs = [Sub(positions[k], combo[k]) for k in range(len(positions))]
            out.append(ConcreteRequest(apply_subs(base, subs), combo))
        return out
    if attack_type == "cluster-bomb":
        out = []
        for combo in itertools.product(*payload_lists):
            subs = [Sub(positions[k], combo[k]) for k in range(len(positions))]
            out.append(ConcreteRequest(apply_subs(base, subs), tuple(combo)))
        return out
    raise ValueError(f"unknown attack type {attack_type!r} (want one of {ATTACK_TYPES})")
