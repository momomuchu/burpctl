"""A2 — client-side fuzz engine: byte substitution + the 4 attack-type generators.

See ``docs/ALGORITHMS.md`` §A2. The Burp extension only does sniper/by-name, so ``bp`` does
all fuzzing itself: A1 resolves positions, A2 expands the combinations and substitutes payloads
(byte-offset precise, right-to-left), then each concrete request is fired via /repeater/send.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from dataclasses import dataclass

from bp.pos import Position, PosError
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
    """Apply non-overlapping ``subs`` to ``base`` (right-to-left), recomputing Content-Length.

    Raises ``PosError('POS_OVERLAP', ...)`` if any two positions overlap (start < prev end).
    Adjacent positions (start == prev end) are allowed.
    """
    if len(subs) > 1:
        sorted_subs = sorted(subs, key=lambda x: x.pos.start)
        prev = sorted_subs[0]
        for s in sorted_subs[1:]:
            if s.pos.start < prev.pos.end:
                raise PosError(
                    "POS_OVERLAP",
                    f"positions overlap: {prev.pos.name!r} (end={prev.pos.end})"
                    f" and {s.pos.name!r} (start={s.pos.start})",
                )
            prev = s
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
    new_val = b" " + str(new_len).encode()
    for name, v_start, v_end in iter_headers(raw):
        if name.lower() == b"content-length":
            # v_start is OWS-trimmed (first non-space after ':').
            # v_end is OWS-trimmed (last non-space before CRLF).
            # Find the colon that precedes this value region and the CRLF that follows,
            # so we replace the entire ": <old-value-with-ows>" with ": <new-value>".
            colon = raw.rfind(b":", 0, v_start)
            # Find the CRLF (or LF) terminating this header line.
            crlf = raw.find(b"\r\n", v_end)
            lf = raw.find(b"\n", v_end)
            if crlf != -1 and (lf == -1 or crlf <= lf):
                line_end = crlf
                term = b"\r\n"
            elif lf != -1:
                line_end = lf
                term = b"\n"
            else:
                line_end = len(raw)
                term = b""
            return raw[: colon + 1] + new_val + term + raw[line_end + len(term) :]
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
