"""A2 — bounded, restartable client-side fuzz request generation."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import overload

from bp.pos import Position, PosError
from bp.rawhttp import body_start, parse_request

ATTACK_TYPES = ("sniper", "battering-ram", "pitchfork", "cluster-bomb")
MAX_FUZZ_SHOTS = 10_000
# Compatibility/readability aliases for callers that describe requests rather than shots.
MAX_FUZZ_REQUESTS = MAX_FUZZ_SHOTS


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
    position_index: int | None = None


def _validate_positions(base: bytes, positions: Sequence[Position]) -> None:
    """Validate bounds and reject every ambiguous pair before substitution starts."""
    ordered = sorted(positions, key=lambda position: (position.start, position.end))
    for position in ordered:
        if position.start < 0 or position.end < position.start:
            raise PosError(
                "BAD_SELECTOR",
                f"position {position.name!r} has invalid range {position.start}-{position.end}",
            )
        if position.end > len(base):
            raise PosError(
                "POS_NOT_FOUND",
                f"position {position.name!r} ends at {position.end}, beyond request length {len(base)}",
            )
    for previous, current in zip(ordered, ordered[1:]):
        # Half-open adjacent ranges are safe.  Equal starts (including two zero-width insertion
        # points) are ambiguous because stable sort order would otherwise decide their meaning.
        if current.start < previous.end or current.start == previous.start:
            raise PosError(
                "POS_OVERLAP",
                f"positions overlap: {previous.name!r} (end={previous.end})"
                f" and {current.name!r} (start={current.start})",
            )


def apply_subs(base: bytes, subs: Sequence[Sub]) -> bytes:
    """Apply non-overlapping substitutions right-to-left and repair body length framing."""
    positions = [sub.pos for sub in subs]
    _validate_positions(base, positions)
    for sub in subs:
        if not isinstance(sub.payload, bytes):
            raise TypeError("fuzz payloads must be bytes")

    body0 = body_start(base)
    for sub in subs:
        if sub.pos.start < body0 and any(byte in sub.payload for byte in (0x00, 0x0A, 0x0D)):
            raise ValueError(
                "CR, LF, and NUL control-byte injection is not supported outside the body"
            )

    body_touched = any(sub.pos.start >= body0 or sub.pos.end > body0 for sub in subs)
    out = base
    for sub in sorted(subs, key=lambda item: item.pos.start, reverse=True):
        out = out[: sub.pos.start] + sub.payload + out[sub.pos.end :]
    if body_touched:
        out = _recompute_content_length(out)
    return out


def _recompute_content_length(raw: bytes) -> bytes:
    """Return ``raw`` with exactly one canonical Content-Length for its byte body."""
    try:
        parsed = parse_request(raw)
    except (TypeError, ValueError):
        # ``apply_subs`` is also a general byte-splicing primitive in the public API.  If its input
        # is not an HTTP message there is no framing field to repair; the wire bridge will still
        # reject such bytes before a target send.
        return raw

    new_value = b" " + str(len(raw) - parsed.body_start).encode("ascii")
    lengths = [header for header in parsed.headers if header.name.lower() == b"content-length"]
    if lengths:
        result = raw
        for header in reversed(lengths[1:]):
            result = result[: header.line_start] + result[header.line_end + len(parsed.newline) :]
        first = lengths[0]
        # Duplicate removals are all after the first occurrence, so its original offsets hold.
        result = (
            result[: first.name_end + 1]
            + new_value
            + parsed.newline
            + result[first.line_end + len(parsed.newline) :]
        )
        return result

    insert_at = parsed.body_start - len(parsed.newline)
    inserted_header = b"Content-Length:" + new_value + parsed.newline
    return raw[:insert_at] + inserted_header + raw[insert_at:]


def _validate_layout(
    positions: Sequence[Position],
    payload_lists: Sequence[Sequence[bytes]],
    attack_type: str,
) -> tuple[int, ...]:
    if attack_type not in ATTACK_TYPES:
        raise ValueError(f"unknown attack type {attack_type!r} (want one of {ATTACK_TYPES})")
    if not positions:
        raise ValueError("fuzz requires at least one --pos position")
    expected = 1 if attack_type in ("sniper", "battering-ram") else len(positions)
    if len(payload_lists) != expected:
        raise ValueError(
            f"{attack_type} requires {expected} payload list(s), got {len(payload_lists)}"
        )
    return tuple(len(payloads) for payloads in payload_lists)


def _bounded_product(factors: Sequence[int], limit: int) -> int:
    if any(factor == 0 for factor in factors):
        return 0
    total = 1
    for factor in factors:
        if total > limit // factor:
            raise ValueError(f"fuzz plan exceeds the maximum of {limit:,} payload shots")
        total *= factor
    return total


def plan_cardinality(
    positions: Sequence[Position],
    payload_lists: Sequence[Sequence[bytes]],
    attack_type: str,
    *,
    limit: int = MAX_FUZZ_SHOTS,
) -> int:
    """Return the exact shot count, failing before multiplication can exceed ``limit``."""
    if limit < 0:
        raise ValueError("fuzz shot limit must be non-negative")
    sizes = _validate_layout(positions, payload_lists, attack_type)
    if attack_type == "sniper":
        count = _bounded_product((len(positions), sizes[0]), limit)
    elif attack_type == "battering-ram":
        count = sizes[0]
    elif attack_type == "pitchfork":
        count = min(sizes)
    else:
        count = _bounded_product(sizes, limit)
    if count > limit:
        raise ValueError(f"fuzz plan exceeds the maximum of {limit:,} payload shots")
    return count


class FuzzPlan(Sequence[ConcreteRequest]):
    """A bounded, restartable sequence that materializes only the current request."""

    def __init__(
        self,
        base: bytes,
        positions: Sequence[Position],
        payload_lists: Sequence[Sequence[bytes]],
        attack_type: str,
        *,
        limit: int = MAX_FUZZ_SHOTS,
    ) -> None:
        self._base = base
        self._positions = tuple(positions)
        self._attack_type = attack_type
        _validate_positions(base, self._positions)
        count = plan_cardinality(
            self._positions,
            payload_lists,
            attack_type,
            limit=limit,
        )
        if count == 0:
            raise ValueError("fuzz requires at least one concrete request")

        # Snapshot only after the cardinality guard.  This makes the two passes deterministic even
        # if a caller mutates its input lists while the baseline is in flight, without ever retaining
        # expanded requests or structured request dictionaries.
        frozen: tuple[tuple[bytes, ...], ...]
        if attack_type in ("sniper", "battering-ram"):
            frozen = (tuple(payload_lists[0]),)
        elif attack_type == "pitchfork":
            frozen = tuple(
                tuple(payloads[index] for index in range(count)) for payloads in payload_lists
            )
        else:
            frozen = tuple(tuple(payloads) for payloads in payload_lists)
        for payloads in frozen:
            for payload in payloads:
                if not isinstance(payload, bytes):
                    raise TypeError("fuzz payloads must be bytes")
                try:
                    payload.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        f"fuzz payload cannot cross the structured REST bridge as UTF-8: {exc}"
                    ) from None
        self._payload_lists: tuple[tuple[bytes, ...], ...] = frozen
        self._count = count

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Iterator[ConcreteRequest]:
        if self._attack_type == "sniper":
            payloads = self._payload_lists[0]
            for index, position in enumerate(self._positions):
                for payload in payloads:
                    yield ConcreteRequest(
                        apply_subs(self._base, [Sub(position, payload)]),
                        (payload,),
                        position_index=index,
                    )
            return

        if self._attack_type == "battering-ram":
            for payload in self._payload_lists[0]:
                yield ConcreteRequest(
                    apply_subs(
                        self._base,
                        [Sub(position, payload) for position in self._positions],
                    ),
                    (payload,),
                )
            return

        if self._attack_type == "pitchfork":
            for index in range(self._count):
                combo = tuple(payloads[index] for payloads in self._payload_lists)
                yield ConcreteRequest(
                    apply_subs(
                        self._base,
                        [
                            Sub(position, combo[position_index])
                            for position_index, position in enumerate(self._positions)
                        ],
                    ),
                    combo,
                )
            return

        sizes = tuple(len(payloads) for payloads in self._payload_lists)
        for ordinal in range(self._count):
            remainder = ordinal
            indices = [0] * len(sizes)
            for index in range(len(sizes) - 1, -1, -1):
                indices[index] = remainder % sizes[index]
                remainder //= sizes[index]
            combo = tuple(
                self._payload_lists[index][payload_index]
                for index, payload_index in enumerate(indices)
            )
            yield ConcreteRequest(
                apply_subs(
                    self._base,
                    [
                        Sub(position, combo[position_index])
                        for position_index, position in enumerate(self._positions)
                    ],
                ),
                combo,
            )

    @overload
    def __getitem__(self, index: int) -> ConcreteRequest: ...

    @overload
    def __getitem__(self, index: slice) -> list[ConcreteRequest]: ...

    def __getitem__(self, index: int | slice) -> ConcreteRequest | list[ConcreteRequest]:
        if isinstance(index, slice):
            start, stop, step = index.indices(self._count)
            return [self[offset] for offset in range(start, stop, step)]
        normalized = index + self._count if index < 0 else index
        if normalized < 0 or normalized >= self._count:
            raise IndexError("fuzz plan index out of range")
        for offset, item in enumerate(self):
            if offset == normalized:
                return item
        raise IndexError("fuzz plan index out of range")


def expand(
    base: bytes,
    positions: Sequence[Position],
    payload_lists: Sequence[Sequence[bytes]],
    attack_type: str,
) -> FuzzPlan:
    """Return a bounded restartable plan for one of the four attack types."""
    return FuzzPlan(base, positions, payload_lists, attack_type)
