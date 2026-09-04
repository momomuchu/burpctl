"""Deterministic property-style checks for fuzz expansion and byte substitution."""

import random

from bp.fuzz import Sub, apply_subs, expand
from bp.pos import Position, resolve_pos


def test_randomized_non_overlapping_substitutions_preserve_unaffected_bytes() -> None:
    rng = random.Random(0xB00F)
    alphabet = b"abcdefghijklmnopqrstuvwxyz"
    for _ in range(200):
        base = bytes(rng.choice(alphabet) for _ in range(40))
        cuts = sorted(rng.sample(range(41), 6))
        ranges = [(cuts[i], cuts[i + 1]) for i in range(0, 6, 2)]
        replacements = [
            bytes(rng.choice(alphabet) for _ in range(rng.randrange(6))) for _ in ranges
        ]
        subs = [
            Sub(Position(start, end, f"offset:{start}-{end}"), replacement)
            for (start, end), replacement in zip(ranges, replacements, strict=True)
        ]

        expected_parts: list[bytes] = []
        cursor = 0
        for (start, end), replacement in zip(ranges, replacements, strict=True):
            expected_parts.extend((base[cursor:start], replacement))
            cursor = end
        expected_parts.append(base[cursor:])

        assert apply_subs(base, list(reversed(subs))) == b"".join(expected_parts)


def test_randomized_attack_cardinality_and_restartability() -> None:
    rng = random.Random(0xF022)
    base = b"GET /?a=_&b=_&c=_ HTTP/1.1\r\nHost: h\r\n\r\n"
    positions = [resolve_pos(base, f"query:{name}") for name in "abc"]

    for _ in range(100):
        sizes = [rng.randrange(1, 8) for _ in positions]
        payload_lists = [
            [f"{position}-{value}".encode() for value in range(size)]
            for position, size in enumerate(sizes)
        ]
        shared = [payload_lists[0]]
        expected = {
            "sniper": len(positions) * sizes[0],
            "battering-ram": sizes[0],
            "pitchfork": min(sizes),
            "cluster-bomb": sizes[0] * sizes[1] * sizes[2],
        }
        for attack_type, count in expected.items():
            lists = shared if attack_type in {"sniper", "battering-ram"} else payload_lists
            plan = expand(base, positions, lists, attack_type)
            first = [request.payloads for request in plan]
            second = [request.payloads for request in plan]
            assert len(plan) == count
            assert len(first) == count
            assert second == first


def test_boundary_insertions_are_deterministic_and_adjacent() -> None:
    base = b"middle"
    subs = [
        Sub(Position(0, 0, "offset:start"), b"<"),
        Sub(Position(len(base), len(base), "offset:end"), b">"),
    ]

    assert apply_subs(base, subs) == b"<middle>"
