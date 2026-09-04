"""Property checks for fuzz expansion, payload loading, and byte substitution."""

import base64
import json
import random
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from bp.fuzz import Sub, apply_subs, expand, load_payload_file
from bp.pos import Position, resolve_pos
from bp.wire import to_send_request


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

        per_position_sniper = expand(base, positions, payload_lists, "sniper")
        assert len(per_position_sniper) == sum(sizes)
        assert [request.position_index for request in per_position_sniper] == [
            index for index, size in enumerate(sizes) for _ in range(size)
        ]


def test_boundary_insertions_are_deterministic_and_adjacent() -> None:
    base = b"middle"
    subs = [
        Sub(Position(0, 0, "offset:start"), b"<"),
        Sub(Position(len(base), len(base), "offset:end"), b">"),
    ]

    assert apply_subs(base, subs) == b"<middle>"


@given(st.binary(max_size=512))
@settings(max_examples=200)
def test_any_body_bytes_survive_the_python_rest_intent(payload: bytes) -> None:
    """F3/F5/F6: the REST intent must carry exact bytes; target arrival is a separate live oracle."""
    base = b"POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\nx"
    fuzzed = apply_subs(
        base,
        [Sub(Position(len(base) - 1, len(base), "offset:body"), payload)],
    )

    request = to_send_request(fuzzed, "https", "h")

    assert "body" not in request
    assert base64.b64decode(request["bodyBase64"], validate=True) == payload
    content_lengths = [
        header["value"]
        for header in request["headers"]
        if header["name"].lower() == "content-length"
    ]
    assert content_lengths == [str(len(payload))]


@given(st.binary(max_size=512))
@settings(max_examples=200)
def test_any_bytes_round_trip_from_payload_file_to_wire_intent(payload: bytes) -> None:
    base = b"POST /echo HTTP/1.1\r\nHost: h\r\nContent-Length: 1\r\n\r\nx"
    position = Position(len(base) - 1, len(base), "offset:body")
    encoded = json.dumps([{"b64": base64.b64encode(payload).decode("ascii")}]).encode()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "payloads.txt"
        path.write_bytes(b"#!bp-payloads-json-v1\n" + encoded)
        loaded = load_payload_file(path)

    request = to_send_request(expand(base, [position], [loaded], "sniper")[0].raw, "https", "h")

    assert base64.b64decode(request["bodyBase64"], validate=True) == payload
