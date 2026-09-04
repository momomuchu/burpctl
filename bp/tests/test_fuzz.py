"""RED tests for A2 — the client-side fuzz engine (docs/ALGORITHMS.md §A2)."""

from pathlib import Path

import pytest

from bp.fuzz import ConcreteRequest, Sub, apply_subs, expand, load_payload_file
from bp.pos import Position, PosError, resolve_pos

# base with two single-char query values to fuzz; '_' marks each position.
BASE: bytes = b"GET /?u=_&p=_ HTTP/1.1\r\nHost: h\r\n\r\n"


class _UnderreportedPayloads(list[bytes]):
    """A mutable/custom Sequence whose reported size does not match its iterator."""

    def __len__(self) -> int:
        return 1


def _positions() -> tuple[Position, Position]:
    return resolve_pos(BASE, "query:u"), resolve_pos(BASE, "query:p")


# --- apply_subs: right-to-left correctness + Content-Length -------------------


def test_apply_subs_right_to_left_with_length_change() -> None:
    base = b"AAAA-BBBB"
    out = apply_subs(base, [Sub(Position(0, 4, "a"), b"X"), Sub(Position(5, 9, "b"), b"YY")])
    assert out == b"X-YY"  # left-to-right would corrupt the second offset


def test_apply_subs_recomputes_content_length() -> None:
    base = (
        b"POST / HTTP/1.1\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=42"
    )
    out = apply_subs(base, [Sub(resolve_pos(base, "body:id"), b"9999")])
    assert b"Content-Length: 7\r\n" in out  # body is now "id=9999" (7 bytes)
    assert out.endswith(b"id=9999")


# --- the 4 attack types -------------------------------------------------------


def test_sniper_one_position_at_a_time() -> None:
    pu, pp = _positions()
    reqs = expand(BASE, [pu, pp], [[b"x", b"y", b"z"]], "sniper")
    assert len(reqs) == 6  # 2 positions * 3 payloads
    # each request fuzzes exactly one position; the other keeps '_'
    r0 = next(r for r in reqs if r.position_index == 0 and r.payloads == (b"x",))
    assert b"u=x" in r0.raw and b"p=_" in r0.raw


def test_sniper_uses_each_supplied_position_payload_list() -> None:
    """A named list per position must not be accepted and then silently discarded."""
    pu, pp = _positions()

    reqs = expand(BASE, [pu, pp], [[b"A1", b"A2"], [b"B1", b"B2", b"B3"]], "sniper")

    assert len(reqs) == 5
    assert [(request.position_index, request.payloads) for request in reqs] == [
        (0, (b"A1",)),
        (0, (b"A2",)),
        (1, (b"B1",)),
        (1, (b"B2",)),
        (1, (b"B3",)),
    ]
    assert reqs[-1].raw == b"GET /?u=_&p=B3 HTTP/1.1\r\nHost: h\r\n\r\n"


def test_battering_ram_same_payload_all_positions() -> None:
    pu, pp = _positions()
    reqs = expand(BASE, [pu, pp], [[b"a", b"b", b"c"]], "battering-ram")
    assert len(reqs) == 3
    r = reqs[0]
    assert r.payloads == (b"a",)
    assert b"u=a" in r.raw and b"p=a" in r.raw


def test_battering_ram_rejects_an_extra_payload_list() -> None:
    """A second set is ambiguous for a shared-set algorithm and must not be ignored."""
    pu, pp = _positions()

    with pytest.raises(ValueError, match=r"battering-ram requires 1 payload list.*got 2"):
        expand(BASE, [pu, pp], [[b"A"], [b"B"]], "battering-ram")


def test_pitchfork_lockstep_pairs_min_length() -> None:
    pu, pp = _positions()
    reqs = expand(BASE, [pu, pp], [[b"a", b"b", b"c"], [b"1", b"2"]], "pitchfork")
    assert len(reqs) == 2  # min(3, 2)
    assert reqs[0].payloads == (b"a", b"1")
    assert reqs[1].payloads == (b"b", b"2")
    assert b"u=b" in reqs[1].raw and b"p=2" in reqs[1].raw


def test_cluster_bomb_cartesian_product() -> None:
    pu, pp = _positions()
    reqs = expand(BASE, [pu, pp], [[b"a", b"b"], [b"1", b"2"]], "cluster-bomb")
    assert len(reqs) == 4  # 2 * 2
    assert {r.payloads for r in reqs} == {(b"a", b"1"), (b"a", b"2"), (b"b", b"1"), (b"b", b"2")}
    r_a1 = next(r for r in reqs if r.payloads == (b"a", b"1"))
    assert b"u=a" in r_a1.raw and b"p=1" in r_a1.raw


def test_returns_concrete_requests() -> None:
    pu, pp = _positions()
    reqs = expand(BASE, [pu, pp], [[b"a", b"b"], [b"1", b"2"]], "cluster-bomb")
    assert all(isinstance(r, ConcreteRequest) for r in reqs)


def test_expand_rejects_zero_positions() -> None:
    """MED: with no positions, battering-ram/cluster-bomb silently emitted unmodified copies
    of the base request — a fuzz campaign that fires N identical no-op requests. Reject it."""
    base = b"GET /?x=v HTTP/1.1\r\nHost: h\r\n\r\n"
    for attack in ("sniper", "battering-ram", "pitchfork", "cluster-bomb"):
        raised = False
        try:
            expand(base, [], [[b"a", b"b"]], attack)
        except ValueError:
            raised = True
        assert raised, f"{attack} must reject zero positions, not emit unmodified requests"


# --- [02] apply_subs must INSERT Content-Length when header is absent ---


def test_apply_subs_inserts_content_length_when_absent() -> None:
    """[02] POST with body but no Content-Length header must have C-L inserted after substitution."""
    base = (
        b"POST /api HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=1"
    )
    # Fuzz the body value; no Content-Length present in the base request
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    assert b"Content-Length:" in out
    # The body is "id=9999" (7 bytes)
    assert b"Content-Length: 7\r\n" in out
    assert out.endswith(b"id=9999")


def test_apply_subs_still_updates_existing_content_length() -> None:
    """[02] Regression: existing Content-Length must still be updated (not duplicated)."""
    base = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Length: 4\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=1"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    # Exactly one Content-Length header in output
    assert out.count(b"Content-Length:") == 1
    assert b"Content-Length: 7\r\n" in out


# --- [01] Overlapping positions must raise PosError(POS_OVERLAP) before substitution ---


def test_overlapping_positions_raise_pos_overlap() -> None:
    """[01] Two positions that overlap byte ranges must raise PosError('POS_OVERLAP')
    from apply_subs before any substitution is applied."""
    from bp.pos import PosError

    # offset:0-10 and offset:5-15 overlap (5-10 is shared)
    base = b"GET /api/endpoint HTTP/1.1\r\nHost: h\r\n\r\n"
    p1 = Position(0, 10, "offset:0-10")
    p2 = Position(5, 15, "offset:5-15")
    with pytest.raises(PosError) as ei:
        apply_subs(base, [Sub(p1, b"AAAA"), Sub(p2, b"BBBB")])
    assert ei.value.code == "POS_OVERLAP"


def test_adjacent_positions_are_not_overlap() -> None:
    """[01] Adjacent (touching but non-overlapping) positions must NOT raise POS_OVERLAP."""
    base = b"AAAA-BBBB"
    p1 = Position(0, 4, "offset:0-4")
    p2 = Position(4, 9, "offset:4-9")
    # Should not raise
    out = apply_subs(base, [Sub(p1, b"XX"), Sub(p2, b"YY")])
    assert out == b"XXYY"


def test_identical_positions_raise_pos_overlap() -> None:
    """[01] Two positions with the same byte range are a degenerate overlap."""
    from bp.pos import PosError

    base = b"AAAA-BBBB"
    p1 = Position(0, 4, "offset:0-4")
    p2 = Position(0, 4, "offset:0-4")
    with pytest.raises(PosError) as ei:
        apply_subs(base, [Sub(p1, b"X"), Sub(p2, b"Y")])
    assert ei.value.code == "POS_OVERLAP"


# --- [02] _recompute_content_length must not leave OWS around the new value ---


def test_content_length_rewrite_strips_leading_ows() -> None:
    """[02] Original 'Content-Length:  5 ' (leading OWS) after body change must become
    exactly 'Content-Length: <N>\\r\\n' with no residual whitespace."""
    # Build request manually with OWS around the value
    base = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Length:  5 \r\n"  # leading + trailing OWS
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=AB"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    # Must be exactly one space before digits, no trailing space
    assert b"Content-Length: 7\r\n" in out
    # Must not have double-space or trailing space before CRLF
    assert b"Content-Length:  " not in out
    assert b"Content-Length: 7 \r\n" not in out


def test_content_length_rewrite_strips_trailing_ows() -> None:
    """[02] OWS after the digit (e.g. 'Content-Length: 5 ') must also be removed."""
    base = (
        b"POST /api HTTP/1.1\r\n"
        b"Content-Length: 5 \r\n"  # trailing OWS only
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=AB"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    assert b"Content-Length: 7\r\n" in out
    assert b"Content-Length: 7 \r\n" not in out


# --- [01] duplicate Content-Length headers must be collapsed to exactly one ---


def test_duplicate_content_length_collapsed_to_one() -> None:
    """[01] A request with two Content-Length headers after body substitution must have
    exactly ONE Content-Length with the correct new value — no stale second header."""
    base = (
        b"POST /smuggle HTTP/1.1\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=AB"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    # Exactly one Content-Length header in output
    assert out.count(b"Content-Length:") == 1
    # That header must have the correct new value (body is "id=9999" = 7 bytes)
    assert b"Content-Length: 7\r\n" in out


def test_duplicate_content_length_stale_value_absent() -> None:
    """[01] The stale old value must not appear in the output header block at all."""
    base = (
        b"POST /smuggle HTTP/1.1\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 99\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=AB"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    # Only one Content-Length header
    assert out.count(b"Content-Length:") == 1
    # The correct value is present
    assert b"Content-Length: 7\r\n" in out
    # The stale value 99 must not be present as a Content-Length line
    assert b"Content-Length: 99" not in out


def test_triple_content_length_collapsed_to_one() -> None:
    """[01] Even three Content-Length headers must be collapsed to exactly one."""
    base = (
        b"POST /smuggle HTTP/1.1\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=AB"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    assert out.count(b"Content-Length:") == 1
    assert b"Content-Length: 7\r\n" in out


# --- bounded, restartable planning -------------------------------------------


def test_expand_is_restartable_without_materializing_a_list() -> None:
    pu, pp = _positions()
    plan = expand(BASE, [pu, pp], [[b"a", b"b"], [b"1", b"2"]], "cluster-bomb")

    assert not isinstance(plan, list)
    assert len(plan) == 4
    assert [item.payloads for item in plan] == [item.payloads for item in plan]


def test_expand_rejects_over_limit_cardinality_before_iteration() -> None:
    pu, pp = _positions()
    with pytest.raises(ValueError, match="10,000"):
        expand(
            BASE,
            [pu, pp],
            [[b"a"] * 101, [b"b"] * 100],
            "cluster-bomb",
        )


def test_expand_accepts_exact_limit_without_materializing_requests() -> None:
    pu, pp = _positions()
    plan = expand(
        BASE,
        [pu, pp],
        [[b"a"] * 100, [b"b"] * 100],
        "cluster-bomb",
    )
    assert len(plan) == 10_000


def test_sniper_per_position_lists_still_enforce_the_global_cap() -> None:
    pu, pp = _positions()

    with pytest.raises(ValueError, match="10,000"):
        expand(BASE, [pu, pp], [[b"a"] * 5_001, [b"b"] * 5_000], "sniper")


def test_custom_sequence_cannot_underreport_past_the_global_cap() -> None:
    position = resolve_pos(BASE, "query:u")
    payloads = _UnderreportedPayloads([b"x"] * 10_001)

    with pytest.raises(ValueError, match="10,000"):
        expand(BASE, [position], [payloads], "sniper")


def test_expand_rejects_overlapping_plan_even_for_sniper() -> None:
    p = resolve_pos(BASE, "query:u")
    with pytest.raises(PosError) as exc_info:
        expand(BASE, [p, p], [[b"a"]], "sniper")
    assert exc_info.value.code == "POS_OVERLAP"


def test_expand_rejects_out_of_range_position_before_iteration() -> None:
    with pytest.raises(PosError):
        expand(BASE, [Position(0, len(BASE) + 1, "offset:bad")], [[b"x"]], "sniper")


@pytest.mark.parametrize("newline", [b"\r\n", b"\n"])
def test_empty_body_replacement_sets_one_zero_content_length(newline: bytes) -> None:
    base = newline.join(
        [
            b"POST / HTTP/1.1",
            b"Host: example.test",
            b"Content-Length: 3",
            b"Content-Type: application/octet-stream",
            b"",
            b"abc",
        ]
    )
    start = len(base) - 3
    out = apply_subs(base, [Sub(Position(start, len(base), "offset:body"), b"")])

    assert out.endswith(newline + newline)
    assert out.lower().count(b"content-length:") == 1
    assert b"Content-Length: 0" + newline in out


def test_body_replacement_content_length_uses_utf8_byte_count() -> None:
    base = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nx"
    pos = Position(len(base) - 1, len(base), "offset:body")

    out = apply_subs(base, [Sub(pos, "🙂".encode())])

    assert out.endswith("🙂".encode())
    assert b"Content-Length: 4\r\n" in out


def test_body_nul_replacement_repairs_content_length() -> None:
    base = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\nx"
    pos = Position(len(base) - 1, len(base), "offset:body")

    out = apply_subs(base, [Sub(pos, b"a\x00b")])

    assert out.endswith(b"a\x00b")
    assert b"Content-Length: 3\r\n" in out


@pytest.mark.parametrize(
    ("element", "expected"),
    [
        ('""', b""),
        ('" "', b" "),
        ('"A\\nB"', b"A\nB"),
        ('"caf\\u00e9 \\u03b1\\u03b2\\u03b3 \\ud83d\\ude00"', "café αβγ 😀".encode()),
        ('"\\u0000"', b"\x00"),
        ('{"b64":"/wBhCg=="}', b"\xff\x00a\n"),
    ],
)
def test_versioned_payload_file_represents_exact_bytes(
    tmp_path: Path, element: str, expected: bytes
) -> None:
    payload_file = tmp_path / "payloads.txt"
    payload_file.write_bytes(b"#!bp-payloads-json-v1\n[" + element.encode("ascii") + b"]")

    assert load_payload_file(payload_file) == [expected]


def test_legacy_payload_file_behavior_is_unchanged(tmp_path: Path) -> None:
    payload_file = tmp_path / "legacy.txt"
    payload_file.write_bytes(b"A\n\n   \nB\r\n")

    assert load_payload_file(payload_file) == [b"A", b"B"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"#!bp-payloads-json-v1\nnot-json", "valid UTF-8 JSON"),
        (b"#!bp-payloads-json-v1\n{}", "JSON array"),
        (b"#!bp-payloads-json-v1\n[7]", r"payload\[0\]"),
        (b'#!bp-payloads-json-v1\n[{"b64":"***"}]', r"payload\[0\].*base64"),
        (b'#!bp-payloads-json-v1\n[{"b64":"YR=="}]', r"payload\[0\].*base64"),
        (
            b'#!bp-payloads-json-v1\n[{"b64":"YQ==","b\\u00364":"Yg=="}]',
            r"payload\[0\].*duplicate.*b64",
        ),
        (b'#!bp-payloads-json-v1\n[{"b64":"YQ==","extra":1}]', r"payload\[0\]"),
    ],
)
def test_versioned_payload_file_rejects_malformed_content(
    tmp_path: Path, content: bytes, message: str
) -> None:
    payload_file = tmp_path / "bad.txt"
    payload_file.write_bytes(content)

    with pytest.raises(ValueError, match=message):
        load_payload_file(payload_file)


def test_apply_subs_rejects_negative_and_reversed_positions() -> None:
    for position in (
        Position(-1, 1, "offset:negative"),
        Position(3, 2, "offset:reversed"),
    ):
        with pytest.raises(PosError):
            apply_subs(BASE, [Sub(position, b"x")])
