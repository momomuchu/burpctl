"""RED tests for A2 — the client-side fuzz engine (docs/ALGORITHMS.md §A2)."""

import pytest

from bp.fuzz import ConcreteRequest, Sub, apply_subs, expand
from bp.pos import Position, resolve_pos

# base with two single-char query values to fuzz; '_' marks each position.
BASE: bytes = b"GET /?u=_&p=_ HTTP/1.1\r\nHost: h\r\n\r\n"


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


def test_battering_ram_same_payload_all_positions() -> None:
    pu, pp = _positions()
    reqs = expand(BASE, [pu, pp], [[b"a", b"b", b"c"]], "battering-ram")
    assert len(reqs) == 3
    r = reqs[0]
    assert r.payloads == (b"a",)
    assert b"u=a" in r.raw and b"p=a" in r.raw


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
        b"Content-Length:  5 \r\n"   # leading + trailing OWS
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
        b"Content-Length: 5 \r\n"   # trailing OWS only
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"id=AB"
    )
    pos = resolve_pos(base, "body:id")
    out = apply_subs(base, [Sub(pos, b"9999")])
    assert b"Content-Length: 7\r\n" in out
    assert b"Content-Length: 7 \r\n" not in out
