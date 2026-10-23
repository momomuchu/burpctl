"""Validator for the frozen command audit oracle manifest."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Final, Mapping, cast

import pytest

MANIFEST: Final[Path] = (
    Path(__file__).resolve().parents[2] / "quality" / "command-audit" / "oracles.json"
)
KINDS: Final[set[str]] = {"F", "G", "L"}
TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\{\{(?:PORT|PAYLOAD_FILE|CID|SID|OPID)\}\}")


class ManifestError(ValueError):
    """Invalid oracle manifest."""


def _canonical_without_hash(row: dict[str, object]) -> bytes:
    copy = json.loads(json.dumps(row))
    seal = copy["seal"]
    assert isinstance(seal, dict)
    seal["hash"] = ""
    return json.dumps(copy, separators=(",", ":"), sort_keys=True).encode()


def materialize_argv(row: dict[str, object], bindings: Mapping[str, str]) -> list[str]:
    """Bind fixture tokens before invocation and reject unresolved templates."""
    template = row.get("argv_template")
    if not isinstance(template, list) or not all(isinstance(part, str) for part in template):
        raise ManifestError(f"{row.get('id')}: missing argv_template")
    rendered: list[str] = []
    for part in template:
        value = part
        for token, replacement in bindings.items():
            value = value.replace("{{" + token + "}}", replacement)
        if TOKEN_RE.search(value):
            raise ManifestError(f"{row.get('id')}: unresolved template token in argv: {value}")
        rendered.append(value)
    return rendered


def seal_for_invocation(row: dict[str, object], bindings: Mapping[str, str]) -> dict[str, object]:
    """Return a sealed invocation record before executing argv."""
    sealed = cast(dict[str, object], json.loads(json.dumps(row)))
    sealed["argv"] = materialize_argv(row, bindings)
    seal = sealed["seal"]
    assert isinstance(seal, dict)
    seal["sealed"] = True
    seal["hash"] = hashlib.sha256(_canonical_without_hash(sealed)).hexdigest()
    return sealed


def validate_manifest(path: Path) -> tuple[int, int, int, int]:
    """Validate counts, sources, expected streams/effects, seals, and temporal order."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    rows = data.get("rows")
    if not isinstance(rows, list):
        raise ManifestError("missing rows")
    environment = data.get("environment")
    if not isinstance(environment, dict) or environment.get("BP_AGENT") != "1":
        raise ManifestError("missing BP_AGENT=1 audit environment")
    sealed_at = data.get("sealed_at")
    if not isinstance(sealed_at, str):
        raise ManifestError("missing manifest sealed_at")
    try:
        manifest_sealed_at = datetime.fromisoformat(sealed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ManifestError("invalid manifest sealed_at") from exc
    if manifest_sealed_at.year < 2026:
        raise ManifestError("unrealistic manifest sealed_at")
    ids: set[str] = set()
    counts = {"F": 0, "G": 0, "L": 0}
    bindings = {
        "PORT": "18089",
        "PAYLOAD_FILE": "/tmp/burpctl-audit/PAYLOAD_FILE",
        "CID": "cid-001",
        "SID": "sid-001",
        "OPID": "op-001",
    }
    for row in rows:
        if not isinstance(row, dict):
            raise ManifestError("row is not an object")
        row_id, kind = row.get("id"), row.get("kind")
        if not isinstance(row_id, str) or row_id in ids:
            raise ManifestError(f"duplicate or missing id: {row_id}")
        if kind not in KINDS:
            raise ManifestError(f"{row_id}: invalid kind")
        ids.add(row_id)
        counts[kind] += 1
        authority = row.get("authority")
        sources = authority.get("sources", []) if isinstance(authority, dict) else []
        if (
            not isinstance(sources, list)
            or not sources
            or not all(
                isinstance(source, str) and re.fullmatch(r"[^:]+:\d+", source) for source in sources
            )
        ):
            raise ManifestError(f"{row_id}: missing source citation")
        expected = row.get("expected")
        if not isinstance(expected, dict) or not all(
            key in expected for key in ("exit", "stdout", "stderr", "effect")
        ):
            raise ManifestError(f"{row_id}: incomplete expected exit/streams/effect")
        if not all(isinstance(expected[key], dict) for key in ("stdout", "stderr", "effect")):
            raise ManifestError(f"{row_id}: malformed expected streams/effect")
        seal = row.get("seal")
        if (
            not isinstance(seal, dict)
            or seal.get("sealed") is not True
            or not isinstance(seal.get("expected_at"), str)
            or not seal.get("hash")
        ):
            raise ManifestError(f"{row_id}: unsealed expectation")
        if seal["expected_at"] != sealed_at:
            raise ManifestError(f"{row_id}: seal timestamp differs from manifest seal")
        actual = row.get("actual")
        if (
            isinstance(actual, dict)
            and isinstance(actual.get("observed_at"), str)
            and actual["observed_at"] < seal["expected_at"]
        ):
            raise ManifestError(f"{row_id}: actual timestamp precedes expected timestamp")
        materialize_argv(row, bindings)
        contrast = row.get("contrast")
        if not isinstance(contrast, dict):
            raise ManifestError(f"{row_id}: missing contrast")
        contrast_template = contrast.get("argv_template")
        if row["kind"] == "G" and (
            not isinstance(contrast_template, list) or contrast_template == row["argv_template"]
        ):
            raise ManifestError(f"{row_id}: contrast must be a distinct argv")
        if isinstance(contrast_template, list):
            contrast_row: dict[str, object] = {"id": row_id, "argv_template": contrast_template}
            materialize_argv(contrast_row, bindings)
        expected_hash = seal["hash"]
        if (
            not isinstance(expected_hash, str)
            or expected_hash != hashlib.sha256(_canonical_without_hash(row)).hexdigest()
        ):
            raise ManifestError(f"{row_id}: invalid seal hash")
    if counts != {"F": 18, "G": 7, "L": 32}:
        raise ManifestError(f"wrong inventory counts: {counts}")
    if len(ids) != 57:
        raise ManifestError(f"expected 57 unique IDs, got {len(ids)}")
    return counts["F"], counts["G"], counts["L"], sum(counts.values())


def test_manifest_is_complete_and_sealed() -> None:
    assert validate_manifest(MANIFEST) == (18, 7, 32, 57)


def test_materialization_replaces_templates_before_seal() -> None:
    data = json.loads(MANIFEST.read_text())
    row = next(item for item in data["rows"] if item["id"] == "F04")
    sealed = seal_for_invocation(
        row,
        {
            "PORT": "19123",
            "PAYLOAD_FILE": "/tmp/fixture/payloads.txt",
            "CID": "cid-002",
            "SID": "sid-002",
            "OPID": "op-002",
        },
    )
    argv = sealed["argv"]
    assert isinstance(argv, list)
    assert argv[6] == "id=/tmp/fixture/payloads.txt"
    sealed_seal = sealed["seal"]
    original_seal = row["seal"]
    assert isinstance(sealed_seal, dict) and isinstance(original_seal, dict)
    assert sealed_seal["hash"] != original_seal["hash"]


def test_token_materialization_does_not_replace_substrings() -> None:
    row: dict[str, object] = {"id": "collision", "argv_template": ["PAYLOAD_FILE", "{{PORT}}"]}
    assert materialize_argv(row, {"PORT": "19123", "PAYLOAD_FILE": "/tmp/payloads.txt"}) == [
        "PAYLOAD_FILE",
        "19123",
    ]


def test_tampered_expected_or_hash_is_rejected(tmp_path: Path) -> None:
    data = json.loads(MANIFEST.read_text())
    row = next(item for item in data["rows"] if item["id"] == "F01")
    row["expected"]["exit"] = 99
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError, match="invalid seal hash"):
        validate_manifest(path)


def test_transport_contrast_uses_cli_exit_three() -> None:
    data = json.loads(MANIFEST.read_text())
    row = next(item for item in data["rows"] if item["id"] == "F01")
    assert row["contrast"]["exit"] == 3


def test_manifest_seal_timestamp_is_realistic_and_shared() -> None:
    data = json.loads(MANIFEST.read_text())
    sealed_at = data["sealed_at"]
    assert datetime.fromisoformat(sealed_at.replace("Z", "+00:00")).year >= 2026
    assert {row["seal"]["expected_at"] for row in data["rows"]} == {sealed_at}


def test_usage_and_unsupported_normals_match_current_contract() -> None:
    data = json.loads(MANIFEST.read_text())
    rows = {row["id"]: row for row in data["rows"]}
    assert all(rows[f"G0{index}"]["expected"]["exit"] == 2 for index in range(1, 8))
    for row_id in ("L05", "L14", "L15"):
        assert rows[row_id]["expected"]["exit"] == 1
        assert rows[row_id]["expected"]["effect"]["effect"] == "zero server effect"


def test_matrix_preserves_spaced_and_json_argv_shapes() -> None:
    data = json.loads(MANIFEST.read_text())
    rows = {row["id"]: row for row in data["rows"]}
    assert rows["F11"]["argv"] == ["bp", "encode", "a b", "--enc", "url"]
    assert rows["L21"]["argv"][-1] == '{"audit":{"enabled":true}}'


def test_json_rows_require_explicit_agent_environment_and_group_help_contrasts() -> None:
    data = json.loads(MANIFEST.read_text())
    assert data["environment"]["BP_AGENT"] == "1"
    for row in data["rows"]:
        if row["kind"] == "G":
            assert row["contrast"]["argv_template"][-1] == "--help"
            assert row["contrast"]["exit"] == 0


def test_missing_source_is_rejected(tmp_path: Path) -> None:
    data = json.loads(MANIFEST.read_text())
    next(item for item in data["rows"] if item["id"] == "F01")["authority"]["sources"] = []
    path = tmp_path / "missing-source.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError, match=r"F01: missing source"):
        validate_manifest(path)


def test_actual_before_expected_is_rejected(tmp_path: Path) -> None:
    data = json.loads(MANIFEST.read_text())
    next(item for item in data["rows"] if item["id"] == "F01")["actual"] = {
        "observed_at": "2026-10-22T23:59:59Z"
    }
    path = tmp_path / "late-oracle.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ManifestError, match="actual timestamp precedes"):
        validate_manifest(path)


def main(argv: list[str]) -> int:
    try:
        f, g, leaf_count, total = validate_manifest(Path(argv[1]) if len(argv) > 1 else MANIFEST)
    except ManifestError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"VALID: F={f} G={g} L={leaf_count} total={total} zero unsealed rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
