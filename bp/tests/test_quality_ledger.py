from __future__ import annotations

import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "quality" / "confirmed-defects.yaml"
EXPECTED_IDS = {f"D{index:02d}" for index in range(1, 19)}
ALLOWED_STATUS = {"planned", "tested", "verified"}


def _records() -> list[dict[str, object]]:
    # JSON is a strict YAML 1.2 subset, so this stays machine-readable without
    # adding a runtime parser dependency solely for the quality ledger.
    document = json.loads(LEDGER.read_text(encoding="utf-8"))
    assert document["schemaVersion"] == 1
    records = document["defects"]
    assert isinstance(records, list)
    return records


def test_confirmed_defect_ledger_is_complete_and_well_formed() -> None:
    records = _records()
    assert {record["id"] for record in records} == EXPECTED_IDS

    for record in records:
        assert record["status"] in ALLOWED_STATUS
        assert isinstance(record["invariant"], str) and record["invariant"].strip()
        assert isinstance(record["slice"], str) and record["slice"].strip()
        assert isinstance(record["compatibility"], str) and record["compatibility"].strip()

        tests = record["tests"]
        contracts = record["contracts"]
        assert isinstance(tests, list) and tests
        assert isinstance(contracts, list) and contracts
        for relative_path in [*tests, *contracts]:
            assert isinstance(relative_path, str)
            assert (ROOT / relative_path).exists(), f"missing ledger reference: {relative_path}"


def test_release_gate_requires_verified_records_when_enabled() -> None:
    records = _records()
    incomplete = [str(record["id"]) for record in records if record["status"] != "verified"]
    if os.environ.get("BURPCTL_REQUIRE_ALL_VERIFIED") == "1":
        assert not incomplete, f"unverified confirmed defects: {', '.join(incomplete)}"
