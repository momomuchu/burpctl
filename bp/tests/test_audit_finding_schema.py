"""Schema and deduplication checks for command-audit findings."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from collections.abc import Mapping
from typing import Final

import pytest


ROOT: Final = Path(__file__).resolve().parents[2]
INDEX: Final = ROOT / "quality" / "command-audit" / "defect-index.json"
LEDGER: Final = ROOT / "quality" / "confirmed-defects.yaml"
IDS: Final = {f"D{number:02d}" for number in range(1, 19)}
STATUSES: Final = {"confirmed", "refuted", "inconclusive"}
HEX_SHA: Final = re.compile(r"^[0-9a-f]{40,64}$")


class FindingSchemaError(ValueError):
    """Raised when a finding cannot support its claimed status."""


def _index() -> dict[str, object]:
    with INDEX.open(encoding="utf-8") as stream:
        loaded = json.load(stream)
    assert isinstance(loaded, dict)
    return loaded


def _required(mapping: Mapping[str, object], path: str) -> object:
    value: object = mapping
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise FindingSchemaError(f"missing {path}")
        value = value[part]
    if value in (None, "", []):
        raise FindingSchemaError(f"empty {path}")
    return value


def classify_finding(finding: Mapping[str, object], index: dict[str, object]) -> str:
    """Validate a finding and classify it against the verified defect index."""
    status = finding.get("status")
    if status not in STATUSES:
        raise FindingSchemaError("status must be confirmed, refuted, or inconclusive")
    if status != "confirmed":
        return str(status)

    schema = index["findingSchema"]
    assert isinstance(schema, dict)
    required_paths = schema["requiredForConfirmed"]
    assert isinstance(required_paths, list)
    assert all(isinstance(path, str) for path in required_paths)
    for path in required_paths:
        _required(finding, path)
    evidence_paths = schema["requiredEvidence"]
    assert isinstance(evidence_paths, list)
    assert all(isinstance(path, str) for path in evidence_paths)
    for path in evidence_paths:
        _required(finding, path)
    candidate_hash = _required(finding, "candidateHash")
    if not isinstance(candidate_hash, str) or not HEX_SHA.fullmatch(candidate_hash):
        raise FindingSchemaError("candidateHash must be a 40-64 character lowercase commit hash")
    if _required(finding, "oracle.sealed") is not True:
        raise FindingSchemaError("oracle.sealed must be true")
    if not isinstance(_required(finding, "actual.exitCode"), int):
        raise FindingSchemaError("actual.exitCode must be an integer")
    comparison = _required(finding, "comparison")
    if not isinstance(comparison, dict) or not isinstance(comparison.get("novelEffect"), bool):
        raise FindingSchemaError("comparison.novelEffect must be boolean")

    records = index["defects"]
    assert isinstance(records, list)
    duplicate = any(
        isinstance(record, dict)
        and record.get("invariant") == finding.get("invariant")
        and record.get("rootCause") == finding.get("rootCause")
        for record in records
    )
    if duplicate and comparison["novelEffect"] is False:
        return "existing-verified-or-regression"
    issue_paths = schema["issueReadiness"]
    assert isinstance(issue_paths, list)
    assert all(isinstance(path, str) for path in issue_paths)
    for path in issue_paths:
        _required(finding, path)
    if _required(finding, "issue.ready") is not True:
        raise FindingSchemaError("confirmed novel finding must be issue-ready")
    return "issue-ready"


def _novel_finding() -> dict[str, object]:
    """Build a complete candidate-bound finding for schema mutation tests."""
    return {
        "id": "N01",
        "status": "confirmed",
        "invariant": "new invariant",
        "rootCause": "new-root",
        "candidateHash": "b" * 40,
        "reproduction": {"command": "bp --version"},
        "oracle": {"sealed": True, "expected": {"exitCode": 0}},
        "actual": {"transcript": "stdout: 2.0.0", "exitCode": 1},
        "effects": {"evidence": "route log: zero effects"},
        "comparison": {"novelEffect": True, "matches": []},
        "regression": {"tests": ["bp/tests/test_audit_finding_schema.py"]},
        "issue": {"title": "Version command fails", "body": "reproduction", "ready": True},
    }


def test_index_contains_each_verified_ledger_defect_once() -> None:
    """The comparison index is complete and preserves the ledger's authority."""
    index = _index()
    records = index["defects"]
    assert isinstance(records, list)
    assert [record["id"] for record in records] == sorted(IDS)
    assert len(records) == len(IDS)
    assert all(record["status"] == "verified" for record in records)
    assert all(isinstance(record["invariant"], str) and record["invariant"] for record in records)
    assert all(isinstance(record["rootCause"], str) and record["rootCause"] for record in records)

    with LEDGER.open(encoding="utf-8") as stream:
        ledger = json.load(stream)
    assert isinstance(ledger, dict)
    ledger_records = ledger["defects"]
    assert isinstance(ledger_records, list)
    by_id = {record["id"]: record for record in ledger_records if isinstance(record, dict)}
    for record in records:
        source = by_id[record["id"]]
        assert record["invariant"] == source["invariant"]
        assert record["status"] == source["status"]
        assert record["tests"] == source["tests"]
        assert record["contracts"] == source["contracts"]


def test_confirmed_finding_requires_oracle_transcript_and_effect_evidence() -> None:
    """A claimed novel defect cannot be issue-ready from a title or suspicion alone."""
    finding: dict[str, object] = {"status": "confirmed", "candidateHash": "a" * 40}
    with pytest.raises(FindingSchemaError, match="missing"):
        classify_finding(finding, _index())


def test_confirmed_novel_finding_is_issue_ready() -> None:
    """A complete finding carries reproducible, candidate-bound evidence."""
    finding = _novel_finding()
    assert classify_finding(finding, _index()) == "issue-ready"


@pytest.mark.parametrize(
    "missing_path",
    [
        "reproduction.command",
        "oracle.expected",
        "actual.transcript",
        "actual.exitCode",
        "effects.evidence",
        "issue.title",
        "issue.body",
        "issue.ready",
    ],
)
def test_confirmed_finding_rejects_missing_nested_evidence(missing_path: str) -> None:
    """Every evidence and issue-readiness path is independently mandatory."""
    finding = deepcopy(_novel_finding())
    parent, leaf = missing_path.split(".")
    nested = finding[parent]
    assert isinstance(nested, dict)
    del nested[leaf]
    with pytest.raises(FindingSchemaError, match=f"missing {missing_path}"):
        classify_finding(finding, _index())


def test_d15_duplicate_scope_suspicion_is_not_issue_ready() -> None:
    """A D15-shaped suspicion without a novel effect remains an existing regression."""
    finding: dict[str, object] = {
        "id": "N02",
        "status": "confirmed",
        "invariant": "Scope mutation responses come from the engine and unimplementable complete listing/replacement never claim authority.",
        "rootCause": "montoya-controls",
        "candidateHash": "c" * 40,
        "reproduction": {"command": "bp scope list"},
        "oracle": {"sealed": True, "expected": {"exitCode": 4}},
        "actual": {"transcript": "HTTP 501 unsupported", "exitCode": 4},
        "effects": {"evidence": "scope engine unchanged"},
        "comparison": {"novelEffect": False, "matches": ["D15"]},
        "regression": {"tests": ["src/test/kotlin/com/burprest/services/TargetServiceTest.kt"]},
        "issue": {"title": "scope list suspicion", "body": "duplicate", "ready": False},
    }
    assert classify_finding(finding, _index()) == "existing-verified-or-regression"
