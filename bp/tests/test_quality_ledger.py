from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "quality" / "confirmed-defects.yaml"
QUALITY_README = ROOT / "quality" / "README.md"
# Intentionally explicit: deriving the upper bound from the ledger would let a deleted
# tail record pass unnoticed. Advancing this number is a conscious completeness decision.
LAST_EXPECTED_ID = 73
EXPECTED_IDS = [f"D{index:02d}" for index in range(1, LAST_EXPECTED_ID + 1)]
_EVIDENCE_SET_IDS = {
    "historical": [f"D{index:02d}" for index in range(1, 19)],
    "live": [f"D{index:02d}" for index in range(19, 62)],
    "corrective": [f"D{index:02d}" for index in range(62, 71)],
    "acceptance": [f"D{index:02d}" for index in range(71, LAST_EXPECTED_ID + 1)],
}
EXPECTED_SCOPE = (
    "D01-D18 record the behavior-hardening pass at baseline 663bb56. "
    "D19-D61 record the live v2.0.0 campaign against Burp Suite Professional 2026.3.3 "
    "on 2026-09-04. D62-D70 record corrective defects R1-R9 found during adversarial review "
    f"of the v2.1.0 fix tree. D71-D{LAST_EXPECTED_ID:02d} record defects in the live acceptance "
    "and quality-ledger gates discovered while replaying that tree. This is not a claim that "
    "unknown defects cannot exist."
)
ALLOWED_STATUS = {"confirmed", "fixed", "verified", "unconfirmed", "rejected"}
ALLOWED_SEVERITY = {"critical", "high", "medium", "low"}
_README_SUMMARY_START = "<!-- ledger-summary:start -->"
_README_SUMMARY_END = "<!-- ledger-summary:end -->"
_BASE_FIELDS = {
    "id",
    "invariant",
    "slice",
    "tests",
    "contracts",
    "compatibility",
    "status",
}
_CAMPAIGN_FIELDS = _BASE_FIELDS | {
    "reproduction",
    "observed",
    "expected",
    "severity",
    "discoveringLane",
    "evidence",
}
_OPTIONAL_FIELDS = {"fixEvidence", "verificationNotes", "verificationEvidence"}
_VERIFICATION_EVIDENCE_KEYS = {"live", "causalRed", "nonAuthorReview"}
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TRIVIAL_EVIDENCE = {"yes", "true", "pass", "passed", "n/a", "na", "none", "not established"}


def _records() -> list[dict[str, Any]]:
    # JSON is a strict YAML 1.2 subset, so this stays machine-readable without
    # adding a runtime parser dependency solely for the quality ledger.
    document: Any = json.loads(LEDGER.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    assert set(document) == {"schemaVersion", "scope", "defects"}
    assert document.get("schemaVersion") == 1
    assert document.get("scope") == EXPECTED_SCOPE, (
        "ledger scope must match the enforced evidence sets"
    )
    records = document.get("defects")
    assert isinstance(records, list)
    assert all(isinstance(record, dict) for record in records)
    return records


def _nonempty_text(record: dict[str, Any], field: str) -> None:
    value = record.get(field)
    assert isinstance(value, str) and value.strip(), f"{record.get('id')}: invalid {field}"


def _path_list(record: dict[str, Any], field: str) -> None:
    values = record.get(field)
    assert isinstance(values, list) and values, f"{record.get('id')}: invalid {field}"
    root = ROOT.resolve()
    for relative_path in values:
        assert isinstance(relative_path, str) and relative_path.strip()
        path = Path(relative_path)
        assert not path.is_absolute(), f"{record.get('id')}: {field} path must be relative"
        resolved = (root / path).resolve()
        assert resolved.is_relative_to(root), f"{record.get('id')}: {field} path escapes repository"
        assert resolved.is_file(), f"missing ledger file reference: {relative_path}"


def _evidence_text(value: Any, field: str, record_id: str) -> str:
    assert isinstance(value, str) and len(value.strip()) >= 12, f"{record_id}: invalid {field}"
    assert value.strip().lower() not in _TRIVIAL_EVIDENCE, f"{record_id}: vacuous {field}"
    return value


def _repository_file(value: Any, field: str, record_id: str, *, root: Path = ROOT) -> Path:
    text = _evidence_text(value, field, record_id)
    path = Path(text)
    assert not path.is_absolute(), f"{record_id}: {field} must be repository-relative"
    resolved_root = root.resolve()
    resolved = (resolved_root / path).resolve()
    assert resolved.is_relative_to(resolved_root), f"{record_id}: {field} escapes repository"
    assert resolved.is_file(), f"{record_id}: missing {field}: {text}"
    return resolved


def _verification_artifact(value: Any, field: str, record_id: str, *, root: Path) -> Path:
    text = _evidence_text(value, field, record_id)
    path = Path(text)
    assert path.parts[:2] == ("quality", "evidence"), (
        f"{record_id}: {field} must be under quality/evidence"
    )
    assert path.suffix == ".json", f"{record_id}: {field} must be a JSON receipt"
    resolved = _repository_file(text, field, record_id, root=root)
    receipt_root = (root.resolve() / "quality" / "evidence").resolve()
    assert resolved.is_relative_to(receipt_root), f"{record_id}: {field} escapes quality/evidence"
    return resolved


def _matching_sha256(path: Path, value: Any, field: str, record_id: str) -> None:
    assert isinstance(value, str) and _SHA256.fullmatch(value), f"{record_id}: invalid {field}"
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert value == actual, f"{record_id}: {field} does not match artifact bytes"


def _receipt_payload(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in evidence.items()
        if key not in {"artifact", "artifactSha256", "reviewCommit"}
    }


def _validate_receipt_content(
    path: Path,
    *,
    kind: str,
    record_id: str,
    evidence: dict[str, Any],
) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{record_id}: {kind} artifact is not a JSON receipt") from exc
    expected = {
        "schemaVersion": 1,
        "defectId": record_id,
        "kind": kind,
        "evidence": _receipt_payload(evidence),
    }
    assert document == expected, f"{record_id}: {kind} artifact is not bound to its receipt fields"


def _git_bytes(*args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, (
        f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', errors='replace').strip()}"
    )
    return result.stdout


def _commit_author_identity(commit: Any, field: str, record_id: str) -> tuple[str, str]:
    assert isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit), (
        f"{record_id}: invalid {field}"
    )
    lines = _git_bytes("show", "-s", "--format=%H%n%an%n%ae", commit).decode().splitlines()
    assert len(lines) >= 3 and lines[0] == commit, f"{record_id}: {field} is not an exact commit"
    name, email = lines[1:3]
    assert name.strip(), f"{record_id}: {field} has no author name"
    assert "@" in email, f"{record_id}: {field} has no author email"
    return name.strip().casefold(), email.casefold()


def _git_is_ancestor(ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", ancestor, descendant],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _validate_non_author_review_identity(
    review: dict[str, Any],
    *,
    artifact: Path,
    artifact_root: Path,
    record_id: str,
    implementation_paths: list[str],
    regression_paths: list[str],
) -> None:
    author_commit = review["authorCommit"]
    review_commit = review["reviewCommit"]
    _commit_author_identity(author_commit, "nonAuthorReview.authorCommit", record_id)
    _commit_author_identity(review_commit, "nonAuthorReview.reviewCommit", record_id)
    author_lane = review["authorLane"]
    reviewer_lane = review["reviewerLane"]
    assert isinstance(author_lane, str) and len(author_lane.strip()) >= 3, (
        f"{record_id}: invalid nonAuthorReview.authorLane"
    )
    assert isinstance(reviewer_lane, str) and len(reviewer_lane.strip()) >= 3, (
        f"{record_id}: invalid nonAuthorReview.reviewerLane"
    )
    assert reviewer_lane.strip().casefold() != author_lane.strip().casefold(), (
        f"{record_id}: non-author review requires distinct attested lanes"
    )
    assert _git_is_ancestor(author_commit, review_commit), (
        f"{record_id}: review commit must descend from the implementation commit"
    )

    author_paths = set(
        _git_bytes("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", author_commit)
        .decode()
        .splitlines()
    )
    correction_paths = [*implementation_paths, *regression_paths]
    assert set(correction_paths).issubset(author_paths), (
        f"{record_id}: implementation commit must contain every implementation and regression path"
    )
    for correction_path in correction_paths:
        committed_file = _git_bytes("show", f"{author_commit}:{correction_path}")
        current_file = (ROOT / correction_path).read_bytes()
        assert committed_file == current_file, (
            f"{record_id}: current correction differs from the identified implementation commit"
        )

    artifact_path = str(artifact.relative_to(artifact_root.resolve()))
    changed_paths = set(
        _git_bytes("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", review_commit)
        .decode()
        .splitlines()
    )
    assert changed_paths == {artifact_path}, (
        f"{record_id}: review commit must be receipt-only and must not author the correction"
    )
    committed_bytes = _git_bytes("show", f"{review_commit}:{artifact_path}")
    assert committed_bytes == artifact.read_bytes(), (
        f"{record_id}: current review receipt differs from the identified review commit"
    )


def _validate_verification_evidence(record: dict[str, Any], *, artifact_root: Path = ROOT) -> None:
    record_id = str(record.get("id"))
    evidence = record.get("verificationEvidence")
    assert isinstance(evidence, dict), f"{record_id}: verified requires verificationEvidence"
    assert set(evidence) == _VERIFICATION_EVIDENCE_KEYS, (
        f"{record_id}: verificationEvidence requires exactly live, causalRed, nonAuthorReview"
    )

    live = evidence["live"]
    assert isinstance(live, dict) and set(live) == {
        "artifact",
        "artifactSha256",
        "case",
        "observedAt",
        "binarySha256",
        "oracle",
        "outcome",
    }, f"{record_id}: invalid live verification evidence"
    live_artifact = _verification_artifact(
        live["artifact"], "live.artifact", record_id, root=artifact_root
    )
    _matching_sha256(live_artifact, live["artifactSha256"], "live.artifactSha256", record_id)
    _validate_receipt_content(live_artifact, kind="live", record_id=record_id, evidence=live)
    assert isinstance(live["binarySha256"], str) and _SHA256.fullmatch(live["binarySha256"]), (
        f"{record_id}: invalid live.binarySha256"
    )
    _evidence_text(live["case"], "live.case", record_id)
    _evidence_text(live["oracle"], "live.oracle", record_id)
    assert live["outcome"] == "pass", f"{record_id}: live outcome must be pass"
    assert isinstance(live["observedAt"], str)
    observed_at = datetime.fromisoformat(live["observedAt"].replace("Z", "+00:00"))
    assert observed_at.tzinfo is not None, f"{record_id}: live.observedAt needs timezone"

    causal_red = evidence["causalRed"]
    assert isinstance(causal_red, dict) and set(causal_red) == {
        "artifact",
        "artifactSha256",
        "test",
        "failure",
        "observedAt",
        "redCommand",
        "redOutcome",
        "greenCommand",
        "greenOutcome",
    }, f"{record_id}: invalid causal RED evidence"
    red_artifact = _verification_artifact(
        causal_red["artifact"], "causalRed.artifact", record_id, root=artifact_root
    )
    _matching_sha256(
        red_artifact, causal_red["artifactSha256"], "causalRed.artifactSha256", record_id
    )
    _validate_receipt_content(
        red_artifact, kind="causalRed", record_id=record_id, evidence=causal_red
    )
    test_path = _repository_file(causal_red["test"], "causalRed.test", record_id)
    assert test_path.suffix in {".py", ".kt"}, f"{record_id}: causalRed.test must be executable"
    test_reference = str(test_path.relative_to(ROOT.resolve()))
    assert test_reference in record.get("tests", []), (
        f"{record_id}: causalRed.test must be one of the record's regression references"
    )
    _evidence_text(causal_red["failure"], "causalRed.failure", record_id)
    _evidence_text(causal_red["redCommand"], "causalRed.redCommand", record_id)
    _evidence_text(causal_red["greenCommand"], "causalRed.greenCommand", record_id)
    assert causal_red["redOutcome"] == "assertion-failed", (
        f"{record_id}: causalRed.redOutcome must be assertion-failed"
    )
    assert causal_red["greenOutcome"] == "pass", f"{record_id}: causalRed.greenOutcome must be pass"
    assert isinstance(causal_red["observedAt"], str)
    red_observed_at = datetime.fromisoformat(causal_red["observedAt"].replace("Z", "+00:00"))
    assert red_observed_at.tzinfo is not None, f"{record_id}: causalRed.observedAt needs timezone"

    review = evidence["nonAuthorReview"]
    assert isinstance(review, dict) and set(review) == {
        "artifact",
        "artifactSha256",
        "authorCommit",
        "authorLane",
        "correctionKind",
        "implementationPaths",
        "reviewCommit",
        "reviewerLane",
        "reviewedAt",
        "verdict",
    }, f"{record_id}: invalid non-author review evidence"
    review_artifact = _verification_artifact(
        review["artifact"], "nonAuthorReview.artifact", record_id, root=artifact_root
    )
    _matching_sha256(
        review_artifact,
        review["artifactSha256"],
        "nonAuthorReview.artifactSha256",
        record_id,
    )
    _validate_receipt_content(
        review_artifact, kind="nonAuthorReview", record_id=record_id, evidence=review
    )
    assert review["verdict"] == "pass", f"{record_id}: non-author review verdict must be pass"
    implementation_paths = review["implementationPaths"]
    assert isinstance(implementation_paths, list) and implementation_paths, (
        f"{record_id}: non-author review needs implementationPaths"
    )
    assert all(isinstance(path, str) and path.strip() for path in implementation_paths), (
        f"{record_id}: invalid nonAuthorReview.implementationPaths"
    )
    test_references = {str(path) for path in record.get("tests", [])}
    correction_kind = review["correctionKind"]
    assert correction_kind in {"implementation", "test-only"}, (
        f"{record_id}: invalid nonAuthorReview.correctionKind"
    )
    if correction_kind == "implementation":
        assert any(path not in test_references for path in implementation_paths), (
            f"{record_id}: implementation correction needs a non-regression path"
        )
    else:
        assert record.get("slice") == "contracts-ci", (
            f"{record_id}: only contracts-ci defects may use test-only correctionKind"
        )
        assert set(implementation_paths).issubset(test_references), (
            f"{record_id}: test-only implementationPaths must be regression references"
        )
    for implementation_path in implementation_paths:
        _repository_file(implementation_path, "nonAuthorReview.implementationPaths", record_id)
    assert isinstance(review["reviewedAt"], str)
    reviewed_at = datetime.fromisoformat(review["reviewedAt"].replace("Z", "+00:00"))
    assert reviewed_at.tzinfo is not None, f"{record_id}: nonAuthorReview.reviewedAt needs timezone"
    _validate_non_author_review_identity(
        review,
        artifact=review_artifact,
        artifact_root=artifact_root,
        record_id=record_id,
        implementation_paths=[str(path) for path in implementation_paths],
        regression_paths=[str(path) for path in record.get("tests", [])],
    )


def _validate_campaign_evidence(record: dict[str, Any]) -> None:
    reproduction = record.get("reproduction")
    assert isinstance(reproduction, list) and reproduction
    assert all(isinstance(command, str) and command.strip() for command in reproduction)

    _nonempty_text(record, "observed")
    _nonempty_text(record, "expected")
    _nonempty_text(record, "discoveringLane")

    evidence = record.get("evidence")
    assert isinstance(evidence, dict)
    artifact = evidence.get("artifact")
    cases = evidence.get("cases")
    assert isinstance(artifact, str) and artifact.strip()
    assert isinstance(cases, list) and cases
    assert all(isinstance(case, str) and case.strip() for case in cases)

    status = record["status"]
    severity = record.get("severity")
    if status in {"unconfirmed", "rejected"}:
        assert severity is None, f"{record['id']}: {status} entries must have null severity"
    else:
        assert severity in ALLOWED_SEVERITY, f"{record['id']}: invalid severity {severity!r}"


def _id_range(records: list[dict[str, Any]]) -> str:
    ids = [str(record["id"]) for record in records]
    assert ids
    return ids[0] if len(ids) == 1 else f"{ids[0]}–{ids[-1]}"


def _readme_summary(records: list[dict[str, Any]]) -> str:
    groups: dict[str, list[dict[str, Any]]] = {
        "historical": [],
        "live": [],
        "corrective": [],
        "acceptance": [],
    }
    for record in records:
        record_id = str(record["id"])
        if record_id in _EVIDENCE_SET_IDS["historical"]:
            group = "historical"
        elif record_id in _EVIDENCE_SET_IDS["live"]:
            group = "live"
        elif record_id in _EVIDENCE_SET_IDS["corrective"]:
            group = "corrective"
        elif record_id in _EVIDENCE_SET_IDS["acceptance"]:
            group = "acceptance"
        else:
            raise AssertionError(f"{record_id}: no evidence-set membership")
        groups[group].append(record)

    counts = Counter(str(record["status"]) for record in records)
    live_rejected = sum(record["status"] == "rejected" for record in groups["live"])
    live_total = len(groups["live"])
    rejected_ratio = 100 * live_rejected / live_total
    return "\n".join(
        [
            _README_SUMMARY_START,
            (
                "- Evidence-set ranges: "
                f"historical `{_id_range(groups['historical'])}`; "
                f"original live campaign `{_id_range(groups['live'])}`; "
                f"corrective review `{_id_range(groups['corrective'])}`; "
                f"quality-gate findings `{_id_range(groups['acceptance'])}`."
            ),
            (
                f"- Status counts: **{len(records)} total** — "
                f"**{counts['verified']} verified**, **{counts['confirmed']} confirmed**, "
                f"**{counts['fixed']} fixed**, **{counts['unconfirmed']} unconfirmed**, "
                f"and **{counts['rejected']} rejected**."
            ),
            (
                "- Original live-campaign adjudication: "
                f"**{live_rejected} rejected of {live_total} candidates "
                f"({rejected_ratio:.1f}%)**."
            ),
            _README_SUMMARY_END,
        ]
    )


def test_confirmed_defect_ledger_is_complete_and_well_formed() -> None:
    records = _records()
    ids = [record.get("id") for record in records]
    assert ids == EXPECTED_IDS, (
        f"defect ids must be unique, ordered, and contiguous D01-D{LAST_EXPECTED_ID:02d}"
    )

    for index, record in enumerate(records, start=1):
        allowed_fields = (
            _BASE_FIELDS | _OPTIONAL_FIELDS if index <= 18 else _CAMPAIGN_FIELDS | _OPTIONAL_FIELDS
        )
        required_fields = _BASE_FIELDS if index <= 18 else _CAMPAIGN_FIELDS
        assert required_fields <= record.keys(), f"{record.get('id')}: missing required field"
        assert record.keys() <= allowed_fields, f"{record.get('id')}: unknown field"
        assert record["status"] in ALLOWED_STATUS
        _nonempty_text(record, "invariant")
        _nonempty_text(record, "slice")
        _nonempty_text(record, "compatibility")
        _path_list(record, "tests")
        _path_list(record, "contracts")
        if "fixEvidence" in record:
            _nonempty_text(record, "fixEvidence")
        if "verificationNotes" in record:
            _nonempty_text(record, "verificationNotes")
        if index > 18:
            _validate_campaign_evidence(record)
        if record["status"] == "verified":
            _validate_verification_evidence(record)
        else:
            assert "verificationEvidence" not in record, (
                f"{record.get('id')}: verificationEvidence is reserved for verified records"
            )


def test_verified_status_requires_structured_receipts() -> None:
    """A status-string flip cannot impersonate the three promotion receipts."""
    with pytest.raises(AssertionError, match="verified requires verificationEvidence"):
        _validate_verification_evidence({"id": "DXX", "status": "verified"})

    vacuous = {
        "id": "DXX",
        "status": "verified",
        "verificationEvidence": {
            "live": "yes",
            "causalRed": "yes",
            "nonAuthorReview": "yes",
        },
    }
    with pytest.raises(AssertionError, match="invalid live verification evidence"):
        _validate_verification_evidence(vacuous)


def _test_receipt(
    root: Path, *, record_id: str, kind: str, payload: dict[str, Any]
) -> dict[str, Any]:
    relative_path = f"quality/evidence/{kind}.json"
    evidence = {"artifact": relative_path, **payload}
    document = {
        "schemaVersion": 1,
        "defectId": record_id,
        "kind": kind,
        "evidence": _receipt_payload(evidence),
    }
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    evidence["artifactSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    return evidence


def _complete_test_verification_record(root: Path) -> dict[str, Any]:
    record_id = "DXX"
    return {
        "id": record_id,
        "status": "verified",
        "tests": ["bp/tests/test_quality_ledger.py"],
        "verificationEvidence": {
            "live": _test_receipt(
                root,
                record_id=record_id,
                kind="live",
                payload={
                    "case": "VERIFY-DXX complete live acceptance case",
                    "observedAt": "2026-09-04T12:00:00+02:00",
                    "binarySha256": "a" * 64,
                    "oracle": "Authoritative post-state contained the expected controlled marker.",
                    "outcome": "pass",
                },
            ),
            "causalRed": _test_receipt(
                root,
                record_id=record_id,
                kind="causalRed",
                payload={
                    "test": "bp/tests/test_quality_ledger.py",
                    "failure": "Assertion reached: expected protected state, observed old behavior.",
                    "observedAt": "2026-09-04T11:00:00+02:00",
                    "redCommand": "python -m pytest bp/tests/test_quality_ledger.py before fix",
                    "redOutcome": "assertion-failed",
                    "greenCommand": "python -m pytest bp/tests/test_quality_ledger.py",
                    "greenOutcome": "pass",
                },
            ),
            "nonAuthorReview": _test_receipt(
                root,
                record_id=record_id,
                kind="nonAuthorReview",
                payload={
                    "authorCommit": "1" * 40,
                    "authorLane": "implementation-lane",
                    "correctionKind": "implementation",
                    "implementationPaths": ["bp/src/bp/output.py"],
                    "reviewCommit": "2" * 40,
                    "reviewerLane": "independent-review-lane",
                    "reviewedAt": "2026-09-04T12:30:00+02:00",
                    "verdict": "pass",
                },
            ),
        },
    }


def test_complete_structured_verification_receipts_are_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The promotion validator discriminates; it is not an always-fail gate."""
    record = _complete_test_verification_record(tmp_path)
    verification = record["verificationEvidence"]
    assert isinstance(verification, dict)
    review = verification["nonAuthorReview"]
    assert isinstance(review, dict)
    review_artifact_value = review["artifact"]
    assert isinstance(review_artifact_value, str)
    review_artifact = tmp_path / review_artifact_value

    identities = {
        "1" * 40: ("implementation author", "author@example.test"),
        "2" * 40: ("review attestor", "reviewer@example.test"),
    }
    monkeypatch.setattr(
        f"{__name__}._commit_author_identity",
        lambda commit, *_args: identities[commit],
    )
    monkeypatch.setattr(f"{__name__}._git_is_ancestor", lambda *_args: True)

    def fake_git_bytes(*args: str) -> bytes:
        author_commit = "1" * 40
        review_commit = "2" * 40
        if args[0] == "diff-tree" and args[-1] == author_commit:
            return b"bp/src/bp/output.py\nbp/tests/test_quality_ledger.py\n"
        if args[0] == "diff-tree" and args[-1] == review_commit:
            return b"quality/evidence/nonAuthorReview.json\n"
        if args[0] == "show" and args[1].startswith(f"{author_commit}:"):
            relative_path = args[1].split(":", 1)[1]
            return (ROOT / relative_path).read_bytes()
        if args[0] == "show" and args[1].startswith(f"{review_commit}:"):
            return review_artifact.read_bytes()
        raise AssertionError(f"unexpected git call: {args}")

    monkeypatch.setattr(f"{__name__}._git_bytes", fake_git_bytes)
    _validate_verification_evidence(record, artifact_root=tmp_path)


def test_review_identity_requires_exact_commits_and_distinct_attested_lanes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(AssertionError, match="invalid nonAuthorReview.authorCommit"):
        _commit_author_identity("implementation-lane", "nonAuthorReview.authorCommit", "DXX")

    commit = "1" * 40
    monkeypatch.setattr(
        f"{__name__}._git_bytes",
        lambda *_args: f"{commit}\nMohamed MAACHE\nauthor@example.test\n".encode(),
    )
    assert _commit_author_identity(commit, "nonAuthorReview.authorCommit", "DXX") == (
        "mohamed maache",
        "author@example.test",
    )

    artifact = tmp_path / "quality/evidence/nonAuthorReview.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("{}", encoding="utf-8")
    review = {
        "authorCommit": "1" * 40,
        "authorLane": "same-lane",
        "reviewCommit": "2" * 40,
        "reviewerLane": "same-lane",
    }
    monkeypatch.setattr(
        f"{__name__}._commit_author_identity",
        lambda *_args: ("same committer", "same@example.test"),
    )
    with pytest.raises(AssertionError, match="distinct attested lanes"):
        _validate_non_author_review_identity(
            review,
            artifact=artifact,
            artifact_root=tmp_path,
            record_id="DXX",
            implementation_paths=["bp/src/bp/output.py"],
            regression_paths=["bp/tests/test_quality_ledger.py"],
        )


def test_review_author_commit_must_contain_regressions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "quality/evidence/nonAuthorReview.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("{}", encoding="utf-8")
    review = {
        "authorCommit": "1" * 40,
        "authorLane": "implementation-lane",
        "reviewCommit": "2" * 40,
        "reviewerLane": "independent-review-lane",
    }
    identities = iter(
        [
            ("implementation author", "author@example.test"),
            ("review attestor", "reviewer@example.test"),
        ]
    )
    monkeypatch.setattr(f"{__name__}._commit_author_identity", lambda *_args: next(identities))
    monkeypatch.setattr(f"{__name__}._git_is_ancestor", lambda *_args: True)
    monkeypatch.setattr(f"{__name__}._git_bytes", lambda *_args: b"unrelated/file.py\n")
    with pytest.raises(AssertionError, match="every implementation and regression path"):
        _validate_non_author_review_identity(
            review,
            artifact=artifact,
            artifact_root=tmp_path,
            record_id="DXX",
            implementation_paths=["bp/src/bp/output.py"],
            regression_paths=["bp/tests/test_quality_ledger.py"],
        )


def test_verification_artifact_content_is_bound_to_defect(tmp_path: Path) -> None:
    """An unrelated file with a valid digest cannot serve as a promotion receipt."""
    record = _complete_test_verification_record(tmp_path)
    live = record["verificationEvidence"]["live"]
    path = tmp_path / live["artifact"]
    document = json.loads(path.read_text(encoding="utf-8"))
    document["defectId"] = "DOTHER"
    path.write_text(json.dumps(document), encoding="utf-8")
    live["artifactSha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(AssertionError, match="artifact is not bound to its receipt fields"):
        _validate_verification_evidence(record, artifact_root=tmp_path)


def test_ledger_references_cannot_escape_or_name_directories() -> None:
    with pytest.raises(AssertionError, match="must be relative"):
        _path_list({"id": "DXX", "tests": [str(ROOT / "bp" / "tests")]}, "tests")
    with pytest.raises(AssertionError, match="missing ledger file reference"):
        _path_list({"id": "DXX", "tests": ["bp/tests"]}, "tests")


def test_readme_ledger_summary_matches_records() -> None:
    """Human-facing ranges, counts, and ratio cannot drift from the ledger."""
    records = _records()
    readme = QUALITY_README.read_text(encoding="utf-8")
    assert readme.count(_README_SUMMARY_START) == 1
    assert readme.count(_README_SUMMARY_END) == 1
    start = readme.index(_README_SUMMARY_START)
    end = readme.index(_README_SUMMARY_END, start) + len(_README_SUMMARY_END)
    assert readme[start:end] == _readme_summary(records)


def _release_incomplete(records: list[dict[str, Any]]) -> list[str]:
    return [str(record["id"]) for record in records if record["status"] in {"confirmed", "fixed"}]


def test_release_gate_excludes_terminal_non_defects() -> None:
    records = [
        {"id": "D01", "status": "verified"},
        {"id": "D02", "status": "rejected"},
        {"id": "D03", "status": "unconfirmed"},
        {"id": "D04", "status": "fixed"},
        {"id": "D05", "status": "confirmed"},
    ]
    assert _release_incomplete(records) == ["D04", "D05"]


def test_release_gate_requires_verified_records_when_enabled() -> None:
    records = _records()
    incomplete = _release_incomplete(records)
    if os.environ.get("BURPCTL_REQUIRE_ALL_VERIFIED") == "1":
        for record in records:
            if record["status"] == "verified":
                _validate_verification_evidence(record)
        assert not incomplete, f"unverified established defects: {', '.join(incomplete)}"
