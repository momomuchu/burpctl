# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# ─── How to run ───
# uv run quality/command-audit/build_command_matrix_v2.py <output-directory>

"""Build and verify the canonical 57-form command audit matrix."""

# allow: SIZE_OK — task ownership requires one standalone evidence builder/validator.

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Final, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]

ROOT: Final = Path(__file__).resolve().parents[2]
QUALITY: Final = ROOT / "quality" / "command-audit"
ORACLES: Final = QUALITY / "oracles.json"
CORRECTIONS: Final = QUALITY / "oracle-corrections-flat-read.json"
EVIDENCE: Final = QUALITY / "evidence"
EVIDENCE_PROVENANCE: Final = QUALITY / "evidence-provenance.json"
SOURCE_FILES: Final = (
    "observations-flat-read.json",
    "observations-flat-effects.json",
    "observations-scan-collab.json",
    "observations-checks.json",
    "observations-scope-session.json",
    "observations-config-history.json",
)
VARIANTS: Final = ("normal", "contrast")
VERDICTS: Final = {
    "PASS",
    "FAIL",
    "INCONCLUSIVE",
    "ORACLE_MISMATCH",
    "PRODUCT_CONTRACT_DEFECT",
    "SAFETY_LIMITED",
}
FIXTURE_PATH: Final = re.compile(
    r"/private/var/folders/[^\"'\s]+?/bp-audit-[^/\"'\s]+"
)
WORKTREE_PATH: Final = re.compile(
    r"/Users/maache/burpctl-ulw-worktrees-20261023/[^/\"'\s]+"
)
ATTEMPT_PATH: Final = re.compile(
    r"/Users/maache/burpctl-ulw-20261023/\.omo/evidence/ulw/"
    r"burpctl-ultra-ci-20261023/G001-cloner-et-auditer-burp-ctl-avec-une/a1"
)


class MatrixError(RuntimeError):
    """The evidence cannot produce a contradiction-free canonical matrix."""


def _load(path: Path) -> JsonValue:
    try:
        value: JsonValue = json.loads(path.read_text(encoding="utf-8"))
        return value
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot read JSON evidence {path}: {exc}") from exc


def _object(value: JsonValue, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise MatrixError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise MatrixError(f"{label} must be an array")
    return value


def _text(value: JsonValue, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MatrixError(f"{label} must be a non-empty string")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonicalize(value: JsonValue) -> JsonValue:
    if isinstance(value, str):
        canonical = ATTEMPT_PATH.sub("{{ATTEMPT_DIR}}", value)
        canonical = WORKTREE_PATH.sub("{{WORKTREE}}", canonical)
        return FIXTURE_PATH.sub("{{FIXTURE_ROOT}}", canonical)
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _canonicalize(item) for key, item in value.items()}
    return value


def _provenance() -> dict[str, JsonObject]:
    document = _object(_load(EVIDENCE_PROVENANCE), str(EVIDENCE_PROVENANCE))
    rows = _array(document.get("files"), "evidence provenance files")
    result: dict[str, JsonObject] = {}
    for value in rows:
        row = _object(value, "evidence provenance row")
        name = _text(row.get("name"), "evidence provenance name")
        if name in result:
            raise MatrixError(f"duplicate evidence provenance row: {name}")
        result[name] = row
    return result


def _evidence_file(name: str, role: str, declared_original: JsonValue = None) -> JsonObject:
    provenance = _provenance().get(name)
    if provenance is None:
        raise MatrixError(f"missing bundled evidence provenance: {name}")
    path = EVIDENCE / name
    digest = _sha256(path)
    if provenance.get("sanitizedSha256") != digest:
        raise MatrixError(f"bundled evidence SHA mismatch: {name}")
    original = _text(provenance.get("originalSha256"), f"{name}.originalSha256")
    if declared_original is not None and declared_original != original:
        raise MatrixError(f"original evidence SHA mismatch: {name}")
    return {
        "role": role,
        "path": str(path.relative_to(ROOT)),
        "sha256": digest,
        "originalSha256": original,
    }


def _pointer(document: JsonValue, pointer: str) -> JsonValue:
    if pointer in {"", "/"}:
        return document
    current = document
    for raw_token in pointer.removeprefix("/").split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise MatrixError(f"pointer {pointer} crosses a scalar")
    return current


def _source_rows() -> tuple[dict[str, tuple[Path, int, JsonObject]], dict[str, tuple[Path, int, JsonObject]]]:
    primary: dict[str, tuple[Path, int, JsonObject]] = {}
    manifest_contrasts: dict[str, tuple[Path, int, JsonObject]] = {}
    for name in SOURCE_FILES:
        path = QUALITY / name
        rows = _array(_load(path), name)
        for index, value in enumerate(rows):
            row = _object(value, f"{name}[{index}]")
            row_id = _text(row.get("id"), f"{name}[{index}].id")
            if row.get("scenario") == "original-manifest-contrast":
                manifest_contrasts[row_id] = (path, index, row)
            else:
                if row_id == "H01":
                    continue
                if row_id in primary:
                    raise MatrixError(f"duplicate primary observation {row_id}")
                primary[row_id] = (path, index, row)
    return primary, manifest_contrasts


def _external_files(lane: JsonObject) -> list[JsonObject]:
    evidence_value = lane.get("evidence")
    if not isinstance(evidence_value, dict):
        return []
    files: list[JsonObject] = []
    for key, value in evidence_value.items():
        if not (key.endswith("File") or key.endswith("Path") or key in {"expected", "actual"}):
            continue
        name = Path(_text(value, f"evidence.{key}")).name
        declared_key = (
            f"{key}Sha256" if key in {"expected", "actual"} else key.removesuffix("Path") + "FileSha256"
        )
        declared = evidence_value.get(declared_key)
        files.append(_evidence_file(name, key, declared))
    return files


def _f10_lane(variant: str) -> tuple[JsonObject, list[JsonObject]]:
    matches = sorted(EVIDENCE.glob(f"task-6-f10-c001-corrected-{variant}-bp-*-actual.json"))
    if len(matches) != 1:
        raise MatrixError(f"F10/{variant} requires exactly one corrected actual, found {len(matches)}")
    actual_path = matches[0]
    expected_path = actual_path.with_name(actual_path.name.replace("-actual.json", "-expected.json"))
    lane = _object(_load(actual_path), str(actual_path))
    expected_file = _object(_load(expected_path), str(expected_path))
    for key in ("argv", "expected", "preRunSeal", "oracleHash"):
        if lane.get(key) != expected_file.get(key):
            raise MatrixError(f"F10/{variant} expected/actual contradiction at {key}")
    files = [
        _evidence_file(expected_path.name, "expected"),
        _evidence_file(actual_path.name, "actual"),
    ]
    return lane, files


def _manifest_case(row: JsonObject, row_id: str) -> tuple[JsonObject, int, list[JsonValue]]:
    cases = _array(row.get("manifestCases"), f"{row_id}.manifestCases")
    matching = [
        (index, _object(value, f"{row_id}.manifestCases[{index}]"))
        for index, value in enumerate(cases)
        if isinstance(value, dict)
        and isinstance(value.get("case"), str)
        and str(value["case"]).startswith("contrast")
    ]
    if not matching:
        raise MatrixError(f"{row_id} has no exact manifest contrast")
    selected_index, selected = matching[-1]
    history: list[JsonValue] = [
        {"pointer": f"manifestCases/{index}", "case": case.get("case"), "verdict": case.get("verdict")}
        for index, case in matching[:-1]
    ]
    return selected, selected_index, history


def _correction() -> tuple[JsonObject, str]:
    document = _object(_load(CORRECTIONS), str(CORRECTIONS))
    corrections = _array(document.get("corrections"), "corrections")
    correction = next(
        _object(value, "F10-C001")
        for value in corrections
        if isinstance(value, dict) and value.get("id") == "F10-C001"
    )
    seal = _object(correction.get("seal"), "F10-C001.seal")
    canonical = {key: value for key, value in correction.items() if key != "seal"}
    digest = hashlib.sha256(
        json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    if seal.get("hash") != digest:
        raise MatrixError("F10-C001 correction seal is invalid")
    return correction, digest


def build() -> list[JsonObject]:
    manifest = _object(_load(ORACLES), str(ORACLES))
    oracle_rows = _array(manifest.get("rows"), "oracles.rows")
    primary, manifest_contrasts = _source_rows()
    correction, correction_hash = _correction()
    rows: list[JsonObject] = []
    for oracle_index, value in enumerate(oracle_rows):
        oracle = _object(value, f"oracles.rows[{oracle_index}]")
        row_id = _text(oracle.get("id"), "oracle.id")
        source_path, source_index, source_row = primary[row_id]
        oracle_hash = _text(_object(oracle.get("seal"), f"{row_id}.seal").get("hash"), "hash")
        if source_row.get("oracleHash") != oracle_hash:
            raise MatrixError(f"{row_id} observation uses a different original oracle")
        for variant in VARIANTS:
            external: list[JsonObject] = []
            prior_cases: list[JsonValue] = []
            pointer = f"/{source_index}/{variant}"
            lane = _object(source_row.get(variant), f"{row_id}.{variant}")
            active_oracle: JsonValue = None
            if row_id == "F10":
                lane, external = _f10_lane(variant)
                source_path = ROOT / _text(external[1].get("path"), "F10 actual path")
                pointer = "/"
                active_oracle = {
                    "source": str(CORRECTIONS.relative_to(ROOT)),
                    "pointer": f"/corrections/0/{variant}",
                    "hash": correction_hash,
                    "classification": correction.get("originalEvidenceClassification"),
                    "reason": correction.get("reason"),
                }
            elif row_id in {"F04", "F15"} and variant == "contrast":
                lane, case_index, prior_cases = _manifest_case(source_row, row_id)
                pointer = f"/{source_index}/manifestCases/{case_index}"
            elif row_id in manifest_contrasts and variant == "contrast":
                source_path, source_index, lane = manifest_contrasts[row_id]
                pointer = f"/{source_index}"
            external.extend(_external_files(lane))
            external_values: list[JsonValue] = list(external)
            comparison = lane.get("oracleComparison", lane.get("authorityClassification"))
            if comparison is None and lane.get("classifications") is not None:
                comparison = {
                    "classifications": lane.get("classifications"),
                    "manifestVsActual": lane.get("manifestVsActual"),
                }
            try:
                raw_source = str(source_path.relative_to(ROOT))
            except ValueError:
                raw_source = str(source_path)
            row: JsonObject = {
                "schema": "burpctl.command-audit/matrix-v2",
                "id": row_id,
                "variant": variant,
                "candidate": lane.get("candidate", source_row.get("candidate")),
                "oracle": {
                    "original": {
                        "source": str(ORACLES.relative_to(ROOT)),
                        "pointer": f"/rows/{oracle_index}/{'expected' if variant == 'normal' else 'contrast'}",
                        "rowHash": oracle_hash,
                        "sourceSha256": _sha256(ORACLES),
                    },
                    "correction": active_oracle,
                    "comparison": comparison if comparison is not None else source_row.get("provenanceAudit"),
                },
                "argv": _canonicalize(lane.get("argv")),
                "expectedPreRun": _canonicalize(lane.get("expected")),
                "preRunSeal": _canonicalize(lane.get("preRunSeal")),
                "actual": _canonicalize(lane.get("actual")),
                "rawEvidence": {
                    "source": raw_source,
                    "pointer": pointer,
                    "sourceSha256": _sha256(source_path),
                    "files": external_values,
                    "priorCases": prior_cases,
                },
                "verdict": lane.get("verdict"),
                "limits": _canonicalize(lane.get("limits")),
            }
            rows.append(row)
    return rows


def validate(rows: list[JsonObject]) -> JsonObject:
    pairs = [(_text(row.get("id"), "id"), _text(row.get("variant"), "variant")) for row in rows]
    if len(rows) != 114 or len(set(pairs)) != 114:
        raise MatrixError(f"expected 114 unique pairs, got {len(rows)}/{len(set(pairs))}")
    if "H01" in {row_id for row_id, _variant in pairs}:
        raise MatrixError("H01 is outside the canonical 57-form inventory")
    scan_pairs = 0
    evidence_names: set[str] = set()
    for row in rows:
        row_id = _text(row.get("id"), "id")
        variant = _text(row.get("variant"), "variant")
        verdict = _text(row.get("verdict"), f"{row_id}/{variant}.verdict")
        if verdict not in VERDICTS:
            raise MatrixError(f"invalid verdict {verdict} for {row_id}/{variant}")
        if row.get("argv") is None or row.get("expectedPreRun") is None or row.get("actual") is None:
            raise MatrixError(f"incomplete evidence for {row_id}/{variant}")
        raw = _object(row.get("rawEvidence"), "rawEvidence")
        source = ROOT / _text(raw.get("source"), "rawEvidence.source")
        if raw.get("sourceSha256") != _sha256(source):
            raise MatrixError(f"source SHA mismatch for {row_id}/{variant}")
        pointed = _object(_pointer(_load(source), _text(raw.get("pointer"), "pointer")), "lane")
        for key, output_key in (("argv", "argv"), ("expected", "expectedPreRun"), ("preRunSeal", "preRunSeal"), ("actual", "actual"), ("verdict", "verdict"), ("limits", "limits")):
            if _canonicalize(pointed.get(key)) != row.get(output_key):
                raise MatrixError(f"{row_id}/{variant} contradicts raw evidence at {key}")
        oracle = _object(row.get("oracle"), "oracle")
        original = _object(oracle.get("original"), "oracle.original")
        oracle_source = ROOT / _text(original.get("source"), "oracle.source")
        if original.get("sourceSha256") != _sha256(oracle_source):
            raise MatrixError(f"oracle source SHA mismatch for {row_id}/{variant}")
        if _pointer(_load(oracle_source), _text(original.get("pointer"), "oracle.pointer")) is None:
            raise MatrixError(f"empty oracle pointer for {row_id}/{variant}")
        for value in _array(raw.get("files"), "rawEvidence.files"):
            evidence_file = _object(value, "rawEvidence.files[]")
            evidence_path = ROOT / _text(evidence_file.get("path"), "evidence path")
            if evidence_file.get("sha256") != _sha256(evidence_path):
                raise MatrixError(f"evidence SHA mismatch for {row_id}/{variant}: {evidence_path}")
            evidence_names.add(evidence_path.name)
        if row_id.startswith("L0") and int(row_id[1:]) <= 8:
            files = _array(raw.get("files"), "rawEvidence.files")
            if len(files) != 2:
                raise MatrixError(f"{row_id}/{variant} lacks immutable scan evidence pair")
            scan_pairs += 1
        if row_id in {"L19", "L20", "L28", "L29", "L30", "L31"} and variant == "contrast":
            comparison = _object(oracle.get("comparison"), "oracle.comparison")
            if comparison.get("classification") != "ORACLE_MISMATCH":
                raise MatrixError(f"{row_id}/contrast lacks explicit oracleComparison")
        if "/Users/" in json.dumps(row, sort_keys=True):
            raise MatrixError(f"machine-specific user path leaked into {row_id}/{variant}")
    if scan_pairs != 16:
        raise MatrixError(f"expected 16 immutable scan pairs, got {scan_pairs}")
    provenance_names = set(_provenance())
    if evidence_names != provenance_names or len(provenance_names) != 60:
        raise MatrixError(
            f"bundled evidence inventory mismatch: used={len(evidence_names)} declared={len(provenance_names)}"
        )
    f15 = next(row for row in rows if row.get("id") == "F15" and row.get("variant") == "contrast")
    f15_raw = _object(f15.get("rawEvidence"), "F15.rawEvidence")
    f15_prior = _array(f15_raw.get("priorCases"), "F15.rawEvidence.priorCases")
    safety_declared = f15.get("verdict") == "SAFETY_LIMITED" or any(
        isinstance(value, dict) and value.get("verdict") == "SAFETY_LIMITED" for value in f15_prior
    )
    if not safety_declared:
        raise MatrixError("F15/contrast must preserve its historical SAFETY_LIMITED declaration")
    counts = Counter(_text(row.get("verdict"), "verdict") for row in rows)
    missing: list[JsonValue] = []
    if f15.get("verdict") == "SAFETY_LIMITED":
        missing.append(
            {
                "id": "F15",
                "variant": "contrast",
                "missing": "safe installed-CLI subprocess trace for the exact non-loopback manifest argv",
                "currentVerdict": "SAFETY_LIMITED",
            }
        )
    return {
        "schema": "burpctl.command-audit/matrix-v2-summary",
        "forms": 57,
        "observations": 114,
        "counts": dict(sorted(counts.items())),
        "coverage": {
            "uniquePairs": 114,
            "bundledEvidenceFiles": 60,
            "pointerAndHashChecks": "PASS",
            "contradictions": 0,
        },
        "c001": {"status": "FAIL" if missing else "PASS", "missing": missing},
        "limits": "H01 excluded; loopback fixtures do not prove unobserved Kotlin/Montoya target effects.",
    }


def main() -> int:
    if len(sys.argv) != 2:
        raise MatrixError("usage: build_command_matrix_v2.py <output-directory>")
    output_dir = Path(sys.argv[1]).resolve()
    if not output_dir.is_dir():
        raise MatrixError(f"output directory does not exist: {output_dir}")
    rows = build()
    summary = validate(rows)
    matrix_path = output_dir / "command-matrix-v2.jsonl"
    summary_path = output_dir / "command-matrix-v2-summary.json"
    matrix_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    summary["matrixSha256"] = _sha256(matrix_path)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
