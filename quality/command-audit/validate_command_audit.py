#!/usr/bin/env python3
"""Validate the sealed audit replay and run source-scoped probe modes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Final, Literal, cast

ROOT: Final = Path(__file__).resolve().parents[2]
QUALITY: Final = ROOT / "quality" / "command-audit"
MATRIX: Final = QUALITY / "command-matrix-v2.jsonl"
SUMMARY: Final = QUALITY / "command-matrix-v2-summary.json"
PROVENANCE: Final = QUALITY / "evidence-provenance.json"
EVIDENCE: Final = QUALITY / "evidence"
BUILDER: Final = QUALITY / "build_command_matrix_v2.py"

MODE_ENV: Final = "BP_COMMAND_AUDIT_MODE"
Mode = Literal["baseline-replay", "historical-live", "current-candidate"]
MODES: Final[tuple[Mode, ...]] = (
    "baseline-replay",
    "historical-live",
    "current-candidate",
)
HISTORICAL_REVISION: Final = "3af139dc0b4020923f831099338c92af3265d7e2"
HISTORICAL_SOURCE_TREE: Final = "73eabb36e5dc2abe80aace1daad1833ac864d18f"
CURRENT_CONTRACT_TESTS: Final = (
    "bp/tests/test_agent_parser_errors.py",
    "bp/tests/test_agent_fuzz_preflight.py",
    "bp/tests/test_agent_preflight_output.py",
)
HASH: Final = re.compile(r"^[0-9a-f]{64}$")


class AuditValidationError(RuntimeError):
    """The requested audit mode cannot establish its stated contract."""


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditValidationError(f"cannot read JSON {path}: {exc}") from exc


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise AuditValidationError(f"cannot hash {path}: {exc}") from exc


def validate_declared_evidence(
    provenance_path: Path = PROVENANCE,
    evidence_dir: Path = EVIDENCE,
    *,
    expected_count: int | None = 60,
) -> int:
    """Check that every declared sanitized evidence file still has its sealed digest."""
    document = _load_json(provenance_path)
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise AuditValidationError("evidence provenance must contain a files array")
    rows = document["files"]
    if expected_count is not None and len(rows) != expected_count:
        raise AuditValidationError(
            f"expected {expected_count} provenance rows, found {len(rows)}"
        )
    names: set[str] = set()
    for index, value in enumerate(rows):
        if not isinstance(value, dict):
            raise AuditValidationError(f"provenance row {index} must be an object")
        name = value.get("name")
        original = value.get("originalSha256")
        sanitized = value.get("sanitizedSha256")
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise AuditValidationError(f"invalid evidence name at provenance row {index}")
        if name in names:
            raise AuditValidationError(f"duplicate evidence provenance row: {name}")
        names.add(name)
        if not isinstance(original, str) or HASH.fullmatch(original) is None:
            raise AuditValidationError(f"invalid original digest for {name}")
        if not isinstance(sanitized, str) or HASH.fullmatch(sanitized) is None:
            raise AuditValidationError(f"invalid sanitized digest for {name}")
        actual = _sha256(evidence_dir / name)
        if actual != sanitized:
            raise AuditValidationError(
                f"sanitized evidence digest mismatch for {name}: {actual} != {sanitized}"
            )
    return len(names)


def _load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("command_audit_matrix_builder", BUILDER)
    if spec is None or spec.loader is None:
        raise AuditValidationError(f"cannot load matrix builder {BUILDER}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def replay_baseline() -> dict[str, object]:
    """Rebuild in memory and compare the immutable 57-form/114-case evidence."""
    evidence_files = validate_declared_evidence()
    builder = _load_builder()
    rows = builder.build()
    summary = builder.validate(rows)
    rendered_matrix = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows)
    committed_matrix = MATRIX.read_text(encoding="utf-8")
    if rendered_matrix != committed_matrix:
        raise AuditValidationError("committed matrix differs from sealed source evidence")
    matrix_digest = hashlib.sha256(rendered_matrix.encode()).hexdigest()
    if not isinstance(summary, dict):
        raise AuditValidationError("matrix builder returned a non-object summary")
    expected_summary = dict(summary)
    expected_summary["matrixSha256"] = matrix_digest
    committed_summary = _load_json(SUMMARY)
    if committed_summary != expected_summary:
        raise AuditValidationError("committed summary differs from replayed matrix summary")
    return {
        "mode": "baseline-replay",
        "historicalRevision": HISTORICAL_REVISION,
        "forms": expected_summary["forms"],
        "cases": expected_summary["observations"],
        "evidenceFiles": evidence_files,
        "matrixSha256": matrix_digest,
    }


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise AuditValidationError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def source_tree() -> str:
    """Identify committed product bytes and reject uncommitted product-source drift."""
    dirty = _git("status", "--porcelain", "--", "bp/src")
    if dirty:
        raise AuditValidationError(f"bp/src has uncommitted changes:\n{dirty}")
    tree = _git("rev-parse", "HEAD:bp/src")
    if re.fullmatch(r"[0-9a-f]{40,64}", tree) is None:
        raise AuditValidationError(f"invalid bp/src tree identity: {tree}")
    return tree


def validate_source_mode(mode: Mode) -> dict[str, object]:
    """Bind live checks to historical bytes or to the current candidate contract."""
    tree = source_tree()
    revision = _git("rev-parse", "HEAD")
    if mode == "historical-live":
        if tree != HISTORICAL_SOURCE_TREE:
            raise AuditValidationError(
                "historical-live requires bp/src tree "
                f"{HISTORICAL_SOURCE_TREE} ({HISTORICAL_REVISION}); observed {tree}"
            )
    elif mode == "current-candidate":
        if tree == HISTORICAL_SOURCE_TREE:
            raise AuditValidationError(
                "current-candidate refuses the historical source tree; use historical-live"
            )
        missing = [path for path in CURRENT_CONTRACT_TESTS if not (ROOT / path).is_file()]
        if missing:
            raise AuditValidationError(
                "current candidate lacks required executable contract tests: " + ", ".join(missing)
            )
    return {"mode": mode, "revision": revision, "sourceTree": tree}


def _pytest(mode: Mode) -> int:
    audit_tests = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "bp/tests").glob(
        "test_command_audit_*.py"
    ))
    tests = audit_tests
    if mode == "current-candidate":
        tests = [*tests, *CURRENT_CONTRACT_TESTS]
    env = dict(os.environ)
    env[MODE_ENV] = mode
    result = subprocess.run(
        ["uv", "run", "--project", "bp", "pytest", "-q", *tests],
        cwd=ROOT,
        env=env,
        check=False,
    )
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay sealed command-audit evidence or run source-scoped contracts."
    )
    parser.add_argument("mode", choices=MODES)
    parser.add_argument(
        "--no-pytest",
        action="store_true",
        help="validate identities and sealed evidence without invoking pytest",
    )
    options = parser.parse_args(argv)
    mode = cast(Mode, options.mode)
    result = replay_baseline()
    if mode != "baseline-replay":
        result.update(validate_source_mode(mode))
    print(json.dumps(result, sort_keys=True))
    return 0 if options.no_pytest else _pytest(mode)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditValidationError as exc:
        print(f"command-audit validation failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
