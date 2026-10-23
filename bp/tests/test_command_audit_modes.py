"""Temporal contract for sealed replay, historical probes, and fixed candidates."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Final

import pytest

ROOT: Final = Path(__file__).resolve().parents[2]
VALIDATOR_PATH: Final = ROOT / "quality" / "command-audit" / "validate_command_audit.py"


def _validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("command_audit_validator", VALIDATOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


VALIDATOR: Final = _validator()
MODE: Final = os.environ.get(VALIDATOR.MODE_ENV, "baseline-replay")
if MODE not in VALIDATOR.MODES:
    raise RuntimeError(f"invalid {VALIDATOR.MODE_ENV}={MODE!r}; expected one of {VALIDATOR.MODES}")

_source_matches_history = False
if MODE == "historical-live":
    _source_matches_history = VALIDATOR.source_tree() == VALIDATOR.HISTORICAL_SOURCE_TREE


def require_historical_live() -> None:
    """Stop collection of a historical probe module outside its exact source mode."""
    if MODE != "historical-live" or not _source_matches_history:
        pytest.skip(
            "historical live probe: run validate_command_audit.py historical-live against "
            "the sealed bp/src tree",
            allow_module_level=True,
        )


def test_baseline_replay_matches_all_sealed_sources() -> None:
    replay = VALIDATOR.replay_baseline()
    assert replay["historicalRevision"] == VALIDATOR.HISTORICAL_REVISION
    assert (replay["forms"], replay["cases"], replay["evidenceFiles"]) == (57, 114, 60)


def test_tampered_declared_evidence_is_rejected(tmp_path: Path) -> None:
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence = evidence_dir / "proof.json"
    evidence.write_text('{"observed":"baseline"}\n', encoding="utf-8")
    digest = VALIDATOR._sha256(evidence)
    provenance = tmp_path / "provenance.json"
    provenance.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "name": evidence.name,
                        "originalSha256": "0" * 64,
                        "sanitizedSha256": digest,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert VALIDATOR.validate_declared_evidence(provenance, evidence_dir, expected_count=1) == 1

    evidence.write_text('{"observed":"rewritten"}\n', encoding="utf-8")
    with pytest.raises(VALIDATOR.AuditValidationError, match="digest mismatch"):
        VALIDATOR.validate_declared_evidence(provenance, evidence_dir, expected_count=1)


def test_selected_live_mode_is_bound_to_its_source_contract() -> None:
    if MODE == "baseline-replay":
        return
    result = VALIDATOR.validate_source_mode(MODE)
    assert result["mode"] == MODE
    if MODE == "historical-live":
        assert result["sourceTree"] == VALIDATOR.HISTORICAL_SOURCE_TREE
    else:
        assert result["sourceTree"] != VALIDATOR.HISTORICAL_SOURCE_TREE
