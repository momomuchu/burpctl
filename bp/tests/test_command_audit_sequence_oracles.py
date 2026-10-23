"""Focused validator for sealed, preparation-only sequence oracles.

# noqa: SIZE_OK
One-file ownership requires the validator, negative tests, and 50 contract digests.
"""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Final, TypeAlias, TypeGuard, cast

import pytest

Json: TypeAlias = None | bool | int | float | str | list["Json"] | dict[str, "Json"]

ROOT: Final = Path(__file__).resolve().parents[2]
ORACLES: Final = ROOT / "quality" / "command-audit" / "sequence-oracles.json"
ORDER: Final = (
    ("S1", *(f"S1.{n}" for n in range(1, 6))),
    ("S2", *(f"S2.{n}" for n in range(1, 10))),
    ("S3", *(f"S3.{n}" for n in range(1, 13))),
    ("S4", *(f"S4.{n}" for n in range(1, 10))),
    ("S5", *(f"S5.{n}" for n in range(1, 6))),
    ("S6", *(f"S6.{n}" for n in range(1, 11))),
)
CONTRACT_HASHES: Final = dict(
    item.split(":")
    for item in """
S1.1:d0a8097a525bd77c4e3dc7762b90947e0013c6e2db5ad0589a332d30d36fec5c S1.2:6ab5901f342a17be49a57575c3666a335cceeacc0e3908f2bdad8f6a9223c27a S1.3:21464b927060c973ef52186d445a3957066ce43b699ecf17dbad48c056fdace7 S1.4:4b76a4a054e044a446d0f908f829f33b9e4174a19a890dffe3ad332d192597aa S1.5:3261c469133a35dd160f8b169ec7029d4024c0eef464295baf7ca2cbdeaa810e
S2.1:ec9146be6aaecb98824a62718259d762cfbf08785bea1fe64c30920717db4c40 S2.2:ba8f34b76184c0866e275feb8a5cda2a8daab4c15ebce0c91943f13f7bdc63fe S2.3:b167f28d0d9df15c926cd9589d0a1384dae36ff6da199baaa336563598bf65ac S2.4:0c51939d783a9bd7cf7ad6b0d5789b1e4cca4a85ac2b5e1f24036519c84008c1 S2.5:47d1e6c01c5f9cd0f7b4d791d0e681bbe9b5e4fec1a643a4e25d78dc03d0bde5 S2.6:26ee0edb43fa328e41a643f1fed5c04c96be7965acf4e9b7a186c18ad134867f S2.7:723bbdbfd92f41cd657a1116b2843c079dfce8f3f2b957c8d5f12ef10c298edc S2.8:9d893b58e51cb293652b959ab79e880d83661e335cdcea75cea6bca19fe717fd S2.9:8e5d99f4e35d0fbfcbaadedeb61680bd27c1159477489c02fc9999df8bf356a1
S3.1:f2b14a2db96574ba7d411f24efa89d24509cf15166b485d30b82efa52a89f301 S3.2:3d88294ffbc4951dbe9af072cf26a3c8807d0fd39864df20649e2bcdef44dbcc S3.3:74b26cf8fc8e0f213c889fcfe17d1d4e9166d587d7e39886e1c8049ccec45193 S3.4:071e8b8a1b9c9f016b181a1b46513270ff62052c99c7354fd670510747356c60 S3.5:c338497f0a8f0bdfad043ba330b6213b63f1b099871fd1476025b77f0b4d28ed S3.6:2a63a5be4c38fef1fe4e69a88e6a7add9f96f18dc8afe3ec03c816946927c982 S3.7:37ac722dae6f8b721eabb4906a7198467b875134797c53b6bd3667eca27c292f S3.8:68bb2d00a1fb1e506daee719a492c0414f5a34df851084707be853693a82cf8d S3.9:1b1f258e306934270ad7283609d648de16be8ab8a53783bc67587c3d7c99c6c0 S3.10:76040f9be5491b1cf8b9a7d6b271bb0fa41ff3557c0681b3de8ff6c513001384 S3.11:09c049c73e2c1edff7f3d6d328e2108aa58dcbbe284fcd6dd1df84e1f2dde272 S3.12:1389720ca285a337f8fff53dd2c617694bb0f8389b0b69e70dab28bbe873e180
S4.1:0285973217000685c1238c56e7c5426e77dd78cff7ae2408b5444e9aeb48e836 S4.2:a810561d5dd74d8e4d6c1815f0ebfc139f0c68f99db403cce4c92073c7fb73f0 S4.3:3cf136890157a4781693e47869225e3ba66574eecbd08079bd07a8cb92925db2 S4.4:808b580ff72e494c78449174b73fc1a1fadd3dec481adc5416fb0b19b29f257d S4.5:908b1e738b18a310aa5bcadac788ecb76d315fd3ea6ae51d2e27985c4c13a838 S4.6:bd5c236d371981ddd896b1261311772c9eeddf07e08c59c14b7b3bc576c6bf84 S4.7:e7fd81b7a2f61ec8dc3ec27bee0865c4e1d4ad4e76348cd93e1a1a3c885c677c S4.8:6fe493ed0fc6c92af3c6576289c8d53c9f6622d8cb095f27cfe3f144f6ea6309 S4.9:a14385fb4f89e4f74964dfe77532bca7e9cc8b7e2b11d71c8fe455e90c989870
S5.1:308f1ccb37d3131495d6071be28902d4f4c5699177a8c87f07fcd37037a0d26e S5.2:d3c34ec31cee3d305534af82f1a65c5942d6094d166d16bc8b484e472fc00d4d S5.3:43ec55af0f1776ad65c407f702ff6b9c76b615ab99c27a4c45ad0dfdba803669 S5.4:e123de29997f4f75866c671b917c554552be4d4eee017751d673e88b66de2801 S5.5:8b7e29ca6c0df6bc0124b7910613eef90065988c5aaf8bfea942a0f389398adf
S6.1:9693a44377cc9ab4a1db2090fb8de954476362ad86af95e2d77d88db6710e785 S6.2:3f2e189fa42db10b5dc5c70c6f51af74f10c28334e008ae50c7b5321d099df83 S6.3:ed35cd5301ebb5db34a923e12a9cff47246ef9ec468a2207e38e0206c82a6bf0 S6.4:8ad8cbd6c2b531ee0262d6d4da0323322bfdc730658ede31ddff7a76fb521d0d S6.5:bc85738678068edcb7dbfbe8ffe1d24efc1fe955c68099e2dc7c706d6decc66b S6.6:56ff85e12d1d52fae3ddb71df75986c24cd42ff0eedd9ad7bd0aa7ea27937bc4 S6.7:047256e3a03c682daaf4adcf22f179561ab35b60e79585ca5bba84f2cc1d23dd S6.8:7582d2560ace428d3f329ea0a809de18e703d027cf4e2694eddb85bc12ab639a S6.9:f353f655f4ee739321eee2dc1368c93df21f92838ac7800f843704d1ff4e3b25 S6.10:80d851d6ec7d0ffcd4874934a835448f068987d23de62f46ea02231583e28ad6
""".split()
)
STATUSES: Final = {"PREFLIGHT_NO_EFFECT", "COMPLETED", "UNKNOWN_INCONCLUSIVE"}
CITATION: Final = re.compile(r"^[^:]+:\d+$")
HASH: Final = re.compile(r"^[0-9a-f]{64}$")


class SequenceOracleError(ValueError):
    """A preparation oracle is incomplete, changed, or implies execution."""


def _map(value: Json, label: str) -> dict[str, Json]:
    if not isinstance(value, dict):
        raise SequenceOracleError(f"{label} must be an object")
    return value


def _need(mapping: dict[str, Json], key: str, label: str) -> Json:
    if key not in mapping or mapping[key] in (None, "", []):
        raise SequenceOracleError(f"{label}: missing {key}")
    return mapping[key]


def _strings(value: Json, *, empty_ok: bool = False) -> TypeGuard[list[str]]:
    return isinstance(value, list) and (empty_ok or bool(value)) and all(
        isinstance(item, str) and bool(item) for item in value
    )


def _walk(value: Json, path: str = "root") -> None:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key)
            if key in {"actual", "observed", "observed_at", "transcript", "actual_snapshot"} or key.startswith(("actual_", "observed_")):
                raise SequenceOracleError(f"{path}: forbidden execution field {key}")
            _walk(child, f"{path}.{key}")
    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]")


def _expected(value: Json, label: str) -> None:
    result = _map(value, label)
    exit_code = _need(result, "exit", label)
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise SequenceOracleError(f"{label}: exit must be an integer")
    for name in ("stdout", "stderr"):
        stream = _map(_need(result, name, label), f"{label}.{name}")
        for key in ("mode", "shape"):
            if not isinstance(_need(stream, key, f"{label}.{name}"), str):
                raise SequenceOracleError(f"{label}.{name}: invalid {key}")
        if not _strings(stream.get("selected_values"), empty_ok=True):
            raise SequenceOracleError(f"{label}.{name}: invalid selected_values")


def _effects(value: Json, label: str) -> tuple[str, int | list[int]]:
    effects = _map(value, label)
    routes = _need(effects, "rest_route_count", label)
    if not isinstance(routes, int) or isinstance(routes, bool) or routes < 0:
        raise SequenceOracleError(f"{label}: invalid rest_route_count")
    status = _need(effects, "status", label)
    count = _need(effects, "live_target_effect_count", label)
    if not isinstance(status, str) or status not in STATUSES:
        raise SequenceOracleError(f"{label}: invalid effect status")
    if status == "UNKNOWN_INCONCLUSIVE":
        if not isinstance(count, list) or len(count) != 2 or not all(isinstance(n, int) and not isinstance(n, bool) for n in count):
            raise SequenceOracleError(f"{label}: unknown effect requires target range")
        numbers = cast(list[int], count)
        if numbers[0] < 0 or numbers[0] > numbers[1]:
            raise SequenceOracleError(f"{label}: invalid target range")
        return status, numbers
    elif not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise SequenceOracleError(f"{label}: invalid live_target_effect_count")
    return status, count


def _reconciliation(value: Json, label: str, count: int | list[int]) -> None:
    read = _map(value, label)
    for key in ("action", "expected", "status_after"):
        if not isinstance(_need(read, key, label), str):
            raise SequenceOracleError(f"{label}: invalid {key}")
    if isinstance(count, list):
        outcomes = _need(read, "outcomes", label)
        if not isinstance(outcomes, list) or len(outcomes) < 2:
            raise SequenceOracleError(f"{label}: unknown effect requires outcomes")
        observed: list[int] = []
        for index, item in enumerate(outcomes):
            outcome = _map(item, f"{label}.outcomes[{index}]")
            _need(outcome, "state", label)
            target = _need(outcome, "live_target_effect_count", label)
            if not isinstance(target, int) or isinstance(target, bool):
                raise SequenceOracleError(f"{label}: outcome target count must be exact")
            observed.append(target)
        if min(observed) != count[0] or max(observed) != count[1]:
            raise SequenceOracleError(f"{label}: outcomes do not cover target range")


def _source_projection(value: Json, label: str) -> None:
    projection = _map(value, label)
    if projection.get("status") != "UNVERIFIED_HYPOTHESIS" or projection.get("contract_relation") != "EXPECTED_MISMATCH":
        raise SequenceOracleError(f"{label}: invalid hypothesis status")
    if not isinstance(_need(projection, "hypothesis", label), str):
        raise SequenceOracleError(f"{label}: missing hypothesis")
    _expected(_need(projection, "probable_result", label), f"{label}.probable_result")
    citations = _need(projection, "citations", label)
    if not _strings(citations) or not all(CITATION.fullmatch(item) for item in citations):
        raise SequenceOracleError(f"{label}: missing source citation")


def _digest(value: Json) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _step(value: Json, sealed_at: str) -> tuple[str, str]:
    step = _map(value, "step")
    step_id = _need(step, "id", "step")
    if not isinstance(step_id, str):
        raise SequenceOracleError("step id must be text")
    for key in ("action", "branch_marker", "prestate", "transition", "state_owner"):
        if not isinstance(_need(step, key, step_id), str):
            raise SequenceOracleError(f"{step_id}: {key} must be text")
    invocation = _map(_need(step, "invocation", step_id), f"{step_id}.invocation")
    if not (_strings(invocation.get("argv_template")) or isinstance(invocation.get("fixture_action"), str) and invocation["fixture_action"]):
        raise SequenceOracleError(f"{step_id}: missing invocation")
    _expected(_need(step, "expected", step_id), f"{step_id}.expected")
    citations = _need(step, "citations", step_id)
    if not _strings(citations) or not all(CITATION.fullmatch(item) for item in citations):
        raise SequenceOracleError(f"{step_id}: missing source citation")
    if not _strings(_need(step, "assumptions", step_id)):
        raise SequenceOracleError(f"{step_id}: missing assumptions")
    if step_id == "S3.7":
        _source_projection(_need(step, "source_projection", step_id), f"{step_id}.source_projection")
    rest = _map(_need(step, "rest", step_id), f"{step_id}.rest")
    route_count = _need(rest, "route_effect_count", f"{step_id}.rest")
    if not isinstance(route_count, int) or isinstance(route_count, bool) or route_count < 0:
        raise SequenceOracleError(f"{step_id}: invalid route_effect_count")
    if route_count:
        for key in ("method", "path"):
            if not isinstance(_need(rest, key, f"{step_id}.rest"), str):
                raise SequenceOracleError(f"{step_id}.rest: invalid {key}")
        if "payload" not in rest:
            raise SequenceOracleError(f"{step_id}.rest: missing payload")
    elif not isinstance(_need(rest, "no_rest_reason", f"{step_id}.rest"), str):
        raise SequenceOracleError(f"{step_id}.rest: invalid no_rest_reason")
    status, count = _effects(_need(step, "effects", step_id), f"{step_id}.effects")
    effects = _map(step["effects"], f"{step_id}.effects")
    if effects["rest_route_count"] != route_count:
        raise SequenceOracleError(f"{step_id}: REST effect counts differ")
    if status == "UNKNOWN_INCONCLUSIVE":
        _reconciliation(_need(step, "reconciliation", step_id), f"{step_id}.reconciliation", count)
    failure = _map(_need(step, "failure_injection", step_id), f"{step_id}.failure")
    for key in ("point", "injected_fault", "state_after"):
        if not isinstance(_need(failure, key, f"{step_id}.failure"), str):
            raise SequenceOracleError(f"{step_id}.failure: invalid {key}")
    _expected(_need(failure, "expected", f"{step_id}.failure"), f"{step_id}.failure.expected")
    failure_status, failure_count = _effects(_need(failure, "effects", f"{step_id}.failure"), f"{step_id}.failure.effects")
    _reconciliation(_need(failure, "reconciliation", f"{step_id}.failure"), f"{step_id}.failure.reconciliation", failure_count)
    retry = _need(failure, "retry_allowed", f"{step_id}.failure")
    if not isinstance(retry, bool) or failure_status == "UNKNOWN_INCONCLUSIVE" and retry:
        raise SequenceOracleError(f"{step_id}: invalid retry policy")
    seal = _map(_need(step, "seal", step_id), f"{step_id}.seal")
    digest = _need(seal, "hash", f"{step_id}.seal")
    if seal.get("algorithm") != "sha256" or seal.get("sealed") is not True or seal.get("expected_at") != sealed_at or not isinstance(digest, str) or not HASH.fullmatch(digest):
        raise SequenceOracleError(f"{step_id}: invalid seal")
    canonical = deepcopy(step)
    _map(canonical["seal"], f"{step_id}.seal")["hash"] = ""
    if _digest(canonical) != digest:
        raise SequenceOracleError(f"{step_id}: invalid seal hash")
    semantic = {key: child for key, child in step.items() if key != "seal"}
    return step_id, _digest(semantic)


def validate_sequence_oracles(path: Path) -> tuple[int, int]:
    """Validate ordered inventory, schema, seals, and independent contracts."""
    document = _map(cast(Json, json.loads(path.read_text(encoding="utf-8"))), "root")
    _walk(document)
    if document.get("schema") != "burpctl.command-audit/sequence-oracles" or document.get("schema_version") != 2 or document.get("status") != "PRE_EXECUTION_ONLY":
        raise SequenceOracleError("invalid preparation schema")
    candidate = _map(document.get("candidate"), "candidate")
    policy = _map(document.get("execution_policy"), "execution_policy")
    if candidate.get("revision") != "3af139dc0b4020923f831099338c92af3265d7e2" or policy.get("network_scope") != "LOOPBACK_ONLY" or policy.get("external_targets_forbidden") is not True or policy.get("execution_performed") is not False:
        raise SequenceOracleError("invalid candidate or execution policy")
    sealed_at = _need(document, "sealed_at", "root")
    sequences = _need(document, "sequences", "root")
    if not isinstance(sealed_at, str) or not isinstance(sequences, list):
        raise SequenceOracleError("invalid root inventory")
    found: list[tuple[str, ...]] = []
    semantic: dict[str, str] = {}
    for raw_sequence in sequences:
        sequence = _map(raw_sequence, "sequence")
        sequence_id = _need(sequence, "id", "sequence")
        steps = _need(sequence, "steps", str(sequence_id))
        if not isinstance(sequence_id, str) or not isinstance(steps, list) or not steps:
            raise SequenceOracleError("invalid sequence")
        checked = [_step(item, sealed_at) for item in steps]
        found.append((sequence_id, *(item[0] for item in checked)))
        semantic.update(checked)
    if tuple(found) != ORDER or document.get("sequence_step_count") != 50:
        raise SequenceOracleError("ordered sequences or steps differ")
    if semantic != CONTRACT_HASHES:
        raise SequenceOracleError("sealed semantic contract differs")
    return len(found), len(semantic)


def _load() -> dict[str, Json]:
    return _map(cast(Json, json.loads(ORACLES.read_text(encoding="utf-8"))), "root")


def _step_by_id(document: dict[str, Json], step_id: str) -> dict[str, Json]:
    for raw_sequence in cast(list[Json], document["sequences"]):
        for raw_step in cast(list[Json], _map(raw_sequence, "sequence")["steps"]):
            step = _map(raw_step, "step")
            if step.get("id") == step_id:
                return step
    raise AssertionError(step_id)


def _write(tmp_path: Path, document: dict[str, Json], name: str) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _reseal(step: dict[str, Json]) -> None:
    seal = _map(step["seal"], "seal")
    seal["hash"] = ""
    seal["hash"] = _digest(step)


def test_sequence_oracles_are_complete_and_sealed() -> None:
    assert validate_sequence_oracles(ORACLES) == (6, 50)


@pytest.mark.parametrize("path", ["citations", "assumptions", "state_owner", "failure_injection", "expected.stdout", "expected.stderr", "failure_injection.expected", "failure_injection.reconciliation", "rest.route_effect_count", "rest.path", "effects.live_target_effect_count", "effects.status", "seal.hash"])
def test_missing_contract_is_rejected(tmp_path: Path, path: str) -> None:
    document = _load()
    current = _step_by_id(document, "S1.1")
    parts = path.split(".")
    for key in parts[:-1]:
        current = _map(current[key], path)
    current.pop(parts[-1])
    with pytest.raises(SequenceOracleError):
        validate_sequence_oracles(_write(tmp_path, document, f"missing-{path}.json"))


@pytest.mark.parametrize("kind", ["sequence", "step", "sequence-order", "step-order"])
def test_ordered_inventory_is_enforced(tmp_path: Path, kind: str) -> None:
    document = _load()
    sequences = cast(list[Json], document["sequences"])
    if kind == "sequence":
        sequences.pop()
    elif kind == "step":
        cast(list[Json], _map(sequences[0], "sequence")["steps"]).pop()
    elif kind == "sequence-order":
        sequences[0], sequences[1] = sequences[1], sequences[0]
    else:
        steps = cast(list[Json], _map(sequences[0], "sequence")["steps"])
        steps[0], steps[1] = steps[1], steps[0]
    with pytest.raises(SequenceOracleError, match="ordered sequences or steps differ"):
        validate_sequence_oracles(_write(tmp_path, document, f"{kind}.json"))


@pytest.mark.parametrize("key", ["actual", "observed", "observed_at", "transcript", "actual_snapshot"])
def test_execution_fields_are_rejected(tmp_path: Path, key: str) -> None:
    document = _load()
    _step_by_id(document, "S1.1")[key] = True
    with pytest.raises(SequenceOracleError, match="forbidden execution field"):
        validate_sequence_oracles(_write(tmp_path, document, f"{key}.json"))


def test_exact_target_count_is_rejected_while_completion_is_unknown(tmp_path: Path) -> None:
    document = _load()
    failure = _map(_step_by_id(document, "S1.2")["failure_injection"], "failure")
    _map(failure["effects"], "effects")["live_target_effect_count"] = 0
    with pytest.raises(SequenceOracleError, match="unknown effect requires target range"):
        validate_sequence_oracles(_write(tmp_path, document, "unknown-exact.json"))


@pytest.mark.parametrize("case", ["remove", "conflate"])
def test_s3_7_source_projection_cannot_be_removed_or_conflated(tmp_path: Path, case: str) -> None:
    document = _load()
    step = _step_by_id(document, "S3.7")
    if case == "remove":
        step.pop("source_projection")
    else:
        projection = _map(step["source_projection"], "source_projection")
        step["expected"] = deepcopy(projection["probable_result"])
    _reseal(step)
    with pytest.raises(SequenceOracleError):
        validate_sequence_oracles(_write(tmp_path, document, f"projection-{case}.json"))


@pytest.mark.parametrize("case", ["argv", "route", "payload", "counts", "target", "status", "branch", "selected", "reconciliation", "retry"])
def test_resealed_semantic_changes_are_rejected(tmp_path: Path, case: str) -> None:
    document = _load()
    first = {"argv", "route", "target", "status", "branch", "selected", "retry"}
    step = _step_by_id(document, "S1.1" if case in first else "S1.2")
    if case == "argv":
        cast(list[Json], _map(step["invocation"], "invocation")["argv_template"]).append("--changed")
    elif case == "route":
        _map(step["rest"], "rest")["path"] = "/changed"
    elif case == "payload":
        _map(step["rest"], "rest")["payload"] = {"url": "http://127.0.0.1/changed"}
    elif case == "counts":
        _map(step["rest"], "rest")["route_effect_count"] = 2
        _map(step["effects"], "effects")["rest_route_count"] = 2
    elif case == "target":
        _map(step["effects"], "effects")["live_target_effect_count"] = 1
    elif case == "status":
        _map(step["effects"], "effects")["status"] = "PREFLIGHT_NO_EFFECT"
    elif case == "branch":
        step["branch_marker"] = "changed"
    elif case == "selected":
        stdout = _map(_map(step["expected"], "expected")["stdout"], "stdout")
        stdout["selected_values"] = ["changed"]
    elif case == "reconciliation":
        failure = _map(step["failure_injection"], "failure")
        _map(failure["reconciliation"], "reconciliation")["action"] = "changed read"
    else:
        _map(step["failure_injection"], "failure")["retry_allowed"] = False
    _reseal(step)
    with pytest.raises(SequenceOracleError, match="sealed semantic contract differs"):
        validate_sequence_oracles(_write(tmp_path, document, f"semantic-{case}.json"))
