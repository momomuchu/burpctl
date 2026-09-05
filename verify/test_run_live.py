from __future__ import annotations

import importlib.util
import json
import socket
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("run_live.py")
SPEC = importlib.util.spec_from_file_location("burpctl_verify_run_live", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
run_live = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_live
SPEC.loader.exec_module(run_live)


class HarnessUnitTests(unittest.TestCase):
    def test_six_versions_are_derived_and_equal(self) -> None:
        versions = run_live.derive_versions()
        self.assertEqual(6, len(versions))
        self.assertEqual(1, len(set(versions.values())))

    def test_zero_behavior_cases_can_never_be_clean(self) -> None:
        summary = run_live.summarize([], registered=30, selected=0)
        self.assertFalse(summary["clean"])
        self.assertNotEqual(0, summary["exit_code"])
        self.assertEqual(0, summary["executed_behavior_cases"])

    def test_only_exact_registered_case_ids_are_selected(self) -> None:
        definitions = run_live.cases()
        self.assertEqual([], run_live.select_behavior(definitions, [], ["DOES-NOT-EXIST"]))
        selected = run_live.select_behavior(definitions, [], ["REST-001"])
        self.assertEqual(["REST-001"], [case.case_id for case in selected])

    def test_hash_input_is_strict(self) -> None:
        digest = "a" * 64
        self.assertEqual(digest, run_live.require_expected_hash(digest.upper()))
        for invalid in ("", "a" * 63, "a" * 65, "g" * 64):
            with self.assertRaises(Exception):
                run_live.require_expected_hash(invalid)

    def test_result_schema_is_json_and_names_all_outcomes(self) -> None:
        schema = json.loads(Path(__file__).with_name("result-schema.json").read_text("utf-8"))
        outcomes = schema["$defs"]["case"]["properties"]["outcome"]["enum"]
        self.assertEqual(["PASS", "FAIL", "COULD_NOT_RUN"], outcomes)

    def test_owned_target_is_stopped_and_port_is_rebindable(self) -> None:
        state = run_live.TargetState("unit", 0)
        run_live.start_target(state, "unit-marker")
        self.assertEqual("held", state.disposition)
        self.assertIsNotNone(state.actual_port)
        port = state.actual_port
        run_live.stop_target(state)
        self.assertEqual("released", state.disposition)
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", int(port)))
        finally:
            probe.close()

    def test_containment_forfeiture_is_explicit(self) -> None:
        case = next(case for case in run_live.cases() if case.case_id == "REST-011")
        result = run_live.could_not_run(case, "named missing precondition")
        self.assertEqual("COULD_NOT_RUN", result["outcome"])
        self.assertEqual("named missing precondition", result["missing_precondition"])
        self.assertTrue(result["observed_evidence"]["containmentAbort"])
        self.assertNotIn(
            "unknown",
            {item["status"] for item in result["resource_disposition"].values()},
        )


if __name__ == "__main__":
    unittest.main()
