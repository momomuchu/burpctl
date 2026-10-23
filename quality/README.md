# Quality evidence

`confirmed-defects.yaml` is the bounded completion ledger for the comprehensive behavior-hardening pass begun from commit `663bb56` on 2026-09-03.

It is deliberately narrower than “all possible bugs”: each D01–D18 record corresponds to a confirmed defect family with an invariant, implementation slice, executable regression references, compatibility choice, and verification state.

Statuses move only in this order:

- `planned` — the invariant and expected regression evidence are recorded;
- `tested` — a regression test has demonstrated the pre-fix failure for the intended reason;
- `verified` — the implementation, targeted regression, current contract, and aggregate gates all pass.

`bp/tests/test_quality_ledger.py` validates the document and its references. Set `BURPCTL_REQUIRE_ALL_VERIFIED=1` for the final/release gate; ordinary development runs allow incomplete records so RED-first slices can exist without falsifying completion.

The historical command audit has separate sealed-replay, historical-live, and current-candidate
contracts. See [`command-audit/README.md`](command-audit/README.md); default tests replay and
validate its immutable evidence without requiring fixed code to reproduce historical defects.

The ledger uses JSON syntax in a `.yaml` file. JSON is a strict YAML 1.2 subset, which keeps the artifact consumable without adding a parser dependency solely for this gate.
