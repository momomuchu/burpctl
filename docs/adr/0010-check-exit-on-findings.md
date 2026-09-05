# ADR-0010 — Security-check findings use exit 5

**Status:** accepted 2026-06-19 · amended for inconclusive outcomes 2026-09-05
**Criticality:** [HIGH]

## Context

A security-check command needs to distinguish a completed clean classifier result, a finding, an
inconclusive observation, and operational failure without requiring a script to scrape human output.
A finding is not a generic runtime error, and an absent response is not evidence of a vulnerability.
No claim is made that every other security CLI follows the same convention.

## Decision

Only `bp check auth|idor|headers|cors|endpoints` can use exit 5. The command emits its normal result to
stdout before exit selection.

| Exit | Check meaning |
|---:|---|
| 0 | classifier completed with no finding and no unresolved inconclusive-only outcome |
| 1 | runtime/service error or observations are only inconclusive |
| 2 | invocation/local validation error |
| 3 | REST transport failure |
| 4 | required Pro capability unavailable |
| 5 | one or more classifier findings |

A response anomaly is not automatically a finding. Findings select exit 5 even if other probes are
inconclusive; otherwise an inconclusive-only result selects exit 1. A target HTTP error remains result
data when the bp/Burp operation itself completed.

Exit 5 means only that the implemented classifier emitted a finding. It does not independently prove
ownership, authorization policy, exploitability, or server-held marker origin. Those proof boundaries
are in [`../PROOF-CEILINGS.md`](../PROOF-CEILINGS.md).

## Consequences

- Scripts can branch on the complete 0–5 contract in [`../CLI.md`](../CLI.md).
- Structured stdout is retained for findings and inconclusive observations.
- `EXIT_VULN` remains separate from generic/transport/Pro errors.
- Changes to classifier meaning require synchronized output, exit, documentation, and acceptance
  oracles; a constant pinned to a superseded classifier result is not a valid gate.
