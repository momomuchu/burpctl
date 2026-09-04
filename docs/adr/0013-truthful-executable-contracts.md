# ADR-0013 — Truthful executable contracts and bounded unsupported behavior

**Status:** accepted — 2026-09-03
**Criticality:** [HIGH][BLOCKS:high]

---

## Context

The REST extension and `bp` CLI expose several operations whose names and success envelopes imply effects that the pinned Montoya API cannot perform. The embedded OpenAPI document, current prose, historical Gherkin scenarios, DTOs, and executable routes have also drifted apart. Lenient request decoding can silently ignore a misspelled control field, while output and error paths do not all honor the selected machine-readable format.

A security tool must distinguish an observed effect from an acknowledgement, an anomaly from a finding, and an unavailable capability from success. Compatibility does not justify a successful lie.

## Decision

1. Existing route paths and the `ApiResponse {success,data,error}` envelope remain stable.
2. Requests are decoded strictly. Unknown members, malformed values, and violated semantic invariants are rejected before any target or state effect.
3. Every HTTP failure uses a typed JSON error envelope. The CLI keeps the published exit range 0–5; unsupported and other runtime failures exit 1, local invocation syntax exits 2, connection failures exit 3, Pro gating exits 4, and confirmed check findings exit 5.
4. A route that the pinned Montoya API cannot implement remains discoverable but returns HTTP 501 with code `UNSUPPORTED` before effects. It must never return a successful no-op.
5. Security-check output keeps observations and anomalies separate from confirmed classifier fields. Exit 5 follows only the latter.
6. JSON and NDJSON data are redacted structurally before serialization. Machine-readable errors use the selected machine format, and `raw` is available only when genuine raw/scalar content exists.
7. OpenAPI and CLI-to-route contracts become executable gates. Current behavior documentation is maintained separately from historical design material.
8. `docs/bdd/` is retained as historical scenario material until scenarios are either rewritten against the executable contract and bound to a runner, or removed. Its presence is not evidence that those scenarios pass.
9. Each confirmed defect in the 2026-09-03 repair is tracked in `quality/confirmed-defects.yaml` with regression evidence and an explicit verification state.

## Compatibility policy

Correcting false success, ignored inputs, secret disclosure, state races, or unbounded effects is a compatible hardening even if a previously accepted invalid request now fails. Existing truthful fields are retained where practical; new evidence and capability fields are additive. A response field that cannot be truthfully populated becomes nullable or is documented as unavailable rather than carrying a fabricated value.

No release number is invented by this decision. Source revision, build provenance, and API schema identity are exposed separately from a future published package version.

## Consequences

- Route, DTO, OpenAPI, CLI, and output changes land with RED-first contract tests.
- Mocked Montoya and temporary-storage tests remain the pull-request acceptance boundary; no running Burp instance is required in CI.
- ADR-0004's unshipped async CLI design remains historical rather than an executable contract.
- ADR-0006 remains the methodology decision, but its references to `docs/bdd-clean/` and exit 69 are superseded by this ADR and the executable gates.
- Unsupported operations are noisier for callers, but they can no longer be mistaken for completed work.
