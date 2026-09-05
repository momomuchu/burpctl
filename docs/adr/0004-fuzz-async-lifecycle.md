# ADR-0004 — Historical asynchronous fuzz lifecycle design

**Status:** superseded by [ADR-0013](0013-truthful-executable-contracts.md); never shipped
**Original decision date:** 2026-06-16
**Criticality:** historical

## Historical proposal

The original design proposed one `bp fuzz` verb with synchronous and `--async` modes, backed by server
create/start/status/results operations. It also proposed these client leaves:

```text
bp fuzz status ATTACK_ID
bp fuzz results ATTACK_ID
bp fuzz summary ATTACK_ID
bp fuzz pause|resume|stop ATTACK_ID
bp fuzz quick …
```

None of those options or leaves exists in the current CLI. `bp fuzz` does not perform a server
create+start sequence and does not store an Intruder attack ID in the Run Ledger. It runs synchronously,
expands requests client-side, and fires them through `/repeater/send`.

The server still publishes an independent Intruder lifecycle, but discoverable REST routes do not imply
matching CLI commands. Server start transitions are state-locked; the historical repeated-start race
description is not current behavior.

## Current decision

Do not treat this ADR as a command contract or roadmap commitment. The implemented synchronous grammar
is in [`../CLI.md`](../CLI.md) and the algorithm in [`../ALGORITHMS.md`](../ALGORITHMS.md). A future
asynchronous CLI requires a new accepted decision, current parser registrations, reporting/recovery
semantics, and tests; this historical proposal grants none of those.
