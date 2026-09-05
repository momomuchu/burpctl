# ADR-0003 — `--pos` grammar and client-side attack expansion

**Status:** accepted 2026-06-16 · amended to shipped behavior 2026-09-05
**Criticality:** [CRITICAL][BLOCKS:critical]

## Decision

`bp fuzz` accepts repeatable semantic selectors and resolves them to byte ranges in a captured request:

```text
header:NAME
cookie:NAME
body:FIELD
query:NAME
path:INDEX
offset:START-END
```

`path:INDEX` is 1-based over non-empty path segments. `body:FIELD` supports a top-level JSON object
member or form-urlencoded member; multipart and dot-path selectors are not implemented.

The Python client expands all four attack modes and sends each concrete request through
`POST /repeater/send`:

- sniper: one shared list or one named list per position, changing one position per shot;
- battering-ram: one shared value applied to every position;
- pitchfork: one list per position, lockstep to the shortest;
- cluster-bomb: Cartesian product.

The server-side Intruder API is not the engine behind `bp fuzz`. It supports bounded exact-offset
sniper behavior; unsupported matrix modes return 501 rather than silently executing as sniper. There is
no `bp fuzz --param` shorthand or asynchronous lifecycle CLI.

## Safety and representation

The client rejects overlapping positions, incompatible list layouts, empty plans, and any plan above
10,000 payload shots before target sends. The bound is fixed, not a warning threshold or user
configuration.

Substitution is byte-indexed and applied right-to-left. Body changes recalculate one canonical
`Content-Length`. Exact body bytes can cross the structured bridge through `bodyBase64`, but Montoya
still constructs the outgoing request; this is not raw-framing transport.

## Consequences

- Selector and expansion semantics are contract-tested in Python.
- Named payload files bind deterministically; extra/unused sets are rejected rather than flattened or
  ignored.
- The complete executable algorithm is maintained in [`../ALGORITHMS.md`](../ALGORITHMS.md).
- Any claim about original/final wire identity remains bounded by PC-07 and the structured-bridge
  limits in [`../PROOF-CEILINGS.md`](../PROOF-CEILINGS.md).
