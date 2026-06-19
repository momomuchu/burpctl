# ADR-0003 — `--pos` flexible-fuzzing grammar with client-side expansion

**Status:** accepted — 2026-06-16
**Criticality:** [CRITICAL][BLOCKS:critical]

---

## Decision

The `--pos` flag accepts **semantic selectors** that the CLI resolves to byte-offsets before
calling the Intruder API. Multi-position and 4 attack types are supported. Non-sniper attack
types are expanded **client-side**.

### Selector grammar

```
header:NAME     — value of a named request header
cookie:NAME     — value of a named cookie
body:FIELD      — a named field in a form-urlencoded or JSON body
query:NAME      — a named URL query parameter
path:INDEX      — a path segment by 0-based index
offset:START-END — raw byte range (passthrough, no resolution needed)
```

Multiple `--pos` flags on one command produce a slice of positions.

### Attack types (`--type`)

| Type | Behaviour |
|---|---|
| `sniper` | One payload set; each position fuzzed in turn (server implements this natively). |
| `battering-ram` | Same payload injected into all positions simultaneously (client-side expansion). |
| `pitchfork` | N payload sets, iterated in lock-step; set[i] maps to position[i] (client-side). |
| `cluster-bomb` | N-dimensional Cartesian product; all combinations of all sets (client-side). |

### Offset resolution

The Intruder API only accepts raw byte-offsets (`PayloadPosition{start:Int, end:Int, name:String}`).
`bp` resolves semantic selectors by parsing the raw bytes of the base captured request
(`requestId` from proxy history). This is the **central, non-delegatable work of the CLI**.

---

## Rationale

Decision 2026-06-16. `docs/SPEC.md §5` identifies offset resolution as "the central work
of the CLI." The REST extension's `PayloadPosition` has no semantic selector support — it only
accepts `start`, `end`, `name` as required integers. Without this resolver layer, a user would
need to manually count byte offsets in raw HTTP, which is error-prone and not user-facing quality.

The 4 attack types mirror Burp Intruder's own vocabulary (ubiquitous language, `docs/SPEC.md §11`).
Server-side, only sniper is implemented; the other three are accepted by the API but execute as
sniper. Client-side expansion lets `bp` deliver the correct semantics now without waiting for a
Kotlin extension update.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Expose only byte-offset (`offset:START-END`) | Forces users to count bytes manually. Unusable for a user-facing product. Defeats the purpose of a CLI wrapper. |
| Implement only sniper, defer others | `pitchfork` and `cluster-bomb` are the most valuable attack types for multi-param auth testing (the primary use case). Deferring would ship a half-capable fuzzer. |
| Wait for server to implement all attack types | No timeline for a Kotlin extension update. Client-side expansion is feasible now and produces correct results. Can be deprecated later if the server adds native support. |
| Use field-name substitution (`substitutePayload` pattern) instead of offset resolution | The server's 6-mode substitution is for `quick-fuzz` (`/intruder/quick-fuzz`) only. Full intruder attacks require offsets. The `--param` shorthand for quick-fuzz is exposed separately as `bp fuzz <id> --param NAME`. |

---

## Consequences

- The `--pos` parser and offset resolver are the first units to be RED-tested.
- `cluster-bomb` with N positions and large payload sets can produce very large request counts. `bp`
  must warn when the Cartesian product exceeds a configurable threshold (e.g. >10 000 requests).
- The `--payloads NAME=FILE` flag binds a payload list to a named position. For `pitchfork`/`cluster-bomb`,
  at least one payload file per position is required.
- Caveats from `docs/SPEC.md §5` must be surfaced to the user: only `positions[0].name` is consumed
  in sniper mode; payload map keys have no functional role (all values are flattened).
