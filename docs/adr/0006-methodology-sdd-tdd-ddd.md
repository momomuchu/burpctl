# ADR-0006 — Methodology: SDD + TDD + DDD + spec-as-contract; trunk-based; atomic commits

**Status:** accepted — 2026-06-16
**Criticality:** [HIGH][BLOCKS:high]

---

## Decision

The `bp` project follows four interlocking methodologies and one branching + commit policy:

| Axis | Choice |
|---|---|
| Design | **SDD** — Spec-Driven Development: spec is written and validated before any implementation file is created. |
| Testing | **TDD** — Test-Driven Development: RED test before GREEN implementation, always. Unit tests are written without a running Burp instance. |
| Architecture | **DDD** — Domain-Driven Design: aggregates, ubiquitous language, and bounded context defined in `docs/SPEC.md §11`. |
| Spec role | **spec-as-contract**: `docs/SPEC.md`, `docs/CLI.md`, and `docs/OUTPUT.md` are the authoritative contracts. Diverging from them requires a spec update, not a silent code choice. |
| Branching | **Trunk-based**: all work lands on `main`. Feature branches are short-lived (1–2 days max) and merged via fast-forward or squash. No long-lived feature branches. |
| Commits | **Atomic**: each commit compiles, passes tests, and represents one logical change. No WIP commits on `main`. |

### Community + Pro support

`bp` targets both Burp Suite Community and Professional users. The CLI detects edition at runtime
and degrades gracefully for Pro-only surfaces:

- `collaborator` group → 503 on Community; `bp` exits 69 with a clear message.
- `scanner` start endpoints → 500 on Community; `bp` exits 69.
- All other 11 groups are available on Community (Intruder uses RepeaterService internally, not
  the Pro Intruder engine).

This Community-first posture is explicit: `bp` must not silently fail or hide capability gaps.

### DDD aggregates (from `docs/SPEC.md §11`)

| Aggregate | Invariant |
|---|---|
| `FuzzPlan` | Positions[] + PayloadSets + AttackType. `cluster-bomb` requires ≥1 set per position. |
| `CapturedRequest` | requestId + raw bytes (source for offset resolution). |
| `AttackRun` | State machine: created → running → paused → completed / stopped / error. |
| `LedgerEntry` | One per `bp` invocation. Immutable after write (tag is the only mutable field). |

Ubiquitous language = Burp/Intruder vocabulary (sniper, position, payload set, collaborator,
scope). No invented jargon.

---

## Rationale

Decision 2026-06-16. The combination of SDD + TDD + DDD is the `W` (transverse method)
component in `docs/SPEC.md §4`.

- **SDD** is required because three existing documents contradicted each other (see ADR-0001).
  A spec validated before code prevents the same drift from recurring.
- **TDD** is required because the `--pos` parser and offset resolver are the most complex pieces
  of the CLI and have well-defined inputs/outputs (byte ranges). They must be testable without
  Burp running.
- **DDD** is required to keep the Intruder vocabulary consistent between the CLI surface, the
  test layer, and the API call layer. Renaming concepts mid-stack produces bugs.
- **spec-as-contract** closes the loop: if the spec and the code diverge, the spec wins (update
  the code), unless the spec is wrong (update the spec with a recorded decision).
- **Trunk-based branching** with atomic commits enables the ISO traceability goal of the C4 Run
  Ledger — every commit is a verifiable unit.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Code-first, spec later | Would repeat the existing documentation drift problem. The spec exists; use it as the contract. |
| BDD-only (no TDD unit layer) | BDD scenarios require a running Burp instance for integration; the `--pos` parser does not. A pure BDD approach delays feedback on the core algorithm. |
| Feature branches per command group | With 13 groups and 69 endpoints, long-lived branches would create merge conflicts and make the ledger's atomic-commit audit trail meaningless. Trunk-based is simpler and fits a 1–2 person team. |
| Pro-only support (no Community degradation) | Eliminates the majority of the hunter community who use Burp Community. Graceful degradation costs little and broadens the user base significantly. |

---

## Consequences

- Implementation is test-first: RED tests for the `--pos` parser come first.
- Every new command must have its contract test before its implementation.
- The BDD feature files in `docs/bdd-clean/` serve as the integration acceptance gate.
- Community-mode degradation must be tested in contract tests (mock the 503/500 response; verify
  `bp` exits 69 with the correct message).
- The `FuzzPlan` aggregate's `cluster-bomb` invariant must be enforced in the parser layer (not
  delegated to the server, which silently accepts invalid input).
