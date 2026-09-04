# ADR Index — bp project

Decisions 0001–0006 locked 2026-06-16 by founder. Later ADRs carry their own dates and status.

| ADR | Title | Criticality |
|---|---|---|
| [ADR-0001](0001-rest-source-of-truth.md) | REST API source of truth = `RestServer.kt` at `:8089` | [CRITICAL] |
| [ADR-0002](0002-cli-name-bp.md) | CLI name = `bp`, alias `burpctl` — *superseded by 0011* | [HIGH] |
| [ADR-0003](0003-pos-fuzzing-grammar.md) | `--pos` flexible-fuzzing grammar with client-side expansion | [CRITICAL] |
| [ADR-0004](0004-fuzz-async-lifecycle.md) | `bp fuzz` single verb with `--async`; no split create/start | [HIGH] |
| [ADR-0005](0005-run-ledger-observability.md) | C4 Run Ledger on by default; SQLite `~/.bp/`; `--no-ledger` opt-out | [HIGH] |
| [ADR-0006](0006-methodology-sdd-tdd-ddd.md) | Methodology: SDD + TDD + DDD + spec-as-contract; trunk; atomic commits | [HIGH] |
| [ADR-0011](0011-rebrand-burpctl.md) | Rebrand to `burpctl` (primary) — *superseded by 0012* | [HIGH] |
| [ADR-0007](0007-product-scope-full-functionality-configurable-safety.md) | Full functionality with configurable safety controls | [HIGH] |
| [ADR-0008](0008-implementation-language-python-fully-typed.md) | Fully typed Python CLI implementation | [HIGH] |
| [ADR-0009](0009-global-output-options-position-tolerant.md) | Global output options are position-tolerant | [HIGH] |
| [ADR-0010](0010-check-exit-on-findings.md) | Security checks exit nonzero on confirmed findings | [HIGH] |
| [ADR-0012](0012-primary-name-bp.md) | Primary name reverts to `bp`; `burpctl` kept as alias — supersedes 0011 | [HIGH] |
| [ADR-0013](0013-truthful-executable-contracts.md) | Truthful executable contracts and bounded unsupported behavior | [HIGH] |
| [ADR-0014](0014-state-preserving-reportable-operations.md) | State-preserving, reportable operations and live Montoya release proof | [CRITICAL] |
