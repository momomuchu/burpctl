# ADR index — bp project

Decisions 0001–0006 began on 2026-06-16. Later records amend or supersede their implementation claims;
the status below prevents historical proposals from being mistaken for shipped behavior.

| ADR | Title | Current status | Criticality |
|---|---|---|---|
| [ADR-0001](0001-rest-source-of-truth.md) | REST routing and published-contract authorities | accepted; amended for executable OpenAPI | CRITICAL |
| [ADR-0002](0002-cli-name-bp.md) | CLI name `bp`, alias `burpctl` | accepted; reinstated by ADR-0012 | HIGH |
| [ADR-0003](0003-pos-fuzzing-grammar.md) | `--pos` grammar and client-side expansion | accepted; amended to shipped behavior | CRITICAL |
| [ADR-0004](0004-fuzz-async-lifecycle.md) | Historical asynchronous fuzz lifecycle | superseded by ADR-0013; never shipped | historical |
| [ADR-0005](0005-run-ledger-observability.md) | Run Ledger on by default | accepted | HIGH |
| [ADR-0006](0006-methodology-sdd-tdd-ddd.md) | Contract-first development and evidence boundaries | accepted; amended by ADR-0013/0014 | HIGH |
| [ADR-0007](0007-product-scope-full-functionality-configurable-safety.md) | Product direction and configurable safeguards | accepted as direction; proposals are not commands | CRITICAL |
| [ADR-0008](0008-implementation-language-python-fully-typed.md) | Python implementation with strict static checking | accepted; amended to current stack | CRITICAL |
| [ADR-0009](0009-global-output-options-position-tolerant.md) | Position-tolerant global execution/output options | accepted | HIGH |
| [ADR-0010](0010-check-exit-on-findings.md) | Security-check findings use exit 5 | accepted; amended for inconclusive results | HIGH |
| [ADR-0011](0011-rebrand-burpctl.md) | Rebrand `burpctl` as primary | superseded by ADR-0012; never released | HIGH |
| [ADR-0012](0012-primary-name-bp.md) | Restore `bp` primary; keep `burpctl` alias | accepted; supersedes ADR-0011 | HIGH |
| [ADR-0013](0013-truthful-executable-contracts.md) | Truthful executable contracts and historical BDD disposition | accepted; amended for corpus removal | HIGH |
| [ADR-0014](0014-state-preserving-reportable-operations.md) | State-preserving/reportable operations and live Montoya proof | accepted | CRITICAL |

The implementation and release-evidence hierarchy is summarized in ADR-0001, ADR-0013, and ADR-0014.
No ADR or historical scenario is proof that the final live acceptance pass occurred.
