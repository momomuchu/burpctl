# Historical BDD scenario corpus

The `.feature` files in this directory are retained temporarily as historical product-design material.
They contain 641 scenarios across 16 files and are **not** contracts or an executable acceptance suite:
the repository has no step bindings, Gherkin runner, CI step, or test that has ever executed them, and
independent static audits found all 16 files false overall. ADR-0013 now recommends removing this false
corpus from the release documentation tree. A future scenario suite should be created from the current
contract only when it is bound to executable steps and a retained runner result.

The current source contract is defined and checked by:

1. the Kotlin route/DTO/service tests under `src/test/kotlin`;
2. the Python CLI and contract tests under `bp/tests`;
3. the served OpenAPI document and its route/serializer contract gates;
4. `docs/SPEC.md`, `docs/CLI.md`, `docs/OUTPUT.md`, and `docs/STATE-AND-CONFIG.md` after they are aligned with those executable checks; and
5. the bounded repair ledger in `quality/confirmed-defects.yaml`.

Those sources establish what the implementation says and what local tests exercise. They do not, by
themselves, establish real-Burp behavior or promote any defect to `verified`; see
[ADR-0014](../adr/0014-state-preserving-reportable-operations.md) and the
[proof ceilings](../PROOF-CEILINGS.md).

Do not cite scenario count or a `.feature` file as evidence that behavior works. A scenario becomes
current acceptance evidence only after it is updated to the shipped contract, bound to executable
steps, run, and retained with the evidence needed by the release gate.

See [ADR-0013](../adr/0013-truthful-executable-contracts.md).
