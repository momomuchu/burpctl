# Historical BDD scenario corpus

The `.feature` files in this directory are retained as historical product-design material. They are **not** an executable acceptance suite: the repository has no step bindings or Gherkin runner, and some scenarios describe commands, flags, response shapes, and version behavior that were never shipped or were superseded.

Current behavior is defined and checked by:

1. the Kotlin route/DTO/service tests under `src/test/kotlin`;
2. the Python CLI and contract tests under `bp/tests`;
3. the served OpenAPI document and its route-inventory gate;
4. `docs/SPEC.md`, `docs/CLI.md`, `docs/OUTPUT.md`, and `docs/STATE-AND-CONFIG.md` after they are aligned with those executable checks; and
5. the bounded repair ledger in `quality/confirmed-defects.yaml`.

Do not cite scenario count or a `.feature` file as evidence that behavior works. A scenario becomes current acceptance evidence only after it is updated to the shipped contract, bound to executable steps, and run in CI.

See [ADR-0013](../adr/0013-truthful-executable-contracts.md).
