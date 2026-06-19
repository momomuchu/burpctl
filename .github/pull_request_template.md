<!-- Thanks for contributing! Keep PRs small and focused. See CONTRIBUTING.md. -->

## What & why

<!-- What does this change, and why? Link the issue it closes. -->
Closes #

## Type

<!-- conventional-commit type -->
- [ ] feat  - [ ] fix  - [ ] test  - [ ] refactor  - [ ] docs  - [ ] chore

## Checklist (Definition of Done)

- [ ] **TDD:** a RED test was added first, then the GREEN fix (tests prove the behavior, not a mock).
- [ ] **Kotlin** (if touched): `./gradlew test` is green.
- [ ] **Python** (if touched): `uv run pytest -q`, `uv run mypy --strict src`, `uv run ruff check src tests` all clean.
- [ ] **Spec-first:** no phantom endpoint / no invented field name; `docs/` + `CHANGELOG` updated if behavior changed.
- [ ] **ADR:** a material decision (architecture, dependency, data model, API/exit-code contract) has an `accepted` ADR in `docs/adr/`.
- [ ] **Invariants:** no secret leaks to disk/stdout; the ledger stays fingerprint-only; Pro-only paths degrade with exit `4`, not a traceback.
- [ ] Commits are atomic and conventional (`type(scope): description`).

## Notes for the reviewer

<!-- Anything tricky, trade-offs, follow-ups, or out-of-scope items. -->
