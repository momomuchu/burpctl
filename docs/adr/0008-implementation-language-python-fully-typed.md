# ADR-0008 — Implementation Language: Python, Fully Typed

**Status:** accepted · 2026-06-16
**Criticality:** `[CRITICAL]` (foundation of the entire implementation)

## Decision

`bp` is implemented in **Python 3.11+**, with **complete and strict typing**: type annotations on
**everything** (signatures, models, return types) + strict static checking in CI
(`mypy --strict` or `pyright` strict). Typing is not optional — it is an **enforced discipline**
(the type-safety benefit that made Go attractive, achieved in Python).

**Stack:**
- **Python 3.11+**
- **httpx** — REST client `:8089`, **async mode** for matrix-fuzz concurrency (A2)
- **typer** — CLI (natively driven by type annotations → idiomatic "fully typed")
- **pydantic** — **typed + validated** API models mirroring the Kotlin DTOs (`ApiResponse<T>`,
  `CreateAttackRequest`, …) → enforces the serialization contract (`SPEC §8`, spec-as-contract)
- **sqlite3** (stdlib) — Run Ledger / workspace (`STATE-AND-CONFIG.md`)
- **pytest** — TDD (RED-tests A1/A2 already spec'd)
- **mypy --strict** (or pyright) + **ruff** — strict typing + lint/format as a gate

## Rationale

Decision 2026-06-16: Python is preferred for its simplicity and the owner's proficiency in it
(ADR-0007 decisive factor: **the project owner validates and extends the tool in Python**) → a tool
that is readable and self-extensible takes priority over the elegance of a single binary.

## Rejected Alternatives

- **Go**: rejected — unfamiliar syntax ("looks like C"), learning curve on the key tool while
  validation is ongoing; the only clear advantage (single binary) is workable around on the Python
  side.
- **POSIX sh** (mirror bb-fetch): rejected — breaks down on A2 (expansion/concurrency) and the
  workspace (DB); distribution requires `curl`/`jq`/`sqlite3` to be present.

## Implications

1. **Distribution**: `uv tool install bp` / `pipx install bp` (1 command); zero-dependency binary
   possible later via **PyInstaller** → "standalone distributable" goal met.
2. **Pydantic models = contract**: a mismatch with the Kotlin contract fails at validation
   → reinforces `SPEC §14 #7` (serialization) and the contract-tests (`§14 #9`).
3. **Strict typing as a gate**: `mypy --strict` is enforced in CI.
4. `[BLOCKS:critical]` — unblocks the test-first implementation of the CLI.
