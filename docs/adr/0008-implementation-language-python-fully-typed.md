# ADR-0008 — Python implementation with strict static checking

**Status:** accepted 2026-06-16 · amended to current implementation 2026-09-05
**Criticality:** [CRITICAL]

## Decision

The `bp` CLI is implemented in Python 3.11+ and checked with `mypy --strict` and Ruff in CI. Type
annotations and Pydantic models are used where they improve executable boundaries; this is not a claim
that every runtime object is fully modeled or that `Any` is absent.

Current stack:

- `httpx` for the synchronous REST client;
- Typer/Click for the CLI;
- Pydantic for selected response/request validation;
- stdlib `sqlite3` for the Run Ledger;
- pytest/Hypothesis for executable tests;
- mypy strict and Ruff check/format gates.

Client-side fuzzing is synchronous and sequential. No async-httpx matrix executor is implemented.
Python does not mirror every Kotlin DTO as a Pydantic class; several command boundaries deliberately
handle dictionaries and validate only the shape they consume.

## Distribution

The current build produces a Python sdist and wheel with `bp` and `burpctl` console entry points.
Source installs use the project under `bp/`. A PyInstaller standalone binary is a historical proposal,
not a delivered artifact. Registry commands such as `uv tool install bp` or `pipx install bp` are valid
only after a matching package version has actually been published; source checkout instructions must
say when they mean `uv tool install .` from `bp/`.

## Consequences

- CI checks the supported Python matrix and runs strict analysis at the minimum version.
- Runtime schema validation remains explicit and bounded; static typing is not described as proof of
  remote response correctness.
- The Python package version, Kotlin/Gradle identity, lockfile, and OpenAPI version move together for a
  release.
- A matched CLI/JAR pair is still a caller responsibility until a runtime handshake exists (PC-06 in
  [`../PROOF-CEILINGS.md`](../PROOF-CEILINGS.md)).
