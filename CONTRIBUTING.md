# Contributing to burp-wrapper

Thanks for your interest! `burp-wrapper` is two things in one repo:

- **`bp/`** — the Python CLI client (the recommended interface), and
- **`src/main/kotlin/com/burprest/`** — the Kotlin Burp REST extension (Ktor / Montoya) it talks to on `:8089`.

This project is **spec-driven and test-first**. Contributions that follow the disciplines below get
merged quickly; contributions that skip them will be asked to add the missing pieces first. None of
this is bureaucracy for its own sake — it's what keeps a tool that drives a security proxy correct.

---

## Ways to contribute

| Want to… | Do this |
|---|---|
| Report a bug | Open a **Bug report** issue (template provided). Include component (`bp` / extension), version, repro, and Burp edition. |
| Request a feature | Open a **Feature request** issue. Check [`ROADMAP.md`](ROADMAP.md) first — it may already be planned. |
| Report a vulnerability | **Do not** open a public issue — follow [`SECURITY.md`](SECURITY.md). |
| Fix / build something | Open (or claim) an issue, then send a PR following the flow below. |
| Improve docs | PRs welcome — docs are first-class here (`docs/`, the two READMEs, the ADRs). |

Small, focused PRs are far easier to review than large ones. If you're planning something big, open
an issue first so we can agree on the approach (and which ADR it needs).

---

## Project disciplines (non-negotiable)

The project follows these disciplines (the spec and ADRs in `docs/` are the source of truth):

- **SDD — spec wins.** `docs/SPEC.md`, `docs/CLI.md`, `docs/OUTPUT.md` are the contracts.
  - **No phantom endpoints.** `bp` may only call routes confirmed in `src/main/kotlin/com/burprest/routes/*.kt`.
    A new endpoint = Kotlin route first → `docs/SPEC.md` → then the CLI.
  - **No invented field names.** Output fields map to the Kotlin camelCase identifiers (or are documented `cli:` computed fields in `docs/OUTPUT.md`).
- **TDD — RED before GREEN.** Write the failing test first, then the implementation. Unit and contract
  tests **must not require a running Burp** (mock the boundary). Integration tests skip cleanly when `:8089` is unreachable.
- **DDD.** Use the ubiquitous language from `docs/SPEC.md §11`. No new jargon.
- **Trunk-based + atomic commits.** Short-lived branches; each commit compiles, passes all tests, and is one logical change.
- **Graceful degradation.** Pro-only surfaces (`collab`, `scan` start) detect the failure and exit `4` with a clear message — never fake data or a traceback. Document stubs as stubs.
- **Security invariants.** The Run Ledger stores **sha256 fingerprints only** (never raw bodies); secret redaction is **on by default**; nothing secret is written to `~/.bp` at rest.

**Material decisions** (architecture, a new dependency, a data-model or API-contract change, an
exit-code change) require an **ADR** in [`docs/adr/`](docs/adr/) (`NNNN-slug.md`, status `accepted`)
**before** the implementing change. See the existing ADRs for the format.

---

## Dev setup

You can work on either component independently.

### The Kotlin extension

```bash
# needs JDK 17+
./gradlew build           # compile + run the Kotlin tests
./gradlew test            # tests only
./gradlew shadowJar       # → build/libs/burp-rest-extension.jar (load this in Burp)
```

### The `bp` CLI (Python 3.11+)

```bash
cd bp
uv sync                                   # or: python -m venv .venv && pip install -e ".[dev]"
uv run pytest -q                          # ~430 unit/contract tests, no Burp required
uv run mypy --strict src                  # must be clean
uv run ruff check src tests               # must be clean
```

Live/integration tests need the extension running on `:8089`; they skip automatically when it isn't.

---

## Commit & PR conventions

- **Conventional commits:** `type(scope): short description`
  - **types:** `feat` · `fix` · `test` · `refactor` · `docs` · `chore` · `revert`
  - **scopes** (examples in use): `pos-parser`, `fuzz`, `runner`, `output`, `ledger`, `redact`,
    `history`, `securityscan`, `scan-kt`, `decoder-kt`, `models`, `proxy`, `readme`.
- One logical change per commit; every commit must build and pass tests.
- A PR should: reference its issue, include tests (RED→GREEN), keep the diff focused, and update docs
  (`docs/` / CHANGELOG) when behavior changes. Fill in the PR template checklist.

### Definition of done (what CI and review check)

- [ ] **Kotlin:** `./gradlew test` green (CI runs on JDK 17 **and** 21).
- [ ] **Python:** `pytest` green, `mypy --strict` clean, `ruff check` clean (CI runs these too).
- [ ] New behavior has a RED-first test; behavior changes update the spec/docs/CHANGELOG.
- [ ] Material decision? An `accepted` ADR exists.
- [ ] No phantom endpoint / no invented field name / no leaked secret / no traceback to the user.

---

## Ethical use

`bp` drives a security proxy. Only use it against systems you are **authorized** to test
(your own, a lab, or an in-scope bug-bounty / pentest engagement). Contributions that exist purely to
ease unauthorized or out-of-scope attacks won't be accepted. See [`SECURITY.md`](SECURITY.md).

---

By contributing you agree your work is licensed under the repository's [MIT License](LICENSE).
