# ADR-0009 — `--format` / `--fields` / `--url` must be position-tolerant

- **Status:** accepted — 2026-06-18
- **Criticality:** `[HIGH]` (CLI contract / public interface)
- **Supersedes:** none. Refines ADR-0002 (CLI name/grammar).
- **Trigger:** live UltraQA finding **F1** — `bp health --format json` → `No such option: --format`, exit 2.

## Context

`--format`, `--fields`, and `--url` are declared on the top-level Typer `@app.callback()`
(`bp/src/bp/cli.py`). In Click/Typer, callback (group) options must appear **before** the
subcommand. So only `bp --format json health` works; the natural `bp health --format json`
fails with a usage error (exit 2).

This was invisible to the 124-test suite because:
- `test_cli_conformance.py` only asserts each command's `--help` exits 0 (reachability), and
- `test_output.py` calls the renderer directly, bypassing the CLI grammar.

Found only by running the real binary against the live `:8089` extension.

## Decision

Make the three global output options **position-tolerant**: `bp <cmd> --format X` behaves
identically to `bp --format X <cmd>`.

Implementation: a conservative `argv` pre-processor in the console entrypoint that hoists the
known value-taking global options (`--format`, `--fields`, `--url`, and their values) to the
front, **before** Typer parses, when they appear after the subcommand. The single source of
truth stays the `@app.callback()` declaration — no per-command duplication, no double-declared
precedence.

Scope guard: only the three known global options are hoisted; only when they follow the first
non-option token (the subcommand); `--opt=value` and `--opt value` forms both handled; unknown
options are left untouched for Typer to reject as today.

## Rationale

- The contract `bp <command> [subject] [--format ...]` is what `docs/CLI.md` implies and what
  every user types. Spec-as-contract: the code must match the natural grammar.
- Minimal blast radius: one entrypoint function + one new test file, vs editing ~40 commands.
- Preserves a single option declaration → no precedence ambiguity.

## Alternatives considered

- **Duplicate the options on every command** (via shared decorator): rejected — ~40 call sites,
  double declaration, precedence confusion between callback value and command value.
- **`ignore_unknown_options` on commands**: rejected — would silently drop `--format json` after
  the subcommand (exit 0, wrong output) — strictly worse than the current loud failure.
- **Leave as-is, document global-only**: rejected — documented earlier as a "v1.1 placement note",
  but live use proves it reads as broken on every command; not acceptable for v1 honesty.

## Consequences

- RED test (`tests/test_cli_global_opts.py`): `bp health --format json` exits 0 and emits JSON;
  `bp --format json health` still works; bogus values still exit 2 with the clear message.
- `docs/CLI.md` / `docs/OUTPUT.md`: drop the "options must precede the subcommand (v1.1)" caveat.
- Risk: argv rewriting must not mis-hoist a literal option-like positional value; covered by tests.
