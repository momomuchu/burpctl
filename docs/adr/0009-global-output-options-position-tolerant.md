# ADR-0009 — Global execution/output options are position-tolerant

- **Status:** accepted — 2026-06-18
- **Criticality:** `[HIGH]` (CLI contract / public interface)
- **Supersedes:** none. Refines ADR-0002 (CLI name/grammar).
- **Trigger:** a live integration test (**F1**) — `bp health --format json` → `No such option: --format`, exit 2.

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

Make the five current global execution/output options **position-tolerant**:
`--format`, `--fields`, `--url`, `--no-ledger`, and `--no-redact`. For example,
`bp health --format json` behaves identically to `bp --format json health`.

Implementation: a conservative `argv` pre-processor in the console entrypoint hoists those known
value-taking or boolean options to the front before Typer parses when they appear after a subcommand.
The single source of truth stays the root `@app.callback()` declaration—there is no per-command
duplication or second precedence rule.

Scope guard: only those five options are hoisted, scanning stops at literal `--`, value options accept
`--opt=value` and `--opt value`, and unknown options remain for Typer to reject. Root `--version` is not
hoisted.

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
