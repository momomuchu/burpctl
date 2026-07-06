# ADR-0012 — Primary command name reverts to `bp` (`burpctl` kept as alias)

**Status:** accepted — 2026-07-06
**Criticality:** [HIGH][BLOCKS:low]
**Supersedes:** [ADR-0011](0011-rebrand-burpctl.md) · reinstates the stance of [ADR-0002](0002-cli-name-bp.md)

---

## Decision

The primary command and distribution name is **`bp`** again. **`burpctl` is retained as an installed
alias** (both console scripts remain, both map to `bp.cli:cli_main`). Docs lead with `bp`.

The name-independent improvements introduced alongside ADR-0011 are **kept**: the README reframing
(dropped "wrapper", led with the Repeater/throttle fuzzing hook, demoted the AI-agent framing), the
`prog_name`-follows-invocation fix, and the entry-point/usage regression tests.

The GitHub repository slug stays **`burpctl`** (searchable project brand; the `ripgrep`/`rg` pattern
of a descriptive repo with a short command). This is orthogonal to the command name and can be
revisited without code impact.

---

## Rationale

Founder decision 2026-07-06 (verbatim: "use bp rather as name bc its one token"). `bp` is a single
token: minimal to type for a command run dozens of times per session, and minimal token cost in the
prompts/transcripts of the AI agents this tool explicitly targets. That efficiency outweighs
`burpctl`'s brandability for the *command* itself — while `burpctl` is preserved as an alias so users
who prefer the `*ctl` convention (and the repo brand) still have it.

ADR-0011 briefly made `burpctl` primary; it shipped to `main` (CI green) but was never released
(the entry was `[Unreleased]`). The net change from the last release (1.1.0, `bp`) is therefore just:
`burpctl` alias added, docs reframed, prog-name fix — not a rename.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Keep `burpctl` primary (ADR-0011) | Founder override: `bp` is one token, cheaper to type and to tokenize for agent use. |
| Drop `burpctl` entirely | Costs nothing to keep as an alias; preserves the `*ctl` option and repo-brand consistency. |
| Rename the repo to `bp` too | `bp` is an unsearchable repo slug; the descriptive `burpctl` repo helps a public launch. Command≠repo is the `rg`/`ripgrep` norm. Reversible later if desired. |

---

## Consequences

- `[project.scripts]` keeps both `bp` and `burpctl`; `bp` is listed first / documented as primary.
- Distribution name reverts to `bp` (matches the released 1.1.0; no dist-name change from release).
- Docs/README lead with `bp`; `burpctl` is mentioned as the alias.
- `prog_name` already follows the invoked command, so `bp --help` shows `bp` and `burpctl --help`
  shows `burpctl` — no change needed.
- ADR-0011 marked superseded; ADR-0002's original `bp`-primary stance is effectively reinstated.
- The entry-point regression test continues to assert *both* commands exist — still valid.
