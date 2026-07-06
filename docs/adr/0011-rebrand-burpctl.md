# ADR-0011 — Rebrand to `burpctl` (primary), `bp` as alias

**Status:** accepted — 2026-07-06
**Criticality:** [HIGH][BLOCKS:low]
**Supersedes:** [ADR-0002](0002-cli-name-bp.md)

---

## Decision

The project brand and primary CLI command are **`burpctl`**. `bp` is retained as a 2-character
alias (identical behaviour). The self-describing repo name "burp-wrapper" is dropped everywhere.

- Distribution name (`pyproject.toml [project].name`) = `burpctl`.
- Console entry points: both `burpctl` and `bp` → `bp.cli:cli_main`.
- Python import package stays `bp` (`src/bp/`, `from bp import …`) — not renamed (high churn, zero
  user benefit, would break imports for no gain).
- Documentation and the GitHub repo slug use `burpctl`.

---

## Rationale

Founder decision 2026-07-06, ahead of a public (Reddit) launch. Evidence gathered during the naming
research pass:

1. **"wrapper" self-sabotages.** To a security audience allergic to low-effort "yet another wrapper"
   posts, the word signals a thin shim — the opposite of what the project is (a 400+-test,
   `mypy --strict`, spec-driven project with a custom client-side fuzzing engine).
2. **Discoverability in a crowded field.** The Burp-automation space is full of near-identical
   descriptive names (`burp-rest-api`, `burpa`, `BurpControl`, `BurpSuite-API`) that blur together
   and mostly target *scanner* automation (headless/CI/DAST). `burpctl` reads as "the kubectl for
   Burp" — a distinct mental slot that matches this tool's actual pitch (an interactive CLI control
   plane for hunters), and the `*ctl` convention separates it from the `*-rest-api` crowd.
3. **Trademark risk is low in practice.** "BURP SUITE" is a PortSwigger trademark and their terms
   ask for prior approval, but dozens of long-lived `burp-*` community tools have never been
   enforced against. A distinct standalone brand (à la Caido / Belch) remains a future option if the
   tool gains traction; it is not needed to launch.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Keep `burp-wrapper` (rebrand pitch only) | Leaves a weak, self-deprecating repo name and poor search/brand signal for the launch. |
| Standalone non-"Burp" brand (Caido/Belch style) | Trademark-safest and most brandable, but a bigger bet — building recognition from zero. Deferred; can be done later if the tool takes off. |
| `bp` as primary (original ADR-0002) | `bp` is a fine 2-char shortcut but a poor brand (unsearchable; collides with "blood pressure" / British Petroleum). Keep it as the alias, not the identity. |

---

## Consequences

- `[project.scripts]` installs both `burpctl` and `bp`.
- Dist name change is safe: `--version` reads a hardcoded `__version__` in `bp/__init__.py`, not
  `importlib.metadata`, so renaming the distribution does not break version reporting. CI does not
  reference the dist name. Verified against a green baseline (428 passed / 2 skipped at decision
  time; 433 collected after adding the entry-point + prog-name regression tests in this change).
- The GitHub repo is renamed `burp-wrapper` → `burpctl`; GitHub keeps a redirect from the old slug,
  so existing links and clones continue to resolve.
- Historical CHANGELOG entries are left intact; only release-tag URLs were updated to the new slug.
