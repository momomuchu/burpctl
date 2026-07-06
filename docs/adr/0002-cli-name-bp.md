# ADR-0002 — CLI name = `bp`, alias `burpctl`

**Status:** superseded by [ADR-0011](0011-rebrand-burpctl.md) — 2026-07-06 (original: accepted 2026-06-16)
**Criticality:** [HIGH][BLOCKS:high]

> **Superseded:** the primary name is now `burpctl` (project brand + primary command), with `bp`
> kept as the 2-char alias — the inverse of this ADR's original primacy. Rationale in ADR-0011.

---

## Decision

The CLI binary is named **`bp`**. A second hard alias **`burpctl`** is installed alongside it.

- `bp` is the primary name: 2 characters, fast to type, memorable.
- `burpctl` follows the `*ctl` convention (kubectl, systemctl, iptables-legacy, netctl) for users
  who prefer an explicit namespace.
- Both names invoke identical behaviour; there is no feature split.

---

## Rationale

Founder decision 2026-06-16. `docs/SPEC.md §3` documents the evaluation:

- A short, unique, brandable name reduces friction for a user-facing distributable product.
- `burpctl` gives the tool a recognisable slot in the kubectl / systemctl mental model — useful
  for hunters and security engineers already familiar with that convention.
- Two characters (`bp`) are as short as practical for a command typed dozens of times per session.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| `burp` | Collision with an existing Unix backup tool. Would break systems that have both installed. |
| `bx` | Already taken in the Ruby / Bundler context (`bundle exec` shorthand). Confusing for Ruby developers. |
| `burp-cli` | Hyphenated names are awkward to type and non-standard on Unix. |
| Single name only (no alias) | `burpctl` costs nothing to install alongside and serves users who prefer explicit namespacing. No reason to withhold it. |

---

## Consequences

- Build tooling must produce and install both `bp` and `burpctl` (symlink or second binary).
- Documentation uses `bp` as the canonical name; `burpctl` is mentioned as an alias in the README.
- Shell completion scripts must be provided for both names.
