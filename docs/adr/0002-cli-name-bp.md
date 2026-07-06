# ADR-0002 — CLI name = `bp`, alias `burpctl`

**Status:** accepted 2026-06-16 · briefly superseded by [ADR-0011](0011-rebrand-burpctl.md), then
reinstated by [ADR-0012](0012-primary-name-bp.md) — 2026-07-06
**Criticality:** [HIGH][BLOCKS:high]

> **History:** ADR-0011 briefly made `burpctl` the primary name; ADR-0012 reverted to this ADR's
> original stance — `bp` primary, `burpctl` alias — on the founder's "one token" rationale.

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
