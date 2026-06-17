# ADR-0007 — Product Scope: Full Functionality, Configurable Safety

**Status:** accepted · 2026-06-16
**Criticality:** `[CRITICAL]` (defines the scope of the entire spec)

## Decision

`bp` targets the **full functional surface of a bug bounty tool** — every business concept
identified in `RESEARCH-concepts.md` (35 gaps) becomes a **feature**, not
something "out of scope by design".

**Security and scope are CONFIGURABLE**, never **mandatory blocking guards**:
- Scope verification (anti-OOS pre-fire), the anti-injection envelope (I6), and secret
  redaction (I7) are **configuration options** (enable/disable), not enforced preconditions.
- A reasonable default is fine (e.g. scope-check = `warn`), but the user configures it;
  `bp` **enforces** nothing.

## Rationale

Founder, 2026-06-16 (verbatim): "checking the scope is important, but it's not necessarily
mandatory… it's among the configurations… we just need all the features of the bot, the bug
bounties, plain and simple."

## Rejected Alternatives

- **T1 — Pure driver**: rejected — `bp` alone would not cover the business domain; the 35 gaps would remain.
- **T2 — Mandatory security floor**: rejected — the founder does NOT want an enforced guard; security
  must be configurable, not blocking.

## Implications (spec, not execution)

1. The **command map `CLI.md` expands**: new namespaces — `bp program`, `bp asset`,
   `bp endpoint`, `bp finding`, `bp report`, multi-session (`bp session --as <ctx>`),
   classification, in addition to the current driver.
2. **Safety** features become **flags/config**: `--enforce-scope warn|block|off`,
   `--envelope on|off`, `--redact on|off` (plus config-file equivalents).
3. `RESEARCH-concepts.md` = the **feature roadmap** (the 35 prioritised gaps).
4. Next spec phase: map each gap → concrete command/config and extend
   `SPEC.md` + `CLI.md`. **Still zero execution before your GO.**

## Related

- `docs/RESEARCH-concepts.md` (the 35 gaps) · `ADR-0005` (Run Ledger) · `ADR-0004` (fuzz --async)
- C3 bug-bounty-mini (I6/I7/sole-egress) remains an **optional adapter**; here its concepts are
  adopted as **native configs** of `bp`.
