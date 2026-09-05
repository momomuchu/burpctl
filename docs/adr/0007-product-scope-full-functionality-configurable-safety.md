# ADR-0007 — Product direction and configurable safeguards

**Status:** accepted as product direction 2026-06-16; unimplemented items are not commitments
**Criticality:** [CRITICAL]

## Decision

`bp` may grow toward a broad bug-bounty control surface, but an identified capability becomes a feature
only when source, CLI/REST contract, safety boundary, tests, and required live evidence exist. A model,
ADR, roadmap item, or historical scenario is not implementation.

Target-scope preflight and response envelopes were proposed as configurable safeguards rather than
mandatory global policy. Current configuration parses `enforce_scope`, `envelope`, and `throttle_ms`,
but commands do not consume them and no matching root options are registered. They must not be
advertised as active controls.

The current product does enforce non-configurable correctness/safety invariants where a truthful
operation requires them: origin binding, strict request shape, effect-before-output ordering, bounded
fuzz cardinality, unsupported-operation refusal, and state/reportability rules. “Configurable safety”
does not mean the tool enforces nothing.

Redaction is intended to default on and has an explicit `--no-redact`/`BP_REDACT=off` opt-out. The
release still requires the final disclosure-path review described in `docs/OUTPUT.md`; absence of the
opt-out is not yet claimed as proof that every representation is covered.

## Historical proposals

The original `program`, `asset`, `endpoint`, `finding`, `report`, classification, and named
multi-session namespaces were design ideas. They are not registered commands and have no assigned
release. The accepted command inventory is [`../CLI.md`](../CLI.md); future additions require a new or
amended decision rather than relying on this list.

## Consequences

- Current docs distinguish shipped, unsupported, proposed, and verified.
- User-configurable policy never substitutes for hard consistency/security invariants.
- New functionality starts with an exact effect and evidence boundary, then earns a command/route.
- Proof ceilings in [`../PROOF-CEILINGS.md`](../PROOF-CEILINGS.md) remain explicit even when a feature
  is useful within them.
