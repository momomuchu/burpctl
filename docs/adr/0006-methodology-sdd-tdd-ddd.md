# ADR-0006 — Contract-first development and evidence boundaries

**Status:** accepted 2026-06-16 · amended by [ADR-0013](0013-truthful-executable-contracts.md) and
[ADR-0014](0014-state-preserving-reportable-operations.md)
**Criticality:** [HIGH][BLOCKS:high]

## Decision

The project uses source-aligned contracts, RED-first tests for new corrective behavior, strict static
checks, and small reviewable changes. The authorities are separated:

- Kotlin routes/services/DTO serializers define extension implementation behavior;
- Typer registrations and Python execution/output code define CLI behavior;
- OpenAPI publishes the REST interface and is mechanically joined to serializers;
- current prose explains those executable sources without overriding them;
- real-Burp behavior requires comparable live evidence where Montoya is involved.

A local test or mock is necessary evidence for pure logic but cannot by itself promote a defect to
`verified`. Promotion follows the receipt-backed policy in `quality/README.md` and ADR-0014.

This ADR states a method, not a retrospective claim that every historical change had a retained
assertion-reaching RED or that every commit was green. Where durable evidence is absent, documentation
must say so rather than infer it from intent.

## Current product boundaries

- `bp` targets Python 3.11+ and the extension targets Java 17 bytecode.
- Pro-only capability maps to exit 4, not historical sysexits value 69.
- A Run Ledger row represents one bp-to-extension HTTP operation. One invocation may write several
  rows, and exit/tag fields can be updated after insertion.
- `docs/bdd/` has never had a runner or step bindings and is not an acceptance gate. ADR-0013 marks its
  641 scenarios non-normative and pending removal.
- The current CLI exit set is 0–5; [`../CLI.md`](../CLI.md) owns its meanings.

## Consequences

1. Behavior changes update source, executable tests, published contracts, and current prose together.
2. A shape check must not be described as a semantics check; a mock must not be described as live
   integration proof.
3. RED evidence reaches the named assertion and is retained if it will support verification.
4. A release changing Montoya behavior replays that contract against the pinned real Burp build and
   retains the result.
5. The acceptance instrument itself is versioned and reviewed. The loss of the unversioned `/tmp`
   harness before its repaired cases ran is concrete evidence for this requirement.
6. Historical decisions remain labeled when superseded; they are not silently rewritten as current
   implementation history.
