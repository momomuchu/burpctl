# ADR-0001 — REST routing and published-contract authorities

**Status:** accepted 2026-06-16 · amended 2026-09-05
**Criticality:** [CRITICAL][BLOCKS:critical]

## Decision

The implemented HTTP surface is the set registered by `RestServer.configureRouting()` and
`routes/*.kt`. Service implementations and serializers determine behavior and representation; route
registration alone is not a behavioral oracle.

`src/main/resources/openapi.json` is the published interface. An executable contract gate must keep its
METHOD/path inventory and serializer schemas aligned with Kotlin. `docs/SPEC.md` is a reader-facing
inventory derived from those sources, never a co-equal implementation authority.

The default loopback origin is `http://127.0.0.1:8089`. The runtime port can be configured; clients use
`--url`, `BURP_REST_URL`, configuration, then that default.

## Context and amendment

The original 2026-06-16 decision responded to three contradictory documents: a legacy `spec.md`
described a different Python/MCP/SSE system on port 9876, the README had ghost/missing routes, and the
then-embedded OpenAPI declaration was incomplete. The legacy `spec.md` was later deleted; it is not
archived in the current tree.

The current OpenAPI publication identifies as 2.1.0 and contains 69 operations in 13 groups. The Kotlin
route inventory contains the same 69 METHOD/path pairs. This corrects the former incompleteness but does
not make route count proof of semantics, runtime reachability, or real-Montoya behavior.

## Consequences

- A route change updates Kotlin registration, service/DTO serializers, OpenAPI, contract tests, and
  current documentation together.
- Inventory checks compare exact METHOD/path pairs and unique operation IDs; behavior checks use the
  component that makes the decision.
- OpenAPI shape validation is necessary but cannot validate prose meaning or prove a live operation.
- No legacy document may override the current source or publication.
- Version-sensitive use requires a matched CLI/extension pair; see PC-06 in
  [`../PROOF-CEILINGS.md`](../PROOF-CEILINGS.md).
