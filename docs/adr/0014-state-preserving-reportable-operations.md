# ADR-0014 — State-preserving, reportable operations and live Montoya release proof

**Status:** accepted — 2026-09-04
**Criticality:** [CRITICAL][BLOCKS:critical]
**Supersedes:** the mock-only Montoya acceptance boundary in [ADR-0013](0013-truthful-executable-contracts.md)

---

## Context

The v2.0.0 live campaign found two failures that the green Kotlin suite, Detekt, and coverage gates had not exposed. `GET /proxy/websocket/history` failed on its first populated real-Burp call because an absent Java platform value was treated as non-null. Scanner status, issues, and audit stop failed on real tasks because a state-dependent Montoya counter accessor threw. The mocked Montoya API returned the clean values encoded by the tests, so those tests verified the authors' model of the integration rather than the behavior of Burp Suite Professional 2026.3.3. Live calls found both total functional breaks within minutes. This evidence does not discredit mocks for pure logic; it establishes that they cannot be the only authority for a third-party integration contract.

The campaign also established two reportability failures. `PUT /config/user` imported the extension's own user configuration and reloaded the extension while the request was in flight. Uptime reset twice, an immediate health read returned `CONNECTION_REFUSED`, and extension-owned in-memory state disappeared, including a Collaborator treatment and untouched control. Because the responder is destroyed by its own operation, it cannot truthfully complete that operation. Separately, output validation ran after mutations and destructive reads. The worst case created a real audit task, then exited 2 before printing its id; scanner tasks cannot be enumerated, so the effect became permanently unaddressable through the product.

A documented control operation is not truthful merely because its underlying call occurred. Its declared state boundary and its ability to report the result are part of the operation.

## Decision

1. A documented API operation must not silently destroy caller-visible live state outside its named effect. This includes extension-owned registries, task handles, sessions, pending one-use results, and the responder needed to complete the request.
2. Preconditions that can be decided locally—output mode, field projection, request shape, and reportability—are validated before any target, Burp-state, configuration, task, or destructive-read effect.
3. If an operation cannot return a truthful completion result, it refuses before acting. A self-reloading user-configuration import is therefore unavailable through this extension unless a future design can move execution and acknowledgement to an authority that survives the reload. Project-only import may remain available only while it preserves the extension and can be reported truthfully.
4. An effect that creates an identifier or consumes a one-use value must have its output representation selected before dispatch. If the identifier cannot be returned or recovered from an authoritative enumeration/durable record, the effect does not start.
5. Mocked Montoya tests remain useful for pure logic, mapping, and controlled failure branches, but they are not sufficient release evidence for a Montoya integration claim. A release candidate that changes or claims such behavior must replay the affected contract against the pinned supported real Burp build, including absent/nullable platform values and state-dependent accessors. The result is recorded as live evidence; a green mock suite cannot promote `fixed` to `verified`.
6. When a live action loses its handle or a reload interrupts custody, the resource remains `unknown` until an authoritative oracle proves deletion, completion, or recovery. Lack of traffic, low CPU, or elapsed time does not settle that state.

## Compatibility policy

Refusing an operation that cannot preserve its stated state boundary or report completion is a deliberate safety correction, even if v2.0.0 previously returned success or acted before a usage error. `session clear` broadening to remove the captured cookie jar is an observable semantic change and therefore ships in a minor release. Fields for which real Montoya can return no value become nullable rather than fabricated; that schema change also requires the 2.1.0 contract to be explicit.

## Consequences

- `PUT /config/user` excludes and reports `user_options.extender.extensions`, the inventory whose
  import can reload this responder; safe sibling options remain importable. A future design must still
  refuse before acting if it cannot preserve the responder.
- Output compatibility and field validation move ahead of all effectful calls, including Collaborator polls/generation and scanner task creation.
- Created task/payload identifiers cannot be discarded by a renderer; either they are deliverable/recoverable or creation is refused.
- Release evidence for affected Montoya paths includes a real-Burp smoke/replay. Hermetic suites remain necessary but no longer constitute the whole integration release gate.
- ADR-0013's statement that mocked Montoya tests alone form the acceptance boundary is superseded for release claims. Its strict-input, typed-error, and truthful-unsupported decisions remain in force.
- Existing unknown scanner tasks remain unknown; this decision does not infer their state or invent a
  recovery path. See [PC-04](../PROOF-CEILINGS.md#pc-04--a-scanner-task-cannot-be-recovered-after-its-handle-is-lost).
- No current defect is `verified`; the final redeployed-binary replay and the other structured receipts
  remain release prerequisites. The repaired external acceptance harness was destroyed before it ran,
  which reinforces the requirement that both instrument and result have durable versioned identity.
