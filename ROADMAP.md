# Roadmap

This is a direction, not a dated promise. An item is not shipped merely because an ADR, historical
Gherkin scenario, DTO, or server route names it. The implemented CLI is enumerated in
[`docs/CLI.md`](docs/CLI.md), the REST publication in
[`src/main/resources/openapi.json`](src/main/resources/openapi.json), and unresolved evidence limits in
[`docs/PROOF-CEILINGS.md`](docs/PROOF-CEILINGS.md).

## Release v2.1.0 safely

The immediate work is evidence, not another capability:

1. Replay the corrected acceptance cases against the rebuilt and reloaded v2.1.0 CLI/JAR pair.
2. Record machine-validated receipts for each established defect's redeployed live pass,
   assertion-reaching causal RED, and content-bound review by a distinct attested non-author lane.
3. Promote no ledger row until all three receipts satisfy the gate. The current ledger has zero
   `verified` records, and the all-verified release gate fails.
4. Rebuild and rerun the four superseded-contract oracle treatments. `VERIFY-D24` has a reproduction
   and artifact; `VERIFY-D58`, `VERIFY-D59`, and `VERIFY-D61` were identified by source analysis
   without standalone reproductions or durable artifacts.
5. Keep the replacement acceptance harness under version control. All four oracle repairs existed only
   under `/tmp/burpctl-live/verify/`; an unrelated reboot removed that directory before a run. The new
   in-repository `verify/` suite has produced a non-clean retained run: its system preflight proved the
   deployed binary predates the current source because embedded and source OpenAPI differ, so none of
   the 30 selected REST/CLI behavior cases ran. Redeploy the final matched JAR, rerun from settled
   source/binary state, and retain the result.
6. Build, smoke-test, checksum, tag, and publish the matched extension and Python artifacts only after
   the evidence gate passes.

D01–D18 are `fixed`, not `verified`, because the newer receipt-backed meaning was applied uniformly.
That demotion records missing evidence and does not claim a regression.

## Evidence and recovery gaps

These are current source or proof boundaries, not promises that an implementation is already designed:

- add a recoverable Scanner task inventory while the extension-owned registry survives; pinned Montoya
  cannot rediscover a handle after that registry is lost (PC-04);
- make accepted long scope mutations independently checkable without the GET-query length ceiling
  (PC-05);
- add a general CLI/extension compatibility handshake rather than relying on the caller to compare
  versions (PC-06);
- expose an original-byte response representation before claiming byte identity for malformed UTF-8
  (PC-07);
- strengthen or explicitly bound marker-provenance transforms, record the actual post-override
  method/URL/body rather than pre-send values, and never pretend arbitrary target transformations are
  invertible; the reopened proof-ceiling wording must land with the code regression;
- require real authority evidence before describing the IDOR response-difference heuristic as a proved
  cross-principal read;
- preserve or enumerate any state needed to report an operation after reload, and continue refusing
  self-destructive user-configuration import while it cannot complete truthfully.

## Candidate CLI work

The following spellings are not implemented and have no assigned release:

- `-w` / `--write-out 'TPL'`;
- invocation-time `--tag NAME` (retroactive `bp tag` is implemented);
- `bp send --batch @file`;
- `bp fuzz --param NAME` as a quick-fuzz shortcut;
- `bp show <opId>` or Run Ledger result reconstruction;
- client commands for asynchronous Intruder lifecycle or Scanner pause/resume/stop.

Some related server routes already exist. That does not make the CLI command available: Intruder
lifecycle routes are separate from client-side `bp fuzz`, Scanner pause/resume remain unsupported in
pinned Montoya, and hash-only Run Ledger records cannot reconstruct response content.

## Later Burp surfaces

Sequencer, full Comparer, Logger, Organizer, Engagement, Search, Inspector, Dashboard, and Clickbandit
have no current REST operation. Each needs a source-backed Montoya capability, route, OpenAPI contract,
CLI design, and appropriate live proof; a model or historical scenario alone is not implementation.

## Historical BDD corpus

The files under `docs/bdd/` remain explicitly historical and non-executable. Do not repair them into
apparently current prose while no runner checks them. Either keep them labeled as design history, or
rewrite and bind them to executable steps before calling them acceptance contracts.

## Priorities

1. Truthful release evidence and safe state/reporting boundaries.
2. Recovery paths for effects and one-use values.
3. Small CLI features backed by an existing truthful REST operation.
4. New extension surfaces, each with source, OpenAPI, CLI, and live-contract proof.

Contributions should start with [CONTRIBUTING.md](CONTRIBUTING.md). Security reports follow
[SECURITY.md](SECURITY.md).
