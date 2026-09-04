# Quality evidence

`confirmed-defects.yaml` is the bounded completion ledger for four evidence sets:

- D01–D18: the behavior-hardening pass begun from commit `663bb56` on 2026-09-03;
- D19–D61: the 2026-09-04 live campaign against the shipped v2.0.0 extension and CLI with Burp Suite Professional 2026.3.3;
- D62–D70: corrective defects R1–R9 found during adversarial review of the v2.1.0 fix tree;
- D71–D73: defects found in the live acceptance and quality-ledger gates while replaying that tree.

The block below is checked against `confirmed-defects.yaml` by `bp/tests/test_quality_ledger.py`. Change the ledger without updating its ranges, status counts, or original-campaign rejection ratio and the test fails.

<!-- ledger-summary:start -->
- Evidence-set ranges: historical `D01–D18`; original live campaign `D19–D61`; corrective review `D62–D70`; quality-gate findings `D71–D73`.
- Status counts: **73 total** — **0 verified**, **16 confirmed**, **51 fixed**, **1 unconfirmed**, and **5 rejected**.
- Original live-campaign adjudication: **5 rejected of 43 candidates (11.6%)**.
<!-- ledger-summary:end -->

The fall from 18 `verified` records to zero does **not** mean D01–D18 regressed. The meaning of `verified` became uniformly evidence-bearing. Those 18 corrections retain their original regression/contract references and commit provenance, but their rows lack durable structured receipts for all three newer promotion criteria, so they were demoted to `fixed` rather than grandfathered under a weaker meaning.

It is deliberately narrower than “all possible bugs.” Each record carries an invariant, implementation slice, executable regression references, compatibility choice, and verification state. D19 and later additionally preserve reproductions, observations, severity, discovering lane, and artifact case IDs. `verificationNotes` records a later constraint or disposition without overwriting the original observation. `severity` is null for rejected or unconfirmed candidates because neither is an established product defect. Not every landed campaign mechanism has a one-to-one defect ID: K25 malformed-stored-request handling, scanner enumeration, response `bodyBase64`, H2 byte persistence, the earlier auth-bypass OpenAPI schema regression, and PC-06 version pairing are attached to related records rather than assigned manufactured IDs.

Statuses are:

- `confirmed` — reproduced live; the ledger does not yet accept a candidate correction as fixed;
- `fixed` — corrected behavior is present and the record states the available local, causal, or redeployed-binary evidence, but one or more verification requirements remain unmet;
- `verified` — all three current promotion requirements are established by machine-validated structured receipts: the case passes live against the redeployed binary, an assertion-reaching causal RED failed before the fix and passed after it, and a content-bound review artifact records a passing adversarial review by a distinct attested non-author lane under the identity ceiling stated below;
- `unconfirmed` — an observation exists, but the evidence does not establish a contradiction with the product contract;
- `rejected` — investigation established that the behavior matches the product contract; the record cites the source or documentation that resolves it.

A compilation error, unresolved reference, `NoSuchMethodError`, `MockKException`, `IllegalArgumentException`, or other failure before the named assertion is a broken test, not a causal RED. A record never moves directly from `confirmed` to `verified` on unit-test evidence. A real-Burp reproduction is verified only by the comparable live control after redeployment, and only after the causal RED and non-author review requirements are also met. Unknown resource state remains unknown until an authoritative recovery oracle settles it.

D01–D18 predate the evidence-rich campaign schema. Their historical `verified` labels came from the original pass's older legitimate definition. Each row retains its listed regression and contract references, and commit `8a166e9` records D01–D18 as having RED-first coverage and aggregate gates. Cheap recovery found no durable per-record live-redeployment receipt, assertion-reaching RED transcript, or non-author review receipt. Recovering or recreating those receipts would require a separate archaeology/replay campaign, not a ledger edit. The rows are therefore now `fixed`: the demotion means “missing receipts for the newer uniform standard,” not “the correction regressed” or “the original verification never happened.”

For D62–D70, the supplied handoff says the causal RED requirement was satisfied. The shared frozen-tree gate completed with Kotlin `clean test detekt --rerun-tasks` BUILD SUCCESSFUL (8 tasks executed), Python 684 passed, and an identical source-tree digest before and after the run. Nothing was cached, Detekt was clean tree-wide, and the Detekt baseline was not regenerated; regenerating that baseline to conceal findings is forbidden evidence manipulation in this campaign. These facts establish local fixed-tree evidence only. All nine records still lack live redeployed-binary and non-author review receipts, and all nine lack a durable in-repository RED artifact; where exact assertion output was not supplied, the record says so rather than manufacturing it.

D68's generalized follow-up showed why the original four-route R7 hand fix was insufficient. Before any schema edit, 7 non-vacuous tests reached 4 assertions and inventoried **294 violations across 67/69 operations plus 4 shared-envelope violations**: 221 route-response, 52 request-schema, 21 parameter, and 4 shared `ApiResponse`. Every one of 61 successful envelope responses pointed at the wrong data model, and five always-unsupported operations advertised impossible 200 responses. The RED console's SHA-256 is `b2daa634076e354b9f20ae7f2ab5730b761dfa099f9e006439060020fbd70358`; its job-temp path may disappear, so the digest and counts are duplicated in D68. Post-fix, the model-derived check covers 69/69 operations and 144 rebuilt components with two reasoned exemptions, six explicit non-emptiness guards, 7/7 passing tests, and clean compile/Detekt without suppression or baseline change. The initial four routes represented only about six percent of the defect; generalization found the other ninety-four percent.

## Collaborator authorization and blockers

On **2026-09-04**, the user explicitly authorized use of the Collaborator provider. That permission allows the relevant D33 and D34 live arms to contact **PortSwigger's public Collaborator server**. It does not authorize any other external destination. Every non-Collaborator destination in this campaign remains limited to `127.0.0.1:8089`, `127.0.0.1:9921`, and `127.0.0.1:9922`.

This removes the missing-authorization cap from D33 and D34. D24 is not Collaborator-blocked: Collaborator accounts for only two of its ten proved-live effect sites, and other effect sites can test the invariant. D46 has no Collaborator content at all; its discriminator is a target transport failure against a closed loopback port. D53 is not Collaborator-dependent either. Its real blocker is the required `bp config set user` reproduction: that user-configuration import path can reload the serving extension mid-request and destroy extension-owned in-memory state, so the campaign forbids it for exactly that reason. The concurrent Collaborator state loss in D53 was collateral evidence of the reload, not its prerequisite.

## 2026-09-04 redeployed-binary acceptance

The acceptance run exercised a freshly redeployed v2.1.0 extension JAR with SHA-256 `15aca5175e936c492fdf0798d82a14bfdad9e3713bccc28beb22675a74be5d27`. Deployment was reported at 12:12:50, with uptime reset observed from 6584 to 2. During the valid run, the editable source-tree digest was `74e6efafe75e95a4ead1987aeb861159cd2cfb8f0f023ad551ff10d2b129ca01` both before and after, while `/health` uptime rose monotonically from 209 to 229. No reload was observed.

`VERIFY-D19` through `VERIFY-D23` passed:

- D19: all three media-type arms returned HTTP 415 JSON with `success=false` and code `UNSUPPORTED_MEDIA_TYPE`;
- D20: all three malformed history integers returned HTTP 400 with code `INVALID_PARAM`;
- D21: both timestamp diagnostics were fixed ISO-8601 messages with no supplied marker, Java name, or parser internals;
- D22: all three machine-mode usage errors exited 2, left stdout byte-empty, and emitted exactly one JSON `USAGE_ERROR` on stderr;
- D23: REST and CLI each returned all 12,675 WebSocket rows; optional-null rows were readable and every CLI NDJSON row parsed.

Those passes satisfy only the redeployed-binary requirement. None of D19–D23 is promoted to `verified`, because none records either an observed assertion-reaching causal RED during its fix or a surviving non-author adversarial review. D22 moves from `confirmed` to `fixed` because its corrected behavior is now directly established against the redeployed pair; D19, D20, D21, and D23 were already `fixed`.

A later Python lane moved D24, D33, D34, and D46 from `confirmed` to `fixed`. Its complete suite passed **706 tests with 2 skipped while network access was denied**, establishing no hidden live dependency in that suite. D24 now has shared preflight plus a request-free matrix over all ten effect sites. D33 now covers the missing quiet essentials and stops inventing scope add/remove values that the CLI never observed. D34 covers the full documented Collaborator poll projection. D46 now treats a mid-campaign `NO_RESPONSE` as terminal as well as mapping it to exit 3. None has a live redeployed-binary replay, so none is `verified`.

The next observation does **not** adjudicate D24. `bp --format raw send 8575 --path '/echo?marker=raw-send-effect-9Q'` exited 0 with byte-empty stderr, added one isolated ledger row, reached `127.0.0.1:9921`, received HTTP 200, and created Burp history row 401. That is correct behavior for an implemented D27 raw-send projection: `bp/src/bp/output.py:172` lists `send` among the four supported raw-HTTP commands, the preflight at line 231 admits them, and `bp/tests/test_output.py:148-153` asserts response-only raw-send rendering. The legitimate supported effect is neither a D24 PASS nor FAIL because it does not test an incompatible selection or D24's ordering invariant. D24's original confirmed defect remains established on its other documented incompatible-output and unknown-field effect sites, including the scanner audit whose task id was discarded. Its record is now `fixed` on the Python lane's local preflight evidence, without a redeployed-binary replay.

The scanner-audit worst case exposes a separate three-link recovery dependency: raw rendering discarded the task id; the product has no service/REST enumeration method to expose the handle while `ScannerService`'s private `ConcurrentHashMap` survives; and after extension reload loses that registry, pinned Montoya has no task-list primitive with which to rediscover the handle. Scanner task enumeration is currently deferred, but this evidence makes it the only product recovery path during the surviving-registry window—not merely a convenience feature.

The harness nevertheless treated that supported D27 behavior as a D24 failure and resource custody as unknown. Its fail-closed containment then correctly stopped; the abort itself was not a defect. Consequently every planned D25–D61 case remained **COULD-NOT-RUN** and has no redeployed-binary verdict. COULD-NOT-RUN is neither PASS nor FAIL. The single false failure cost 37 downstream verifications; that is an observed shared-state harness property to consider for future isolation, not evidence that continuing through unknown custody would have been safe.

Burp history is knowingly one row above its pre-run state. Row 401 is a fully characterized benign GET to `http://127.0.0.1:9921/echo?marker=raw-send-effect-9Q`, created by a legitimate supported raw-send command against a disposable loopback echo server. Future runs must account for that row rather than assuming the pre-run history cardinality.

The acceptance artifact is `/tmp/burpctl-live/verify/acceptance-20260904T101852Z.md`. Its D19–D23 observations and resource receipts remain evidence, but its D24 FAIL/layer-attribution prose is superseded: current source and tests establish that raw send was a supported D27 operation.

## Harness findings

D71 and D72 form one causal chain rather than two isolated accidents:

1. The acceptance manifest default remained `2.0.0`, and the first preflight executed zero cases; the valid run required explicit `--expected-version 2.1.0` (D71).
2. Product source and its unit test implemented D27 raw send, but `docs/OUTPUT.md:11` and `docs/CLI.md:10` still described the projection as unimplemented.
3. `VERIFY-D24` encoded that stale document contract as a mandatory exit 2 (D72).
4. The supported command correctly exited 0, but the oracle manufactured a false product failure.
5. Correct fail-closed containment acted on that false failure, and 37 later verifications were forfeited.

The repairs must synchronize the version/document/oracle inputs and update the D24 treatment without weakening fail-closed handling of genuinely unknown shared state.

D73 records that the ledger previously documented all three promotion criteria but enforced only the `status` string. The repaired gate requires an exact structured receipt for each criterion, explicit live/green/review pass outcomes and an assertion-failed RED outcome, JSON receipt artifacts under `quality/evidence/` whose embedded defect id, criterion kind, and evidence payload exactly match the ledger fields, matching SHA-256 bytes, timezone-bearing live/RED/review times, a causal test listed among the record's executable regression references, and substantive case/oracle/failure/RED-command/GREEN-command text. A non-author review additionally records distinct attested author/reviewer lanes, exact 40-character implementation and review commits, and the correction's implementation paths. The implementation commit must change every declared implementation path and listed regression and contain their exact current bytes; the review must descend from the implementation; and the review commit must be receipt-only, changing and containing the exact current receipt bytes while changing no correction or regression path. Only `contracts-ci` records may explicitly declare a `test-only` correction, whose implementation paths must themselves be listed regressions. Git provides evidence integrity, correction ownership, temporal separation, and history location here; in this single-committer repository it does **not** cryptographically prove lane identity. Non-authorship is therefore an explicit content-bound attestation whose author/reviewer lane identifiers must differ, not a stronger identity-authenticity claim. Free text such as `yes`, an unseparated lane, or a digest of an unrelated repository file cannot satisfy the shape. Records without all three receipts cannot use `verified`.

No current ledger row contains `verificationEvidence`, no row is `verified`, and this campaign asserts no implementation/review commit hash. Commit fields are absent because the campaign work is still uncommitted, not provisional or fabricated. A promotion criterion must be tested for satisfiability against the actual repository before adoption: a gate that can never fire is as useless as one that always passes, and harder to notice. Mandatory signatures and distinct commit-author emails were both rejected because this repository has neither signed history nor multiple committers; either requirement would have made `verified` unreachable without strengthening evidence integrity.

The acceptance harness itself remains an open structural question, not a fourth defect entry. The promotion instrument lives only under `/tmp/burpctl-live/verify/`: it is outside version control, has no tests or history of its own, and may be deleted by the operating system. Yet it currently owns the case definitions, oracles, and containment logic used to decide whether a `fixed` record can become `verified`. Integration must decide whether to move it beside the repository it validates or deliberately keep it external with an equally durable identity/review mechanism. Until then, future promotion evidence cannot rely on an unpinned disposable harness copy without recording that limitation.

## Gates and format

`bp/tests/test_quality_ledger.py` intentionally hardcodes the complete terminal ID (`LAST_EXPECTED_ID`). This earns its maintenance cost: a list derived from the ledger length could detect an interior gap but would silently accept accidental deletion of the last record; the explicit bound catches tail deletion as well as deletion, duplication, reordering, and renumbering elsewhere. Adding a deliberate defect therefore requires advancing the bound. The same test derives the marked README range/count/ratio block from the ledger and fails on drift, so those human-facing statistics cannot silently go stale.

`BURPCTL_REQUIRE_ALL_VERIFIED=1` remains the final/release gate for established defects in `confirmed` or `fixed` state. Terminal `rejected` and `unconfirmed` candidate dispositions are not defects eligible for promotion and are therefore excluded; requiring them to become verified would make the gate impossible to satisfy. Ordinary development runs allow incomplete established records so fixes and live re-verification can proceed without falsifying completion.

The ledger uses JSON syntax in a `.yaml` file. JSON is a strict YAML 1.2 subset, which keeps the artifact consumable without adding a parser dependency solely for this gate.
