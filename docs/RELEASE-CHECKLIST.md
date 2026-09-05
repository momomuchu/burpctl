# v2.1.0 release-readiness checklist

**Current decision: NOT READY.** This checklist records source/document state; it does not replace the
receipt-backed gate or live acceptance evidence.

## Required identities

- [x] `bp/pyproject.toml` = 2.1.0
- [x] `bp/src/bp/__init__.py` = 2.1.0
- [x] the `bp` package entry in `bp/uv.lock` = 2.1.0
- [x] `build.gradle.kts` = 2.1.0
- [x] `BuildIdentity.kt:11` = 2.1.0
- [x] `openapi.json` `info.version` = 2.1.0

Evidence: direct parsing of all six sources and `bp/tests/test_release_identity.py`. The local identity
test passed. This proves source agreement, not which JAR Burp has loaded; runtime pairing remains PC-06.

## Changelog and upgrade material

- [x] Root `CHANGELOG.md` now carries a combined v2.1.0 extension/CLI entry.
- [x] `bp/CHANGELOG.md` carries the corresponding package entry and post-v2.0 errata.
- [x] The entry covers commit `1f79cdb` by source mechanism: marker provenance, session locking/body
  representations, OpenAPI serializer repair, CLI preflight/quiet/Collaborator/NO_RESPONSE behavior,
  and verification-gate changes.
- [x] README/changelogs include source-pair upgrade instructions and observable compatibility changes.
- [ ] No v2.1.0 tag exists, so both entries remain `Unreleased`.

## CLI surface

Documented current leaf set in `docs/CLI.md` (**50**):

```text
health, version, proxy, req, ws, intercept, send, tab, fuzz,
sitemap, encode, decode, hash, ext, diff, endpoints, log, tag,
collab new, collab poll,
scan crawl, scan audit, scan all, scan status, scan issues, scan defs,
check auth, check idor, check headers, check cors, check endpoints,
scope show, scope set, scope add, scope remove, scope check,
config get project, config get user, config set project, config set user,
session set, session get, session clear, session send, session cookies,
history list, history get, history sitemap, history replay, history clear
```

Implemented leaf set from Typer registrations: the same 50.

```text
documented - implemented = empty
implemented - documented = empty
```

The root option set is `--url`, `--format`, `--fields`, `--no-ledger`, `--no-redact`, `--version`, and
`-h/--help`. `docs/CLI.md` enumerates every implemented command-local argument/option; the post-rewrite
set diff is empty. Historical/unimplemented names are explicitly excluded.

- [ ] Static field preflight still diverges at three confirmed sites:
  `scan issues --fields severity`, `sitemap --fields url`, and an absent
  `req --fields listenerPort` all pass preflight then raise during rendering after the GET.
  Documentation states that bound; code must close it before claiming universal
  validation-before-effect.
- [ ] Redaction fixes are still being integrated; the candidate does not yet claim complete coverage.

## REST surface

`src/main/resources/openapi.json` publishes **69 operations on 64 paths**, all with unique operation IDs.
`docs/SPEC.md` enumerates all 69 as `METHOD path — operationId`.

```text
METHOD/path missing from docs = 0
METHOD/path extra in docs      = 0
operationId missing from docs  = 0
operationId mismatch           = 0
```

The Kotlin route inventory is also 69 matching METHOD/path pairs. The moving-tree semantic/status fixes
passed a forced focused `OpenApiContractTest` run under the shared build lock (six tasks executed).

- [x] OpenAPI parses and validates with `openapi-spec-validator`.
- [x] The focused Kotlin contract test was rerun rather than accepted from cache.
- [ ] OpenAPI still calls both `bodyBase64` fields “Exact raw request bytes”; implementation preserves
  exact request-body bytes only. It also omits runtime bounds such as `EndpointsScanRequest.limit`
  1–1000 and marker/cardinality constraints. The focused shape test cannot detect those semantic
  overclaims/omissions.
- [ ] A 69-to-69 shape match is not a live-runtime result. The retained replacement-harness run proved
  the currently deployed JAR's embedded OpenAPI predates this moving source publication.

## Exit codes

Documented and implemented numeric sets are both exactly `{0,1,2,3,4,5}`; neither set has an extra.
Each is reachable in source/tests:

| Code | Reachable category |
|---:|---|
| 0 | success, clean check, help/version, empty successful list |
| 1 | runtime/unsupported/service/render/required-ledger error or inconclusive-only check |
| 2 | parser, option, local validation, field/selector, or confirmation error |
| 3 | REST transport or fuzz `CONNECTION_REFUSED`/`TRANSPORT_ERROR`/`NO_RESPONSE` |
| 4 | `PRO_REQUIRED` |
| 5 | security-check classifier finding |

`documented - implemented = empty`; `implemented - documented = empty`. Target HTTP status is data and
is not another CLI exit category.

## ADRs and proof ceilings

- [x] ADR index enumerates ADR-0001 through ADR-0014 with current/superseded status.
- [x] ADR-0014 exists and is referenced from CLI, output, state, spec, README, changelog, ADR-0013, and
  its implementation-policy applications.
- [x] Current reader paths link `docs/PROOF-CEILINGS.md` for stable no-response, Scanner recovery,
  scope-length, version-pairing, and response-byte contexts.
- [ ] Marker-provenance readers are warned not to rely on PC-03/PC-08 yet. Those sections still use the
  URL, and body are read from the finalized Montoya request. Current code observes final
  headers/cookies but uses pre-send method/URL/body. A separately authorized owner has reopened that
  settled file; RELEASE-DOC did not touch it and its corrected wording/code regression must land before
  these citations are relied on.

## Verification honesty

- [x] Ledger count is stated exactly: 73 total, **0 verified**, 51 fixed, 16 confirmed, one unconfirmed,
  five rejected.
- [x] D01–D18 demotion is described as a uniform change in `verified` meaning, not a regression claim.
- [x] The three receipt requirements are named: redeployed live pass, assertion-reaching causal RED,
  and content-bound non-author review.
- [x] The complete current Python suite passed **799 tests** (one Typer deprecation warning).
- [x] The release gate was exercised separately with `BURPCTL_REQUIRE_ALL_VERIFIED=1`; 11 gate-file
  tests passed and the final gate test failed on the explicit list of all 67 established
  `fixed`/`confirmed` records, as designed.
- [ ] Live verification against the final redeployed candidate is incomplete.
- [ ] Four superseded-contract oracles were identified. Only `VERIFY-D24` has a standalone reproduction
  and artifact; D58/D59/D61 were source-identified. Their repaired unversioned harness was destroyed
  before it ran.
- [x] The replacement harness's local no-Burp unittest selection passed 7 tests. This validates harness
  mechanics only, not the blocked live behavior cases.
- [ ] The in-repository replacement produced a non-clean retained run. A system preflight proved the
  deployed binary predates current source because embedded/source OpenAPI differ; all 30 selected
  REST/CLI behavior cases therefore became `COULD_NOT_RUN`. Redeploy the final matched JAR and rerun.

## Document-set integrity

- [x] Owned current documents were rewritten or amended to remove pre-corrective behavior and
  unimplemented command/output promises.
- [x] Relative Markdown links were checked.
- [x] A documentation credential-pattern scan found no recognized private key, provider token,
  concrete Basic/Bearer credential, or credential-bearing URL.
- [ ] `docs/bdd/` contains 641 scenarios across 16 files, has never had bindings or a runner, and
  independent static audits found all 16 files false overall. ADR-0013 marks it non-normative and
  recommends removal; the `.feature` files are outside this lane's write set and remain present.
- [ ] Non-owned documents still require their owners to reconcile current behavior/release policy:
  `bp/README.md`, `CONTRIBUTING.md`, `.github/pull_request_template.md`, and `SECURITY.md` had concrete
  stale claims at the audit anchor. `config/detekt/README.md` remained true.

## Release artifacts

- [ ] No v2.1.0 Git tag.
- [ ] No final extension JAR, Python wheel, or sdist in this checkout.
- [ ] No checksums/signatures or release manifest joining the CLI and JAR artifacts.
- [ ] CI uploads 30-day build artifacts but no release-publication workflow creates a GitHub release or
  durable published assets.
- [ ] The replacement verification harness/results are currently untracked and therefore not yet part
  of the release artifact. Its README, tests, result schema, fixture, and one retained non-clean result
  are present; generated `__pycache__` files must not be packaged.
- [ ] A promised demo tape/GIF does not exist; media docs no longer pretend the tape is checked in.

Release only after the mandatory evidence gate passes, the final matched artifacts are built and
identified, all non-owned stale documents are fixed, forbidden-file custody is settled, and a clean
replacement acceptance run is retained.
