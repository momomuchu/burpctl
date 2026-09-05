# Changelog

All notable product-wide changes to the `bp` CLI and `burp-rest-extension` are recorded here. The
Python package's older history remains in [`bp/CHANGELOG.md`](bp/CHANGELOG.md).

## [2.1.0] - Unreleased

The source identifies as 2.1.0. This entry describes implemented source behavior; it does **not** claim
that the candidate has passed its release gate.

### Security and correctness

- Security-check marker rejection now examines supported equivalent representations across supplied
  method/URL/body and observed final header/cookie channels. Final method/URL/body are not yet re-read
  from the Montoya request, so the release does not claim complete post-override provenance.
- Session credential/epoch snapshots use one lock order. `session clear` now clears configured
  credentials, origin binding, and captured cookies; both clear paths prevent older responses from
  restoring cleared cookie state.
- User configuration import excludes and reports the extension-inventory path that can reload its own
  responder, while validated safe siblings remain importable. A completed-but-unobservable import
  reports applied state and a do-not-retry warning.
- Known output/field incompatibilities are preflighted before REST effects. Three remaining catalog
  divergences (`scan issues --fields severity`, `sitemap --fields url`, and absent
  `req --fields listenerPort`) can fail after a GET; the blanket pre-effect claim remains blocked until
  those code paths are corrected.
- Discoverable operations unavailable in pinned Montoya return typed 501 `UNSUPPORTED`; permanent
  unsupported routes no longer advertise or return impossible success.

### Fixed in source

- Strict typed server failures now cover 415 media/parse failures, malformed history filters, sanitized
  timestamp errors, and unsupported operations.
- WebSocket listing tolerates absent platform values. Scanner status/issues preserve available values
  when individual accessors fail, and stop reports completion only after deletion succeeds.
- Repeater/session construction preserves ordered duplicate headers/cookies, exact request-body bytes,
  and UTF-8 text bytes without factory browser defaults. Session history records the sent request and
  response text is decoded from response bytes.
- Client fuzzing adds a magic-gated JSON/Base64 payload representation, rejects invalid/unused lists
  before sends, normalizes fragments, retains attempted evidence rows, and treats `NO_RESPONSE` as
  terminal exit 3.
- Local machine-mode errors, history filters, four-command raw HTTP reconstruction, Collaborator
  optional leaves, and allowlisted quiet output are implemented. Commands without a documented quiet
  essential emit no invented value.
- The OpenAPI serializer contract was rebuilt after 294 violations were found across 67/69 operations
  plus four shared-envelope violations. The model-derived gate now covers 69/69 operations; the
  release-audit summary/status semantics were corrected and a forced focused contract run passed.

### Changed

- Python package, lockfile, Gradle project, extension build identity, and OpenAPI source version are
  2.1.0.
- `session clear` has a broader observable boundary and WebSocket response-side values can be nullable;
  generated OpenAPI consumers must be regenerated.
- `verified` now requires structured receipts for a redeployed-binary pass, an assertion-reaching
  causal RED, and content-bound non-author review. D01–D18 moved from `verified` to `fixed` because the
  word changed meaning and those newer receipts are absent—not because they regressed.
- The unexecuted BDD corpus is non-normative and pending removal. Its 641 scenarios across 16 files have
  never had step bindings or a runner; independent static audits found all 16 files false overall.

### Verification status

- `quality/confirmed-defects.yaml` has **73 records: 0 verified, 51 fixed, 16 confirmed, 1 unconfirmed,
  and 5 rejected**. The mandatory all-verified gate fails on all 67 established `fixed`/`confirmed`
  records.
- Live verification against the final redeployed v2.1.0 binary has not been completed. A prior partial
  run covered D19–D23 only and does not satisfy the three-receipt promotion rule.
- Four acceptance oracles were identified as pinned to superseded contracts. `VERIFY-D24` has a full
  causal reproduction and artifact; `VERIFY-D58`, `VERIFY-D59`, and `VERIFY-D61` were identified by
  source analysis without standalone reproductions or durable artifacts. All four repairs lived only
  in an unversioned `/tmp` harness that an unrelated reboot destroyed before it ever ran. Its
  in-repository replacement produced a non-clean retained run: a system preflight proved the deployed
  binary predates current source because embedded/source OpenAPI differ, so all 30 selected REST/CLI
  behavior cases correctly became `COULD_NOT_RUN`. That is not release proof.
- Redaction disclosure fixes and the final method/URL/body provenance boundary remain under review. No
  stronger guarantee is made here.
- No v2.1.0 tag, release JAR, Python sdist/wheel, or published checksums exist yet.

### Upgrade from v2.0.0

- Upgrade the CLI and JAR together and compare `bp --version` with `bp version`; no general runtime
  handshake enforces pairing.
- Regenerate OpenAPI clients and accept nullable WebSocket fields.
- Expect `session clear` to clear the captured jar, inconclusive-only checks to exit 1,
  `NO_RESPONSE` fuzz termination to exit 3, and quiet output to be empty for undeclared essentials.
- Legacy line payload files remain valid; use `#!bp-payloads-json-v1` for values that line syntax cannot
  represent.

The evidence limits behind these notes are in [`docs/PROOF-CEILINGS.md`](docs/PROOF-CEILINGS.md), and
the blocking release work is in [`ROADMAP.md`](ROADMAP.md).

## [2.0.0] - 2026-09-04

See [`bp/CHANGELOG.md`](bp/CHANGELOG.md#200---2026-09-04) for the release history.
