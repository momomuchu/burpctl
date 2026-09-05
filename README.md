<div align="center">
  <img src="docs/media/logo.png" alt="burpctl (bp) — a CLI for Burp Suite" width="128" height="128">
</div>

# bp

[![Release](https://img.shields.io/github/v/release/momomuchu/burpctl?sort=semver&color=blue)](https://github.com/momomuchu/burpctl/releases)
[![CI](https://github.com/momomuchu/burpctl/actions/workflows/ci.yml/badge.svg)](https://github.com/momomuchu/burpctl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](bp/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%20%2F%20Community-orange.svg)](https://portswigger.net/burp)

`bp` is a Python CLI for the Kotlin `burp-rest-extension`. It drives Burp Suite through a local REST
API, including captured-request replay, client-side positional fuzzing, proxy/history inspection,
sessions, scope, Collaborator, Scanner, decoder utilities, and bounded security checks. The same CLI
is installed under the `burpctl` alias.

```text
operator -> bp CLI -> REST on 127.0.0.1:8089 -> burp-rest-extension -> Montoya -> Burp Suite
```

## v2.1.0 release-candidate status

The source tree identifies as **2.1.0**, but this candidate is **not release-verified**:

- [`quality/confirmed-defects.yaml`](quality/confirmed-defects.yaml) contains 73 records: **0
  `verified`**, 51 `fixed`, 16 `confirmed`, one `unconfirmed`, and five `rejected`.
- Live verification against the redeployed v2.1.0 binary has **not been completed**. Local tests and a
  source-level fix do not promote a record to `verified`.
- Four acceptance oracles were identified as pinned to superseded contracts. `VERIFY-D24` has a
  recorded reproduction and causal artifact; `VERIFY-D58`, `VERIFY-D59`, and `VERIFY-D61` were
  identified by source analysis without standalone reproductions or durable artifacts. All four were
  repaired only in an unversioned harness under `/tmp/burpctl-live/verify/`; an unrelated reboot then
  destroyed that harness before it was ever run. An in-repository replacement under `verify/` now
  exists and has produced a non-clean retained run. Its current run selected all 30 REST/CLI behavior
  cases but executed none: a system preflight proved the deployed binary predates the current release
  source because its embedded OpenAPI differs, so all 30 behavior cases correctly became
  `COULD_NOT_RUN`. That is not release verification.
- D01–D18 were demoted from `verified` to `fixed` because `verified` now requires machine-validated
  receipts for a redeployed live pass, an assertion-reaching causal RED, and content-bound non-author
  review. The demotion records missing evidence under the new meaning; it does not claim those fixes
  regressed.
- The mandatory `BURPCTL_REQUIRE_ALL_VERIFIED=1` release gate currently fails on every established
  record still at `fixed` or `confirmed`.

Do not present this candidate as verified or publish it as v2.1.0 until that gate passes. See the
[quality evidence policy](quality/README.md), [ADR-0014](docs/adr/0014-state-preserving-reportable-operations.md),
and the [proof ceilings](docs/PROOF-CEILINGS.md).

## What the source implements

- **Client-side fuzzing:** `header:`, `cookie:`, `body:`, `query:`, `path:`, and raw `offset:`
  selectors with sniper, battering-ram, pitchfork, and cluster-bomb expansion. Substitution is
  byte-indexed inside the reconstructed request, but the REST/Montoya bridge is not an exact raw-wire
  transport.
- **Burp control surface:** 69 OpenAPI operations in 13 groups. An operation that pinned Montoya
  cannot perform remains discoverable and returns HTTP 501 `UNSUPPORTED` instead of a successful
  no-op.
- **Security checks:** auth-bypass, IDOR-style response comparison, header-bypass, CORS, and endpoint
  probes. Exit 5 means the implemented classifier produced a finding; it is not by itself proof of
  authorization, ownership, exploitability, or a protected read. The marker-provenance proof-ceiling
  text is currently being corrected alongside a code regression and is not release evidence yet.
- **Output:** table, compact JSON/NDJSON, quiet projections, and reconstructed raw HTTP for four
  registered paths. Known incompatible modes and static field names are checked before REST dispatch,
  but nested Scanner/sitemap and absent request-detail projections can still pass that preflight and
  fail after a GET; full validation-before-effect remains a release blocker. Redaction is enabled by
  default, but final review of utility/error-path disclosure fixes is still in progress, so this
  candidate does not yet claim that every representation is covered. See [CLI.md](docs/CLI.md) and
  [OUTPUT.md](docs/OUTPUT.md).
- **Run Ledger:** one local SQLite metadata row per bp-to-extension REST call, with hashes rather than
  raw target bodies. It does not observe browser, curl, or proxy-listener traffic and is not a target
  request evidence store.
- **Edition boundary:** source paths not using Collaborator or active Scanner starts are designed for
  Community; Collaborator and starting scans require Pro. This v2.1.0 boundary still awaits the
  incomplete redeployed-binary verification described above.

## Install a matched source pair

The CLI and extension do not enforce a general runtime version handshake. Build and install both from
the same checkout, then compare the versions before consequential use.

Requirements: Burp Suite, JDK 17+ to build the extension, Python 3.11+, and
[`uv`](https://docs.astral.sh/uv/) or an equivalent Python installer.

```bash
./gradlew shadowJar
cd bp
uv tool install --force .
cd ..

bp --version   # CLI version
bp version     # version reported by the loaded extension
```

Load `build/libs/burp-rest-extension.jar` in Burp through **Extensions -> Add -> Java**. Stop if the
two version commands do not report the same release. This is a caller check, not a runtime-enforced
compatibility guarantee; see [PC-06](docs/PROOF-CEILINGS.md#pc-06--cliextension-version-pairing-is-required-but-not-runtime-enforced).

There is no v2.1.0 tag or downloadable v2.1.0 artifact yet. The latest published release may therefore
be a different version from this checkout.

## Command-shape quickstart

These examples use implemented command and option names. They still require a loaded matching
extension, an authorized target, a captured request at index `42`, and caller-created payload files.

```bash
bp health
bp proxy --host target.example --limit 20

printf '%s\n' '127.0.0.1' '10.0.0.1' > /tmp/bp-ips.txt
printf '%s\n' 'user' 'admin' > /tmp/bp-roles.txt
bp fuzz 42 \
  --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=/tmp/bp-ips.txt \
  --pos 'cookie:role' --payloads role=/tmp/bp-roles.txt \
  --type cluster-bomb --anomalous-only

# A finding exit is classifier output, not proof of cross-principal access.
bp check idor 'https://target.example/api/user?id=1' --param id --own 1 --target 2
```

The default output is a human table. Use `--format json` for compact JSON/NDJSON or `--format quiet`
for a documented essential projection. `--format raw` is limited to `req`, `send`, `history get`, and
`history replay`. Global `--url`, `--format`, `--fields`, `--no-ledger`, and `--no-redact` options are
position-tolerant until `--`.

## Upgrade from v2.0.0

Upgrade the CLI and JAR together; do not pair a 2.1.0 source install with the v2.0.0 release JAR.
Observable source-contract changes include:

- `session clear` now clears both configured session credentials and the captured cookie jar;
- nullable WebSocket response-side values are represented as `null` instead of failing the whole list;
- unsupported operations advertise and return 501 rather than impossible success responses;
- request/output validation happens before effects, and raw HTTP rendering is limited to four named
  commands;
- missing optional Collaborator interaction leaves render as `null` rather than becoming a post-poll
  usage failure;
- client fuzzing treats `NO_RESPONSE` as terminal and exits 3;
- marker-based security checks reject actor-supplied marker representations as inconclusive;
- legacy line payload files remain supported, while `#!bp-payloads-json-v1` adds an explicit JSON form
  for empty, whitespace, embedded-line-break, NUL, and Base64 byte payloads.

Consumers of OpenAPI or generated models must regenerate from
[`src/main/resources/openapi.json`](src/main/resources/openapi.json): response schemas and unsupported
success responses changed broadly. These are source-level migration notes, not a claim that the
redeployed live acceptance pass has completed.

## Repository map

| Path | Purpose |
|---|---|
| [`bp/`](bp/) | Python CLI; [package README](bp/README.md) and [package changelog](bp/CHANGELOG.md) |
| [`src/main/kotlin/com/burprest/`](src/main/kotlin/com/burprest/) | Kotlin/Ktor/Montoya extension |
| [`src/main/resources/openapi.json`](src/main/resources/openapi.json) | published 2.1.0 OpenAPI contract: 69 operations |
| [`docs/SPEC.md`](docs/SPEC.md) | current REST inventory and source boundaries |
| [`docs/CLI.md`](docs/CLI.md) | implemented CLI command grammar |
| [`docs/OUTPUT.md`](docs/OUTPUT.md) | output and exit contract |
| [`docs/PROOF-CEILINGS.md`](docs/PROOF-CEILINGS.md) | limits on what observations prove |
| [`quality/`](quality/) | defect ledger and verification policy |
| [`verify/`](verify/) | in-repository live release harness and retained result schema |
| [`docs/RELEASE-CHECKLIST.md`](docs/RELEASE-CHECKLIST.md) | evidence-backed v2.1.0 readiness checklist |
| [`CHANGELOG.md`](CHANGELOG.md) | combined extension/CLI release notes |

## Local checks

These checks are hermetic or source-level; they are not a substitute for the missing real-Burp pass.

```bash
./gradlew build -PtestJvm=17
cd bp
uv sync --frozen
uv run --frozen pytest -q
uv run --frozen mypy --strict src tests
uv run --frozen ruff check src tests
uv run --frozen openapi-spec-validator ../src/main/resources/openapi.json
```

CI runs on pushes to `main` and pull requests targeting `main`. Its contracts job deliberately enables
the all-verified release gate, so the current candidate is expected to fail until the required receipts
exist.

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md), the current [ROADMAP](ROADMAP.md), and
[SECURITY.md](SECURITY.md). Use this security tooling only on systems you own or are explicitly
authorized to test.

## License

[MIT](LICENSE)
