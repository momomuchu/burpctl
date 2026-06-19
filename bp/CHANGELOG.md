# Changelog

All notable changes to `bp`. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.1.0] — 2026-06-19

Post-v1.0.0 hardening: an adversarial UltraQA / Goodhart audit followed by a 9-round
parallel ultraqa→fix convergence loop (84 commits, both suites green throughout).

### Fixed
- **Config-file `ledger=on` silently disabled the ledger.** The `invert` flag (for the
  negatively-named `BP_NO_LEDGER` env var) was wrongly applied to the positive-sense config-file
  key, so the documented default `ledger=on` turned recording OFF. `config.py` had no direct
  tests — added.
- **`--format <bad>` printed a Rich traceback and exited 1.** Now validated in the callback →
  clean usage error (exit 2) before any server call.
- **`--fields <unknown>` silently rendered `None` with exit 0.** Now a usage error (exit 2)
  listing the valid fields, per OUTPUT.md §2.1.

### Changed
- De-duplicated header parsing (3 copies → shared `parse_header`/`parse_headers`; one had a
  hardcoded exit code), the `obs` `log`/`tag` double-registration, the query/form key=value scan,
  and the default-URL literal. Behaviour-preserving.
- Docs aligned with shipped v1: exit-code table (0/1/2/3/4, sysexits mapping superseded),
  TTY-aware default and several documented-but-unshipped surfaces marked `v1.1`, reserved config
  fields (`enforce_scope`/`envelope`/`throttle_ms`/`anomaly_pct`) flagged parsed-but-not-wired.
- Test suite: 112 → 124 (config-file booleans, cliutil chokepoint, header parsing; replaced a
  tautological no-ledger test with real client-guard coverage).

### Fixed — live UltraQA campaign (2026-06-19, against running Burp Pro on :8089)

Found by actually driving `bp` against the live extension plus an adversarial 43-agent
discovery sweep (34 defects confirmed, three-way verified). HIGH:

- **`--format`/`--fields` only worked *before* the subcommand** — `bp health --format json`
  exited 2 "No such option". A conservative argv pre-processor makes the global value-options
  (and `--no-ledger`) position-tolerant (ADR-0009).
- **`BP_REDACT=` (empty) or a config-file typo silently disabled secret redaction.** An empty
  env var is now treated as unset and an unrecognised boolean token keeps the safe default —
  a security control can no longer be turned off by a shell accident.
- **`--pos` resolver mistargeted** cookies present only in a *later* `Cookie` header, and JSON
  string values containing a backslash-escaped quote (silent wrong-bytes fuzz).
- **Non-`ConnectError` transport failures** (read/connect timeouts) escaped as raw tracebacks;
  a **non-JSON / empty-body server response** mapped to exit 2 (usage) instead of exit 1. Both
  are now typed errors → exit 3 / exit 1, each recorded to the ledger.
- **`--no-ledger` is now a real flag** (ADR-0005; previously env-only `BP_NO_LEDGER=1`).

MED and other:

- **Run Ledger `exit_code` was always NULL** — now back-filled per op once the command resolves.
- **Table output leaked Python `repr`** (`None`, `{'k': 'v'}`) — now blank cell / compact JSON.
- **`bp --version`** added (was "No such option"; `bp version` still reports the extension).
- **Fuzz with zero positions** silently fired N unmodified requests — now rejected (usage error).
- **`bp tag` exited 0 when the ledger was disabled** (tag never applied) — now exit 1.

### Known / deferred (not yet fixed)

- **Burp Kotlin extension (server-side; needs extension rebuild + reload):** `burpVersion`
  always null; `bp history list --page <negative>` leaks a JDBC exception; `decode` of
  unclassifiable input surfaces the internal `plain` encoding name; a bad `hash --algo` leaks a
  JVM `NoSuchAlgorithmException`. Grouped for a dedicated extension pass.
- **`bp show <opId>` replay** (ADR-0005) and the `program`/`req_ref`/`resp_ref` ledger columns
  remain v1.1 (refs require `--ledger-bodies`).
- Low-severity help-text cosmetics (e.g. `collab poll` parameter name, `diff` example wrap).

- Test suite: 124 → 158 (config security, argv hoist + `--version` + `--no-ledger`, `--pos`
  edge cases, client transport + non-JSON, ledger `exit_code`, fuzz zero-position, obs tag).

### Fixed — realistic-scenario ultraqa (2026-06-19)

Found by running a real local bug-bounty workflow end-to-end (recon -> JWT -> IDOR fuzz)
against a vulnerable target through Burp, plus a parallel adversarial QA sweep.

- **`check idor` silent false negative (HIGH).** On a URL with neither a `{param}` placeholder
  nor an existing `?param=`, `substituteParam` returned the URL unchanged, so the baseline and
  every target value hit the SAME url and a real IDOR was reported "not vulnerable". It now
  appends `?param=value` when absent. Verified: `check idor http://t/api/user --param id --own 1
  --target 3` now flags VULNERABLE.
- **`bp decode` now handles base64url / JWT.** A JWT segment auto-detected as "plain" (not
  decoded), and `--enc base64` choked on URL-safe payloads (`-`/`_`, no padding). decode now
  normalizes URL-safe + re-pads, and auto-detects an `eyJ…` JWT segment.
- **`--no-redact` flag added.** Redaction (on by default) masked JWTs/tokens in the
  `session send` -> `decode` flow; `--no-redact` (position-tolerant, env `BP_REDACT=off`) lets you
  read a secret you intentionally decode.

- Test suite: 158 → 164 (Python: --no-redact; Kotlin: substituteParam append, base64url/JWT).

### Fixed — UltraQA convergence loop (2026-06-19)

A parallel adversarial UltraQA round (8 lanes, 43 findings confirmed three-way) fixed in six
parallel per-file lanes, then re-verified live against Burp `:8089` + a local vuln target. HIGH:

- **`--pos` JSON resolver corrupted multi-element bodies.** `body:FIELD` on an array/object value
  truncated at the first comma (`["admin","user"]` → `["admin"`), and a nested same-named key won
  over the intended top-level field. `_resolve_json` is now a depth-aware top-level scanner.
- **`bp check idor` false negative on small responses.** The IDOR detector's 10-byte "same as
  baseline" floor masked a different user's record when the byte delta was small (alice 71B vs
  bob 67B). Detection is now content-primary — a different `bodyPreview` is flagged regardless of
  delta. Verified live: a 4-byte-delta cross-account read is now reported VULNERABLE.
- **`bp check auth` flagged every public 200.** Now compares the unauthenticated probe against the
  authenticated baseline instead of flagging any 200 response.
- **Decoder auto-detect mis-classified hex and base64url.** `deadbeef` decoded as base64 garbage
  (hex is now checked first); url-safe base64 (`-`/`_`, non-JWT) is auto-detected (UTF-8-gated);
  hex/base64 of non-UTF-8 bytes now raise a clean error instead of silently emitting U+FFFD.
- **`bp history list --fields` / `--format table` were unusable** — the raw page-wrapper was passed
  to the renderer, so entry-level fields errored (exit 2) and table showed one giant JSON blob.
  Entries are now flattened; `--fields id,url` and a row-per-entry table both work.
- **`bp fuzz --payloads <missing-file>`** raised a raw `FileNotFoundError` traceback (exit 1) →
  clean usage error (exit 2).
- **`--fields` was inconsistent across formats** — json raised on an unknown/absent field while
  table silently rendered blanks. Table now validates per row identically (exit 2).
- **Empty result sets wrote a lone newline**, breaking NDJSON line readers — now zero bytes.

MED and other:

- **`bp check` now exits 5 when findings are present** (`vulnerableCount`/`anomalousCount > 0`),
  exit 0 when clean — so pipelines can gate on results (ADR-0010, nmap/nuclei convention).
- **IDOR response surfaces `ignoredOwnValues`** (only the first `--own` is the baseline) and a
  `note` documenting the privilege-direction heuristic limitation (cross-object access is reported
  regardless of direction; verify manually).
- **`check endpoints` auth-bypass** probes with the request's original method, not a hardcoded GET.
- Smaller correctness: fuzz adds `Content-Length` when the touched body had none; `path:<=0` is a
  BAD_SELECTOR; a no-Content-Type `{...}`/`[...]` body resolves as JSON; `fuzz --type <invalid>`
  names the bad type; `scan status` only prints its stub caveat on success; `bp log` matches
  `bp tag` (exit 1 when ledger disabled); `encode`/`decode --enc <bad>` is a usage error with a
  valid-values hint; quiet renders `None` as blank; table unions heterogeneous row keys; `raw` on
  a list is a usage error.
- Docs: ledger `command` column documented as subcommand-name-only (not full argv); CLI exit-code
  list gains `5`.

### Fixed — UltraQA convergence loop, rounds 2–9 (2026-06-19)

The loop continued: each round = a parallel adversarial hunt (≈9 lanes, find→verify) → parallel
per-file fix lanes (TDD) → both-suite verify → live re-check on `:8089`/`:8888` → atomic commits.
HIGH/MED per round trended 32→14→11→7→11→4→14, then a partial round (session-limited) + cleanup.
Grouped by theme (all live-verified where observable):

- **IDOR detector, rebuilt for correctness.** sameAsBaseline now compares the FULL response body
  (not a 200-char preview), so same-prefix/same-length records differing only in the tail are
  caught; an empty baseline vs a non-empty target counts as different; a non-2xx (own) baseline can
  no longer produce false positives; and `--param ID` matches an existing `?id=` case-insensitively
  while PRESERVING the URL's param-name casing (so a case-sensitive server is actually hit).
- **Decoder auto-detect, made principled.** All-hex strings decide terminally (hex if valid UTF-8,
  else plain — never reinterpreted as base64); unpadded standard base64 is detected; a non-JWT
  base64url branch (UTF-8-gated); smart-decode peels a trailing `+`-form-url layer; `decode`
  normalizes the echoed encoding to lowercase; HTML auto-detect recognises `&quot;`/`&#x27;`; a
  malformed `%`-escape no longer leaks the `URLDecoder` JDK class name.
- **Secret redaction completeness.** `redact()` now masks Cookie/Set-Cookie values and
  `Authorization: Basic`/`Token`/`Digest` credentials (header-line AND JSON-embedded forms), not
  just Bearer/JWT.
- **PII / output hygiene.** `bp check idor`, `bp req`, and `bp history replay` no longer dump raw
  response bodies/headers (cookies, SSNs) to default stdout — they project to safe display fields
  (bodies remain available via `--format json`); the IDOR heuristic `note` moved to stderr.
- **Ledger robustness (ADR-0005).** A `Ledger()` construction failure (read-only `~/.bp`) warns and
  proceeds instead of aborting with a traceback; `record`/`set_exit_code`/`tag`/`query` self-protect
  against `sqlite3.Error`; URL userinfo is stripped from the ledger `target` (no credentials at
  rest); and a `bp check` that exits 5 now records `exit_code=5`.
- **Exit-code contract.** Scanner Pro-only failures travel as `PRO_REQUIRED` → exit 4 while a missing
  DB stays `SERVICE_UNAVAILABLE` → exit 1 (so `check endpoints` no longer falsely signals "Pro
  required"); a pydantic `ValidationError` is a clean "unexpected response shape" (exit 1, no
  class-name leak); an unauthorized `INVALID_REQUEST→exit 2` remap was reverted.
- **Output contract (OUTPUT.md).** Table headers/keys render UPPERCASE; `--fields` matches
  case-insensitively with canonical-cased output; a field is "unknown" only when absent from the
  union of all rows; an empty result + `--fields` is empty output in json and table alike.
- **Fuzz / `--pos` correctness.** Overlapping positions raise `POS_OVERLAP` (was silent corruption);
  JSON keys with escape sequences resolve by their logical name; duplicate `Content-Length` headers
  collapse to one; `query:` strips the URL fragment; non-array/empty bodies get accurate errors.
- **Contract drift & robustness.** `ProxyEntry`/`HistoryEntryResponse` nullability mirrors the Kotlin
  contract; a malformed replay shape is a clean error (not a `KeyError` traceback); `runner` maps
  unexpected server shapes to clean errors; `bp log`/`tag` honor `--no-ledger` and guard sqlite;
  the auth-bypass probe degrades gracefully on a bad endpoint.
- **Doc honesty.** The IDOR algorithm, the decoder BDD flags (`--enc`/`--algo`/`--format quiet`),
  and the collaborator exit-code mechanism were corrected to match the shipped code.
- **LOW cleanup:** headersBypass small-response dead zone, form-body leading-whitespace tolerance,
  invalid numeric-config warnings, and an `EXIT_USAGE` constant in `intercept`.

- Test suite: 164 → 392 Python tests + the Kotlin suite, green every round; `mypy --strict` + `ruff`
  clean throughout. ~65 atomic commits across the loop. Two principled rewrites (full-body IDOR,
  terminal hex-detection) broke the high-severity recurrence; remaining QA findings are deep
  edge-cases / spec-polish rather than the original defect classes.

## [1.0.0] — 2026-06-17

First release. A fully-typed, spec-driven CLI client for the Burp REST extension on `:8089`.

### Added
- **Fuzzing engine (client-side):** `bp fuzz` — `--pos` grammar resolving semantic selectors
  (`header/cookie/body/query/path`) + raw `offset:` to byte ranges (A1), matrix expansion for
  all 4 attack types `sniper/battering-ram/pitchfork/cluster-bomb` with right-to-left
  substitution + Content-Length recompute (A2), fired via `/repeater/send`, with baseline +
  anomaly detection. The extension's Intruder is sniper/by-name only, so `bp` owns this.
- **13 command groups / full :8089 surface:** health, version, proxy, req, ws, intercept, send,
  tab, collab, scan (Pro), check, scope, sitemap, encode/decode/hash, config, ext, session,
  diff, endpoints, history, log, tag — flat verbs + groups per `docs/CLI.md` (48 commands,
  conformance-tested).
- **Run Ledger (observability, ON by default):** every operation recorded to `~/.bp/ledger.db`
  with sha256 fingerprints (raw bodies never stored); `bp log` / `bp tag` to query/annotate;
  `--no-ledger` opt-out. Secret redaction (JWT/Authorization/Cookie) on output by default.
- **Output contract:** `--format json|table|raw|quiet`, `--fields`, agent-mode NDJSON.
- **Config system:** flag > env > `~/.bp/config` > default.
- **Honest caveats:** stubs (`/config`, `/proxy/intercept`, `/extensions`) surfaced to stderr
  rather than silently returning fake data.

### Fixed (extension)
- Version consistency (`/docs` OpenAPI was `0.2.0` vs `/health` `0.1.0` → unified `0.1.0`).
- `/proxy/intercept` now reports the tracked API-driven state instead of a hardcoded `false`.
- Build: gradle wrapper bumped `8.7 → 8.13` (local 8.7 dist was corrupt → infinite re-download).

### Quality
- 111 tests (TDD), `mypy --strict` + `ruff` clean. Source-grounded spec (`docs/`, 8 ADRs).
  Built via a verified multi-agent fan-out with CLI-conformance + Goodhart/code-review gates.

### Known gaps (v1.1)
- Async fuzz lifecycle (`bp fuzz status|results …`) — v1 is synchronous.
- Per-command unit tests (commands covered by CLI-conformance + live smoke; logic layers are
  unit-tested). Scope-as-pre-fire-gate and the bug-bounty-mini adapter (ADR-0007/C3) remain
  roadmap (`docs/RESEARCH-concepts.md`).

[1.1.0]: https://github.com/momomuchu/burp-wrapper/releases/tag/v1.1.0
[1.0.0]: https://github.com/momomuchu/burp-wrapper/releases/tag/v1.0.0
