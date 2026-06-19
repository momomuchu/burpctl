# Changelog

All notable changes to `bp`. Format: [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

Post-v1.0.0 fixes surfaced by an adversarial UltraQA / Goodhart audit (three-way verified).

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

[1.0.0]: https://example.com/bp/releases/tag/v1.0.0
