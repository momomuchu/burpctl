# Changelog

All notable changes to `bp`. Format: [Keep a Changelog](https://keepachangelog.com/).

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
