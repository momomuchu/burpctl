# Roadmap

Where `burp-wrapper` is going. This is the honest, source-grounded plan — every item below is already
marked in the docs (`docs/CLI.md`, `docs/SPEC.md`, `bp/CHANGELOG.md`) as deferred or `v1.1`. It is a
direction, not a promise of dates.

**Want to take one?** Comment on (or open) the matching issue and say so, then read
[`CONTRIBUTING.md`](CONTRIBUTING.md). Items tagged **needs-extension** require Kotlin work in
`src/main/kotlin/com/burprest/` (a new route + `docs/SPEC.md` entry) before the CLI can expose them.

---

## ✅ Shipped — v1.1.0

Post-v1.0.0 hardening from a 9-round adversarial UltraQA loop: IDOR/decoder rebuilds, JSON-safe
secret redaction, PII suppression, ledger hardening (ADR-0005), exit-code contract (ADR-0010, `check`
exits `5` on findings), OUTPUT.md compliance, and contract-drift fixes. See
[`bp/CHANGELOG.md`](bp/CHANGELOG.md).

---

## 🎯 Next — v1.1.x CLI surface (no extension changes needed)

These are `bp`-side features whose backend routes already exist; they're documented as `v1.1 — not
shipped` in `docs/CLI.md`.

- **`-w` / `--write-out 'TPL'`** — curl-style output templates (`%{status} %{payload}`…).
- **`--tag NAME`** global flag — tag an op in the Run Ledger (the `tag` column already exists; the flag isn't wired).
- **`bp send --batch @file`** → `POST /repeater/send/batch`.
- **`bp fuzz <id> --param NAME --payloads @f`** — the one-parameter quick-fuzz shortcut → `POST /intruder/quick-fuzz`.
- **`bp history list` extra filters** — `--source` / `--search` / `--since` / `--until` / `--page-size`.
- **TTY-aware default format** — auto-pick `table` for a terminal, `json` for a pipe (today the default is always `table`).
- **`bp show <opId>`** — replay an op from the ledger, plus the `program` / `req_ref` / `resp_ref`
  columns (requires `--ledger-bodies`, ADR-0005).

## ⏳ Async attack lifecycle (needs-extension)

The current fuzzer is **synchronous** (client-side, fired via `/repeater/send`). The async path is
specced but not shipped:

- **`bp fuzz status | results | pause | resume | stop <attackId>`** → `/intruder/attack/{id}/*`.
- **`bp scan pause | resume | stop <scanId>`** → the scanner lifecycle verbs.

## 🧭 Bigger bets (deferred, needs-extension + an ADR)

- **Bug-bounty-mini adapter (C3, ADR-0007)** — an optional wrapper adding scope-check, op logging,
  and anti-injection guards for bounty workflows. Three sub-choices to elaborate (see `docs/SPEC.md §12`).
- **Scope-as-pre-fire-gate** — refuse to fire a request at an out-of-scope host before it leaves `bp`.
- **New Burp tool groups** — Sequencer / Comparer / Logger / Dashboard. None are in the extension's
  `configureRouting()` yet; each needs Montoya wiring + routes + spec before a CLI verb.

---

## 🔬 Known limitations (improvements welcome)

Surfaced and accepted during the UltraQA campaign — heuristic edges, not bugs:

- **IDOR detection is exact full-body comparison.** Robust against same-length/different-content
  records, but a target that differs only by volatile noise (timestamps, CSRF tokens) may read as
  "different." A normalization/fuzzy-compare option is a good contribution.
- **Decoder auto-detect is best-effort.** Ambiguous short strings (e.g. all-hex that's also valid
  base64) resolve conservatively to `plain`; pass an explicit `--enc` for certainty.
- **CI gates the diff, not a live Burp.** Live/integration coverage runs locally against `:8089`.

---

## How priorities are set

1. Correctness & security invariants (ledger/redaction/scope) come first.
2. Then `bp`-side features that need no extension change (low risk, high value).
3. Then extension work behind an ADR.

Issues labelled `good-first-issue` are a friendly entry point. Don't see your idea? Open a feature
request — the roadmap grows from real use.
