# Roadmap

Where `bp` is headed. This is a direction, not a dated promise — priorities follow real
usage and contributions. Every item here is a product feature already marked `v1.1 / not shipped` in
[`docs/CLI.md`](docs/CLI.md).

**Want to build one?** Open (or comment on) the matching issue, then read
[`CONTRIBUTING.md`](CONTRIBUTING.md). Items marked **needs extension** require a new Kotlin route +
spec entry before the CLI can expose them.

---

## ✅ Recently shipped — v1.1.0

A hardening release: the IDOR and decoder engines were rebuilt, secret redaction was completed and
made JSON-safe, response bodies/PII are suppressed from default output, the Run Ledger was hardened
(private files, no credentials at rest), and `bp check` now exits `5` when it finds something.
Full notes in [`bp/CHANGELOG.md`](bp/CHANGELOG.md).

## 🎯 Next — CLI features (backend already exists)

Quick wins on the `bp` side; the REST endpoints are already there.

- **`-w` / `--write-out 'TPL'`** — curl-style output templates, e.g. `%{status} %{payload}`.
- **`--tag NAME`** — label an operation in the Run Ledger.
- **`bp send --batch @file`** — fire a batch of repeater requests from a file.
- **`bp fuzz --param NAME`** — a one-parameter quick-fuzz shortcut.
- **More `bp history list` filters** — by source, free-text search, and time range.
- **TTY-aware output** — default to `table` in a terminal, `json` in a pipe (today it's always `table`).
- **`bp show <opId>`** — re-render a past operation from the Run Ledger.

## ⏳ Async attack & scan lifecycle *(needs extension)*

Today fuzzing is synchronous. The async path is specced but not built:

- **`bp fuzz status | results | pause | resume | stop <id>`**
- **`bp scan pause | resume | stop <id>`**

## 🧭 Later — more Burp tools *(needs extension)*

Surfacing additional Burp tools through the REST API + CLI. None are wired yet; each needs Montoya
integration, routes, and a spec entry first:

- **Sequencer** (token randomness analysis)
- **Comparer** (diff two items)
- **Logger / Dashboard** (event + issue feeds)

---

## 🔬 Known limitations (improvements welcome)

Honest edges, surfaced during testing — not bugs:

- **IDOR detection uses full-body comparison.** Strong against same-length / different-content
  records, but a response that differs only by volatile noise (timestamps, CSRF tokens) can read as
  "different." A normalization / fuzzy-compare mode would be a great contribution.
- **Decoder auto-detect is best-effort.** Genuinely ambiguous short strings resolve conservatively to
  `plain`; pass an explicit `--enc` when you need certainty.

---

## How priorities are set

1. **Correctness & security** invariants first (ledger, redaction, exit codes).
2. Then **`bp`-side features** that need no extension change — low risk, high value.
3. Then **extension work**, each behind a design record.

New here? Issues labelled `good-first-issue` are the friendliest start. Idea not listed? Open a
feature request — the roadmap grows from real use.
