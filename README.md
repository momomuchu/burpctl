# burpctl

[![Release](https://img.shields.io/github/v/release/momomuchu/burpctl?sort=semver&color=blue)](https://github.com/momomuchu/burpctl/releases)
[![CI](https://github.com/momomuchu/burpctl/actions/workflows/ci.yml/badge.svg)](https://github.com/momomuchu/burpctl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](bp/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%20%2F%20Community-orange.svg)](https://portswigger.net/burp)

> **Drive Burp Suite from the command line.** Mark any byte range, fuzz it fast, and get clean
> parsable output — *without leaving Burp's session, scope, and history behind.*

The reason to reach for `burpctl` over `ffuf` or Turbo Intruder: those are fast, but they run
*outside* Burp — you lose your session, cookies, upstream config, and scope. `burpctl` builds the
attack client-side and sends every shot through Burp's **Repeater** (`/repeater/send`), *not* Burp's
Intruder engine — so your fuzzing inherits all of that context in one scriptable command instead of a
UI full of clicks. And because it rides Repeater, it sidesteps the deliberate rate-throttle that
**Burp Community** applies to Intruder: multi-position, matrix-style fuzzing at full speed while
staying inside the proxy you're already using.

It's two pieces:

- **`burpctl`** — a fast, fully-typed **Python CLI** (the interface you'll use; `bp` is a 2-char alias).
- **burp-rest-extension** — a **Kotlin** Burp extension that exposes Burp's [Montoya API](https://portswigger.net/burp/documentation/desktop/extensions/creating) as a local REST API for `burpctl` to drive.

```
 you ──►  burpctl (CLI)  ──REST :8089──►  burp-rest-extension  ──Montoya──►  Burp Suite (Pro / Community)
```

## Features

- 💥 **Flexible client-side fuzzing** — mark *any* byte range (`header:`, `cookie:`, `body:`, `query:`, `path:`, raw `offset:`), multiple positions at once, and all four attack types (sniper, battering-ram, pitchfork, cluster-bomb) with built-in anomaly detection. Not throttled on Community.
- 🎯 **Full Burp surface from one CLI** — proxy history, repeater, intruder, scanner, target/scope, decoder, collaborator, sitemap, sessions.
- 🔎 **Security checks** — built-in probes for auth-bypass, IDOR, CORS, and security headers; exit code `5` on findings so you can gate CI/scripts.
- 📒 **Run Ledger** — every operation is recorded locally with **sha256 fingerprints only** (never raw bodies), and **secret redaction is on by default**.
- 🧰 **Works on Community too** — only `collaborator` and `scan` start need Pro (they exit `4` with a clear message); everything else runs on Community.
- 🔩 **Scriptable & automation-friendly** — `--format json` emits NDJSON (one record per line); stable exit codes; no interactive prompts. That also makes it easy to drive from scripts or AI agents.
- ✅ **Spec-driven & tested** — 433 Python tests + a Kotlin suite, `mypy --strict` + `ruff` clean, CI on every push.

## Quickstart

**Requirements:** Burp Suite (Pro or Community) · JDK 17+ (to build the extension) · Python 3.11+ (for `burpctl`).

**1. Build & load the extension**

```bash
./gradlew shadowJar     # → build/libs/burp-rest-extension.jar
```

In Burp: **Extensions → Add → Extension type: Java → select the JAR.**
The REST server auto-starts — look for `Server started on http://127.0.0.1:8089` in the extension's Output tab.

> Prefer not to build? Grab the prebuilt jar from the [latest release](https://github.com/momomuchu/burpctl/releases/latest).

**2. Install & use `burpctl`**

```bash
cd bp && uv tool install .          # or: pipx install .   (installs `burpctl` + `bp` alias)

burpctl health                                       # is the extension up?
burpctl proxy --host target.example --limit 20       # captured history → request IDs

# fuzz two positions at once, cluster-bomb, show only anomalies:
burpctl fuzz 42 --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=ssrf.txt \
                --pos 'cookie:role'            --payloads role=privesc.txt \
                --type cluster-bomb --anomalous-only

burpctl check idor 'https://target/api/user?id=1' --param id --own 1 --target 2   # exits 5 if vulnerable
```

> **Output:** default is a human `table`; add `--format json` (NDJSON), `raw`, or `quiet` for scripts and agents.
> Global flags (`--url` / `--format` / `--fields`) work in either position. `bp` is a drop-in alias for `burpctl`.

👉 **Full command reference: [`bp/README.md`](bp/README.md).**

## Repository layout

| Path | What |
|---|---|
| [`bp/`](bp/) | The `burpctl` CLI (Python) — [README](bp/README.md) · [CHANGELOG](bp/CHANGELOG.md) |
| `src/main/kotlin/com/burprest/` | The Burp REST extension (Kotlin / Ktor / Montoya) |
| [`docs/`](docs/) | Source-grounded contracts: [SPEC](docs/SPEC.md) · [CLI grammar](docs/CLI.md) · [OUTPUT](docs/OUTPUT.md) · [ALGORITHMS](docs/ALGORITHMS.md) · [ADRs](docs/adr/) |

The REST surface is **13 route groups / 69 endpoints**, all source-verified in `docs/SPEC.md`; every
response is `{success, data, error}`.

## Build & test

```bash
./gradlew test                                              # Kotlin extension
cd bp && uv run pytest -q && uv run mypy --strict src && uv run ruff check src tests   # burpctl: 433 tests, typed, linted
```

## Contributing

Issues and PRs welcome — `burpctl` is spec-driven and test-first. Start with
**[CONTRIBUTING.md](CONTRIBUTING.md)** (disciplines, dev setup, Definition of Done), see the
**[ROADMAP](ROADMAP.md)** for what's planned, and report vulnerabilities privately per
**[SECURITY.md](SECURITY.md)**.

> ⚠️ **Authorized use only.** This drives a security proxy — use it solely against systems you own or are explicitly permitted to test.

## License

[MIT](LICENSE)
