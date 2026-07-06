<div align="center">
  <img src="docs/media/logo.png" alt="burpctl (bp) — a CLI for Burp Suite" width="128" height="128">
</div>

# bp

[![Release](https://img.shields.io/github/v/release/momomuchu/burpctl?sort=semver&color=blue)](https://github.com/momomuchu/burpctl/releases)
[![CI](https://github.com/momomuchu/burpctl/actions/workflows/ci.yml/badge.svg)](https://github.com/momomuchu/burpctl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](bp/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%20%2F%20Community-orange.svg)](https://portswigger.net/burp)

> **Drive Burp Suite from the command line.** Mark any byte range, fuzz it fast, and get clean
> parsable output — *without leaving Burp's session, scope, and history behind.*
>
> A scriptable **Burp Suite CLI** and **Intruder alternative** for bug-bounty hunters and pentesters.

<!-- DEMO: once recorded (see docs/media/README.md), drop the GIF here:
     ![burpctl demo — proxy to multi-position fuzz to anomaly, in one command](docs/media/demo.gif) -->

The reason to reach for `bp` over `ffuf` or Turbo Intruder: those are fast, but they run *outside*
Burp — you lose your session, cookies, upstream config, and scope. `bp` builds the attack
client-side and sends every shot through Burp's **Repeater** (`/repeater/send`), *not* Burp's
Intruder engine — so your fuzzing inherits all of that context in one scriptable command instead of a
UI full of clicks. And because it rides Repeater, it sidesteps the deliberate rate-throttle that
**Burp Community** applies to Intruder: multi-position, matrix-style fuzzing at full speed while
staying inside the proxy you're already using.

It's two pieces:

- **`bp`** — a fast, fully-typed **Python CLI** (the interface you'll use; also installed as `burpctl`).
- **burp-rest-extension** — a **Kotlin** Burp extension that exposes Burp's [Montoya API](https://portswigger.net/burp/documentation/desktop/extensions/creating) as a local REST API for `bp` to drive.

```
 you ──►  bp (CLI)  ──REST :8089──►  burp-rest-extension  ──Montoya──►  Burp Suite (Pro / Community)
```

## Features

- 💥 **Flexible client-side fuzzing** — mark *any* byte range (`header:`, `cookie:`, `body:`, `query:`, `path:`, raw `offset:`), multiple positions at once, and all four attack types (sniper, battering-ram, pitchfork, cluster-bomb) with built-in anomaly detection. Not throttled on Community.
- 🎯 **Full Burp surface from one CLI** — proxy history, repeater, intruder, scanner, target/scope, decoder, collaborator, sitemap, sessions.
- 🔎 **Security checks** — built-in probes for auth-bypass, IDOR, CORS, and security headers; exit code `5` on findings so you can gate CI/scripts.
- 📒 **Run Ledger** — every operation is recorded locally with **sha256 fingerprints only** (never raw bodies), and **secret redaction is on by default**.
- 🧰 **Works on Community too** — only `collaborator` and `scan` start need Pro (they exit `4` with a clear message); everything else runs on Community.
- 🔩 **Scriptable & automation-friendly** — `--format json` emits NDJSON (one record per line); stable exit codes; no interactive prompts. That also makes it easy to drive from scripts or AI agents.
- ✅ **Spec-driven & tested** — 433 Python tests + a Kotlin suite, `mypy --strict` + `ruff` clean, CI on every push.

## How it compares

Where `bp` fits next to the tools you already reach for when Burp's Intruder is too slow or too clicky:

| | Runs **inside** Burp (session/scope/cookies) | All 4 attack types | Fast on **Community** | Shell-scriptable CLI |
|---|:---:|:---:|:---:|:---:|
| **`bp`** | ✅ | ✅ sniper · ram · pitchfork · cluster-bomb | ✅ (fires via Repeater) | ✅ |
| Burp Intruder (Pro) | ✅ | ✅ | ✅ | ❌ GUI only |
| Burp Intruder (Community) | ✅ | ✅ | ❌ deliberately throttled | ❌ GUI only |
| [Turbo Intruder](https://github.com/PortSwigger/turbo-intruder) | ✅ (extension) | ⚠️ Python-scripted | ✅ very fast | ⚠️ in-Burp scripting |
| [ffuf](https://github.com/ffuf/ffuf) | ❌ outside Burp | ✅ | ✅ | ✅ |

Honest take: `ffuf` and Turbo Intruder win on raw throughput. `bp` wins when you want a **one-line,
scriptable command that stays inside your authenticated Burp session and scope** — and full-speed
multi-position fuzzing on **Community** without the GUI throttle.

## Quickstart

**Requirements:** Burp Suite (Pro or Community) · JDK 17+ (to build the extension) · Python 3.11+ (for `bp`).

**1. Build & load the extension**

```bash
./gradlew shadowJar     # → build/libs/burp-rest-extension.jar
```

In Burp: **Extensions → Add → Extension type: Java → select the JAR.**
The REST server auto-starts — look for `Server started on http://127.0.0.1:8089` in the extension's Output tab.

> Prefer not to build? Grab the prebuilt jar from the [latest release](https://github.com/momomuchu/burpctl/releases/latest).

**2. Install & use `bp`**

```bash
cd bp && uv tool install .          # or: pipx install .   (installs `bp` + `burpctl` alias)

bp health                                       # is the extension up?
bp proxy --host target.example --limit 20       # captured history → request IDs

# fuzz two positions at once, cluster-bomb, show only anomalies:
bp fuzz 42 --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=ssrf.txt \
           --pos 'cookie:role'            --payloads role=privesc.txt \
           --type cluster-bomb --anomalous-only

bp check idor 'https://target/api/user?id=1' --param id --own 1 --target 2   # exits 5 if vulnerable
```

> **Output:** default is a human `table`; add `--format json` (NDJSON), `raw`, or `quiet` for scripts and agents.
> Global flags (`--url` / `--format` / `--fields`) work in either position. `burpctl` is a drop-in alias for `bp`.

👉 **Full command reference: [`bp/README.md`](bp/README.md).**

## Repository layout

| Path | What |
|---|---|
| [`bp/`](bp/) | The `bp` CLI (Python) — [README](bp/README.md) · [CHANGELOG](bp/CHANGELOG.md) |
| `src/main/kotlin/com/burprest/` | The Burp REST extension (Kotlin / Ktor / Montoya) |
| [`docs/`](docs/) | Source-grounded contracts: [SPEC](docs/SPEC.md) · [CLI grammar](docs/CLI.md) · [OUTPUT](docs/OUTPUT.md) · [ALGORITHMS](docs/ALGORITHMS.md) · [ADRs](docs/adr/) |

The REST surface is **13 route groups / 69 endpoints**, all source-verified in `docs/SPEC.md`; every
response is `{success, data, error}`.

## Build & test

```bash
./gradlew test                                              # Kotlin extension
cd bp && uv run pytest -q && uv run mypy --strict src && uv run ruff check src tests   # bp: 433 tests, typed, linted
```

## FAQ

**Does it work on Burp Suite Community?**
Yes. Every command runs on Community except `collaborator` and starting an active `scan` — those need
Pro and exit `4` with a clear message. Fuzzing in particular is *not* subject to Community's Intruder
throttle, because `bp` fires each request through Burp's Repeater.

**How is this different from ffuf?**
`ffuf` is a great standalone fuzzer, but it runs *outside* Burp — it doesn't know your Burp session,
cookies, upstream/proxy config, or scope. `bp` drives Burp itself, so your fuzzing inherits all of
that. Use `ffuf` for raw speed on unauthenticated endpoints; use `bp` when you're mid-hunt inside an
authenticated Burp session.

**Do I need Burp Suite Professional?**
No, for almost everything. Only Collaborator (out-of-band payloads) and starting an active scan
require Pro. Proxy history, Repeater, fuzzing, scope, decoder, sitemap, and the IDOR/CORS/auth-bypass
checks all work on Community.

**Can I drive it from a script or an AI agent?**
Yes — `--format json` emits NDJSON (one record per line), exit codes are stable and documented, and
there are no interactive prompts. That makes it easy to wire into CI, shell pipelines, or an agent.

**Is `bp` the same as `burpctl`?**
Yes. `bp` is the primary command (short, one token); `burpctl` is an installed alias — identical
behaviour.

## Contributing

Issues and PRs welcome — `bp` is spec-driven and test-first. Start with
**[CONTRIBUTING.md](CONTRIBUTING.md)** (disciplines, dev setup, Definition of Done), see the
**[ROADMAP](ROADMAP.md)** for what's planned, and report vulnerabilities privately per
**[SECURITY.md](SECURITY.md)**.

> ⚠️ **Authorized use only.** This drives a security proxy — use it solely against systems you own or are explicitly permitted to test.

## License

[MIT](LICENSE)
