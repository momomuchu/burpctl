# burp-wrapper

Drive **Burp Suite** from the command line. Two components in this repo:

1. **[`bp`](bp/)** — a fast, fully-typed **CLI client** (Python, **v1.0.0**) — *the recommended interface.*
   One command instead of hand-crafted JSON: capture, **flexible client-side fuzzing** (any
   injection position, all attack types), scans, decoder, and a **Run Ledger** that records every
   op. Built for bug-bounty hunters and AI agents.
2. **burp-rest-extension** — a **Kotlin** Burp extension exposing the Montoya API as a REST API on
   `http://127.0.0.1:8089`. The backend `bp` talks to (you can also `curl` it directly).

```
 you / AI agent ──►  bp (CLI)  ──REST :8089──►  burp-rest-extension  ──Montoya──►  Burp Suite Pro
```

## Quickstart

### 1. Load the extension (backend)

```bash
./gradlew shadowJar                 # → build/libs/burp-rest-extension.jar  (needs JDK 17)
```
In Burp: **Extensions → Add → Extension Type: Java → Select the JAR.** REST auto-starts on `:8089`
(watch the extension Output tab for `Server started on http://127.0.0.1:8089`).

### 2. Use `bp`

```bash
cd bp && uv tool install .          # or: pipx install .   (Python 3.11+)

bp health                                       # extension liveness
bp proxy --host target.example --limit 20       # captured history → request ids

# fuzz: mark ANY byte range, multi-position, matrix attacks (client-side)
bp fuzz 42 --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=ssrf.txt \
           --pos 'cookie:role'            --payloads role=privesc.txt \
           --type cluster-bomb --anomalous-only

bp collab new                                   # OOB payload (blind SSRF/RCE) — Pro
bp scan all https://target.example              # crawl + audit — Pro
bp encode 'a:b' --enc base64                    # offline decoder
bp log --tag recon                              # query the Run Ledger
```

Full CLI guide: **[`bp/README.md`](bp/README.md)**.

## What's where

| Path | What |
|---|---|
| [`bp/`](bp/) | The `bp` CLI client (Python, v1.0.0) — [README](bp/README.md) · [CHANGELOG](bp/CHANGELOG.md) |
| `src/main/kotlin/com/burprest/` | The Burp REST extension (Kotlin / Ktor / Montoya) |
| [`docs/`](docs/) | Source-grounded spec: [SPEC](docs/SPEC.md) (69 endpoints / 13 groups), [CLI](docs/CLI.md) grammar, [OUTPUT](docs/OUTPUT.md), [ALGORITHMS](docs/ALGORITHMS.md), 8 [ADRs](docs/adr/) |

> The REST surface is **13 route groups / 69 endpoints**, source-verified in `docs/SPEC.md`.
> All endpoints return `{success, data, error}`. The historical `spec.md` design (Python wrapper,
> port 9876) is **superseded** — see `docs/SPEC.md` and ADR-0001.

## Requirements

- **Burp Suite Pro** (Community works for non-Pro features; `bp` degrades gracefully).
- **JDK 17+** to build the extension · **Python 3.11+** for `bp`.

## Build & test

```bash
./gradlew shadowJar          # extension fat JAR
cd bp && uv run pytest -q && uv run mypy && uv run ruff check   # bp: 112 tests, typed, lint
```

## License

MIT
