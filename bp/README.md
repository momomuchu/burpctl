# bp — Burp Suite REST CLI

`bp` drives **Burp Suite** from the command line via the `burp-rest-extension` on
`http://127.0.0.1:8089`: one command instead of hand-crafted JSON, with **flexible client-side
fuzzing** (arbitrary injection positions, all attack types) through Burp's HTTP stack, concise
output, and a **Run Ledger** that records every bp-to-extension operation. A captured replay keeps
its request cookies and headers; Burp target scope classifies traffic but does not block forwarding.
Scriptable and
agent-friendly by design.

> **`burpctl` is an alias for `bp`** — they are identical. Examples below use `bp` (the primary command).

Fully typed (Python 3.11+, `mypy --strict`), spec-driven (`docs/`), test-driven (`pytest`).

## Requirements

- **Burp Suite** (Pro or Community) with the `burp-rest-extension` JAR loaded (REST auto-starts
  on `:8089`). Community works for every group except `collab` and `scan` start — those exit `4`
  with a clear message on Community.
  Build it: `./gradlew shadowJar` → load `build/libs/burp-rest-extension.jar` in Burp.
- **Python 3.11+**

## Install

```bash
uv tool install .          # or: pipx install .
# dev:
uv sync && uv run bp --help
```

## Quickstart

```bash
bp health                                  # extension liveness + version
bp proxy --host example.com --limit 20     # captured proxy history -> request ids
bp req 42                                  # full detail of one request

# fuzz: mark ANY byte range, multi-position, matrix attacks (client-side)
bp fuzz 42 --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=ssrf.txt \
           --pos 'cookie:role'            --payloads role=privesc.txt \
           --type cluster-bomb --anomalous-only

bp collab new                              # OOB payload (blind SSRF/RCE) — Pro
bp scan audit https://target.example       # target-seeded active audit — Pro
bp encode 'a:b' --enc base64               # offline decoder
bp scope check https://target.example      # classify with Burp's scope engine
bp log --tag recon --limit 50              # query bp REST-operation records
```

## Command surface

`--pos` selectors: `header:N` `cookie:N` `body:F` `query:N` `path:i` `offset:a-b` ·
attack types: `sniper` `battering-ram` `pitchfork` `cluster-bomb`.

Flat verbs: `health version proxy req ws intercept send tab fuzz sitemap encode decode hash
diff endpoints ext log tag`. Groups: `scope scan check collab config session history`.
Full grammar: [`docs/CLI.md`](../docs/CLI.md).

## Output & config

- `--format json|table|raw|quiet`, `--fields a,b,c`, `--url` (or `BURP_REST_URL`).
- **Run Ledger** ON by default (`~/.bp/ledger.db`): every bp REST op recorded with sha256
  fingerprints (never raw bodies); it is not a complete curl/xh/browser traffic log.
  `BP_NO_LEDGER=1` opts out; secrets are redacted by default.
- Config precedence: flag > env > `~/.bp/config` > default. See [`docs/OUTPUT.md`](../docs/OUTPUT.md),
  [`docs/STATE-AND-CONFIG.md`](../docs/STATE-AND-CONFIG.md).

## Architecture

`bp` owns all four fuzz attack types client-side. The bounded extension Intruder surface supports
sniper only; other server-side modes report `UNSUPPORTED`. The CLI path is:
`--pos` → byte offsets (A1) → bounded lazy expansion + substitution (A2) → fire via `/repeater/send`.
See [`docs/ALGORITHMS.md`](../docs/ALGORITHMS.md), [`docs/SPEC.md`](../docs/SPEC.md), and ADRs in
[`docs/adr/`](../docs/adr/).

## License

MIT
