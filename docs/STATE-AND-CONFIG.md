# `bp` — Persistence (Run Ledger) & Configuration (spec)

> **DRAFT — spec, not code.** Ref: `ADR-0005` (Ledger ON by default, SQLite `~/.bp/`),
> `ADR-0007` (configurable security guards, non-blocking), `OUTPUT.md` (`bp log`), gaps research
> (resp_sha256 / never raw bodies, redaction I7).

## 1 · Run Ledger — SQLite schema (`~/.bp/ledger.db`)

ON by default (`--no-ledger` to opt out per operation). **We store fingerprints + refs, NOT raw
bodies** by default (bb-mini concept: no leakage, lightweight ledger).

```sql
CREATE TABLE ops (
  id          TEXT PRIMARY KEY,   -- short, temporally sortable (e.g. ULID)
  ts          TEXT NOT NULL,      -- ISO-8601 UTC
  command     TEXT,               -- bp command line (redacted if redact=on)
  burp_op     TEXT,               -- e.g. "POST /intruder/attack/create"
  target      TEXT,               -- targeted host/url
  program     TEXT,               -- nullable (future workspace, ADR-0007)
  tag         TEXT,               -- nullable (--tag)
  status      TEXT NOT NULL,      -- ok | error | refused
  exit_code   INTEGER,
  req_sha256  TEXT,               -- fingerprint of sent request
  resp_sha256 TEXT,               -- fingerprint of response
  resp_status INTEGER,
  resp_len    INTEGER,
  duration_ms INTEGER,
  error_code  TEXT,               -- nullable (CONNECTION_REFUSED, PRO_REQUIRED, …)
  req_ref     TEXT,               -- nullable: Burp history id or blob path if bodies are stored
  resp_ref    TEXT
);
CREATE INDEX idx_ops_ts     ON ops(ts);
CREATE INDEX idx_ops_target ON ops(target);
CREATE INDEX idx_ops_tag    ON ops(tag);
```

- **Bodies**: not stored by default. `--ledger-bodies` (opt-in) → writes to `~/.bp/blobs/<sha256>`, **after redaction** if `redact=on`.
- `bp log [--since T --until T --target H --tag X --status S --limit N]` → SELECT on `ops`.
- `bp tag <opId> <name>` → UPDATE tag. (Query surface = `OUTPUT.md`.)
- **Integrity** (bb-certify concept, future): `bp certify` could produce a SHA-256 manifest — out of driver scope, noted on roadmap.

## 2 · Configuration — file + env + flags

**Precedence (strongest wins):** CLI flag > env variable > `~/.bp/config` > built-in default.

**`~/.bp/config`** — `KEY=value` format (sh-sourceable, simple):
```
burp_rest_url   = http://127.0.0.1:8089
enforce_scope   = warn        # warn | block | off   (default warn — NEVER enforced, ADR-0007)
envelope        = off         # on | off  (anti-injection envelope around surfaced response bodies, I6)
redact          = on          # on | off  (masks JWT/cookies/Authorization/keys in log+output, I7)
ledger          = on          # on | off
throttle_ms     = 0
anomaly_pct     = 5           # length anomaly threshold (see ALGORITHMS A2)
agent_mode      = auto        # auto | on | off (NDJSON for AI agent, see OUTPUT.md)
```

**Env variables** (prefix `BP_`, plus legacy `BURP_REST_URL`):
`BURP_REST_URL`, `BP_ENFORCE_SCOPE`, `BP_ENVELOPE`, `BP_REDACT`, `BP_NO_LEDGER`, `BP_THROTTLE_MS`, `BP_AGENT` (see OUTPUT.md).

**Equivalent flags** (per command): `--url`, `--enforce-scope`, `--envelope`, `--redact`, `--no-ledger`, `--throttle-ms`. Each flag overrides env+config for that invocation.

**Guard semantics (non-blocking by default — ADR-0007):**
- `enforce_scope=warn` (default): fires anyway, **warns** if the target is out of scope.
- `enforce_scope=block`: refuses (exit 4) if out of scope. **Opt-in**, never enforced by default.
- `enforce_scope=off`: no scope check.
- `envelope=on`: wraps `<BP_TARGET_DATA>…</BP_TARGET_DATA>` around surfaced target bodies (agent anti-injection). Default off (configurable).
- `redact=on` (default): masks known secrets before logging/display — protects **your own** secrets, low downside.

## 3 · RED test cases (TDD)

- Precedence: flag > env > config > default (4 levels, one test each).
- `enforce_scope=warn` + out-of-scope target → fires **and** emits the warning (does not fail).
- `enforce_scope=block` + out of scope → exit 4, does not fire.
- `redact=on` → an `Authorization: Bearer X` does not appear in `ops.command` or in the output.
- Ledger: an `ok` op inserts 1 row with a non-null `resp_sha256` and **no raw body** stored (without `--ledger-bodies`).
- `--no-ledger` → 0 rows inserted.

## Status

`[HIGH][BLOCKS:high]` — completes the *driver* surface (persistence + config). Together with
`A1/A2` (ALGORITHMS) and this doc, the **driver is spec-complete**. Two decisions remain **yours**:
implementation language + `SPEC §14` validation. **Zero code before GO.**
