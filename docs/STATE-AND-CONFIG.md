# `bp` — Persistence (Run Ledger) & Configuration (spec)

# Current state and configuration contract

This section supersedes stale implementation descriptions later in this historical document.

- Python configuration precedence is explicit flag > environment > `~/.bp/config` > default. The path is resolved at invocation time so isolated `HOME` values work.
- REST base URLs must be valid HTTP(S) origins without userinfo, query, fragment, or a non-root path. `enforce_scope`, booleans, throttle, and anomaly percentage are validated.
- The Python Run Ledger is SQLite under `~/.bp/`, owner-only, and stores fingerprints/metadata—not raw target request or response bodies. Complete encoded query identity affects the fingerprint but raw query/userinfo does not enter text columns. Command outcome starts failed and becomes success only after invocation and rendering finish.
- Extension request/session/sitemap persistence is H2/MVStore under `~/.burp-rest/`, not SQLite. Its directory/files are tightened to owner-only modes where the filesystem supports them; unsafe symlink paths are rejected.
- H2 operations use scoped connections and transactions. History+sitemap record/clear and complete session persistence do not expose partial commits.
- The configured singleton session is an immutable snapshot bound to one origin; it is not a named multi-principal session store. Observed response cookies are a separate jar with a separate clear operation.

See [ADR-0013](adr/0013-truthful-executable-contracts.md).

---


> Ref: `ADR-0005` (Ledger ON by default, SQLite `~/.bp/`),
> `ADR-0007` (configurable security guards, non-blocking), `OUTPUT.md` (`bp log`).

## 1 · Run Ledger — SQLite schema (`~/.bp/ledger.db`)

ON by default (`--no-ledger` to opt out per operation). **We store fingerprints + refs, NOT raw
bodies** by default — no leakage, lightweight ledger.

```sql
CREATE TABLE ops (
  id          TEXT PRIMARY KEY,   -- short, temporally sortable (e.g. ULID)
  ts          TEXT NOT NULL,      -- ISO-8601 UTC
  command     TEXT,               -- bp subcommand name only (e.g. "bp check idor"); URL/header/payload args NOT stored
  burp_op     TEXT,               -- e.g. "POST /intruder/attack/create"
  target      TEXT,               -- targeted host/url
  program     TEXT,               -- nullable (reserved, v1.1)
  tag         TEXT,               -- nullable (--tag, user label)
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

The Run Ledger records `bp`'s control-plane REST operations, not Burp's complete target traffic.
For example, `bp send` produces an `ops` row whose `burp_op` is `POST /repeater/send`, whose
`target` is the REST listener host (not the target application), and whose request/response
fingerprints cover that REST exchange. Plain `curl`, `xh`, and browser traffic produces no Run
Ledger row. Use Burp proxy history for traffic that traverses its proxy listener.

### 1.1 · Workspace request ledgers remain caller-owned

`bp send` does not append a workspace `requests.jsonl` row. The target URL returned by Burp may
contain userinfo, OAuth codes, reset/invitation capabilities, signed-query credentials, path tokens,
or application-specific secrets; writing it automatically cannot satisfy both exact-request and
no-secret-at-rest contracts without a caller-supplied safe representation and an explicit schema.
The local Run Ledger row and extension DB history do not substitute for that workspace evidence.

## 2 · Configuration — file + env + flags

**Precedence (strongest wins):** CLI flag > env variable > `~/.bp/config` > built-in default.

**`~/.bp/config`** — `KEY=value` format (sh-sourceable, simple):
```
burp_rest_url   = http://127.0.0.1:8089
enforce_scope   = warn        # warn | block | off   (default warn — NEVER enforced, ADR-0007)
envelope        = off         # on | off  (anti-injection envelope around surfaced response bodies)
redact          = on          # on | off  (masks JWT/cookies/Authorization/keys in log+output)
ledger          = on          # on | off
throttle_ms     = 0
anomaly_pct     = 5           # length anomaly threshold (see ALGORITHMS A2)
```

**Env variables** (prefix `BP_`, plus legacy `BURP_REST_URL`):
`BURP_REST_URL`, `BP_ENFORCE_SCOPE`, `BP_ENVELOPE`, `BP_REDACT`, `BP_NO_LEDGER`, `BP_THROTTLE_MS`,
and `BP_AGENT` (see OUTPUT.md).

**Equivalent flags** (per command): `--url`, `--format`, `--fields`, `--no-ledger`, and `--no-redact`.
These are the only configuration-related flags currently exposed by the CLI. Each flag overrides
any lower-precedence setting for that invocation.

> **Implementation status.** `--url`, `--no-ledger`, `--format`, `--fields`, `--no-redact`, and
> `--version` are wired flags; `redact` and `ledger` are consumed at runtime (the chokepoint
> reads exactly those two knobs). `enforce_scope`, `envelope`, `throttle_ms`, and `anomaly_pct`
> are loaded and validated from configuration, but are not applied to command execution yet.
> There are no CLI flags for those settings. `BP_AGENT=1` selects JSON output; TTY-aware automatic
> format detection is not implemented yet, so the default without `BP_AGENT=1` or an explicit
> `--format` is `table`.

**Guard semantics (non-blocking by default — ADR-0007):**
- `enforce_scope=warn` (default): fires anyway, **warns** if the target is out of scope. _(v1.1 — not yet wired; no warning is emitted in v1.)_
- `enforce_scope=block`: intended to refuse (exit 4) if out of scope. **Opt-in**, never enforced by default. _(v1.1 — NOT yet implemented: `block` does NOT currently refuse out-of-scope targets.)_
- `enforce_scope=off`: no scope check.
- `envelope=on`: wraps `<BP_TARGET_DATA>…</BP_TARGET_DATA>` around surfaced target bodies (agent anti-injection). Default off. _(v1.1 — not yet wired.)_
- `redact=on` (default): masks known secrets before logging/display — protects **your own** secrets, low downside. **(active in v1.)**

## 3 · RED test cases (TDD)

- Precedence: flag > env > config > default (4 levels, one test each). _(active in v1)_
- `redact=on` → an `Authorization: Bearer X` does not appear in `ops.command` or in the output. _(active in v1)_
- Ledger: an `ok` op inserts 1 row with a non-null `resp_sha256` and **no raw body** stored (without `--ledger-bodies`). _(active in v1)_
- `BP_NO_LEDGER=1` **or** `--no-ledger` → 0 rows inserted.
- _(v1.1, not yet implemented)_ `enforce_scope=warn` + out-of-scope target → fires **and** emits the warning (does not fail).
- _(v1.1, not yet implemented)_ `enforce_scope=block` + out of scope → exit 4, does not fire.

## Status

`[HIGH][BLOCKS:high]` — completes the *driver* surface (persistence + config). Together with
`A1/A2` (ALGORITHMS) and this doc, the **driver is spec-complete**.
