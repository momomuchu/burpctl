# `bp` — OUTPUT Contract Specification

> **DEEP output-contract spec for the `bp` CLI.**
> Companion to `docs/SPEC.md` (grammar §5, intruder results §6.4, ledger §9, Kotlin contract §8).
> Generated 2026-06-16.

---

## Overview

**What this means** — This locks down exactly what every `bp` command *prints*, so a human and an AI agent read the same tool through one stable contract: four formats, a curl-style `-w` template, selectable fields, and a deterministic JSON schema for agents.

**The core loop** —
1. Every `bp` command emits records (fuzz rows, history rows, issues, interactions…).
2. `--format` picks the *shape*: `json` (agent), `table` (human), `raw` (Burp bytes), `quiet` (one value).
3. `--fields` picks *which* columns and their order; `-w` builds a *custom line* from `%{tokens}`.
4. Default format is `table` for all streams in v1; pass `--format json` for agents/pipes. _(v1.1 — TTY-aware auto-detect not yet implemented)_
5. Errors always go to **stderr** as one JSON object; data goes to **stdout**; exit code carries success/failure.
6. Every shown record is also written to the **Run Ledger** (`~/.bp/`) unless `--no-ledger`.
7. `bp fuzz ... -w '%{status} %{payload}'` prints ONLY the HTTP code + payload, one line per request.

**Terms** — *AX* = agent experience (machine-readable output). *Record* = one row/entry. *write-out* = a `-w` template line. *Anomalous* = a fuzz result that differs from baseline. *Ledger* = local SQLite audit log of every op.

**Key design decisions** — The four-format model, the `-w` token grammar, the AX stable-schema rule, and the stderr/exit-code contract. The field catalog is *derived* from SPEC §6 models (not invented).

**Open decisions** — (1) Default-`json`-when-piped vs always-`table`. (2) The `%{anomalous}` token only being meaningful for `quick-fuzz` (server only sets it there). (3) Whether `--quiet` should exit non-zero when the single value is empty. (4) Token-efficiency cap defaults (50 rows, 256-byte body preview). (5) Whether `raw` is allowed for multi-record commands or single-record only.

**Where to look** — §1 (four formats) and §3 (`-w` grammar) are the load-bearing sections. §4 is the agent contract.

---

## 0 · Scope, axioms, and how to read this

This document specifies **only output** — what bytes leave `bp` on stdout/stderr, in what shape,
under which flags. It does **not** re-specify the API (see SPEC §6) or the `--pos` grammar (SPEC §5).

Each requirement is tagged with a criticality scale: `[IMPORTANCE][BLOCKS:level]`.

### 0.1 · Axioms (load-bearing, apply everywhere)

- **[CRITICAL][BLOCKS:critical] A1 — One output model, every command.** The four global flags
  (`--format`, `--fields`, `-w/--write-out`, `--quiet`) plus `--tag` / `--no-ledger` exist on
  **every** `bp` subcommand. No command invents its own output flags.
- **[CRITICAL][BLOCKS:high] A2 — Data to stdout, diagnostics to stderr.** Records, tables, and
  `-w` lines go to **stdout**. Errors, warnings, Pro/Community degradation notices, and progress
  go to **stderr**. A consumer reading stdout never sees a human warning mixed into data.
- **[CRITICAL][BLOCKS:high] A3 — Stable JSON schema for agents.** In `--format json`, field
  **names, types, and order are frozen** per the field catalog (§2). New fields may be *appended*
  (never reordered, never renamed) — additive-only, mirroring the Kotlin `ignoreUnknownKeys` /
  `encodeDefaults` contract (SPEC §8).
- **[HIGH][BLOCKS:high] A4 — Default format is context-aware.** `table` when stdout is a TTY;
  `json` when stdout is piped, redirected, or `BP_AGENT=1` is set. This is the single biggest
  AX-friendliness lever: an agent piping `bp` gets parseable JSON with zero flags.
  _(v1.1 — not yet implemented; the current default is `table` for all streams — pass `--format json` for agents/pipes)_
- **[HIGH][BLOCKS:none] A5 — Never dump full bodies by default.** Response bodies are summarized
  (preview-capped) unless the user explicitly asks (`--fields body` or `--format raw` on a single
  record). Token efficiency is a contract, not a courtesy (SPEC handoff: "summarise, don't dump").
- **[HIGH][BLOCKS:low] A6 — Determinism.** Same input → same byte output (modulo timing fields).
  Field order, number formatting, and null rendering are fixed. No locale-dependent formatting.
- **[MEDIUM][BLOCKS:none] A7 — Ledger is orthogonal to format.** What you *see* and what gets
  *recorded* are decoupled: changing `--format` never changes what the ledger stores (§6).

### 0.2 · Precedence of output flags (deterministic resolution)

When multiple output flags are combined, resolve in this exact order:

```
1. --write-out / -w   → if present, it OWNS stdout. --format and --fields are ignored for
                        record rendering. (-w is itself a format.)
2. --quiet            → if present (and no -w), emit only the single essential value per record.
3. --format           → json | table | raw  (explicit beats the A4 default).
4. --fields           → applies ONLY to json and table; selects + orders columns.
5. default (A4)        → table if TTY else json.
```

- **[CRITICAL][BLOCKS:high] R-PREC** `-w` and `--quiet` are mutually exclusive with each other;
  supplying both is a usage error (exit 2, stderr). `-w` + `--format` is *not* an error —
  `--format` is simply ignored for rows (it may still affect the ledger-disabled banner, which is
  stderr anyway).
- `--fields` with `--format raw` is a usage error (raw has no columns) → exit 2.

---

## 1 · The four formats

Every command family below shows the same underlying records (`bp fuzz results`) rendered four ways,
then per-family deltas. The canonical example record set is two intruder `quick-fuzz` results.

### 1.1 · `json` — agent-native, compact, stable

- **[CRITICAL][BLOCKS:critical] F-JSON** One **record per line** (NDJSON / JSON-Lines), compact
  (no pretty-print, mirroring server `prettyPrint=false`, SPEC §8). Each line is a complete,
  independently-parseable JSON object. **No outer array.** This lets an agent stream-parse line by
  line and stop early without reading the whole set.
- Field order is the catalog order (§2). All declared fields are present (`encodeDefaults=true`
  parity) — nulls render as `null`, never omitted.
- A single-record command (e.g. `bp repeater send`) emits exactly **one** line.
- Numbers are JSON numbers (no quotes); booleans are `true`/`false`; strings are JSON-escaped.

```
$ bp fuzz results a1b2c3d4 --format json
{"index":0,"payload":"admin","status":200,"length":1487,"time":42,"contentType":"application/json","anomalous":false,"location":null,"requestId":318}
{"index":1,"payload":"' OR 1=1--","status":500,"length":622,"time":58,"contentType":"text/html","anomalous":true,"location":null,"requestId":319}
```

- **Envelope handling:** the server wraps responses in `ApiResponse<T>` (SPEC §8). `bp` **unwraps**
  it: on `success:true` it emits `data`'s records; on `success:false` it emits an error object to
  **stderr** (§5) and prints nothing to stdout. The agent never has to parse the envelope.
- **Optional metadata line:** with `--meta`, the FIRST stdout line is a single object
  `{"_meta":{...}}` carrying counts/paging (`total`, `shown`, `truncated`, `attackId`). Off by
  default to keep the stream pure records. `_meta` is the only key allowed to lead with `_`.

### 1.2 · `table` — aligned human view

- **[HIGH][BLOCKS:low] F-TABLE** Column-aligned, fixed header row, one record per line. Columns =
  `--fields` selection or the family default set. Long values are **truncated with `…`** to keep
  rows on one screen line (default terminal width, or `$COLUMNS`); the untruncated value is always
  available in `json`/`raw`.
- Header is uppercase field names. Null renders as empty cell (`-` is reserved; we use blank).
- Numbers right-aligned, strings left-aligned. This is the **only** format that targets eyeballs.

```
$ bp fuzz results a1b2c3d4 --format table
INDEX  PAYLOAD      STATUS  LENGTH  TIME  CONTENTTYPE        ANOMALOUS
0      admin        200     1487    42    application/json   false
1      ' OR 1=1--   500     622     58    text/html          true
```

### 1.3 · `raw` — Burp raw bytes (verbatim)

- **[HIGH][BLOCKS:none] F-RAW** Emits the **raw HTTP bytes** Burp returns (request or response),
  verbatim, no wrapper, no field selection. This is for commands that have a single dominant byte
  artifact: `bp repeater send` (the raw response), `bp history get <id>` (raw req+resp),
  `bp proxy history get <id>` (raw), `bp fuzz results <id> --index N` (that one response's raw bytes).
- **[HIGH][BLOCKS:low] R-RAW-SINGLE** `raw` requires a **single** record in scope. On a multi-record
  command without an index selector, `raw` is a usage error (exit 2, stderr message: *"raw requires
  a single record; add --index N or use --format json"*). Rationale: concatenated raw HTTP streams
  are ambiguous to parse.
- When both request and response exist, they are separated by a single line containing exactly
  `\x1e` (ASCII record separator) so a consumer can split deterministically; `--raw-part req|res`
  selects only one.

```
$ bp repeater send --id 42 --format raw
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 1487

{"ok":true,...}
```

### 1.4 · `quiet` — the single essential value

- **[CRITICAL][BLOCKS:high] F-QUIET** Prints only the **one most essential value** per record,
  one per line, nothing else — no header, no alignment, no key. The essential value is defined
  **per command family** (§1.5). `--quiet` (the flag) and `--format quiet` are equivalent.
- Designed for shell composition: `if [ "$(bp scope check --url X --quiet)" = "in-scope" ]`.
- Empty/absent essential value renders as an empty line. **[MEDIUM][BLOCKS:none] OPEN-Q1:** should
  an empty essential value force exit≠0? Default: **no** (presence of the record is success).

```
$ bp fuzz results a1b2c3d4 --format quiet
200
500
```

### 1.5 · Per-family essential value (what `quiet` prints)

- **[HIGH][BLOCKS:low] R-ESSENTIAL** Each family declares its single `quiet` value:

| Command family | `--quiet` prints | Rationale |
|---|---|---|
| `bp fuzz results` | `status` (HTTP code) | the headline triage signal |
| `bp repeater send` | `status` | did the replay land |
| `bp proxy history` / `bp history` | `id` | feed the next command (`--id`) |
| `bp scanner issues` | `severity` | triage |
| `bp collaborator poll` | `interactionId` (or `none`) | did OOB fire |
| `bp collaborator new` | the payload host | the thing you paste into a target |
| `bp scope check` | `in-scope` \| `out-of-scope` | branch a script |
| `bp health` | `ok` \| `down` | liveness gate |
| `bp ledger list` | `id` | chain to `bp show` |
| `bp scan *` (securityscan) | `vulnerable` \| `clean` | one-word verdict |

---

## 2 · `--fields` selection + the FIELD CATALOG

### 2.1 · `--fields` semantics

- **[CRITICAL][BLOCKS:high] R-FIELDS** `--fields f1,f2,...` selects **which** fields appear and
  **in what order** for `json` and `table`. The given order is honored exactly (overrides catalog
  default order for display; the *stable* catalog order still defines the canonical schema when
  `--fields` is absent — A3).
- Unknown field name → usage error (exit 2, stderr lists valid fields). Case-insensitive match,
  canonical-cased on output.
- `--fields all` selects the full catalog in catalog order. `--fields '*'` is a synonym.
- Field names are **stable identifiers** (camelCase, matching the Kotlin contract SPEC §8 where a
  server field exists). Computed/CLI-only fields (e.g. `time` alias for `durationMs`) are documented
  per catalog.
- With `--format json`, omitting a field via `--fields` **does** remove it from the line (this is an
  explicit user narrowing, not a schema break — A3 protects the *default* schema, not user-narrowed
  output).

### 2.2 · FIELD CATALOG — per command family

Catalog order = canonical JSON order. `★` marks the `quiet` essential value. `srv:` notes the
source Kotlin field (SPEC §6/§8); `cli:` marks a `bp`-computed field.

#### 2.2.1 · `bp fuzz results` (Intruder `AttackResultEntry`, SPEC §6.4)

| Field | Type | Source | Notes |
|---|---|---|---|
| `index` | int | srv:`index` | 0-based position in the attack |
| `payload` | string | srv:`payload` | the injected value |
| `status` ★ | int | srv:`statusCode` | `0` if request errored (renamed `statusCode`→`status` for `-w` ergonomics) |
| `length` | int | srv:`length` | response byte length |
| `time` | int(ms) | srv:`durationMs` | alias; `durationMs` also accepted |
| `contentType` | string\|null | srv:`contentType` | |
| `anomalous` | bool | srv:`anomalous` | **only meaningful in `quick-fuzz`** (SPEC §6.4: server sets it only there). For `attack/results` it is `false`/absent → `bp` renders `null`, not a false `false`. **[HIGH][BLOCKS:none] R-ANOM** |
| `error` | string\|null | srv:`error` | transport error message |
| `location` | string\|null | cli: parsed from response `Location:` header | redirect target |
| `requestId` | int\|null | cli: history index if the row was persisted | for chaining to `bp repeater send --id` |
| `bodyPreview` | string\|null | srv:`bodyPreview` | capped (§4.3); NOT in default fields |

Default `table`/`json` fields (when `--fields` absent): `index,payload,status,length,time,contentType,anomalous`. `error`, `location`, `requestId`, `bodyPreview` are opt-in.

#### 2.2.2 · `bp proxy history` (`ProxyHistoryEntry`, SPEC §6.2)

| Field | Type | Source | Notes |
|---|---|---|---|
| `id` ★ | int | srv:`id` | **offset-relative → unstable** across offsets (SPEC §6.2). Prefer `bp history` for stable Long ids |
| `method` | string | srv | |
| `host` | string | srv | |
| `url` | string | srv | full URL |
| `status` | int\|null | srv:`statusCode` | |
| `length` | int\|null | srv | response length |
| `mimeType` | string\|null | srv | |
| `timestamp` | string\|null | srv | **always null** (SPEC §6.2 flag) — rendered `null` |

Default fields: `id,method,status,host,url,length`.

#### 2.2.3 · `bp history` (DB-backed `HistoryEntryResponse`, SPEC §6.13)

> **[HIGH][BLOCKS:high] R-HIST-404** This family 404s entirely if the SQLite DB failed to init
> (SPEC §6.13). `bp` detects the 404 and prints to **stderr**: *"history unavailable: extension DB
> not initialized"* and exits **1** (generic error). It does NOT emit an empty success.

| Field | Type | Source | Notes |
|---|---|---|---|
| `id` ★ | long | srv:`id` | **Long** (SPEC §8) — stable DB key |
| `method` | string | srv | |
| `host` | string | srv | |
| `url` | string | srv | |
| `status` | int\|null | srv:`statusCode` | |
| `source` | string | srv | proxy\|repeater\|replay\|intruder |
| `reqLength` | int\|null | cli: len(reqBody) | |
| `length` | int\|null | srv | response length |
| `since` / `timestamp` | string\|null | srv | ISO8601 |
| `reqBody` | string\|null | srv | capped; opt-in |
| `resBody` | string\|null | srv | capped; opt-in |

Default fields: `id,method,status,host,url,source,length`.

#### 2.2.4 · `bp scanner issues` (`ScanIssue`, SPEC §6.6)

| Field | Type | Source | Notes |
|---|---|---|---|
| `name` | string | srv | issue title |
| `severity` ★ | string | srv | HIGH\|MEDIUM\|LOW\|INFORMATION\|FALSE_POSITIVE |
| `confidence` | string | srv | CERTAIN\|FIRM\|TENTATIVE |
| `url` | string | srv | affected URL |
| `host` | string | cli: parsed from url | |
| `typeIndex` | long | srv | **always 0L** (SPEC §6.6 flag) → render as-is but documented dead |
| `detail` | string\|null | srv | capped; opt-in |

Default fields: `severity,confidence,name,url`. Sorted by severity rank (HIGH→…) then confidence.

#### 2.2.5 · `bp collaborator poll` / `new` (`Interaction`, SPEC §6.5)

> **[HIGH][BLOCKS:high] R-COLLAB-PRO** Pro-only. On Community / unconfigured → server 503. `bp`
> prints to **stderr**: *"collaborator requires Burp Suite Professional"* and exits **4** (PRO_REQUIRED).

| Field | Type | Source | Notes |
|---|---|---|---|
| `interactionId` ★ | string | srv | local key, **not** a Burp UUID (SPEC §6.5) |
| `type` | string | srv | DNS\|HTTP\|SMTP (`.name` of Montoya enum) |
| `clientIp` | string\|null | srv | source of the OOB hit |
| `timestamp` | string | srv | `Instant.now()` at poll, **not** capture time (SPEC §6.5 flag) |
| `payload` | string | srv | the collaborator host (for `new`, this is the ★ essential value) |
| `found` | bool | srv | **caveat:** poll errors silently coerce to `found:false` (SPEC §6.5) — indistinguishable from "no hit yet" |

Default fields: `interactionId,type,clientIp,timestamp`.

#### 2.2.6 · `bp repeater send` (single record: req+resp+timing, SPEC §6.3)

| Field | Type | Source | Notes |
|---|---|---|---|
| `status` ★ | int | srv | response code |
| `length` | int | srv | response length |
| `time` | int(ms) | srv | round-trip |
| `method` | string | cli/srv | request method sent |
| `host` | string | cli | |
| `contentType` | string\|null | srv | |
| `location` | string\|null | cli: `Location:` | |
| `requestId` | int\|null | srv | history index if persisted |
| `reqRaw` / `resRaw` | string | srv | raw bytes — surfaced via `--format raw`, not table |

Default fields: `status,length,time,method,host,contentType`.

#### 2.2.7 · `bp ledger list` / `bp show` (LedgerEntry, SPEC §9)

| Field | Type | Source | Notes |
|---|---|---|---|
| `id` ★ | int | ledger | local autoincrement |
| `tag` | string\|null | ledger:`name`/`tag` | user label (`--tag`) |
| `timestamp` | string | ledger | ISO8601 |
| `command` | string | ledger | the `bp` subcommand name (e.g. `bp check idor`), **not** the full argv — URL/header/payload args are intentionally omitted for privacy |
| `target` | string\|null | ledger | host/url |
| `burpOp` | string | ledger | REST endpoint called (e.g. `POST /intruder/attack/create`) |
| `status` | string | ledger | ok\|err |
| `requestRef` | string\|null | ledger | pointer to stored request |
| `responseRef` | string\|null | ledger | pointer to stored response |

Default fields: `id,timestamp,tag,status,target,burpOp`.

---

## 3 · `-w` / `--write-out` template grammar

The headline AX feature: a curl-style template that prints exactly the bytes you ask for, per record.

### 3.1 · Headline example

```
$ bp fuzz --id 42 --pos 'body:q' --payloads xss.txt --type sniper -w '%{status} %{payload}'
200 <script>alert(1)</script>
403 ' OR '1'='1
500 ../../etc/passwd
```

Exactly one line per result: HTTP code, a space, the payload. No header, no envelope, no extra
columns. `-w` owns stdout (R-PREC).

### 3.2 · Token list (full)

- **[CRITICAL][BLOCKS:high] R-WTOK** The template is literal text with `%{token}` substitutions.
  Tokens resolve **per record**; the template is applied once per emitted record (one line of
  output per record, unless the template itself contains no newline — see §3.4). See §3.1 for the headline example.

| Token | Value | Source / notes |
|---|---|---|
| `%{status}` | HTTP status code (int) | `statusCode`; `0` on transport error |
| `%{length}` | response byte length (int) | |
| `%{time}` | round-trip ms (int) | `durationMs` |
| `%{payload}` | injected payload (string) | empty for non-fuzz records |
| `%{location}` | `Location:` header value | empty if absent |
| `%{anomalous}` | `true`/`false`/empty | empty when not meaningful (R-ANOM); `true`/`false` only in quick-fuzz |
| `%{contentType}` | response Content-Type | empty if absent |
| `%{index}` | 0-based record index (int) | |
| `%{requestId}` | history index (int) | empty if not persisted |
| `%{host}` | target host (string) | parsed from request URL |
| `%{method}` | request method (string) | GET/POST/… |

- **[HIGH][BLOCKS:low] R-WCATALOG** A token that names a **catalog field** for the current family
  but is not in the above core list resolves to that field's value (e.g. `%{severity}` on
  `bp scanner issues`, `%{interactionId}` on `bp collaborator poll`, `%{tag}` on `bp ledger list`).
  The core 11 tokens above are guaranteed on **every** family (resolving to empty where the family
  lacks them). This keeps the headline contract universal while letting power users reach any field.
- **[MEDIUM][BLOCKS:none] R-WUNKNOWN** An unknown token (not core, not a catalog field) is a usage
  error (exit 2) — fail loud, do not silently emit the literal `%{...}`. Rationale: a silent
  passthrough hides agent typos.

### 3.3 · Escaping & literals

- **[HIGH][BLOCKS:low] R-WESC** Escape sequences in the template are interpreted: `\n` newline,
  `\t` tab, `\r` CR, `\\` backslash, `\%` literal percent-not-a-token. A literal `{` or `}` outside
  a `%{...}` needs no escaping. To emit a literal `%{` write `%%{`.
- Values are inserted **verbatim** (no shell-quoting, no JSON-escaping) — `-w` is for building your
  own line format; if you need safe quoting, use `--format json`. **[HIGH][BLOCKS:none] R-WSAFE:**
  because payloads can contain newlines/control bytes, `bp` replaces raw `\n`/`\r` *inside a token
  value* with their escaped forms (`\n`→`\\n`) so one record stays on one line — UNLESS `--raw-w`
  is passed (then verbatim, caller owns parsing).
- A trailing newline is appended after each record's rendered template unless the template already
  ends in `\n` (no double newline). If the template ends with `\c` (curl-style), the trailing
  newline is suppressed.

### 3.4 · Defaults & interaction

- `-w` with no `%{}` token prints the literal string once per record (rarely useful; allowed).
- `-w` ignores `--fields` (it has its own field references) and ignores `--format` for rows
  (R-PREC). It does **not** suppress stderr diagnostics or the ledger.
- **Single-record commands** (`bp repeater send`, `bp scope check`) apply the template once.
- `--meta` is incompatible with `-w` (no place to put it) → ignored with a stderr note.

### 3.5 · Worked examples

```
# Triage table-free: code + length + payload, tab-separated
bp fuzz --id 7 --pos 'header:X-Forwarded-For' --payloads ips.txt \
        -w '%{status}\t%{length}\t%{payload}'

# Only anomalous lines, CSV-ish, for a spreadsheet
bp fuzz --id 7 --pos 'body:role' --payloads roles.txt --anomalous-only \
        -w '%{index},%{status},%{anomalous},%{payload}'

# Collaborator: print just the host you paste into a target
bp collaborator new -w '%{payload}'        # one host, no decoration

# History: build replay one-liners for a shell loop
bp history --host t.com -w 'bp history replay --id %{id}  # %{method} %{url}'

# Scanner: severity + url, ready to grep
bp scanner issues SCAN_ID -w '%{severity}\t%{url}\t%{name}'
```

---

## 4 · Agent-mode (AX) contract

This is the contract an AI agent (or `bb-fetch`-style harness) relies on. It is the reason `json` is
the default when piped (A4).

### 4.1 · Activation

- **[CRITICAL][BLOCKS:high] AX-ACTIVATE** Agent mode is active when ANY of: `BP_AGENT=1` in env,
  or `--format json` explicit. _(v1.1 — TTY-detection trigger not yet implemented; until then, always
  pass `--format json` explicitly for agent/pipe use.)_ In agent mode the default format is `json`
  and human niceties (color, spinners, progress bars) are **fully suppressed** (they would corrupt
  stdout *and* stderr parsing).

### 4.2 · The stable schema guarantee

- **[CRITICAL][BLOCKS:critical] AX-SCHEMA** For a given command + version, JSON output is:
  - **NDJSON**, one record per line, no outer array (F-JSON).
  - **Fixed field set & order** = catalog default order (§2) when `--fields` is absent.
  - **All fields present every time** (`encodeDefaults` parity) — agents may rely on key presence;
    missing-data is `null`, never an absent key.
  - **Types fixed** per catalog. `status` is always an int; `anomalous` always bool-or-null.
  - **Additive evolution only.** A new release may append a new trailing field; it may never rename,
    retype, or reorder existing fields without a major version bump. `bp --schema fuzz-results`
    prints the JSON Schema for that record type for agent self-description.
- **[HIGH][BLOCKS:low] AX-VERSION** Every command accepts `--schema-version` and `bp version
  --format json` reports `{"bp":"x.y.z","schema":"N"}`. Agents pin `schema`.

### 4.3 · Token-efficiency rules (anti-dump)

- **[HIGH][BLOCKS:high] AX-CAP-ROWS** Multi-record output is **capped at 50 records by default**
  (`--limit`, `--limit 0` = no cap). When capped, a `_meta` line (if `--meta`) reports
  `{"total":N,"shown":50,"truncated":true}`; without `--meta` the cap is silent on stdout but noted
  on **stderr** (`shown 50/318 — use --limit 0 for all`). Agents never get a surprise 10k-line dump.
- **[HIGH][BLOCKS:high] AX-CAP-BODY** Response bodies are **never** in default output. `bodyPreview`
  is capped at **256 bytes** (configurable `--preview-bytes`), control chars escaped. Full body only
  via explicit `--fields resBody` / `bp history get <id> --format raw` / `--index N --format raw`.
- **[HIGH][BLOCKS:none] AX-SUMMARIZE** For large fuzz sets, `bp fuzz summary <attackId>` emits a
  single JSON object aggregating by status code + anomaly count, instead of N rows:
  ```
  {"attackId":"a1b2c3d4","total":318,"byStatus":{"200":300,"403":15,"500":3},"anomalous":3,"slowest":620}
  ```
  This is the **recommended first call** for an agent triaging a big attack — cheap, then drill in
  with `--anomalous-only`.
- **[MEDIUM][BLOCKS:none] AX-NO-PRETTY** Never pretty-print in agent mode (compact NDJSON). A human
  wanting pretty JSON uses `bp ... --format json --pretty` (TTY only; `--pretty` is ignored/declined
  in agent mode to protect line-parsers).

### 4.4 · How an agent parses `bp` (recommended contract)

```
1. Pass --format json (v1 does not auto-detect pipes; TTY-aware default is v1.1).
2. Read stdout line by line; json.loads(line) → one record. Stop early if satisfied.
3. On empty stdout + exit 0 → zero records (valid empty result).
4. On exit ≠ 0 → read the SINGLE json object on stderr: {"error":{"code":..,"message":..}} (§5).
5. For big sets: call `bp fuzz summary` first, then `--anomalous-only`, then `--index N` for raw.
6. Pin schema via `bp version --format json` → schema integer.
```

- **[HIGH][BLOCKS:high] AX-STDERR-JSON** In agent mode, **errors on stderr are also JSON** (single
  object, §5) — so an agent has one parser for both streams. In human mode, stderr errors are plain
  prose. Detection: `BP_AGENT=1` or explicit `--format json` (A4; TTY-detection not yet in v1).

### 4.5 · Determinism for agents

- **[HIGH][BLOCKS:none] AX-DETERMIN** Ordering is fixed: fuzz results by `index` asc; history by
  `id` desc (matches server, SPEC §6.13); issues by severity rank then confidence; ledger by `id`
  desc. Timing fields (`time`, `timestamp`) are the only non-deterministic values and are clearly
  scoped so a diff-based agent can ignore them.

---

## 5 · Exit codes, error routing, and `--quiet` interaction

### 5.1 · Stream routing

- **[CRITICAL][BLOCKS:high] E-STREAMS** **stdout = data only.** **stderr = everything else**
  (errors, warnings, Pro/Community degradation, progress, the AX truncation note). Re-statement of
  A2 with teeth: a command that fails prints **nothing** to stdout (no partial record, no `null`),
  so `$(bp ... )` capture is always clean.

### 5.2 · Error object shape

- **[HIGH][BLOCKS:low] E-SHAPE** The server's `ApiError{code,message}` (SPEC §8) is surfaced. In
  agent mode, stderr carries exactly one line:
  ```
  {"error":{"code":"INVALID_REQUEST","message":"exactly one of request/requestId required","httpStatus":400,"burpOp":"POST /repeater/send"}}
  ```
  `code` is the server code (`INVALID_REQUEST` / `SERVICE_UNAVAILABLE` / `INTERNAL_ERROR` /
  `INVALID_PARAM`) or a `bp`-side code (`BP_USAGE`, `BP_CONN_REFUSED`, `BP_PRO_REQUIRED`,
  `BP_DB_UNAVAILABLE`). In human mode it is one prose line: `error: exactly one of request/requestId
  required (INVALID_REQUEST)`.

### 5.3 · Exit code table

- **[CRITICAL][BLOCKS:high] E-EXIT** Exit codes are the shipped set, defined in `CLI.md §Output`
  and implemented in `cliutil.py`. The earlier `sysexits.h` mapping (codes 64/65/68/69/70/76) was
  superseded — agents and scripts must branch on the table below, not on `sysexits` values.

| Exit | Meaning | When |
|---|---|---|
| `0` | success | request ok (even if 0 records, even if HTTP 4xx/5xx *target* response — see E-TARGET) |
| `1` | generic error | uncategorized `bp` error |
| `2` | usage error | bad flag combo, unknown field/token |
| `3` | `CONNECTION_REFUSED` | `:8089` not listening — Burp/extension down |
| `4` | `PRO_REQUIRED` | Pro-only feature (collaborator, scanner start) used on Community |

- **[HIGH][BLOCKS:high] E-TARGET** Critical distinction: a **target** HTTP 403/500 (the thing you
  fuzzed responded 500) is a **successful `bp` operation** → exit `0`, `status:500` in the record.
  Exit codes describe whether **`bp` + Burp** worked, never the target's HTTP status. An agent reads
  the target status from the `status` field, not the exit code. (This is why `--fail-on-anomalous`
  is opt-in, for the narrow scripting case that wants a non-zero gate.)

### 5.4 · `--quiet` × errors

- **[HIGH][BLOCKS:low] E-QUIET** `--quiet` affects **stdout only**. Errors still go to **stderr**
  and still set the exit code. So:
  - Success → essential value(s) on stdout, exit 0.
  - Failure → **nothing** on stdout, error on stderr (prose in human mode, JSON in agent mode),
    exit per §5.3.
  - This makes `V=$(bp scope check --url X --quiet) || handle_error` correct: on failure `$V` is
    empty and the `||` branch fires.
- **[MEDIUM][BLOCKS:none] E-QUIET-EMPTY** (re OPEN-Q1) A successful op that yields an empty
  essential value prints an empty line, exit `0` by default. `--strict` upgrades empty-essential to
  exit `1`.

---

## 6 · Composition with the Run Ledger

### 6.1 · Every shown record is recorded

- **[MEDIUM][BLOCKS:none] L-RECORD** Per SPEC §9, every `bp` operation that hits `:8089` writes one
  **LedgerEntry** to `~/.bp/` SQLite, **independent of `--format`** (A7). The ledger stores the
  *operation* (command line, target, burpOp, request/response refs, status, timestamp, tag) — not
  the rendered stdout. Changing `--format`/`--fields`/`-w` never changes what is recorded; it only
  changes what you *see*. This is the `bp`-vs-`curl` differentiator (SPEC §4 C4).
- **[MEDIUM][BLOCKS:none] L-GRAIN** Granularity: **one ledger entry per `bp` invocation**, not per
  result row. A fuzz of 318 payloads = **one** entry whose `responseRef` points to the stored result
  set (so `bp show <id>` can re-render any format later). This keeps the ledger compact and ISO-
  auditable without exploding on large attacks.

### 6.2 · `--tag` and `--no-ledger`

- **[MEDIUM][BLOCKS:none] L-TAG** `--tag NAME` writes `NAME` into the entry's `tag`/`name` field at
  record time (user label, SPEC §9). Equivalent to a later `bp tag <id> NAME`. The tag is
  **metadata only** — it never appears in stdout records unless the user selects `--fields tag`
  (ledger family) — so `--tag` never pollutes data output.
- **[HIGH][BLOCKS:none] L-NOLEDGER** `--no-ledger` suppresses the ledger write for that one
  invocation. Use for dry-runs, health polls, or when an entry would be noise. It does **not** affect
  stdout/stderr/exit at all. A `--no-ledger` op leaves **zero** trace in `~/.bp/` (verifiable: ledger
  count unchanged).
- **[LOW][BLOCKS:none] L-READONLY** Read-only `bp` subcommands that don't touch `:8089`
  (`bp ledger list`, `bp show`, `bp version`, `bp --schema`) never write a ledger entry regardless of
  `--no-ledger` (nothing to record). `bp health` records by default (it *is* a `:8089` op) but is a
  common `--no-ledger` candidate.

### 6.3 · Re-rendering from the ledger

- **[MEDIUM][BLOCKS:none] L-REPLAY-FMT** Because the ledger stores the raw response refs, **all four
  formats + `--fields` + `-w` work identically on `bp show <id>`** as they did on the live command.
  `bp show 17 --format json`, `bp show 17 -w '%{status} %{payload}'` re-render the stored result set.
  This closes the loop: the output contract is uniform whether data is live or replayed from the
  ledger — the same parser, same schema, same tokens. **[HIGH][BLOCKS:none]**

### 6.4 · Ledger banner discipline

- **[HIGH][BLOCKS:none] L-BANNER** When an op is recorded, `bp` may emit a one-line confirmation
  (`recorded as ledger #17 [tag: ssrf-probe]`) — but **only to stderr**, never stdout, so it never
  contaminates data or `-w` output. With `--no-ledger`, no banner. In agent mode the banner is
  suppressed entirely (it's noise for a parser; the agent can `bp ledger list` if it wants the id).

---

## 7 · Cross-cutting requirements summary (criticality-grouped)

### CRITICAL

- [CRITICAL][BLOCKS:critical] A1 — one output model (4 flags) on every command.
- [CRITICAL][BLOCKS:critical] F-JSON / AX-SCHEMA — NDJSON, frozen field order, additive-only.
- [CRITICAL][BLOCKS:critical] R-FIELDS catalog is source-grounded (SPEC §6/§8), no invented fields.
- [CRITICAL][BLOCKS:high] A2 / E-STREAMS — data→stdout, errors→stderr, fail = empty stdout.
- [CRITICAL][BLOCKS:high] A3 — stable agent schema, additive evolution only.
- [CRITICAL][BLOCKS:high] F-QUIET — single essential value per family.
- [CRITICAL][BLOCKS:high] R-WTOK — full 11-token `-w` grammar (see §3.1 for the headline example).
- [CRITICAL][BLOCKS:high] E-EXIT / E-TARGET — shipped exit codes (0/1/2/3/4); target HTTP status ≠ exit code.
- [CRITICAL][BLOCKS:high] AX-ACTIVATE — agent mode = non-TTY/BP_AGENT/explicit json.

### HIGH

- [HIGH][BLOCKS:high] A4 — context-aware default format (table TTY / json piped) _(v1.1 — not yet implemented; default is `table` for all streams)_.
- [HIGH][BLOCKS:high] AX-CAP-ROWS / AX-CAP-BODY — anti-dump caps (50 rows, 256-byte preview).
- [HIGH][BLOCKS:high] R-HIST-404 / R-COLLAB-PRO — degrade gracefully, exit 1 (R-HIST-404) / exit 4 PRO_REQUIRED (R-COLLAB-PRO), stderr.
- [HIGH][BLOCKS:high] E-TARGET — exit code reflects bp+Burp, not target response.
- [HIGH][BLOCKS:low] F-TABLE / F-RAW / R-RAW-SINGLE — human + raw-bytes shapes.
- [HIGH][BLOCKS:low] R-WESC / R-WSAFE — escaping + control-byte safety in `-w`.
- [HIGH][BLOCKS:none] A5 / AX-SUMMARIZE — never dump bodies; summary-first for big sets.
- [HIGH][BLOCKS:none] R-ANOM — `anomalous` only meaningful in quick-fuzz; else null.
- [HIGH][BLOCKS:none] L-REPLAY-FMT / L-NOLEDGER — uniform re-render; clean opt-out.

### MEDIUM

- [MEDIUM][BLOCKS:none] L-RECORD / L-GRAIN / L-TAG — one entry per invocation, format-independent.
- [MEDIUM][BLOCKS:none] AX-NO-PRETTY — compact in agent mode; `--pretty` TTY-only.
- [MEDIUM][BLOCKS:none] R-WUNKNOWN — unknown token fails loud.
- [MEDIUM][BLOCKS:none] OPEN-Q1 / E-QUIET-EMPTY — empty-essential exit policy (open decision, see §8).

### LOW (convergence tail)

- [LOW][BLOCKS:none] L-READONLY — read-only subcommands never record.
- [LOW][BLOCKS:none] `--meta`, `--pretty`, `--strict`, `--raw-w`, `--raw-part` ergonomics.

---

## 8 · Open decisions (output-specific)

| # | Decision | Default proposed | State |
|---|---|---|---|
| **O1** | Empty essential value under `--quiet` → exit 0 or 1? | exit 0 (record exists = success); `--strict` for 1 | open |
| **O2** | `raw` on multi-record: hard error vs concatenate w/ separators? | hard error (R-RAW-SINGLE), require `--index` | open |
| **O3** | `--fail-on-anomalous` exit 2 — default on or opt-in? | opt-in (E-TARGET keeps exit clean) | open |
| **O4** | Default row cap (50) and preview bytes (256). | 50 / 256, both flag-overridable | open |
| **O5** | `%{anomalous}` for non-quick-fuzz results: empty vs literal `false`? | empty (R-ANOM) — don't fake a signal the server didn't set | open |
| **O6** | Should `bp health` default to `--no-ledger`? | no (it's a real op); document as common opt-out | open |

---

> Grounded against `docs/SPEC.md` §5 (grammar), §6.2/§6.4/§6.5/§6.6/§6.13 (result models),
> §8 (Kotlin serialization contract), §9 (Run Ledger).
