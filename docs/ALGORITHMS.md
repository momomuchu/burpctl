# `bp` — Load-bearing algorithms (spec, not code)

> Implementation spec, language-neutral (pseudocode). The 2 algorithms implemented by `bp`.
> Reference: `CLI.md` (`--pos` grammar), `SPEC.md §6.4` (Intruder models).
> Actual REST model: `PayloadPosition{start:Int, end:Int, name:String}` (all required),
> `CreateAttackRequest{positions:[…], payloads:Map<name,[String]>, attackType:String}`.
>
> **v2.0.0 live qualification (2026-09-04):** A1/A2 describe the intended expansion model, not a
> claim of end-to-end byte fidelity. Against real Burp 2026.3.3, the structured bridge added twelve
> browser headers (D38), collapsed an unrelated duplicate Cookie field (D39), and corrupted a
> multibyte body (D40). Extra named lists were silently ignored in sniper/battering-ram (D41), payload
> files could not represent empty/space/embedded-LF values (D43), NUL bodies were rejected (D44), and
> a captured fragment-bearing URL could not be normalized (D45). Unequal pitchfork lists stopping at
> the shortest list is intentional and remains the contract (D42 rejected). No repair is treated as
> verified until these live reproductions pass after redeployment.

---

## A1 · `--pos` resolver: semantic selector → byte-offset

**Contract:** `resolvePos(rawRequest: bytes, selector: string) -> PayloadPosition{start,end,name}`
where `start`/`end` are **byte offsets** into `rawRequest` (`end` exclusive), and the slice
`rawRequest[start:end]` = **the value** to fuzz. Multiple `--pos` → list sorted by `start`.

**Pre-parse** (once per request) — HTTP/1.1 split:
```
request-line = METHOD SP request-target SP HTTP-version CRLF
headers      = ( field-name ":" OWS field-value OWS CRLF )*
CRLF                       # blank line
body         = remaining octets
```
Store offsets of: request-target, each header (name+value), body start.
Assumes CRLF; if LF-only is detected, adjust line-ending length (1 vs 2).

**Per selector type:**

| Selector | Resolution | `name` |
|---|---|---|
| `offset:A-B` | `{A, B}` as-is. Validate `0 ≤ A < B ≤ len`. | `offset:A-B` |
| `header:NAME` | header where `field-name` == NAME (**case-insensitive**). Span = `field-value` after OWS, up to end of value (before CRLF). **1st occurrence** (see rule below). | `header:NAME` |
| `cookie:NAME` | within the `Cookie:` header value, find token `NAME=`, span = after `=` up to the next `;` or end of value. | `cookie:NAME` |
| `query:NAME` | within `request-target` after `?`, find `NAME=`, span = up to the next `&` or end. Span = **raw encoded value**. | `query:NAME` |
| `path:INDEX` | path = `request-target` before `?`, segments separated by `/`. **1-based** (`path:1` = 1st segment after the leading `/`). Span = segment bytes. | `path:INDEX` |
| `body:FIELD` | dispatch on `Content-Type` (see below). | `body:FIELD` |

**`body:FIELD` by content-type:**
- `application/x-www-form-urlencoded` → `FIELD=value` in the body, span = value up to `&`/end.
- `application/json` → value of key `FIELD` (top-level; **extension**: dot-path `body:a.b`). String → span = **inside the quotes**; number/bool/null → the literal.
- `multipart/form-data` → part `name="FIELD"`, span = part body. *(supported v2)*
- other → error `UNSUPPORTED_BODY`.

**Rules & errors:**
- Selector not found → `POS_NOT_FOUND` (exit 2).
- Repeated headers/params → **1st occurrence by default**; `header:NAME[k]` (index) as extension.
- 2 positions that **overlap** → `POS_OVERLAP` (exit 2) (otherwise A2 expansion breaks).
- Offsets are **bytes** (not characters) — watch out for multi-byte UTF-8.

**RED test cases (TDD) — fixture request:**
```
POST /api/v2/users/42?redirect=/home HTTP/1.1\r\n
Host: t.example.com\r\n
Authorization: Bearer abc123\r\n
Cookie: sid=XYZ; role=user\r\n
Content-Type: application/json\r\n
\r\n
{"id":42,"name":"bob"}
```
| Selector | Expected (`rawRequest[start:end]`) |
|---|---|
| `header:Authorization` | `Bearer abc123` |
| `cookie:role` | `user` |
| `query:redirect` | `/home` |
| `path:3` | `42` (segments: api/v2/users/42 → 1=api,2=v2,3=users… **verify convention**) |
| `body:id` | `42` (JSON literal) |
| `body:name` | `bob` (inside quotes) |
| `offset:0-4` | `POST` |
| `header:Nope` | error `POS_NOT_FOUND` |

> ⚠️ The `path:INDEX` convention (does it include the empty 1st segment before `/api`?) must be
> **locked in** by a test: recommendation `path:1`=`api` (non-empty segments).

---

## A2 · Attack expansion (matrix-style, client-side)

**Source verdict (`IntruderService.kt`, verified 2026-06-16):** the extension's intruder is
**unusable for real fuzzing** — `executeAttack()` **ignores `attackType`**, only uses
**the 1st position** (`positions.firstOrNull()`), substitutes **by NAME** (regex template/query/body/
header, not by byte-offset), and flattens all payloads into sniper. No battering-ram, no
pitchfork, no cluster-bomb, no multi-position. → **`bp` handles the ENTIRE attack client-side**,
for **all 4 types including sniper**: A1 resolves offsets, A2 expands + substitutes (precise
byte-offset) + fires each request via `POST /repeater/send`. The native `/intruder/attack/create`
is **not** used for fuzzing (exposed at most as a passthrough). The only native path that works
is `/intruder/quick-fuzz` (sniper 1-param, by name, with baseline) — `bp` can wrap it as a
shortcut, but the real engine = A1+A2 client-side.

**Contract:** `expand(base: bytes, positions: [Pos], payloads: Map<name,[String]>, type) -> [ConcreteRequest]`

**Substitution primitive (the critical correctness point):**
```
applySubs(base, subs: [{start, end, payload}]) -> bytes:
    # subs do not overlap (guaranteed by A1 POS_OVERLAP)
    sort subs by start DESCENDING          # ← right→left, otherwise offsets shift
    out = base
    for sub in subs:
        out = out[0:sub.start] + sub.payload + out[sub.end:]
    if any substitution touches the body:
        recalculate Content-Length = byteLength(body after the blank line)  # on out
        keep one Content-Length field; collapse duplicates
    return out
```
> **Transport boundary:** byte-offset precision describes this substitution, not the final wire
> message. `bp` converts the result to structured method/URL/headers/body data and the REST
> extension asks Montoya to build and send it. Body substitution therefore cannot preserve
> conflicting length fields, transfer-coding/trailers, request-line HTTP version, or non-UTF-8 body
> bytes. `bp send` and `bp fuzz` are not raw-framing transports and must not be used where exact
> framing is the experiment.
>
> **Why right→left:** substituting a value of different length shifts all offsets *after* it.
> By applying from the largest `start` to the smallest, offsets not yet processed remain valid.
> This is THE classic bug to avoid.

**Combination generators** (positions `p_1..p_n`, sets `s_1..s_n`):

| `type` | Sets | Generation | # requests |
|---|---|---|---|
| `sniper` | either one shared `S`, or one named `s_k` per position | shared form: for each `p_k`, each `v∈S`; named form: for each `p_k`, each `v∈s_k`; only one position changes per shot | shared: `n × |S|`; named: `Σ|s_k|` |
| `battering-ram` | exactly 1 shared set `S` | for each `v∈S`: subs=`[{p_k,v} ∀k]` (same payload everywhere); more than one supplied list is rejected before any send | `|S|` |
| `pitchfork` | `s_k`/position | `m=min(|s_k|)`; for `i∈0..m-1`: subs=`[{p_k, s_k[i]} ∀k]` | `m` |
| `cluster-bomb` | `s_k`/position | for each tuple ∈ `product(s_1,…,s_n)`: subs=`[{p_k, tuple[k]} ∀k]` | `∏|s_k|` |

The named sniper form is additive: existing one-set callers retain the shared-set behavior. For two
positions with list lengths 2 and 3, named sniper emits **5** shots, pitchfork emits **2**, and
cluster-bomb emits **6**; battering-ram rejects the two-list plan because it has exactly one shared set.

**Payload-file representations (2.1.0 contract; live verification pending):**

- A file without a magic header retains the legacy line-oriented behavior: each nonblank line is one
  payload, an optional CR before LF is removed, and empty/whitespace-only lines are skipped. This form
  cannot represent an empty, whitespace-only, or embedded-line-break payload.
- A byte-safe file starts with the exact first line `#!bp-payloads-json-v1`, then a UTF-8 JSON array.
  Each array element is either a JSON string (encoded to UTF-8, so `""`, `" "`, `"A\\nB"`, and
  `"\\u0000"` are distinct payloads) or exactly `{ "b64": "..." }` for arbitrary bytes. Invalid JSON,
  a non-array document, malformed Base64, or any other element shape is a usage error before sending.
- The magic-gated form is additive; existing legacy payload files keep their prior nonblank-line
  behavior. This documents the repair for D43/D44 without pretending the v2.0.0 live reproduction has
  already passed.

**Firing + baseline + anomaly (intended contract; v2.0.0 deviations above):**
1. Expand, convert through the structured REST bridge, and validate every `ConcreteRequest` without
   retaining the whole prepared corpus;
   an empty/invalid plan returns a usage error before any target send (and an empty selector list
   before any REST call).
2. Fire the unmodified `base` once and emit that attempted control first as
   `{index:-1, payloads:[], baseline:true, anomalous:false, status, length, duration_ms, error,
   error_code}`.
3. For each `ConcreteRequest`, `POST /repeater/send` and emit a result with `baseline:false`.
4. A successful payload is anomalous when `statusCode ≠ status0` or `|length − len0|` exceeds the
   threshold. A payload send error emits `status:0`, `length:0`, `anomalous:false`, `error`, and
   `error_code`: no target response exists to compare, so infrastructure failure is not an anomaly.
   A baseline send error emits its baseline error row and stops before payload sends.
5. `--anomalous-only` retains the baseline and every error row, filtering only successful ordinary
   payload rows; error rows make the command exit in the typed stable category after rendering all
   attempted-shot evidence (`CONNECTION_REFUSED`/`TRANSPORT_ERROR` remain exit 3; generic errors 1).
   Connection/transport and invalid-response errors stop the remaining prepared corpus after their
   triggering row; per-shot server failures may continue. JSON output gets a JSON stderr summary.

The fresh baseline prevents a stale history response from inverting anomaly classification after
session, state, or target drift. Every attempted target send has one returned row: N payloads produce
N+1 attempts and N+1 rows when all run, with the extra row explicitly identified as the baseline.
Response `length` is UTF-8 body bytes, not the host language's character count.

**Guards (config, non-blocking by default — ADR-0007):**
- Total count `> threshold` (recommendation 10000) → **warn** (or confirm if `--confirm`), not a hard block.
- `--enforce-scope warn|block|off`: if enabled, check host of `base` before firing.

**Worked example — "2 headers + 1 cookie":**
```
bp fuzz 42 --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=a.txt(2) \
           --pos 'header:X-Real-IP'       --payloads X-Real-IP=a.txt(2) \
           --pos 'cookie:role'            --payloads role=b.txt(3) \
           --type cluster-bomb
→ resolvePos × 3 → 3 Pos (sorted offsets, non-overlapping)
→ product 2×2×3 = 12 ConcreteRequest, each applySubs(right→left) + Content-Length if body
→ 13 shots /repeater/send → 13 FuzzResult rows: 1 explicit fresh baseline + 12 payload rows
```

**RED test cases (TDD):**
- `applySubs`: 2 subs of different lengths → verify that the lower offset remains correct after splicing the upper one (right→left anti-regression).
- `applySubs` body → `Content-Length` recalculated == new body length.
- `cluster-bomb` [a,b]×[1,2] → 4 requests, exact combinations `{a,1},{a,2},{b,1},{b,2}`.
- `pitchfork` sets of sizes 3 and 2 → 2 requests (min), paired by index.
- `sniper` 2 positions, set of 3 → 6 requests, only one position modified at a time.
- `battering-ram` set of 3, 2 positions → 3 requests, same payload at both positions.

---

## Status

`[CRITICAL][BLOCKS:critical]` A1 + A2 are the **core of the driver** — without them, no fuzzing.
Conventions locked in by tests: `path:INDEX` (base), anomaly threshold, repeated header occurrence.
