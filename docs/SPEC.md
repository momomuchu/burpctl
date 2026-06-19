# `bp` — Product Spec

Canonical spec rebuilt from source
(`RestServer.kt` + `routes/*.kt`).
Enumeration: **13 groups · 69 endpoints ·
verdict COMPLETE**.
Generated 2026-06-16.

---

## Table of Contents

1. Mission
2. Source-of-truth
3. Name
4. Components
5. `--pos` grammar
6. API — 13 groups / 69 endpoints
7. Community vs Pro
8. Kotlin contract (serialization)
9. C4 Run Ledger
10. Test architecture (TDD)
11. DDD
12. Coverage roadmap
13. Resolved decisions
14. Acceptance criteria

---

## 1 · Mission

`bp` (alias `burpctl`) is a **standalone POSIX
CLI** that drives Burp Suite through its local
REST API at `:8089`. It provides **flexible
fuzzing** (`--pos` grammar with multi-position +
4 attack-types) and **observability** for every
operation. Target: a distributable user-facing
product, not an internal tool.
Default config: `BURP_REST_URL =
http://127.0.0.1:8089`.

---

## 2 · Source-of-truth

The 3 docs in the repo contradict each other. **Only
one tells the truth.**

| Doc | Verdict |
|---|---|
| `spec.md` | **OUTDATED** — port 9876, Python, MCP wrapper. Describes the pre-rewrite architecture. |
| `README.md` | **PARTIAL** — omits session/scan/utils/history; references ghost routes. |
| `RestServer.kt` | **TRUTH** — the actual `configureRouting()` wiring. |

**Consequence:** the spec is rebuilt from
source, never from a doc. `spec.md` will be
marked deprecated (archived, not deleted).

### Critical docMismatches

- **CRITICAL** — `spec.md` states port **9876**;
  the actual port is **8089**. Any client built
  against `spec.md` hits the wrong port and fails.
- **HIGH** — `spec.md` describes a
  Python/SSE/**MCP PortSwigger** wrapper; the actual
  implementation is a flat **Kotlin/Ktor REST**
  extension (no SSE, no MCP).
- **HIGH** — `README` lists `/sequencer/*`,
  `/comparer/*`, `/logger/*`, `/search` as
  active: **none are wired** (ghost endpoints).
- **MEDIUM** — `README` omits
  `/session/*`, `/scan/*`, `/utils/*` entirely (3
  groups that are actually functional).
- **LOW** — the OpenAPI spec embedded at
  `/docs` declares **0.2.0** while
  `/health` and `/version` return **0.1.0**;
  it also omits several real endpoints.

---

## 3 · Name

**`bp`** — 2 letters, unoccupied, memorable.
**Alias: `burpctl`** (`*ctl` convention:
kubectl / systemctl).

| Rejected | Reason |
|---|---|
| `burp` | collision with an existing backup tool. |
| `bx` | already taken (Ruby / bundler context). |

`bp` is the canonical name; `burpctl` is the alias.

---

## 4 · Components

| # | Component | Status |
|---|---|---|
| **C1** | API spec (this source-grounded enumeration). | priority |
| **C2** | Standalone CLI `bp` — DX + AX, core = `--pos` grammar. | priority |
| **C4** | **Run Ledger** — every operation stored in a local DB, named, taggable, verifiable (§9). | shipped |
| **W** | SDD / TDD / DDD / spec-as-contract methodology. | cross-cutting |

> **C4 = the differentiating value vs `curl`.** Without
> a ledger, `bp` is just another HTTP wrapper.
> With it, it becomes a **traceable / ISO-grade** tool.

---

## 5 · `--pos` grammar

Load-bearing core of the CLI. Mark any
byte-range: header / cookie / body /
query / path, multi-position, 4 attack-types.

### Selectors (target)

| Selector | Target |
|---|---|
| `header:NAME` | a header value |
| `cookie:NAME` | a cookie value |
| `body:FIELD` | form field / JSON field |
| `query:NAME` | URL parameter |
| `path:INDEX` | path segment |
| `offset:START-END` | raw byte-range |

### Attack-types (Intruder)

| Type | Combination |
|---|---|
| `sniper` | 1 payload set; each position **in turn** (only 1 active at a time). |
| `battering-ram` | **same** payload injected into **all** positions simultaneously. |
| `pitchfork` | N **parallel** sets: set[i] ↔ position[i], iterated in lock-step (shortest length wins). |
| `cluster-bomb` | N-dimensional **Cartesian product**: every combination of every set. |

### Matrix fuzzing (cluster-bomb)

`cluster-bomb` = **Cartesian product**. With
2 headers + 1 cookie, there is a **3D matrix**:
`a × b × c` requests.

```
bp fuzz --id 42 \
  --pos 'header:X-Forwarded-For' \
  --pos 'header:X-Real-IP' \
  --pos 'cookie:role' \
  --type cluster-bomb \
  --payloads X-Forwarded-For=ips.txt \
  --payloads X-Real-IP=ips.txt \
  --payloads role=roles.txt \
  --throttle-ms 500 --anomalous-only
```

If `ips.txt`=a lines, `ips.txt`=b, `roles.txt`=c
→ **a × b × c** requests sent.

### Key note — offset resolution

> REST positions are **byte-offsets**:
> `PayloadPosition { start:Int, end:Int,
> name:String }` (all 3 required, no defaults).
> The API accepts **only** raw offsets,
> not parameter names.
>
> **Therefore `bp` MUST RESOLVE** semantic selectors
> (`header:X`, `body:f`…) **into
> byte-ranges** by parsing the captured base request.
> This is the CLI's central task.

**Current API Intruder implementation caveats**
(to surface to the user):

- Only `positions[0].name` is consumed in
  sniper mode.
- All `payloads` values
  (`Map<String,List<String>>`) are **flattened**
  (`values.flatten()`) into a single list — map keys
  have no functional role.
- Only `sniper` is implemented server-side;
  the other 3 types are **accepted but
  execute sniper**. `battering-ram` /
  `pitchfork` / `cluster-bomb` must be
  implemented **client-side by `bp`** (matrix
  expansion + multiple sends) or by a later Kotlin
  extension.
- `options.throttleMs` active;
  `followRedirects` / `maxRetries` accepted but
  **not wired**.

---

## 6 · API — 13 groups / 69 endpoints

Adverse critical verdict: **COMPLETE** (69
source handlers = 69 enumerated, 0 missed).
Source `routes/*.kt` is the sole authority —
no invented endpoints.

Legend: **P** = Pro required · **C** = Community
OK · **stub** = dummy handler.

---

### 6.1 · health `/` — 3 endpoints · C

Pure server introspection. No Montoya, no
Pro, no DB. Paths without prefix.

| Method | Path | Pro | Request model | Hunter usage |
|---|---|---|---|---|
| GET | `/health` | C | — | poll at session start: confirms extension is up + uptime. |
| GET | `/version` | C | — | confirms the deployed version. |
| GET | `/docs` | C | — | fetches the embedded OpenAPI spec (⚠ incomplete, declares 0.2.0). |

- **pre/post/err**: Ktor server listening;
  unconditional HTTP 200; `INTERNAL_ERROR`
  500 only on unexpected Throwable.
- Responses: `ApiResponse<HealthResponse>`
  {status:'ok', version:'0.1.0', uptime:Long,
  burpVersion:null}. `/docs` = raw JSON (**not**
  wrapped, `respondText()`).
- **Flag**: `burpVersion` is never populated.

---

### 6.2 · proxy `/proxy` — 8 endpoints · C

⚠ **4 of the 8 are stubs / hardcoded.**

| Method | Path | Pro | Request model (fields · Kotlin types) | Hunter usage |
|---|---|---|---|---|
| GET | `/proxy/history` | C | query: `limit:Int?`, `offset:Int?=0`, `host:String?` | dumps history filtered by host + paginated. |
| GET | `/proxy/history/{id}` | C | path: `id:Int` (toIntOrNull) | single entry by absolute index. |
| GET | `/proxy/websocket/history` | C | — | inspect WS messages (direction + payload). |
| GET | `/proxy/intercept` | C | — **stub** | always `{enabled:false}` — unreliable. |
| POST | `/proxy/intercept/enable` | C | — | enables intercept before manual navigation. |
| POST | `/proxy/intercept/disable` | C | — | disables after inspection. |
| POST | `/proxy/intercept/forward` | C | — **stub** | `{forwarded:true}` no-op. |
| POST | `/proxy/intercept/drop` | C | — **stub** | `{dropped:true}` no-op. |

- **Key contract**: `ProxyHistoryResponse.total`
  = filtered size before pagination; `id` =
  `start+idx` (offset-relative → **unstable**
  across offsets). Use `/{id}` (absolute index)
  for stability.
- **err**: `/{id}` non-integer → `INVALID_PARAM`;
  out of bounds → 500 Ktor (unmapped).
- **Flags**: `listenerInterface`, `clientIp`,
  `timestamp` (HTTP) always null. WS
  `timestamp` = `Instant.now()` at call time (not
  capture time). `forward`/`drop` **absent from
  `/docs`**.

---

### 6.3 · repeater `/repeater` — 3 endpoints · C · **fuzz-critical**

`/send` + `/send/batch` drive
`http().sendRequest()` (HTTP engine, **not**
the UI). `/tab/create` opens a UI tab without
traffic. DB optional (row silently skipped if init fails).

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| POST | `/repeater/send` | C | `SendRequest` { request:HttpRequestData?=null, requestId:Int?=null, modifications:RequestModifications?=null } — **exactly one** of request/requestId | replay/craft with on-the-fly overrides; returns req+resp+timing. |
| POST | `/repeater/send/batch` | C | `BatchSendRequest` { requests:List\<SendRequest\> } | multiple requests in one call (sequential). |
| POST | `/repeater/tab/create` | C | `CreateTabRequest` { name:String?=null, request:HttpRequestData?=null, requestId:Int?=null } | pushes a request into the Repeater UI. |

- **pre/post/err**: `/send` requires exactly one of
  request/requestId; history row (source=
  'repeater') + sitemap upsert if DB.
  `INVALID_REQUEST` 400 (neither/both /
  out of bounds / malformed JSON),
  `SERVICE_UNAVAILABLE` 503, `INTERNAL_ERROR`
  500. `/send/batch` is strictly sequential;
  failure on item N → **total abort**, no partial
  result. `/tab/create` no traffic, no
  DB; if both request AND requestId are null → **silent
  fallback** to `https://example.com`.

#### fuzzModels — repeater

```
SendRequest (inline + modifications) :
{ "request":{"method":"POST","url":"https://t/api",
   "headers":[{"name":"Authorization","value":"Bearer T"}],
   "body":"{...}"},
  "requestId":null,
  "modifications":{"headers":{"X-Role":"admin"},
   "body":"FUZZ","method":"POST","path":"/api?x=FUZZ"} }

SendRequest (history replay) :
{ "requestId":42, "modifications":{"body":"FUZZ"} }

RequestModifications {
  headers:Map<String,String>?  // replace (remove+add)
  body:String?                 // replaces the entire body
  method:String?               // replaces the verb
  path:String?                 // replaces the path (not the URL)
}  // 4 independent fields; only non-null fields are applied
```

> No positional markers here: repeater fuzzing
> is done via the full payload in
> `body`/`path`. **For positional fuzzing →
> Intruder.**

---

### 6.4 · intruder `/intruder` — 8 endpoints · C(limited) · **fuzz-critical**

Attack state in memory (ConcurrentHashMap,
lost on reload). `/quick-fuzz` synchronous;
`/attack/create`+`/start` async (background thread). ⚠ **Only sniper is implemented.**

> Pro: Burp Pro's Intruder is **not**
> used directly — sending is delegated to
> RepeaterService (HTTP engine). So this
> surface runs on **Community** (no Community Intruder
> throttling), but remains
> limited to sniper server-side.

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| POST | `/intruder/attack/create` | C | `CreateAttackRequest` { requestId:Int?=null, request:HttpRequestData?=null, attackType:String="sniper", positions:List\<PayloadPosition\>=[], payloads:Map\<String,List\<String\>\>={}, options:AttackOptions=() } | creates the attack, returns `attackId`. |
| POST | `/intruder/attack/{id}/start` | C | path: `id:String` | starts the background thread. |
| GET | `/intruder/attack/{id}/status` | C | path: `id:String` | polls progress 0-100 / isComplete. |
| GET | `/intruder/attack/{id}/results` | C | path `id:String`; query `offset:Int=0`, `limit:Int=0` (0=all) | inspects statusCode/length/anomalous. |
| POST | `/intruder/attack/{id}/pause` | C | path: `id:String` | cooperative pause. |
| POST | `/intruder/attack/{id}/resume` | C | path: `id:String` | resumes. |
| POST | `/intruder/attack/{id}/stop` | C | path: `id:String` | stops (no interrupt). |
| POST | `/intruder/quick-fuzz` | C | `QuickFuzzRequest` { requestId:Int?=null, request:HttpRequestData?=null, param:String (required), payloads:List\<String\> (required non-empty), options:AttackOptions=() } | synchronous 1-param fuzz + baseline + anomalous. |

- **Key contract**: `attackId:String` (8-char
  UUID); `requestId:Int` (0-based history index).
- **pre/post/err**: `create` does **not** validate
  request/requestId (validated at `/start`).
  `/start` starts a **new Thread on every
  call** → race condition if attack already running.
  `isComplete` = status ∈ {completed, stopped,
  error}. `quick-fuzz`: baseline = first result
  with `error==null`; `anomalous` if statusCode≠ OR
  |Δlength| > max(length·0.2, 20) OR
  contentType≠. 400 if param blank / payloads
  empty / neither request nor requestId.

#### fuzzModels — intruder (load-bearing `--pos`)

```
PayloadPosition { "start":42, "end":52, "name":"username" }
// start/end = offsets (Int, required, no defaults).
// name = substitution key. Only positions[0].name used in sniper.

CreateAttackRequest {
  "requestId":3,                  // OR "request" inline
  "attackType":"sniper",          // only sniper is implemented
  "positions":[{"start":42,"end":52,"name":"username"}],
  "payloads":{"set1":["admin","root","' OR 1=1--"]},
                                   // ALL values are flattened
  "options":{"followRedirects":true,"maxRetries":0,"throttleMs":100} }

QuickFuzzRequest {
  "requestId":3, "param":"q",     // param String required non-blank
  "payloads":["<script>alert(1)</script>","' OR '1'='1"],
  "options":{"throttleMs":0} }

AttackResultEntry {  // differential analysis
  index, payload, statusCode (0 on err), length, durationMs,
  error:String?, contentType:String?, bodyPreview:String?,
  anomalous:Boolean }  // anomalous only in quick-fuzz
```

**6 substitution modes** (substitutePayload):
URL `{param}` · query `?param=*` · body
`{param}` · form `param=*` · JSON
`"param":"*"` · header whose name == param
(case-insensitive).

---

### 6.5 · collaborator `/collaborator` — 4 endpoints · **P**

⚠ **Burp Suite Professional required** (Community
does not have the Collaborator API). State in memory
(lost on restart).

| Method | Path | Pro | Request model | Hunter usage |
|---|---|---|---|---|
| POST | `/collaborator/generate` | **P** | — | generates 1 OAST payload (SSRF/XXE/OOB blind). |
| POST | `/collaborator/generate/batch` | **P** | `BatchGenerateRequest` { count:Int=1 } | N distinct payloads in one call. |
| GET | `/collaborator/poll` | **P** | — | sweeps all interactions for the session. |
| GET | `/collaborator/poll/{id}` | **P** | path: `id:String` | poll scoped to a specific payload. |

- **err**: `SERVICE_UNAVAILABLE` 503 if Collaborator
  API is null (Community / server not
  configured) or client cannot be created.
- **Flags**: `interactionId == id` (local key,
  not a Burp UUID). `timestamp` =
  `Instant.now()` at poll time. Poll errors
  **silently swallowed** → `found=false`
  (HTTP 200); impossible to distinguish "unknown id"
  from "no interaction yet".
  `Interaction.type` = `.name` of Burp enum
  (DNS/HTTP/SMTP). `/generate/batch` and
  `/poll/{id}` **absent from `/docs`**.

#### fuzzModels — collaborator

```
BatchGenerateRequest { "count":<Int> }
// fuzz: 0, negatives, very large, omitted (→1), non-integer (→ deser error)
Interaction.type : "DNS" | "HTTP" | "SMTP"
```

---

### 6.6 · scanner `/scanner` — 9 endpoints · **P**

⚠ **Burp Suite Professional required** for the 3
start endpoints (crawl/audit/crawl-and-audit). State in
memory.

| Method | Path | Pro | Request model | Hunter usage |
|---|---|---|---|---|
| POST | `/scanner/crawl` | **P** | `ScanRequest` { url:String, config:ScanConfig=() } | spiders the app, maps endpoints. |
| POST | `/scanner/audit` | **P** | `ScanRequest` (⚠ url **ignored**) | active checks (LEGACY_ACTIVE) — scope = Burp scope. |
| POST | `/scanner/crawl-and-audit` | **P** | `ScanRequest` | full scan in one call. |
| GET | `/scanner/{id}/status` | **P** | path: `id:String` | issueCount (crawl/auditProgress = stub 0). |
| GET | `/scanner/{id}/issues` | **P** | path: `id:String` | list of vulns (name/url/severity/confidence). |
| POST | `/scanner/{id}/pause` | **P** | path: `id:String` — **stub** | does NOT pause (returns status). |
| POST | `/scanner/{id}/resume` | **P** | path: `id:String` — **stub** | resumes nothing. |
| POST | `/scanner/{id}/stop` | **P** | path: `id:String` | removes from map; **does NOT stop** the Burp scan. |
| GET | `/scanner/issue-definitions` | C | — | issue definitions from the sitemap (graceful degradation). |

- **err**: `IllegalStateException` 500 on
  Community (explicit message "requires Burp
  Suite Professional"). Many exceptions
  **silently swallowed** → HTTP 200 with `status='error'`
  or empty list.
- **Flags**: `audit` does **not** use `url`;
  `pause`/`resume` are stubs; `stop` decouples
  tracking from execution (the Burp task continues);
  `crawl/auditProgress` always 0;
  `typeIndex` always 0L. **Entire group
  absent from `/docs`.**
- `severity`: HIGH/MEDIUM/LOW/INFORMATION/
  FALSE_POSITIVE. `confidence`: CERTAIN/FIRM/
  TENTATIVE.

> `/scanner/issue-definitions` reads the sitemap →
> **degrades on Community** (empty list if
> unavailable), making it the only endpoint in the group
> usable without Pro.

---

### 6.7 · securityscan `/scan` — 5 endpoints · C

Custom scanner (≠ Pro ScannerRoutes). All
probes go through `SessionService.send()` +
Burp HTTP engine. **An active session is
required** for auth probes. Synchronous /
blocking.

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| POST | `/scan/auth-bypass` | C | `AuthBypassRequest` { endpoints:List\<String\> (required), baseUrl:String (required), method:String="GET" } | triple-probe (withAuth/withoutAuth/cookieOnly) → unauthenticated access. |
| POST | `/scan/idor` | C | `IdorRequest` { endpoint, param, ownValues:List\<String\>, targetValues:List\<String\> (all required), method="GET", body:String?, extraHeaders:Map?\} | cross-account access: target full-body differs from the own baseline (content equality, empty-vs-non-empty guard) with both 2xx and a 2xx baseline. |
| POST | `/scan/headers` | C | `HeadersBypassRequest` { url:String (required), method="GET", body:String? } | 16 IP-spoof/URL-override headers → 403 bypass. |
| POST | `/scan/cors` | C | `CorsRequest` { url:String (required), method="GET" } | 8 crafted origins → exploitable credentialed CORS. |
| POST | `/scan/endpoints` | C **+DB** | `EndpointsScanRequest` { host:String (required), tests:List\<String\>=["auth-bypass","method-switch"], limit:Int=100 } | bulk scan of proxy history by host. |

- **pre/post/err**: `INVALID_REQUEST` 400 on
  empty lists / malformed JSON; `INTERNAL_ERROR`
  500. `/scan/endpoints` requires the **SQLite DB**
  (otherwise `SERVICE_UNAVAILABLE` 503).
- **Flags**: SPA HTML catch-all filter
  (body `<!` and >50000 → status 302/length 0).
  `headers` = 16 fixed entries. `cors` = 8
  fixed origins. No-auth probes **not recorded**
  in history. **Entire group absent from `/docs`.**

#### fuzzModels — securityscan

```
AuthBypassRequest {"endpoints":["/api/admin"],"baseUrl":"https://t","method":"GET"}
IdorRequest {"endpoint":"https://t/orders/{id}","param":"id",
  "ownValues":["123"],"targetValues":["124","125"],"method":"GET"}
HeadersBypassRequest {"url":"https://t/admin","method":"GET"}
CorsRequest {"url":"https://t/api/data","method":"GET"}
EndpointsScanRequest {"host":"t.com","tests":["auth-bypass","method-switch"],"limit":100}
```

---

### 6.8 · target `/target` — 6 endpoints · C

Scope tracked **in memory** (JVM heap, reset on
restart). `/scope/check` delegates to the Burp
scope engine (reflects the UI).

| Method | Path | Pro | Request model | Hunter usage |
|---|---|---|---|---|
| GET | `/target/sitemap` | C | query: `url:String?` (prefix) | dumps the Burp sitemap (wordlist / hidden endpoints). |
| GET | `/target/scope` | C | — | reads the in-memory scope (≠ Burp UI). |
| POST | `/target/scope` | C | `SetScopeRequest` { includes:List\<String\> (required), excludes:List\<String\>=[] } | **replaces** (clear+set) the entire scope. |
| POST | `/target/scope/add` | C | `AddScopeRequest` { url:String (required) } | adds 1 URL. |
| POST | `/target/scope/remove` | C | `AddScopeRequest` { url:String } | excludes 1 URL (same DTO as add). |
| GET | `/target/scope/check` | C | query: `url:String` (required) | authoritative scope verdict (Burp engine). |

- **Flags**: `POST /target/scope` is a
  **full replace** — `includes=[]` clears the entire
  scope. `GET /target/scope` does **not** see
  the scope configured in the UI; `/scope/check`
  does. `/scope/check` without url → `INVALID_PARAM`
  inside an **HTTP 200** envelope (early-return).
  `ScopeCheckRequest` = **dead** DTO (unused).

#### fuzzModels — target

```
SetScopeRequest {"includes":["https://ex.com"],"excludes":["https://ex.com/logout"]}
AddScopeRequest {"url":"https://ex.com/api"}  // add AND remove
SitemapEntry {"url":"...","method":"GET","statusCode":200,"mimeType":"HTML"}
// statusCode/mimeType nullable → appear as null (encodeDefaults=true)
```

---

### 6.9 · decoder `/decoder` — 4 endpoints · C

Pure JVM (Base64/URL/hex/HTML + MessageDigest).
No Montoya, no Pro.

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| POST | `/decoder/encode` | C | `EncodeRequest` { data:String, encoding:String } — encoding ∈ {base64,url,hex,html} | encodes a payload to survive a WAF. |
| POST | `/decoder/decode` | C | `DecodeRequest` { data:String, encoding:String?=null } — null → auto-detect | decodes cookie/token; auto if encoding omitted. |
| POST | `/decoder/hash` | C | `HashRequest` { data:String, algorithm:String } — md5/sha1/sha256/384/512 | compares a token against a candidate hash. |
| POST | `/decoder/smart-decode` | C | `DecodeRequest` (encoding **ignored**) | peels up to 10 layers + step-by-step trace. |

- **err**: `INVALID_REQUEST` 400 (encoding out of
  set / invalid base64 / odd-length hex / malformed
  JSON). `INTERNAL_ERROR` 500.
- **Flags**: `html` encodes only 5 entities
  (`& < > " '`). `smart-decode` **ignores**
  `encoding`. Auto-detect can fail on
  short/ambiguous inputs. `hash` echoes
  the requested algorithm name (not the normalized JVM name).

#### fuzzModels — decoder

```
EncodeRequest {"data":"<s>","encoding":"base64|url|hex|html"}
DecodeRequest {"data":"<s>","encoding":"base64|url|hex|html|null"}
HashRequest {"data":"<s>","algorithm":"md5|sha1|sha-1|sha256|...|<raw-jvm>"}
DecodeStep (response) {"encoding":"<scheme>","result":"<intermediate>"}
```

---

### 6.10 · config `/config` — 5 endpoints · C

⚠ **All 4 `/config/*` are stubs**: GET
returns a hardcoded map `{"type":"..."}`;  PUT
echoes the payload without writing to Burp.

| Method | Path | Pro | Request model | Hunter usage |
|---|---|---|---|---|
| GET | `/config/project` | C — **stub** | — | returns `{"type":"project"}`. |
| PUT | `/config/project` | C — **stub** | `ConfigUpdateRequest` { config:Map\<String,String\> } | echo (no durable write). |
| GET | `/config/user` | C — **stub** | — | returns `{"type":"user"}`. |
| PUT | `/config/user` | C — **stub** | `ConfigUpdateRequest` { config:Map } | echo. |
| GET | `/extensions` | C | — | self-metadata (filename); total **always 1**. |

- **Flag**: `/extensions` is mounted at the root
  (`/extensions`, **not** `/config/extensions`)
  but belongs to the config group by
  ownership. Montoya only allows inspecting the active
  extension → `total=1` hardcoded.

---

### 6.11 · session `/session` — 7 endpoints · C

Shared singleton session. Cookies/headers
applied to all `/send` calls. Persisted via
SessionDao (SQLite `~/.burp-rest/burpdata`) if
DB is available. Cookie-jar (auto-captured Set-Cookie)
is **distinct** from session cookies.

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| POST | `/session/set` | C | `SetSessionRequest` { cookies:Map (required), headers:Map?=null, name:String?=null } | loads auth cookies+headers (full **replace**). |
| GET | `/session/get` | C | — | inspects the active session. |
| DELETE | `/session/clear` | C | — | resets cookies/headers (not the cookie-jar). |
| POST | `/session/send` | C | `AuthenticatedRequest` { method="GET", url:String (required), body:String?=null, extraHeaders:Map?=null } | authenticated request via Burp (appears in history). |
| POST | `/session/send/batch` | C | `BatchAuthenticatedRequest` { requests:List\<AuthenticatedRequest\> } | multi-step sequence (workflow / IDOR). |
| GET | `/session/cookie-jar` | C | — | auto-captured cookies by domain. |
| DELETE | `/session/cookie-jar` | C | — | clears the cookie-jar (not the session). |

- **Flags**: `/session/set` = full replace.
  `extraHeaders` **overrides** session
  headers (not additive). Cookie-jar is in-memory
  (not DB); survives `clear`, wiped on reload.
  `/send/batch` sequential; failure → total abort.
  **Entire group absent from `/docs`.**

---

### 6.12 · utils `/utils` — 2 endpoints · C

Depends on SessionService (Burp HTTP engine).
No DB required.

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| POST | `/utils/diff` | C | `DiffRequest` { a:DiffTarget, b:DiffTarget } — DiffTarget { url:String (required), method="GET", body:String?, extraHeaders:Map? } | 2 live requests → diff of status/length/headers (access-control). |
| POST | `/utils/extract-endpoints` | C | `ExtractEndpointsRequest` { url:String (required) } | extracts API endpoints from HTML + JS (regex). |

- **Flags**: `diff` body-diff = set-based summary
  (not unified diff). `extract-endpoints`
  fetches up to **10 JS bundles** (cap), errors
  per bundle are swallowed, filters out static
  assets + w3.org. **Entire group absent from `/docs`.**

---

### 6.13 · history `/history` — 5 endpoints · C · **CONDITIONAL DB**

> ⚠ **Group registered ONLY if
> `historyDao != null && sitemapDao != null`.**
> If DB init (`~/.burp-rest/burpdata`)
> fails, **all 5 endpoints return 404** —
> the group is silently absent.
> **`bp` must handle this absence** (probe +
> graceful degradation).

| Method | Path | Pro | Request model (Kotlin types) | Hunter usage |
|---|---|---|---|---|
| GET | `/history` | C+DB | `HistoryFilter` (query): host?, method?, statusCode:Int?, source?, search?, since?, until?, page:Int=0, pageSize:Int=50 | paginates all traffic; grep secrets/JWT. |
| GET | `/history/{id}` | C+DB | path: `id:Long` (toLongOrNull) | single full entry (req+resp). |
| GET | `/history/sitemap` | C+DB | query: `host:String?` | unique host+path+method tuples + hitCount. |
| POST | `/history/{id}/replay` | C+DB | path: `id:Long` | replays an entry verbatim (live via Burp). |
| DELETE | `/history` | C+DB | — | **destructive**: wipes history + sitemap. |

- **Key contract**: `HistoryEntryResponse.id` =
  **Long**; `HistoryPageResponse.total` =
  **Long**; `SitemapListResponse.total` =
  **Int** (assumed type inconsistency).
  Entries sorted id DESC. Bodies truncated to
  **1 MB** at insert.
- **err**: non-Long id → `INVALID_REQUEST` 400;
  missing id → 400; DB failed → **404** (route
  absent).
- **Flags**: `replay` not persisted (id=0,
  source='replay') but RepeaterService may
  re-insert. `?search=` = unescaped SQL LIKE
  (`%`/`_` = wildcards). `DELETE` **irreversible,
  no confirmation**, non-transactional across
  the 2 tables.

#### fuzzModels — history

```
HistoryFilter (query) :
host&method&statusCode=<int>&source=proxy|repeater|replay|intruder
&search&since=<ISO8601>&until=<ISO8601>&page=0&pageSize=50
// fuzz: statusCode=abc (ignored), page=-1, pageSize=0, search=%25
HistoryEntryResponse : nullables = reqBody, statusCode, resHeaders, resBody
```

---

## 7 · Community vs Pro matrix

`bp` must **degrade gracefully**: detect
Pro/Community at runtime and disable/warn
on Pro-only groups.

| Group | Pro required? | Detail |
|---|---|---|
| health | **No (C)** | pure introspection. |
| proxy | **No (C)** | Montoya proxy available on Community; 4 stubs. |
| repeater | **No (C)** | HTTP engine, available on Community. |
| intruder | **No (C)** | delegated to Repeater (not Pro Intruder); **sniper only** server-side. |
| collaborator | **YES (P)** | Collaborator API = **Pro only** → 503 on Community. |
| scanner | **YES (P)** | crawl/audit = Pro → 500 on Community. `issue-definitions` degrades (C). |
| securityscan `/scan` | **No (C)** | probes via HTTP engine + session; `/scan/endpoints` requires DB. |
| target | **No (C)** | scope API available on Community. |
| decoder | **No (C)** | pure JVM. |
| config | **No (C)** | stubs. |
| session | **No (C)** | HTTP engine. |
| utils | **No (C)** | HTTP engine. |
| history | **No (C)** but **+DB** | conditional on SQLite init. |

**Summary**: only **collaborator** and
**scanner (start)** are strictly Pro
(derived from `conditional`/`caveats` in the
source). Everything else runs on Community. Intruder
runs on Community: the source shows it **does not
use** Pro Intruder (sending delegated to Repeater).

---

## 8 · Kotlin contract (serialization)

Global Json config (RestServer.configurePlugins):

```
Json {
  prettyPrint = false
  isLenient = true
  ignoreUnknownKeys = true
  encodeDefaults = true
}
```

**Client implications (`bp`)**:

- `prettyPrint=false` → compact single-line responses.
- `isLenient=true` → server tolerates slightly
  invalid JSON on input (unquoted keys, trailing
  commas).
- `ignoreUnknownKeys=true` → `bp` can send a
  **superset** of fields without error;
  unknown fields are **silently dropped**.
- `encodeDefaults=true` → responses
  **always include** every field even if
  null/default. `bp` can rely on all declared
  fields being present (no missing key to handle).

**Envelope**: `ApiResponse<T>` { success:
Boolean, data:T?=null, error:ApiError?=null };
`ApiError` { code:String, message:String }.
Exceptions: `/docs` (raw JSON) and the proxy
stubs (`Map<String,Boolean>` inline) are **not**
wrapped.

**StatusPages mapping**:

| Exception | HTTP | code |
|---|---|---|
| BadRequestException | 400 | INVALID_REQUEST |
| SerializationException | 400 | INVALID_REQUEST |
| IllegalArgumentException | 400 | INVALID_REQUEST |
| IllegalStateException | 503 | SERVICE_UNAVAILABLE |
| Throwable | 500 | INTERNAL_ERROR |

**Id types (load-bearing)**:

- `requestId` = **Int** (0-based history index),
  everywhere (repeater, intruder, quick-fuzz).
- `attackId` / `scanId` / collaborator `id` =
  **String** (8-char UUID prefix).
- history `id` = **Long** (DB key).
- `{id}` proxy path parsed via `toIntOrNull` →
  `INVALID_PARAM` (not 404) if non-integer.

**Enum shapes (all as String, not Kotlin
`@Serializable` enum)**:

- `attackType`: "sniper" (impl.) | "battering-ram"
  | "pitchfork" | "cluster-bomb" (accepted,
  execute sniper).
- attack `status`: created | running | paused |
  stopped | completed | error.
- WS `direction` / Interaction `type`: `.name`
  of the Montoya enum (CLIENT_TO_SERVER;
  DNS/HTTP/SMTP).
- scan `severity`: HIGH/MEDIUM/LOW/INFORMATION/
  FALSE_POSITIVE. `confidence`: CERTAIN/FIRM/
  TENTATIVE.

**Notable nullables / defaults**: `body`
omit-safe everywhere; `headers=emptyList()`
serialized as `[]`; `method="GET"` always present
(encodeDefaults); never-populated fields rendered as
`null` (burpVersion, listenerInterface,
clientIp, HTTP timestamp).

**No `@SerialName`** anywhere in the codebase →
JSON names = Kotlin identifiers (camelCase).

---

## 9 · C4 Run Ledger (observability / ISO)

Every `bp` operation (fuzz, send,
scan, collaborator…) is recorded in a
**local SQLite DB under `~/.bp/`**, independent
of the extension's DB. This is `bp`'s differentiator
vs `curl`: every action is traceable, replayable, and
timestamped.

**Fields per entry**:

- `id` (local), `name` / `tag` (user label),
  `timestamp`, `target` (host/url),
  `command` (the `bp` command line executed),
  `request_ref` / `response_ref`, `status`
  (ok/err), `burp_op` (REST endpoint called).

**Queryable**:

- `bp log` — lists / filters runs.
- `bp tag <id> <label>` — annotates after the fact.
- `bp show <id>` — req/resp detail.

**ISO / traceability framing**: a hunter or an
auditor can **replay**, **prove**, and
**timestamp** every action taken against a target —
something `curl` does not provide. Aligns `bp` with
engagement traceability requirements.

**Scope**: all operations are recorded. Retention
and export format (JSON/CSV) are configurable.

---

## 10 · Test architecture (TDD)

3 levels, RED-first for unit.

| Level | What | Burp required? |
|---|---|---|
| **Unit (pure)** | `--pos` parser, offset resolver (semantic selector → byte-range), `CreateAttackRequest` builder. | No. |
| **Contract-tests** | JSON emitted matches the Kotlin contract (types, nullables, enums-as-String, id-types) frozen from source §8. | No. |
| **Integration (live)** | smoke against real `:8089`, endpoint walk. | **YES — accepted (D1 resolved).** |

> **D1 resolved**: the "live tests ↔
> Burp running" dependency is **accepted** —
> Burp must be running for the integration suite;
> clean skip otherwise.

---

## 11 · DDD

**Aggregates**:

- `FuzzPlan` — Positions[] + PayloadSets +
  AttackType. **Invariant**: a `cluster-bomb`
  requires ≥1 set per position.
- `CapturedRequest` — requestId, base bytes
  (source of offset resolution).
- `AttackRun` — state created → running →
  completed + `AttackResultEntry[]`.
- `LedgerEntry` — one traced operation (C4).

**Ubiquitous language** = that of **Burp /
Intruder** (sniper, position, payload set,
collaborator, scope), **not** invented jargon.

---

## 12 · Coverage roadmap

**Not exposed today** (confirmed absent from
`configureRouting()`):

| Surface | Source status |
|---|---|
| **Sequencer** | `SequencerModels.kt` **orphaned** — dead models, no route, no service. |
| **Comparer** | never implemented (`/utils/diff` ≠ full Comparer). |
| **Logger** | never implemented. |
| **Organizer** | never implemented. |
| **Engagement** | never implemented. |
| **Search** | never implemented (listed as ghost in README). |
| **Inspector** | never implemented. |
| **Dashboard** | never implemented. |
| **Clickbandit** | never implemented. |

**Principle**: `bp` must be **extensible**.
Exposing more = **Kotlin extension work**
server-side (new `*Routes.kt` +
`*Service.kt`) — sequenced for future releases.
`bp` can only drive what the API actually exposes.

---

## 13 · Resolved decisions

| # | Decision | Resolution |
|---|---|---|
| **D1** | Live tests ↔ Burp running. | Burp required for integration suite; clean skip otherwise. |
| **D-Name** | CLI name. | **`bp`** with alias **`burpctl`**. |
| **D-Intruder-Pro** | Intruder Community vs Pro? | **Community** — sending delegated to Repeater, not Pro Intruder. Confirmed by source review. |
| **D-Ledger** | Run Ledger scope / retention / export. | All operations recorded; retention and export (JSON/CSV) configurable (§9). |

---

## 14 · Acceptance criteria

Each item carries both axes (importance ·
blocking).

### CRITICAL

- [CRITICAL][BLOCKS:high] The `--pos` grammar
  covers header / cookie / body / path / query +
  `offset:` + multi-position + 4 attack-types.
- [CRITICAL][BLOCKS:high] `bp` resolves
  semantic selectors into **byte-offsets**
  (`start/end/name`) from the base request,
  because the Intruder API only accepts raw offsets.
- [CRITICAL][BLOCKS:critical] The spec is
  **source-grounded**: 69 endpoints / 13
  groups, no invented endpoints, authority =
  `routes/*.kt`.
- [CRITICAL][BLOCKS:high] `bp` targets
  `http://127.0.0.1:8089` (not 9876);
  `spec.md` is treated as **outdated**.

### HIGH

- [HIGH][BLOCKS:high] `bp` detects
  Pro/Community and **degrades gracefully**:
  warns/disables collaborator and scanner
  (start) outside Pro.
- [HIGH][BLOCKS:high] `bp` handles the **conditional
  absence** of the `/history` group (404 if
  DB not initialized).
- [HIGH][BLOCKS:low] The client respects the
  serialization contract: `ApiResponse<T>` envelope,
  StatusPages mapping, id-types
  (requestId Int / attackId String / history
  Long), enums-as-String.
- [HIGH][BLOCKS:high] `cluster-bomb` /
  `pitchfork` / `battering-ram` are implemented
  **client-side** (matrix expansion) as long as
  the extension only implements sniper.
- [HIGH][BLOCKS:low] Contract-tests freeze the
  emitted JSON against real Kotlin models.

### MEDIUM

- [MEDIUM][BLOCKS:none] The **Run Ledger (C4)**
  records every op (id, name/tag, timestamp,
  target, refs, status) and is queryable
  (`bp log`, `bp tag`).
- [MEDIUM][BLOCKS:none] `bp` surfaces the
  **caveats** of stubs (proxy intercept/forward/
  drop, scanner pause/resume, config) rather than
  pretending they work.
- [MEDIUM][BLOCKS:none] The live integration
  suite runs against `:8089` (clean skip if
  Burp is absent).

### LOW (convergence tail)

- [LOW][BLOCKS:none] `bp` signals that `/docs`
  (embedded OpenAPI) is **incomplete** (declares
  0.2.0, omits several groups) and does not
  rely on it for discovery.
- [LOW][BLOCKS:none] The CLI name is `bp` with
  alias `burpctl` (see §3).
- [LOW][BLOCKS:none] Intruder runs on Community:
  sending is delegated to Repeater, not Pro Intruder
  (confirmed by source review — see §6.4).

---
