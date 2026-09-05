# `bp` REST contract

The published v2.1.0 contract is [`src/main/resources/openapi.json`](../src/main/resources/openapi.json).
It declares **69 operations on 64 paths in 13 groups**, and every operation has a unique
`operationId`. Kotlin contract tests join those operations to route request/response serializers. That
is publication and source-level shape evidence, not proof that each operation works against real Burp.
See [ADR-0014](adr/0014-state-preserving-reportable-operations.md), the
[quality ledger](../quality/confirmed-defects.yaml), and the [proof ceilings](PROOF-CEILINGS.md).

## Server boundary

- The extension listens on loopback; the default is `http://127.0.0.1:8089` and the port can be changed
  by the extension configuration. The OpenAPI `servers` value records the default, not every runtime
  port.
- JSON decoding is compact, strict (`isLenient=false`, `ignoreUnknownKeys=false`), and emits defaults.
  Unknown outer DTO members, malformed values, and semantic validation failures are rejected.
- Success and failure normally use `ApiResponse {success,data,error}`. `/docs` is the one raw-document
  success. Framework 404, 405, and 415 failures are converted to typed JSON envelopes; a 415 does not
  distinguish missing/unsupported media type from an unparseable body.
- Request logging records method, path without query, resulting status, duration, and time. It does not
  log query strings, headers, or bodies.
- H2/MVStore state is under `~/.burp-rest/`. Routes remain discoverable when H2 initialization fails
  and return service-unavailable responses where storage is required.
- The OpenAPI document declares no HTTP authentication scheme. That means only “not declared by this
  publication”; it is not a general claim about deployment protections.

## Complete published surface

Each row is `METHOD path — operationId`, copied from the v2.1.0 declaration.

### System

```text
GET /health — get_health
GET /version — get_version
GET /docs — get_docs
```

### Proxy

```text
GET  /proxy/history — get_proxy_history
GET  /proxy/history/{id} — get_proxy_history_id
GET  /proxy/intercept — get_proxy_intercept
POST /proxy/intercept/enable — post_proxy_intercept_enable
POST /proxy/intercept/disable — post_proxy_intercept_disable
GET  /proxy/websocket/history — get_proxy_websocket_history
POST /proxy/intercept/drop — post_proxy_intercept_drop
POST /proxy/intercept/forward — post_proxy_intercept_forward
```

### Repeater

```text
POST /repeater/send — post_repeater_send
POST /repeater/send/batch — post_repeater_send_batch
POST /repeater/tab/create — post_repeater_tab_create
```

### Session

```text
POST   /session/set — post_session_set
GET    /session/get — get_session_get
DELETE /session/clear — delete_session_clear
POST   /session/send — post_session_send
POST   /session/send/batch — post_session_send_batch
GET    /session/cookie-jar — get_session_cookie_jar
DELETE /session/cookie-jar — delete_session_cookie_jar
```

### Intruder

```text
POST /intruder/attack/create — post_intruder_attack_create
POST /intruder/attack/{id}/start — post_intruder_attack_id_start
GET  /intruder/attack/{id}/status — get_intruder_attack_id_status
GET  /intruder/attack/{id}/results — get_intruder_attack_id_results
POST /intruder/attack/{id}/pause — post_intruder_attack_id_pause
POST /intruder/attack/{id}/resume — post_intruder_attack_id_resume
POST /intruder/attack/{id}/stop — post_intruder_attack_id_stop
POST /intruder/quick-fuzz — post_intruder_quick_fuzz
```

### Scanner

```text
POST /scanner/crawl — post_scanner_crawl
POST /scanner/audit — post_scanner_audit
POST /scanner/crawl-and-audit — post_scanner_crawl_and_audit
GET  /scanner/{id}/status — get_scanner_id_status
GET  /scanner/{id}/issues — get_scanner_id_issues
POST /scanner/{id}/pause — post_scanner_id_pause
POST /scanner/{id}/resume — post_scanner_id_resume
POST /scanner/{id}/stop — post_scanner_id_stop
GET  /scanner/issue-definitions — get_scanner_issue_definitions
```

### Target

```text
GET  /target/sitemap — get_target_sitemap
GET  /target/scope — get_target_scope
POST /target/scope — post_target_scope
POST /target/scope/add — post_target_scope_add
POST /target/scope/remove — post_target_scope_remove
GET  /target/scope/check — get_target_scope_check
```

### Collaborator

```text
POST /collaborator/generate — post_collaborator_generate
GET  /collaborator/poll — get_collaborator_poll
GET  /collaborator/poll/{id} — get_collaborator_poll_id
POST /collaborator/generate/batch — post_collaborator_generate_batch
```

### Decoder

```text
POST /decoder/encode — post_decoder_encode
POST /decoder/decode — post_decoder_decode
POST /decoder/hash — post_decoder_hash
POST /decoder/smart-decode — post_decoder_smart_decode
```

### Config

```text
GET /config/project — get_config_project
PUT /config/project — put_config_project
GET /config/user — get_config_user
PUT /config/user — put_config_user
GET /extensions — get_extensions
```

### History

```text
GET    /history — get_history
DELETE /history — delete_history
GET    /history/{id} — get_history_id
POST   /history/{id}/replay — post_history_id_replay
GET    /history/sitemap — get_history_sitemap
```

### Security checks

```text
POST /scan/auth-bypass — post_scan_auth_bypass
POST /scan/cors — post_scan_cors
POST /scan/endpoints — post_scan_endpoints
POST /scan/headers — post_scan_headers
POST /scan/idor — post_scan_idor
```

### Utilities

```text
POST /utils/diff — post_utils_diff
POST /utils/extract-endpoints — post_utils_extract_endpoints
```

## Current behavior by group

### System and proxy

`/health` and `/version` report extension version 2.1.0; Burp version is populated best-effort from
Montoya and may be null if that accessor fails. `/docs` serves the embedded OpenAPI JSON.

Proxy host filtering is exact after normalization and returned IDs remain absolute Burp history
indexes. Intercept status comes from Montoya. Forward/drop cannot be implemented with pinned Montoya
and return 501 `UNSUPPORTED`; they never return fabricated `{forwarded:true}` or `{dropped:true}`
success. WebSocket entries preserve a stable socket identifier, original/edited payload representations,
capture metadata where available, and nullable platform values rather than failing the entire list.

### Repeater and session

Repeater send accepts exactly one inline request or proxy-history `requestId`; batches are validated
before their first target send. A missing target response is typed `NO_RESPONSE`. Successful target
send and optional H2 persistence are separate outcomes, so persistence failure is reported without
claiming the target send did not occur. Repeater tab creation requires exactly one request source and a
nonblank explicit name.

The session is one immutable origin-bound credential snapshot. Body text is encoded as exact UTF-8
bytes for Montoya; `bodyBase64` carries exact request-body bytes. Persisted history is reconstructed
from the request actually sent. Response text is decoded from response bytes rather than
`bodyToString()`, but a text model cannot preserve arbitrary malformed UTF-8 (PC-07).

Configured credentials and captured response cookies are separate stores. `DELETE /session/clear`
clears both. Both clear entry points advance the cookie epoch under the fixed
`sessionMutationLock -> cookieMutationLock` order, so a response from an older snapshot cannot restore
cleared cookies. Cookie output includes `httpOnly`, expiry, and host-only state.

### Intruder and client fuzzing

The server-side Intruder surface supports bounded exact-offset sniper work. Matrix modes are not
silently executed as sniper; unavailable modes return 501 `UNSUPPORTED`. Start/lifecycle transitions
are state-locked. The Python `bp fuzz` command independently implements all four attack expansions and
fires through Repeater; see [`ALGORITHMS.md`](ALGORITHMS.md).

### Scanner

Crawl/audit starts require Pro and use the supplied target. Options unavailable in pinned Montoya are
rejected as `UNSUPPORTED`, including linked crawl-and-audit and pause/resume. Status/count projections
that Montoya cannot supply are nullable. Stop reports success only after task deletion succeeds.

Task handles are extension-owned and no operation enumerates them. A lost handle cannot be recovered
after its registry is gone; task state then remains unknown (PC-04).

### Target

Add/remove/check use Burp's scope engine. Complete scope listing and replacement are not available in
pinned Montoya and return 501 rather than successful partial behavior. Scope classifies traffic; it is
not a forwarding block. The GET check path has a length ceiling that can make a previously accepted
very long mutation independently uncheckable (PC-05).

### Collaborator

Collaborator requires Pro. Identifiers, timestamps, and interaction details come from Montoya; provider
failures are not converted into empty success. The extension registry is in-memory and is lost on
reload. Poll results may be one-use state, so callers must select a valid output representation before
polling.

### Decoder

Encode/decode supports Base64, URL, hexadecimal, and HTML representations; smart decode peels bounded
layers. Hash supports MD5, SHA-1, SHA-256, SHA-384, and SHA-512 spellings accepted by the service. These
are REST operations, not offline Python commands.

### Configuration

Project/user endpoints export real nested Burp JSON and validate supplied object shape before import.
User import excludes only `user_options.extender.extensions`, reports that path, and applies safe
siblings so the operation does not reload its own responder. A completed import whose post-state cannot
be exported returns `applied=true`, `config=null`, and a do-not-retry warning.

`GET /extensions` returns only this extension because that is all pinned Montoya exposes; it is not a
complete loaded-extension inventory.

### History

All history routes stay mounted. If H2 is unavailable they return service-unavailable rather than 404
or an empty success. Numeric/time filters are validated; malformed values are 400 without echoing raw
parser internals. History and sitemap clear in one transaction. Replay returns the original record, a
nullable persisted replay row, and the exact persistence outcome; it does not calculate a comparison.
A null replay row is not permission to retry a completed target send. Only target sends persisted by
Repeater/session services populate this H2 history/sitemap—not all Burp or API traffic.

### Security checks and utilities

The security-check routes return observations, per-probe errors, inconclusive reasons, and classifier
counts. A no-response observation is bounded but does not diagnose timeout versus refusal/resolution
failure (PC-01). `check endpoints` reads extension H2 request identity rather than proxy-listener
history.

A configured marker can support a protected-representation check only when the caller has established
that the server held it and policy withholds it. The implementation rejects recognized actor-supplied
representations in supplied method/URL/body and observed final headers/cookies, under a bounded
transform closure. It does **not** currently record final method/URL/body from the HttpRequest handed to
Montoya; those components remain inferred from pre-send values. This is a code/proof-boundary defect,
not a basis for a stronger documentation claim. The related proof-ceiling sections are under correction
and must be re-verified before release.

The IDOR route compares responses produced under one configured session for caller-labelled object
values. A differing nonempty 2xx representation is a classifier finding, not proof that two principals
were distinguished or that the caller lacked authority. Establish actor identity and ownership
independently before describing a cross-principal read.

Utilities send through the session service. Diff returns observed deltas; endpoint extraction fetches
and analyzes a bounded set of same-origin resources. A missing response can produce 502 `NO_RESPONSE`.

## Permanently unsupported operations

These seven operations remain published for discovery but have no success response in the current
contract and always return 501 under pinned Montoya:

```text
POST /proxy/intercept/forward
POST /proxy/intercept/drop
POST /scanner/crawl-and-audit
POST /scanner/{id}/pause
POST /scanner/{id}/resume
GET  /target/scope
POST /target/scope
```

Other operations can also have request-dependent unsupported arms—for example Scanner options that
pinned Montoya does not expose. Discoverability never implies a successful no-op.

## Publication limits and release status

The serializer contract gate checks operation/model shape. It does not prove that summaries convey the
right semantics, that every reachable status is declared, or that Montoya behaves as a mock does. The
release audit corrected the identified semantic/status descriptions in the moving OpenAPI tree; the
focused `OpenApiContractTest` then passed in a forced six-task run. That remains source-level evidence.

No record in `quality/confirmed-defects.yaml` is `verified`. The final redeployed-binary pass has not
completed. Four acceptance oracles were found pinned to superseded contracts; their repaired
unversioned harness was destroyed before execution. Its in-repository replacement then produced a
non-clean retained run: a system preflight proved the deployed binary predates current source because
embedded and source OpenAPI differ, so all 30 selected REST/CLI behavior cases became
`COULD_NOT_RUN`. Do not infer release readiness from that run or the exact 69-to-69 route inventory.
