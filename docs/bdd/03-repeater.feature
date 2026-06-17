# Feature: Repeater — bp send / bp send --batch / bp tab  (§6.3)
#
# Canonical CLI surface (CLI.md):
#   bp send <id> [--set-header 'N: V']… [--body @f|STR] [--method M] [--path P]
#   bp send --batch @file
#   bp tab <id>
#
# Naming decisions applied (CLI.md §Decisions):
#   --id → positional <id>  (never --request-id, never --id flag)
#   bp send / bp tab        (never bp repeater send / bp repeater batch / bp repeater tab create)
#   --set-header / --body / --method / --path  (not --modify-*)
#   bp log                  (Run Ledger — not bp history)
#
# Real Kotlin types:
#   SendRequest        { request:HttpRequestData?=null, requestId:Int?=null,
#                        modifications:RequestModifications?=null }
#                        EXACTLY ONE of request / requestId required.
#   BatchSendRequest   { requests:List<SendRequest> }
#   CreateTabRequest   { name:String?=null, request:HttpRequestData?=null,
#                        requestId:Int?=null }
#   HttpRequestData    { method:String, url:String,
#                        headers:List<{name,value}>?, body:String? }
#   RequestModifications { headers:Map<String,String>?,   // full replace
#                          body:String?,                  // replaces entire body
#                          method:String?,                // replaces verb
#                          path:String? }                // replaces path (not URL)
#
# Behaviour contracts:
#   /send          drives http().sendRequest(); records row source='repeater' + upserts
#                  sitemap when DB available; silent skip if DB absent; returns req+resp+timing.
#   /send/batch    strictly sequential; failure on item N → total abort, zero partials.
#   /tab/create    opens Repeater UI tab; NO traffic; NO DB; if both request and
#                  requestId are null → silent fallback to https://example.com.
#
# Error codes (§8 StatusPages):
#   INVALID_REQUEST     400  (neither/both request+requestId; out-of-bounds; malformed JSON)
#   SERVICE_UNAVAILABLE 503
#   INTERNAL_ERROR      500
#
# Serialization contract (§8):
#   encodeDefaults=true  — all declared fields always present (never absent, may be null).
#   prettyPrint=false    — compact mono-line JSON.
#   ignoreUnknownKeys=true — extra fields in request body are silently dropped.
#   ApiResponse<T>       { success:Boolean, data:T?=null, error:ApiError?=null }
#
# What is NOT tested here (proven once elsewhere):
#   Output rendering (--format, --fields, -w, --quiet) → 00-output.feature
#   Cross-cutting errors (CONNECTION_REFUSED, generic bad-id, envelope unwrap,
#     PRO_REQUIRED)                                     → 00-common.feature
#
# Tags:
#   @happy      nominal success path
#   @error      error / rejection path
#   @community  all repeater endpoints require no Pro licence
#   @ledger     exercises C4 Run Ledger behaviour
#   @serial     serialization / wire-format contract
#   @chain      multi-step chaining scenario

Feature: Repeater — send, batch-send, and tab-create (§6.3)

  As a bug-bounty hunter using `bp`
  I want to send crafted or replayed HTTP requests through Burp's HTTP engine,
  batch them for multi-step workflows, and open Repeater UI tabs,
  so that I can iterate on modifications and maintain a traceable ledger of every
  request sent.

  Background:
    Given the Burp extension is running and reachable at http://127.0.0.1:8089
    And GET /health returns {"success":true,"data":{"status":"ok","version":"0.1.0"}}
    And proxy history entry 42 exists (POST /api/login, host: auth.example.com)
    And proxy history entry 7  exists (GET  /api/users/me, host: api.example.com)

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — requestId path (replay from proxy history)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @serial
  Scenario: Replay a captured request by positional requestId — full schema (encodeDefaults=true)
    When I run:
      """
      bp send 42 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON top-level keys are exactly "success", "data", "error"
    And "error" is null
    And "data" contains field "statusCode"     with an integer value   (never absent)
    And "data" contains field "responseLength" with an integer value   (never absent)
    And "data" contains field "durationMs"     with an integer value   (never absent)
    And "data" contains field "responseBody"   (value may be null, never absent)
    And "data" contains field "responseHeaders" (value may be [], never absent)
    And "data" contains field "requestBody"    (value may be null, never absent)

  @happy @community
  Scenario: Send an inline-crafted request (HttpRequestData path — no requestId)
    When I run:
      """
      bp send \
        --method POST \
        --url https://api.example.com/api/login \
        --header "Content-Type: application/json" \
        --header "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.sig" \
        --body '{"username":"admin","password":"hunter2"}' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON contains field "statusCode" with an integer value >= 100
    And the JSON contains field "durationMs"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — RequestModifications applied on top of base request
  # Each of the four fields is independent; only non-null fields are applied.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario Outline: Send with a single modification type — each field applied independently
    When I run:
      """
      bp send 42 <flag> <value> --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'
    And the POST /repeater/send body sent to :8089 contains <mod_json>

    Examples:
      | flag          | value                          | mod_json                                              |
      | --method      | DELETE                         | "modifications":{"method":"DELETE"}                   |
      | --path        | /api/v2/login                  | "modifications":{"path":"/api/v2/login"}              |
      | --body        | {"injected":"payload"}         | "modifications":{"body":"{\"injected\":\"payload\"}"}  |
      | --set-header  | X-Role: admin                  | "modifications":{"headers":{"X-Role":"admin"}}        |

  @happy @community
  Scenario: Send with path modification replaces only the path segment — not the full URL
    # path field takes a path+query string, not a full URL; the host is unchanged
    When I run:
      """
      bp send 42 --path '/api/users/2?debug=true' --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains '"path":"/api/users/2?debug=true"'
    And the POST /repeater/send body sent to :8089 does not contain '"url":"/api/users/2"'

  @happy @community
  Scenario: Send with header modification performs full replace of named header
    When I run:
      """
      bp send 42 \
        --set-header "Authorization: Bearer BBBB" \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains '"headers":{"Authorization":"Bearer BBBB"}'

  @happy @community
  Scenario: Send with all four modifications applied simultaneously
    When I run:
      """
      bp send 42 \
        --method PUT \
        --path '/api/v2/resource' \
        --set-header "Authorization: Bearer newtoken" \
        --body '{"key":"value"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains '"method":"PUT"'
    And the POST /repeater/send body sent to :8089 contains '"path":"/api/v2/resource"'
    And the POST /repeater/send body sent to :8089 contains '"Authorization":"Bearer newtoken"'
    And the POST /repeater/send body sent to :8089 contains '"body":"{\"key\":\"value\"}"'

  @happy @community @serial
  Scenario: Only non-null modification fields are serialised — absent fields not sent to server
    # Spec: RequestModifications null fields must not appear in the wire body at all.
    When I run:
      """
      bp send 42 --body 'FUZZ' --format json
      """
    Then the exit code is 0
    And the POST /repeater/send body sent to :8089 contains '"body":"FUZZ"'
    And the POST /repeater/send body sent to :8089 does not contain '"method":'
    And the POST /repeater/send body sent to :8089 does not contain '"path":'
    And the POST /repeater/send body sent to :8089 does not contain '"headers":'

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — Serialization edge contracts (§8)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @serial
  Scenario: ApiResponse envelope is always {success, data, error} — no bare response
    # Spec §8: ApiResponse<T> { success:Boolean, data:T?=null, error:ApiError?=null }
    When I run:
      """
      bp send 42 --format json
      """
    Then stdout is a JSON object with exactly the top-level keys "success", "data", "error"
    And "error" is null on success
    And "data" is non-null on success

  @happy @community @serial
  Scenario: Server silently drops unknown fields in the request body (ignoreUnknownKeys=true)
    When bp sends a POST /repeater/send body containing an extra unknown field "deprecated_flag":true
    Then the exit code is 0
    And the server responds with '"success":true'
    # The extra field must not produce a 400 INVALID_REQUEST

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — DB recording
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Send records a history row with source=repeater when DB is available
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp send 42 --format json
      """
    Then the exit code is 0
    And GET /history on :8089 with filter source=repeater shows a new entry for "auth.example.com"

  @happy @community
  Scenario: Send silently skips DB recording when DB is absent — success is unaffected
    # Spec: "DB optionnelle — enregistrement silencieusement skippé si init échoue"
    Given the SQLite DB at ~/.burp-rest/burpdata is absent or failed to initialise
    When I run:
      """
      bp send 42 --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'
    And stderr does not contain "SERVICE_UNAVAILABLE"
    And stderr does not contain "INTERNAL_ERROR"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — C4 Run Ledger
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Send records a named C4 ledger entry with --tag
    When I run:
      """
      bp send 42 --set-header "X-Role: admin" --tag auth-test-admin --format json
      """
    Then the exit code is 0
    And running "bp log --tag auth-test-admin" returns 1 entry
    And the ledger entry records burp_op "POST /repeater/send"
    And the ledger entry records target "auth.example.com"
    And the ledger entry status is "ok"

  @happy @community @ledger
  Scenario: Send with --no-ledger does not create any ledger entry
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp send 7 --no-ledger --format json
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  @happy @community @ledger
  Scenario: Failed send is still recorded in the Run Ledger with status "error"
    # Even failed operations must be traceable (ISO traceability requirement)
    Given proxy history entry 99999 does NOT exist
    When I run:
      """
      bp send 99999 --format json
      """
    Then the exit code is non-zero
    And the most recent Run Ledger entry records burp_op "POST /repeater/send"
    And the most recent Run Ledger entry has status "error"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send — error paths (endpoint-specific)
  # ═══════════════════════════════════════════════════════════════════════════

  @error @community
  Scenario: Send with neither inline request nor requestId returns INVALID_REQUEST 400
    # Spec: exactly one of request / requestId required; neither → INVALID_REQUEST
    When I run:
      """
      bp send --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "400"

  @error @community
  Scenario: Send batch item with both inline request and requestId returns INVALID_REQUEST 400
    # Spec: exactly one of request / requestId per SendRequest; both → INVALID_REQUEST.
    # Note: --url is the global REST-base flag (not a per-request target override);
    # the "both paths" conflict can only be exercised via the batch JSON body.
    Given a file "/tmp/batch_both_paths.json" with content:
      """
      {"requests":[{"requestId":42,"request":{"method":"GET","url":"https://api.example.com/test"}}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_both_paths.json --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Send with out-of-bounds requestId returns INVALID_REQUEST 400
    Given the proxy history contains 10 entries (indices 0–9)
    When I run:
      """
      bp send 9999 --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Send with a non-integer requestId is rejected client-side before hitting the server
    When I run:
      """
      bp send not-an-int --format json
      """
    Then the exit code is non-zero
    And stderr contains a validation error about the requestId being non-integer

  @error @community
  Scenario: Send returns SERVICE_UNAVAILABLE 503 when Burp HTTP engine is unavailable
    Given the REST API at :8089/repeater/send will respond with HTTP 503 and body:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"HTTP engine not ready"}}
      """
    When I run:
      """
      bp send 42 --format json
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE"

  @error @community
  Scenario: Send returns INTERNAL_ERROR 500 on unexpected server-side Throwable
    Given the REST API at :8089/repeater/send will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected exception"}}
      """
    When I run:
      """
      bp send 42 --format json
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  # ═══════════════════════════════════════════════════════════════════════════
  # Agent / pipeline mode — endpoint-specific schema assertion
  # (output rendering contract lives in 00-output.feature; only the schema is here)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Agent mode — piped output is compact JSON by default (no TTY)
    # Spec §8: prettyPrint=false; non-TTY default = json
    Given stdout is not a TTY (piped to another process)
    When I run:
      """
      bp send 42
      """
    Then stdout is a single compact JSON line (no embedded newlines in the JSON object)
    And the JSON always contains the stable fields "success", "data"
    And "data" always contains "statusCode", "responseLength", "durationMs"

  @happy @community
  Scenario: Agent chaining — extract requestId from send response and replay with modification
    # Validates the requestId-chaining pattern: /repeater/send returns the persisted requestId
    # which can be fed back as the subject of the next bp send call.
    Given I capture the output of:
      """
      bp send 42 --format json
      """
    When I parse the JSON and extract "data.requestId" as NEW_ID
    And I run:
      """
      bp send $NEW_ID --set-header "X-Custom-Token: abc999" --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/send/batch — BatchSendRequest { requests:List<SendRequest> }
  # bp send --batch @file
  # Strictly sequential. Failure on item N → total abort, zero partials.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Batch send two requestIds sequentially — results in input order
    Given a file "/tmp/batch_two.json" with content:
      """
      {"requests":[{"requestId":42},{"requestId":7}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_two.json --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON object where "data.results" is an array with exactly 2 elements
    And "data.results[0]" has statusCode for request 42
    And "data.results[1]" has statusCode for request 7

  @happy @community
  Scenario: Batch send with per-request modifications applied independently per item
    # Each item in the batch carries its own RequestModifications; they do not bleed across items.
    Given a file "/tmp/batch_mods.json" with content:
      """
      {
        "requests": [
          {"requestId":42,"modifications":{"headers":{"Authorization":"Bearer token_user_a"},"body":"{\"username\":\"alice\"}"}},
          {"requestId":42,"modifications":{"headers":{"Authorization":"Bearer token_user_b"},"body":"{\"username\":\"bob\"}"}}
        ]
      }
      """
    When I run:
      """
      bp send --batch /tmp/batch_mods.json --format json
      """
    Then the exit code is 0
    And "data.results" is an array with exactly 2 elements
    And execution was strictly sequential (item 0 completed before item 1 started)

  @happy @community
  Scenario: Batch send mixes inline HttpRequestData and requestId items in one batch
    Given a file "/tmp/batch_mixed.json" with content:
      """
      {
        "requests": [
          {"requestId":42},
          {"request":{"method":"POST","url":"https://api.example.com/api/login","body":"{\"u\":\"a\",\"p\":\"b\"}"}},
          {"requestId":7}
        ]
      }
      """
    When I run:
      """
      bp send --batch /tmp/batch_mixed.json --format json
      """
    Then the exit code is 0
    And "data.results" is an array with exactly 3 elements

  @happy @community @ledger
  Scenario: Batch send with --tag records a single C4 ledger entry for the entire batch
    Given a file "/tmp/batch_tag.json" with content:
      """
      {"requests":[{"requestId":42},{"requestId":7}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_tag.json --tag batch-recon-phase1 --format json
      """
    Then the exit code is 0
    And running "bp log --tag batch-recon-phase1" returns 1 entry
    And the ledger entry records burp_op "POST /repeater/send/batch"

  @happy @community @ledger
  Scenario: Batch send with --no-ledger does not create any ledger entry
    Given a file "/tmp/batch_noledger.json" with content:
      """
      {"requests":[{"requestId":7}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_noledger.json --no-ledger --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  # ─── batch abort-on-first-failure semantics ────────────────────────────────

  @error @community
  Scenario: Batch aborts on item 1 failure — item 2 is never sent (total abort, zero partials)
    # Spec: /send/batch strictly sequential; failure on item N → abort, no partials returned.
    Given a file "/tmp/batch_abort_item1.json" with content:
      """
      {"requests":[{"requestId":99999},{"requestId":7}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_abort_item1.json --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And "data.results" is absent or empty (zero partial results)
    And the second request is never sent to :8089

  @error @community
  Scenario: Batch aborts on item 2 failure — item 1 result is NOT returned (zero partials)
    Given a file "/tmp/batch_abort_item2.json" with content:
      """
      {"requests":[{"requestId":42},{"requestId":99999}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_abort_item2.json --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And "data.results" is absent or empty (no partial result for item 1)

  @error @community
  Scenario: Batch send with empty requests list returns INVALID_REQUEST 400
    When I run:
      """
      bp send --batch /dev/null --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Batch item with both requestId and inline request returns INVALID_REQUEST 400
    # Each SendRequest has the same exactlyOne constraint as a standalone send.
    Given a file "/tmp/batch_both.json" with content:
      """
      {"requests":[{"requestId":42,"request":{"method":"GET","url":"https://api.example.com/test"}}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_both.json --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Batch send returns SERVICE_UNAVAILABLE 503 when HTTP engine is down
    Given the REST API at :8089/repeater/send/batch will respond with HTTP 503 and body:
      """
      {"success":false,"data":null,"error":{"code":"SERVICE_UNAVAILABLE","message":"engine down"}}
      """
    Given a file "/tmp/batch_503.json" with content:
      """
      {"requests":[{"requestId":42}]}
      """
    When I run:
      """
      bp send --batch /tmp/batch_503.json --format json
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE"

  @error @community
  Scenario: Batch from-file with invalid JSON is rejected with a clear parse error
    Given a file "/tmp/bad_batch.json" with content:
      """
      { "requests": [BROKEN
      """
    When I run:
      """
      bp send --batch /tmp/bad_batch.json --format json
      """
    Then the exit code is non-zero
    And stderr contains "failed to parse batch file" or '"code":"INVALID_REQUEST"'

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /repeater/tab/create — CreateTabRequest
  # bp tab <id>
  # Opens Repeater UI tab. NO traffic. NO DB writes.
  # Silent fallback to https://example.com when both request and requestId are null.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Tab create from requestId — opens UI tab, sends no traffic, writes no DB row
    # Core contract: /tab/create is UI-only; no HTTP request is sent to the target.
    Given the SQLite DB is initialised and history has N entries
    When I run:
      """
      bp tab 42 --name "Login replay" --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line containing '"success":true'
    And no HTTP request is sent to auth.example.com during this operation
    And GET /history on :8089 still returns N entries (no new row inserted)

  @happy @community
  Scenario: Tab create from inline HttpRequestData — opens named tab, no traffic
    When I run:
      """
      bp tab \
        --name "Custom XSS probe" \
        --method GET \
        --url "https://xss.example.com/search?q=<script>alert(1)</script>" \
        --header "Accept: text/html" \
        --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'
    And no HTTP request is sent to xss.example.com during this operation

  @happy @community @serial
  Scenario: Tab create without --name sends null name (encodeDefaults=true)
    # Spec: name:String?=null — null is valid; Burp auto-names the tab.
    When I run:
      """
      bp tab 7 --format json
      """
    Then the exit code is 0
    And the POST /repeater/tab/create body sent to :8089 contains '"name":null'

  @happy @community
  Scenario: Tab create with no request and no requestId silently falls back to https://example.com
    # Spec: both null → server-side silent fallback to https://example.com; no error surfaced.
    When I run:
      """
      bp tab --name "Blank tab" --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'
    And the POST /repeater/tab/create body sent to :8089 contains neither "requestId" nor "request" fields

  @happy @community
  Scenario: Tab create with a nonexistent requestId succeeds silently (no server-side validation)
    # Spec: /tab/create performs no validation of requestId before opening the UI;
    # it may create a broken tab or use the fallback URL silently — never an error.
    When I run:
      """
      bp tab 99999 --name "Ghost tab" --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'

  @happy @community
  Scenario: Tab create has no DB dependency — succeeds regardless of DB state
    Given the SQLite DB at ~/.burp-rest/burpdata is absent or failed to initialise
    When I run:
      """
      bp tab 42 --name "DB-free tab" --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'

  @happy @community @ledger
  Scenario: Tab create with --tag records a C4 ledger entry for the operation
    When I run:
      """
      bp tab 42 --name "Recon Tab" --tag tab-recon-phase1 --format json
      """
    Then the exit code is 0
    And running "bp log --tag tab-recon-phase1" returns 1 entry
    And the ledger entry records burp_op "POST /repeater/tab/create"

  @happy @community @ledger
  Scenario: Tab create with --no-ledger does not create a ledger entry
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp tab 42 --name "No Ledger Tab" --no-ledger --format json
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  @error @community
  Scenario: Tab create with both inline --url and positional requestId returns INVALID_REQUEST
    # exactlyOne constraint applies to CreateTabRequest when both paths are provided.
    When I run:
      """
      bp tab 7 --url https://api.example.com/test --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: Tab create returns INTERNAL_ERROR 500 on unexpected server-side Throwable
    Given the REST API at :8089/repeater/tab/create will respond with HTTP 500 and body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"Repeater UI unavailable"}}
      """
    When I run:
      """
      bp tab 42 --name "Fail Tab" --format json
      """
    Then the exit code is non-zero
    And stderr contains "INTERNAL_ERROR"

  # ═══════════════════════════════════════════════════════════════════════════
  # Security-relevant header injection matrix
  # Proves that each header class is forwarded correctly through RequestModifications.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario Outline: Inject security-relevant header classes via --set-header
    When I run:
      """
      bp send 42 --set-header "<header_name>: <header_value>" --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'
    And the POST /repeater/send body sent to :8089 contains '"<header_name>":"<header_value>"'

    Examples:
      | header_name              | header_value                       |
      | X-Forwarded-For          | 127.0.0.1                          |
      | X-Original-URL           | /admin                             |
      | X-Custom-IP-Authorization | 127.0.0.1                         |
      | Authorization            | Bearer eyJtest.payload.sig         |
      | Cookie                   | role=admin; session=abc123         |
      | Origin                   | https://evil.example.com           |
      | Content-Type             | application/x-www-form-urlencoded  |

  # ═══════════════════════════════════════════════════════════════════════════
  # Chaining scenarios — requestId extraction, IDOR probe, full agent workflow
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @chain
  Scenario: Chain send → modify header → compare status (manual IDOR probe)
    # Different Authorization token on same endpoint; status/length divergence signals IDOR.
    Given I capture the response of:
      """
      bp send 7 --format json
      """
    And I store data.statusCode as STATUS_A and data.responseLength as LEN_A
    When I run:
      """
      bp send 7 --set-header "Authorization: Bearer token_user_b" --format json
      """
    Then the exit code is 0
    And I compare data.statusCode and data.responseLength against STATUS_A / LEN_A
    # Equal status + equal length on a user-scoped endpoint = likely IDOR

  @happy @community @chain
  Scenario: Chain send → extract requestId → open in Repeater tab
    # bp send returns data.requestId which can be fed directly to bp tab.
    Given I run and capture:
      """
      bp send \
        --method GET \
        --url https://api.example.com/api/users/me \
        --header "Authorization: Bearer tok_analyst" \
        --format json
      """
    And I extract "data.requestId" as TAB_ID
    When I run:
      """
      bp tab $TAB_ID --name "Live users/me probe" --format json
      """
    Then the exit code is 0
    And stdout contains '"success":true'

  @happy @community @chain @ledger
  Scenario: Full recon loop — send with privilege escalation, push to tab, both tagged
    Given proxy history entry 42 exists
    When I run the send step:
      """
      bp send 42 \
        --set-header "X-Role: admin" \
        --set-header "Authorization: Bearer tok_escalate" \
        --tag priv-esc-probe \
        --format json
      """
    And I store data.statusCode as ESCALATED_STATUS
    And I run the tab-create step:
      """
      bp tab 42 --name "ANOMALY: priv-esc" --tag priv-esc-probe --format json
      """
    Then both commands exit with code 0
    And running "bp log --tag priv-esc-probe" returns at least 2 entries
    And the entries record burp_ops "POST /repeater/send" and "POST /repeater/tab/create"

  @happy @community @chain
  Scenario: Multi-step authentication workflow via batch — login then fetch protected resource
    Given a file "/tmp/batch_auth_flow.json" with content:
      """
      {
        "requests": [
          {
            "request": {
              "method": "POST",
              "url": "https://target.example.com/api/login",
              "headers": [{"name":"Content-Type","value":"application/json"}],
              "body": "{\"username\":\"alice\",\"password\":\"pass\"}"
            }
          },
          {
            "request": {
              "method": "GET",
              "url": "https://target.example.com/api/dashboard",
              "headers": [{"name":"Cookie","value":"session=from-login-step"}]
            }
          }
        ]
      }
      """
    When I run:
      """
      bp send --batch /tmp/batch_auth_flow.json --format json
      """
    Then the exit code is 0
    And "data.results" contains exactly 2 elements
    And "data.results[0]" has a statusCode (login response)
    And "data.results[1]" has a statusCode (dashboard response)
