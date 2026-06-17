# Feature: Session — set/get/clear auth state, authenticated send, batch send, cookie-jar (§6.11)
#
# Ground truth: SPEC.md §6.11 · 7 endpoints · Community · singleton session.
#
# Critical behavioural flags:
#   - Session (cookies + headers) is a singleton; full replace on /session/set (not merge).
#   - /session/set requires at least one cookie; headers-only → INVALID_REQUEST.
#   - headers field defaults to null when --header is omitted.
#   - /session/send goes through Burp HTTP engine → appears in proxy history.
#   - extraHeaders on send/batch OVERRIDE (not merge) session headers.
#   - Batch send is strictly sequential; abort-on-first-failure (no partial success).
#   - Cookie-jar = auto-captured Set-Cookie; in-memory only; survives /session/clear
#     but is wiped on extension reload (no DB backing).
#   - Session state IS persisted to SQLite (~/. burp-rest/burpdata) and survives soft reload.
#   - All /session/* endpoints are absent from /docs (OpenAPI); bp uses hardcoded spec.
#
# Command surface (CLI.md):
#   bp session set   [--cookie 'K=V']… [--header 'N: V']… [--name NAME]
#   bp session get
#   bp session clear
#   bp session send  --url U [--method M] [--body S] [--extra-header 'N: V']…
#   bp session send  --url U …  (batch: pass multiple --request JSON objects)
#   bp session cookies
#   bp session cookies clear    (clear the cookie-jar)
#
# Output rendering (--format/--fields/-w/--quiet) proven once in 00-output.feature.
# Cross-cutting errors (CONNECTION_REFUSED, INTERNAL_ERROR 500, PRO_REQUIRED, encodeDefaults,
#   ignoreUnknownKeys) proven once in 00-common.feature.
#
# Tags:
#   @happy    — nominal success path
#   @error    — error / rejection path
#   @community — all session endpoints run without Burp Pro
#   @ledger   — exercises C4 run-ledger behaviour

Feature: Session — set/get/clear auth state, authenticated send, batch send, and cookie-jar lifecycle

  As a bug-bounty hunter using `bp`
  I want to manage a shared auth session, issue authenticated HTTP requests through Burp,
  and inspect the auto-captured cookie-jar
  so that I can chain multi-step attacks with full ledger traceability.

  Background:
    Given Burp Suite is running and the extension is listening on http://127.0.0.1:8089
    And the bp CLI is installed and targets http://127.0.0.1:8089 by default

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /session/set  →  bp session set
  # Full replace: existing cookies + headers are wiped and replaced.
  # cookies field is required; headers defaults to null when omitted.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Session set — JSON schema contract (cookies, headers, name fields)
    Given no session is currently active
    When I run:
      """
      bp session set \
        --cookie "PHPSESSID=r2t5uvjq495r4q7ib3vtdjq120" \
        --cookie "role=admin" \
        --header "X-Api-Key: sk-prod-aBcDeFgHiJkLmNoPqRsTuVwX" \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"cookies":{"PHPSESSID":"r2t5uvjq495r4q7ib3vtdjq120","role":"admin"},"headers":{"X-Api-Key":"sk-prod-aBcDeFgHiJkLmNoPqRsTuVwX"},"name":null},"error":null}
      """

  @happy @community
  Scenario: Session set — omitting --header leaves headers field null (default contract)
    When I run:
      """
      bp session set \
        --cookie "auth=v2:user42:hmac" \
        --format json
      """
    Then the exit code is 0
    And the JSON field "data.headers" is null
    And the JSON field "data.cookies" equals {"auth":"v2:user42:hmac"}

  @happy @community
  Scenario: Session set — full replace wipes all previous cookies and headers
    Given a session is active with cookies {"old_token":"dead","legacy":"yes"} and headers {"X-Old":"removed"}
    When I run:
      """
      bp session set \
        --cookie "new_token=fresh" \
        --format json
      """
    Then the exit code is 0
    And the JSON field "data.cookies" equals {"new_token":"fresh"}
    And the JSON field "data.headers" is null
    And "old_token" and "legacy" no longer appear in the session

  @happy @community @ledger
  Scenario: Session set — --name is recorded in ledger as tag
    When I run:
      """
      bp session set \
        --cookie "session_token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig" \
        --cookie "csrf_token=abc123" \
        --header "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig" \
        --name "acme-admin-auth"
      """
    Then the exit code is 0
    And the Run Ledger records an entry with burp_op "POST /session/set" and tag "acme-admin-auth"

  @error @community
  Scenario: Session set — missing --cookie (cookies-only required) returns INVALID_REQUEST 400
    When I run:
      """
      bp session set \
        --header "Authorization: Bearer tok" \
        --format json
      """
    Then the exit code is non-zero
    And stderr or the JSON error code is "INVALID_REQUEST"
    And the message references the missing required "cookies" field

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /session/get  →  bp session get
  # Reads current in-memory session (cookies + headers + name).
  # Returns empty/null data when no session has been set.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Session get — returns active session cookies and headers in JSON
    Given a session is active with cookies {"token":"abc"} and headers {"X-Role":"auditor"}
    When I run:
      """
      bp session get --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches the ApiResponse envelope: {"success":true,"data":{...},"error":null}
    And "data.cookies.token" equals "abc"
    And "data.headers.X-Role" equals "auditor"

  @happy @community
  Scenario: Session get — returns empty/null data when no session has been set
    Given no session has been set since Burp started
    When I run:
      """
      bp session get --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.cookies" is null or {}
    And the JSON field "data.headers" is null or {}

  # ═══════════════════════════════════════════════════════════════════════════
  # DELETE /session/clear  →  bp session clear
  # Wipes cookies + headers. Cookie-jar is NOT affected.
  # Idempotent when called on an already-empty session.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Session clear — wipes cookies/headers but leaves cookie-jar intact
    Given a session is active with cookies {"token":"abc"} and headers {"Authorization":"Bearer x"}
    And the cookie-jar contains {"api.example.com": {"__Secure-sid": "jar-value"}}
    When I run:
      """
      bp session clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And a subsequent "bp session get --format json" shows empty cookies and headers
    And a subsequent "bp session cookies --format json" still shows {"api.example.com":{"__Secure-sid":"jar-value"}}
    And the Run Ledger records an entry with burp_op "DELETE /session/clear"

  @happy @community
  Scenario: Session clear — idempotent when session is already empty
    Given no session has been set
    When I run:
      """
      bp session clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

  @happy @community @ledger
  Scenario: Session clear — --no-ledger suppresses ledger recording
    Given a session is active with cookies {"tok":"v"}
    When I run:
      """
      bp session clear --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is created for this operation

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /session/send  →  bp session send --url U [--method M] [--body S] [--extra-header 'N: V']…
  # Routes through Burp HTTP engine → appears in proxy history.
  # extraHeaders OVERRIDE (not merge) session headers.
  # Works even with no active session (sends without auth).
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Session send — GET request; session cookies injected; appears in proxy history
    Given a session is active with cookies {"session_token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/users/profile" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON field "data.statusCode" is an integer
    And the request appears in the Burp proxy history with the session cookie injected
    And the Run Ledger records an entry with burp_op "POST /session/send" and target "api.example.com"

  @happy @community
  Scenario: Session send — POST with body; JSON schema contract (statusCode + body fields)
    Given a session is active with cookies {"auth_token":"v2-tok"} and headers {"X-Csrf-Token":"csrf99"}
    When I run:
      """
      bp session send \
        --url "https://internal.corp.io/api/orders" \
        --method POST \
        --body '{"product_id":42,"qty":1}' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data.statusCode" is an integer
    And the JSON field "data.body" contains the response body (possibly truncated to 1 MB)

  @happy @community
  Scenario: Session send — extraHeaders override session headers (not merge)
    # §6.11: extraHeaders override, not merge — critical for role-switching attacks
    Given a session is active with headers {"X-Role":"user"}
    When I run:
      """
      bp session send \
        --url "https://app.target.io/admin" \
        --method GET \
        --extra-header "X-Role: admin" \
        --format json
      """
    Then the exit code is 0
    And the outbound request carries "X-Role: admin" (not "X-Role: user")
    And the JSON field "data.statusCode" is present

  @happy @community
  Scenario: Session send — request appears in proxy history (side-effect contract)
    # §6.11: /session/send routes through Burp HTTP engine → recorded in proxy history
    Given a session is active with cookies {"auth":"token"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/items" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And a subsequent "bp proxy --host api.example.com --format json" shows this request

  @happy @community
  Scenario: Session send — works with no active session (sends unauthenticated)
    Given no session has been set (session is empty)
    When I run:
      """
      bp session send \
        --url "https://api.example.com/public/status" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the request appears in Burp history without any session cookie header injected
    And the JSON field "data.statusCode" is present

  @happy @community @ledger
  Scenario: Session send — --tag records operation in C4 ledger
    Given a session is active with cookies {"tok":"secret"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/resource" \
        --method GET \
        --tag "manual-recon-v1" \
        --format json
      """
    Then the exit code is 0
    And the Run Ledger entry has:
      | field   | value              |
      | burp_op | POST /session/send |
      | target  | api.example.com    |
      | tag     | manual-recon-v1    |
      | status  | ok                 |

  @happy @community @ledger
  Scenario: Session send — --no-ledger suppresses ledger recording
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send \
        --url "https://api.example.com/v1/resource" \
        --method GET \
        --no-ledger \
        --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is created for this invocation

  @error @community
  Scenario: Session send — missing --url returns INVALID_REQUEST 400
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send --method GET --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INVALID_REQUEST"
    And the message references the missing required "url" field

  @error @community
  Scenario: Session send — target host unreachable returns error (not a panic)
    Given a session is active with cookies {"tok":"y"}
    And "https://unreachable.internal.invalid/api" is not accessible
    When I run:
      """
      bp session send \
        --url "https://unreachable.internal.invalid/api" \
        --method GET \
        --format json
      """
    Then the exit code is non-zero OR the JSON field "success" is false
    And the error code is "SERVICE_UNAVAILABLE" or "INTERNAL_ERROR"

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /session/send/batch  →  bp session send (batch mode)
  # Strictly sequential; abort-on-first-failure (no partial success).
  # Response array preserves request order.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Batch send — multi-step workflow; array schema; sequential proxy history; single ledger entry
    Given a session is active with cookies {"auth":"Bearer-v2-tok"} and headers {"X-Csrf":"csrf42"}
    When I run:
      """
      bp session send \
        --request '{"method":"GET","url":"https://app.corp.io/api/profile"}' \
        --request '{"method":"POST","url":"https://app.corp.io/api/cart","body":"{\"item\":99}"}' \
        --request '{"method":"GET","url":"https://app.corp.io/api/orders"}' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data" is an array of 3 response objects
    And each element has a "statusCode" field
    And all 3 requests appear in the Burp proxy history in order
    And the Run Ledger records a single batch entry with burp_op "POST /session/send/batch"

  @happy @community
  Scenario: Batch send — response array preserves strict request order (sequential contract)
    # §6.11: batch is strictly sequential; order is guaranteed
    Given a session is active with cookies {"tok":"seq"}
    When I run:
      """
      bp session send \
        --request '{"method":"GET","url":"https://api.example.com/step/1"}' \
        --request '{"method":"GET","url":"https://api.example.com/step/2"}' \
        --request '{"method":"GET","url":"https://api.example.com/step/3"}' \
        --format json
      """
    Then the exit code is 0
    And the JSON data array index 0 corresponds to /step/1
    And the JSON data array index 1 corresponds to /step/2
    And the JSON data array index 2 corresponds to /step/3

  @error @community
  Scenario: Batch send — first request fails; batch aborts; second request NOT executed
    # §6.11: abort-on-first-failure; no partial success
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send \
        --request '{"method":"GET","url":"https://INVALID-HOST-404.invalid/"}' \
        --request '{"method":"GET","url":"https://api.example.com/safe"}' \
        --format json
      """
    Then the exit code is non-zero OR the JSON field "success" is false
    And the second request is NOT executed
    And the error message identifies which request in the batch failed

  @error @community
  Scenario: Batch send — empty request list returns INVALID_REQUEST 400
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INVALID_REQUEST"

  @error @community
  Scenario: Batch send — malformed JSON in --request returns INVALID_REQUEST 400
    # SerializationException → 400 INVALID_REQUEST per §8 StatusPages
    Given a session is active with cookies {"tok":"x"}
    When I run:
      """
      bp session send \
        --request '{not valid json}' \
        --format json
      """
    Then the exit code is non-zero
    And the JSON error code is "INVALID_REQUEST"

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /session/cookie-jar  →  bp session cookies
  # Auto-captured Set-Cookie responses; keyed by domain.
  # In-memory only; survives /session/clear but wiped on extension reload.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Cookie-jar — populated after authenticated send returns Set-Cookie
    Given a session is active with cookies {"auth":"token"}
    And I previously ran "bp session send --url https://api.example.com/login --method POST --body '{}'"
    And the server returned Set-Cookie headers for api.example.com
    When I run:
      """
      bp session cookies --format table
      """
    Then the exit code is 0
    And the output shows a table grouped by domain
    And "api.example.com" appears as a domain row with its captured cookies

  @happy @community
  Scenario: Cookie-jar — JSON schema is a map keyed by domain
    Given the cookie-jar contains auto-captured cookies for "shop.internal.io" domain
    When I run:
      """
      bp session cookies --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON field "data" is a map keyed by domain, e.g.:
      """
      {"shop.internal.io":{"__Host-session":"abc123","csrfToken":"xyz"}}
      """

  @happy @community
  Scenario: Cookie-jar — returns empty map when no authenticated requests have been sent
    Given no authenticated requests have been sent (cookie-jar is empty)
    When I run:
      """
      bp session cookies --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data" is {} (empty map)

  @happy @community
  Scenario: Cookie-jar — survives session clear (in-memory, not DB-backed)
    # §6.11: clear resets cookies/headers but NOT the cookie-jar
    Given the cookie-jar contains {"api.example.com": {"tok": "captured"}}
    When I run "bp session clear --format json"
    Then the exit code is 0
    And a subsequent "bp session cookies --format json" still shows {"api.example.com":{"tok":"captured"}}

  # ═══════════════════════════════════════════════════════════════════════════
  # DELETE /session/cookie-jar  →  bp session cookies clear
  # Wipes the cookie-jar; session (cookies + headers) is NOT affected.
  # Idempotent when jar is already empty.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Cookie-jar clear — jar wiped; session unchanged; ledger entry recorded
    Given the cookie-jar contains {"api.example.com":{"sess":"abc"}}
    And a session is active with cookies {"auth_token":"still-here"}
    When I run:
      """
      bp session cookies clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And a subsequent "bp session cookies --format json" shows data: {}
    And a subsequent "bp session get --format json" still shows {"auth_token":"still-here"} in cookies
    And the Run Ledger records an entry with burp_op "DELETE /session/cookie-jar"

  @happy @community
  Scenario: Cookie-jar clear — idempotent when jar is already empty
    Given the cookie-jar is empty
    When I run:
      """
      bp session cookies clear --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

  # ═══════════════════════════════════════════════════════════════════════════
  # Persistence contracts
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Session state persists to SQLite — survives extension soft reload
    # §6.11: SessionDao writes to ~/.burp-rest/burpdata; in-memory session restored after soft reload
    Given the SQLite DB at ~/.burp-rest/burpdata is initialized
    When I run:
      """
      bp session set \
        --cookie "persist_tok=db-persisted" \
        --name "persisted-session" \
        --format json
      """
    Then the exit code is 0
    And the session is retrievable via "bp session get" after a Burp extension soft reload

  @happy @community
  Scenario: Cookie-jar is in-memory only — wiped on extension reload (no DB backing)
    # §6.11: cookie-jar is never written to SQLite
    Given the cookie-jar contains {"api.example.com":{"sess":"abc"}}
    When the Burp extension is reloaded
    Then "bp session cookies --format json" shows data: {}

  @happy @community
  Scenario: Session endpoints absent from /docs — bp uses hardcoded spec, not runtime /docs
    # §6.11: /session/* routes are absent from the embedded OpenAPI at GET /docs
    When I run "bp health --format json"
    Then the /docs endpoint returns OpenAPI spec that omits /session/* routes
    But "bp session get --format json" still succeeds (bp does not rely on /docs for discovery)

  # ═══════════════════════════════════════════════════════════════════════════
  # Multi-step / combined workflow scenarios
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Session refresh pattern — update session mid-workflow with new token
    Given a session is active with cookies {"old_token":"expired-abc"}
    And I run "bp session send --url https://auth.example.com/refresh --method POST --body '{\"refresh\":\"rtoken99\"}' --format json"
    And the response includes Set-Cookie "new_token=fresh-xyz"
    When I run:
      """
      bp session set \
        --cookie "new_token=fresh-xyz" \
        --name "refreshed-session" \
        --format json
      """
    Then the exit code is 0
    And a subsequent fuzz run uses "new_token=fresh-xyz" (not the expired cookie)

  @happy @community
  Scenario: extraHeaders on batch override session headers — enables per-request role-switching
    # §6.11: extraHeaders override (not merge) — useful for privilege-escalation probes
    Given a session is active with cookies {"auth":"user-tok"} and headers {"X-Role":"user"}
    When I run:
      """
      bp session send \
        --request '{"method":"GET","url":"https://admin.internal.io/api/users","extraHeaders":{"X-Role":"admin"}}' \
        --request '{"method":"GET","url":"https://admin.internal.io/api/users","extraHeaders":{"X-Role":"superadmin"}}' \
        --format json
      """
    Then the exit code is 0
    And request 1 in Burp history carries "X-Role: admin" (overrides session "X-Role: user")
    And request 2 in Burp history carries "X-Role: superadmin"

  @happy @community
  Scenario: Cookie-jar auto-capture enables chained login → admin access workflow
    Given no session is active
    When I run:
      """
      bp session send \
        --url "https://webapp.target.io/login" \
        --method POST \
        --body '{"username":"test@corp.io","password":"Passw0rd!"}' \
        --format json
      """
    Then the exit code is 0
    And the server returns Set-Cookie for "webapp.target.io"
    When I run "bp session cookies --format json"
    Then the cookie-jar JSON shows cookies for "webapp.target.io" domain
    When I run:
      """
      bp session send \
        --url "https://webapp.target.io/api/admin/users" \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the request to /api/admin/users includes the auto-captured cookie from the login response

  @happy @community
  Scenario: Auth state maintained across fuzz — session injected into every intruder request
    Given a session is active with cookies {"auth_token":"eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sig"} and headers {"X-Csrf-Token":"f3e4d5c6"}
    And proxy history entry 7 is a POST to "https://api.shop.io/api/search?q=shoes"
    When I run:
      """
      bp fuzz 7 \
        --pos 'query:q' \
        --type sniper \
        --payloads q="' OR '1'='1" \
        --format json
      """
    Then the exit code is 0
    And each fuzz request in the Burp history carries the "auth_token" cookie and "X-Csrf-Token" header
    And the JSON output is an array of result objects each with fields: index, payload, status, length
