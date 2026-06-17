# Feature: Security Scan — 5 custom /scan probes (§6.7)
#
# Ground truth: SPEC.md §6.7 · 5 endpoints · Community (C) · all synchronous/blocking.
# Real Kotlin types: AuthBypassRequest · IdorRequest · HeadersBypassRequest ·
#   CorsRequest · EndpointsScanRequest.
# /scan/endpoints requires SQLite DB (~/.burp-rest/burpdata); all others: session-optional.
# SPA HTML catch-all filter: body starts "<!…" AND length >50000 → synthetic status 302 / length 0.
# Error envelope: ApiResponse<T> { success, data, error:{code,message} }
# Error codes: INVALID_REQUEST 400 · SERVICE_UNAVAILABLE 503 · INTERNAL_ERROR 500.
# Probes are NOT recorded in proxy history.
# The /scan group is entirely absent from /docs (OpenAPI); bp must NOT rely on /docs for discovery.
#
# Output contract (--format/--fields/-w/--quiet) is proven once in 00-output.feature.
# Cross-cutting errors (CONNECTION_REFUSED, generic --id, ApiResponse envelope, PRO_REQUIRED)
#   are proven once in 00-common.feature.
#
# Command surface (CLI.md):
#   bp check auth <baseUrl> --endpoints <paths> [--method M]
#   bp check idor <endpoint> --param N --own-values V --target-values V [--method M] [--body S] [--extra-header 'N: V']
#   bp check headers <url> [--method M] [--body S]
#   bp check cors <url> [--method M]
#   bp check endpoints <host> [--tests T,…] [--limit N]
#
# Tags legend:
#   @happy     — nominal success path
#   @error     — error / rejection path
#   @community — runs without Burp Pro licence
#   @ledger    — exercises C4 run-ledger behaviour

Feature: Security Scan — 5 custom /scan probes (§6.7)

  As a bug-bounty hunter using `bp`
  I want to run the 5 custom security-scan probes via POST /scan/*
  So that I can detect auth-bypass, IDOR, header-bypass, CORS misconfigs,
  and mass endpoint vulnerabilities through Burp's HTTP engine with full ledger traceability.

  Background:
    Given the Burp extension is running and reachable at http://127.0.0.1:8089
    And the extension reports {"success":true,"data":{"status":"ok","version":"0.1.0"}} on GET /health

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/auth-bypass  →  bp check auth <baseUrl>
  # AuthBypassRequest { endpoints:List<String>, baseUrl:String, method:String="GET" }
  # Triple-probe per endpoint: withAuth / withoutAuth / cookieOnly.
  # Session must be active for withAuth and cookieOnly probes to carry credentials.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Auth-bypass — triple-probe schema in JSON mode (agent-mode contract)
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/users \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And each output line is valid JSON
    And each JSON line contains fields "endpoint", "probe", "statusCode", "length", "vulnerable"
    And the JSON lines include one object where "probe" equals "withAuth"
    And the JSON lines include one object where "probe" equals "withoutAuth"
    And the JSON lines include one object where "probe" equals "cookieOnly"

  @happy @community
  Scenario: Auth-bypass — three probes emitted per endpoint (N endpoints → 3N rows)
    Given an active session has been set with cookie "session=abc123; role=user"
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/users,/api/admin/config,/api/admin/logs \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 9 probe objects (3 endpoints × 3 probes)

  @happy @community
  Scenario: Auth-bypass — withoutAuth probe returning 200 sets vulnerable=true
    Given an active session has been set with cookie "session=abc123"
    And the target endpoint /api/admin/users responds 200 to all three probes
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/users \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON line where "probe" is "withoutAuth" has "vulnerable" equal to true

  @happy @community
  Scenario: Auth-bypass — POST method forwarded correctly in request body
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/create \
        --method POST \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/auth-bypass request body sent to :8089 contains "\"method\":\"POST\""

  @happy @community @ledger
  Scenario: Auth-bypass — run recorded in C4 ledger with tag
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/users \
        --tag recon-day1
      """
    Then the exit code is 0
    And running "bp log --last 1" shows a ledger entry with tag "recon-day1"
    And the ledger entry records burp_op "POST /scan/auth-bypass"

  @happy @community @ledger
  Scenario: Auth-bypass — --no-ledger suppresses ledger recording
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/users \
        --no-ledger
      """
    Then the exit code is 0
    And running "bp log --last 1" does not show a new ledger entry for this operation

  @error @community
  Scenario: Auth-bypass — empty endpoints list returns INVALID_REQUEST 400
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "endpoints"

  @error @community
  Scenario: Auth-bypass — missing baseUrl positional argument returns INVALID_REQUEST 400
    When I run:
      """
      bp check auth \
        --endpoints /api/admin/users
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "baseUrl"

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/idor  →  bp check idor <endpoint>
  # IdorRequest { endpoint, param, ownValues, targetValues, method="GET", body?, extraHeaders? }
  # Detection: 2xx response AND |Δlength| > 5% of own-value response length → vulnerable=true.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: IDOR — >5% body-length delta sets vulnerable=true
    Given an active session has been set with cookie "session=victim-abc"
    And the body length for own value "123" is 1000 bytes
    And the body length for target value "124" is 1100 bytes (delta 10%)
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 124,125 \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output for target value "124" has "vulnerable" equal to true
    And the JSON output for target value "124" has "deltaPercent" greater than 5.0

  @happy @community
  Scenario: IDOR — delta below 5% does not flag as vulnerable
    Given an active session has been set with cookie "session=victim-abc"
    And the body length for own value "123" is 1000 bytes
    And the body length for target value "999" is 1030 bytes (delta 3%)
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 999 \
        --format json
      """
    Then the exit code is 0
    And the JSON output for target value "999" has "vulnerable" equal to false

  @happy @community
  Scenario: IDOR — non-2xx response (403) does not flag as vulnerable
    Given an active session has been set with cookie "session=victim-abc"
    And the target endpoint for value "999" returns HTTP 403
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 999 \
        --format json
      """
    Then the exit code is 0
    And the JSON output for target value "999" has "vulnerable" equal to false
    And the JSON output for target value "999" has "statusCode" equal to 403

  @happy @community
  Scenario: IDOR — extra headers forwarded in probe request
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp check idor https://target.example.com/api/invoices/{id} \
        --param id \
        --own-values 100 \
        --target-values 101 \
        --extra-header "X-Tenant-ID: tenant-A" \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/idor request body sent to :8089 contains "\"X-Tenant-ID\":\"tenant-A\""

  @happy @community
  Scenario: IDOR — POST method and body payload forwarded correctly
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp check idor https://target.example.com/api/transfer \
        --param account_id \
        --own-values acc-owner \
        --target-values acc-victim \
        --method POST \
        --body '{"amount":1,"currency":"USD"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/idor request body sent to :8089 contains "\"method\":\"POST\""
    And the POST /scan/idor request body sent to :8089 contains "\"body\":\"{\\\"amount\\\":1"

  @happy @community @ledger
  Scenario: IDOR — ledger entry tagged and retrievable, records target host
    Given an active session has been set with cookie "session=victim-abc"
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values 124 \
        --tag idor-orders-phase2
      """
    Then the exit code is 0
    And running "bp log --tag idor-orders-phase2" returns at least one entry
    And the ledger entry records burp_op "POST /scan/idor"
    And the ledger entry records target "target.example.com"

  @error @community
  Scenario: IDOR — missing --param returns INVALID_REQUEST
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --own-values 123 \
        --target-values 124
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "param"

  @error @community
  Scenario: IDOR — empty --own-values returns INVALID_REQUEST
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --param id \
        --own-values "" \
        --target-values 124
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community
  Scenario: IDOR — empty --target-values returns INVALID_REQUEST
    When I run:
      """
      bp check idor https://target.example.com/orders/{id} \
        --param id \
        --own-values 123 \
        --target-values ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/headers  →  bp check headers <url>
  # HeadersBypassRequest { url, method="GET", body? }
  # Sends 16 hardcoded IP-spoof / URL-override headers; count is fixed, not configurable.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Headers-bypass — exactly 16 probe results with full schema in JSON mode
    When I run:
      """
      bp check headers https://target.example.com/admin \
        --method GET \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 16 objects
    And each JSON object contains fields "header", "headerValue", "statusCode", "length", "bypassed"

  @happy @community
  Scenario: Headers-bypass — bypassed=true when header probe downgrades 403 to 200
    Given the endpoint https://target.example.com/admin returns 403 by default
    And the endpoint returns 200 when header "X-Forwarded-For: 127.0.0.1" is present
    When I run:
      """
      bp check headers https://target.example.com/admin \
        --format json
      """
    Then the exit code is 0
    And at least one JSON object has "bypassed" equal to true
    And that JSON object has "statusCode" equal to 200

  @happy @community
  Scenario: Headers-bypass — POST method and body forwarded correctly
    When I run:
      """
      bp check headers https://target.example.com/admin/action \
        --method POST \
        --body '{"action":"reset"}' \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/headers request body sent to :8089 contains "\"method\":\"POST\""
    And the POST /scan/headers request body sent to :8089 contains "\"body\":\"{\\\"action\\\":\\\"reset\\\"}\""

  @happy @community @ledger
  Scenario: Headers-bypass — ledger entry records target URL and operation
    When I run:
      """
      bp check headers https://target.example.com/admin \
        --tag header-bypass-admin
      """
    Then the exit code is 0
    And running "bp log --tag header-bypass-admin" returns 1 entry
    And the ledger entry records burp_op "POST /scan/headers"
    And the ledger entry records target "https://target.example.com/admin"

  @error @community
  Scenario: Headers-bypass — missing URL positional argument returns INVALID_REQUEST
    When I run:
      """
      bp check headers
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "url"

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/cors  →  bp check cors <url>
  # CorsRequest { url, method="GET" }
  # Tests 8 hardcoded crafted origins for credentialed CORS exploitability.
  # Exploitable = reflected origin AND Access-Control-Allow-Credentials: true.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: CORS — exactly 8 origin probe results with full schema in JSON mode
    When I run:
      """
      bp check cors https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains exactly 8 objects
    And each JSON object contains fields "origin", "reflected", "credentialed", "exploitable"

  @happy @community
  Scenario: CORS — reflected origin + credentials allowed sets exploitable=true
    Given the endpoint https://api.target.example.com/data responds with:
      """
      Access-Control-Allow-Origin: https://evil.example.com
      Access-Control-Allow-Credentials: true
      """
    When I run:
      """
      bp check cors https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And the JSON object where "origin" contains "evil.example.com" has "exploitable" equal to true
    And that JSON object has "reflected" equal to true
    And that JSON object has "credentialed" equal to true

  @happy @community
  Scenario: CORS — non-reflected origin sets exploitable=false
    Given the endpoint https://api.target.example.com/data responds with a static ACAO header
    When I run:
      """
      bp check cors https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And all JSON objects where "reflected" is false have "exploitable" equal to false

  @happy @community
  Scenario: CORS — reflected origin without Allow-Credentials sets exploitable=false
    Given the endpoint reflects the origin but does NOT send Access-Control-Allow-Credentials
    When I run:
      """
      bp check cors https://api.target.example.com/data \
        --format json
      """
    Then the exit code is 0
    And the JSON object where "reflected" is true has "credentialed" equal to false
    And that JSON object has "exploitable" equal to false

  @happy @community
  Scenario: CORS — POST method forwarded correctly in request body
    When I run:
      """
      bp check cors https://api.target.example.com/submit \
        --method POST \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/cors request body sent to :8089 contains "\"method\":\"POST\""

  @happy @community @ledger
  Scenario: CORS — ledger entry captures command and target host
    When I run:
      """
      bp check cors https://api.target.example.com/data \
        --tag cors-api-data
      """
    Then the exit code is 0
    And running "bp log --tag cors-api-data" returns 1 entry
    And the ledger entry records burp_op "POST /scan/cors"
    And the ledger entry records target "api.target.example.com"

  @error @community
  Scenario: CORS — missing URL positional argument returns INVALID_REQUEST
    When I run:
      """
      bp check cors
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "url"

  # ─────────────────────────────────────────────────────────────────────────────
  # §6.7 · POST /scan/endpoints  →  bp check endpoints <host>
  # EndpointsScanRequest { host, tests=["auth-bypass","method-switch"], limit=100 }
  # Requires SQLite DB at ~/.burp-rest/burpdata. Returns SERVICE_UNAVAILABLE 503 if absent.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Endpoints — runs auth-bypass and method-switch, returns per-endpoint results
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 10 requests for host "target.example.com"
    When I run:
      """
      bp check endpoints target.example.com \
        --tests auth-bypass,method-switch \
        --limit 100 \
        --format json
      """
    Then the exit code is 0
    And the JSON output contains one result object per tested endpoint
    And each JSON object contains fields "endpoint", "test", "result", "statusCode", "vulnerable"

  @happy @community
  Scenario: Endpoints — default tests list (auth-bypass + method-switch) when --tests omitted
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints target.example.com \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"tests\":[\"auth-bypass\",\"method-switch\"]"

  @happy @community
  Scenario: Endpoints — default limit of 100 sent when --limit omitted
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints target.example.com \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"limit\":100"

  @happy @community
  Scenario: Endpoints — --limit caps tested endpoints count
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 200 requests for host "target.example.com"
    When I run:
      """
      bp check endpoints target.example.com \
        --limit 10 \
        --format json
      """
    Then the exit code is 0
    And the number of distinct endpoints tested does not exceed 10

  @happy @community
  Scenario: Endpoints — --tests auth-bypass only excludes method-switch results
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints target.example.com \
        --tests auth-bypass \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"tests\":[\"auth-bypass\"]"
    And no JSON result object has "test" equal to "method-switch"

  @happy @community
  Scenario: Endpoints — --limit 0 passed as-is, returns empty result set
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints target.example.com \
        --limit 0 \
        --format json
      """
    Then the exit code is 0
    And the POST /scan/endpoints request body sent to :8089 contains "\"limit\":0"
    And the JSON output is an empty array or contains 0 results

  @happy @community @ledger
  Scenario: Endpoints — ledger entry records host and test list
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints target.example.com \
        --tests auth-bypass,method-switch \
        --tag mass-scan-target
      """
    Then the exit code is 0
    And running "bp log --tag mass-scan-target" returns 1 entry
    And the ledger entry records burp_op "POST /scan/endpoints"
    And the ledger entry records target "target.example.com"

  @error @community
  Scenario: Endpoints — DB absent returns SERVICE_UNAVAILABLE 503 (endpoint-specific precondition)
    Given the SQLite DB at ~/.burp-rest/burpdata is absent or failed to initialise
    When I run:
      """
      bp check endpoints target.example.com \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "SERVICE_UNAVAILABLE"
    And stderr contains a message indicating the database is required

  @error @community
  Scenario: Endpoints — missing host positional argument returns INVALID_REQUEST
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "host"

  @error @community
  Scenario: Endpoints — empty host string returns INVALID_REQUEST
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run:
      """
      bp check endpoints "" \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  # ─────────────────────────────────────────────────────────────────────────────
  # SPA HTML catch-all filter — cross-cutting within /scan group (§6.7)
  # body starts "<!…" AND length >50000 → synthetic statusCode=302, length=0.
  # Verified for two distinct probes; threshold boundary proven once.
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: SPA filter — auth-bypass probe on HTML body >50 KB returns synthetic 302 / length 0
    Given the endpoint https://target.example.com/api/admin responds with:
      | body_starts_with | <!DOCTYPE html> |
      | body_length      | 51000           |
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin \
        --format json
      """
    Then the exit code is 0
    And the JSON probe results for "/api/admin" have "statusCode" equal to 302
    And the JSON probe results for "/api/admin" have "length" equal to 0

  @happy @community
  Scenario: SPA filter — headers-bypass probe on HTML body >50 KB returns synthetic 302 / length 0
    Given the endpoint https://target.example.com/admin responds with HTML body >50000 bytes starting "<!DOCTYPE"
    When I run:
      """
      bp check headers https://target.example.com/admin \
        --format json
      """
    Then the exit code is 0
    And all 16 JSON probe objects have "statusCode" equal to 302
    And all 16 JSON probe objects have "length" equal to 0

  @happy @community
  Scenario: SPA filter — does NOT trigger when HTML body is under 50 KB threshold
    Given the endpoint https://target.example.com/api/data responds with:
      | body_starts_with | <!DOCTYPE html> |
      | body_length      | 49000           |
    When I run:
      """
      bp check cors https://target.example.com/api/data \
        --format json
      """
    Then the exit code is 0
    And the JSON output does not universally show statusCode 302

  # ─────────────────────────────────────────────────────────────────────────────
  # Proxy-history isolation — /scan probes not recorded in GET /proxy/history
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Proxy isolation — auth-bypass probes do not appear in proxy history
    Given an active session has been set with cookie "session=abc123"
    And the proxy history has N entries before the scan
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin/users
      """
    Then the exit code is 0
    And GET /proxy/history at :8089 returns N entries (unchanged — probes not recorded)

  @happy @community
  Scenario: Proxy isolation — headers-bypass probes do not appear in proxy history
    Given the proxy history has M entries before the scan
    When I run:
      """
      bp check headers https://target.example.com/admin
      """
    Then the exit code is 0
    And GET /proxy/history at :8089 returns M entries (unchanged)

  # ─────────────────────────────────────────────────────────────────────────────
  # Community licence — all 5 probes available without Burp Pro
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community
  Scenario: All five /scan probes work without Burp Pro licence (Community edition)
    Given Burp Suite Community edition is running at :8089
    When I run each of the following commands:
      | bp check auth https://t.example.com --endpoints /api/test --format json                                              |
      | bp check idor https://t.example.com/r/{id} --param id --own-values 1 --target-values 2 --format json                |
      | bp check headers https://t.example.com/admin --format json                                                           |
      | bp check cors https://t.example.com/api/data --format json                                                           |
      | bp check endpoints t.example.com --format json                                                                        |
    Then all five commands exit with code 0
    And none of the outputs contains "SERVICE_UNAVAILABLE" or "requires Burp Suite Professional"

  # ─────────────────────────────────────────────────────────────────────────────
  # End-to-end pipeline — composed probe workflow
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @community @ledger
  Scenario: Full recon pipeline — auth-bypass → IDOR → CORS on same target, ledger traces each step
    Given an active session has been set with cookie "session=abc123"
    And the SQLite DB is initialised at ~/.burp-rest/burpdata
    When I run auth-bypass scan:
      """
      bp check auth https://target.example.com \
        --endpoints /api/orders \
        --tag pipeline-step1 \
        --format json
      """
    And I run IDOR scan:
      """
      bp check idor https://target.example.com/api/orders/{id} \
        --param id \
        --own-values 100 \
        --target-values 101,102 \
        --tag pipeline-step2 \
        --format json
      """
    And I run CORS scan:
      """
      bp check cors https://target.example.com/api/orders \
        --tag pipeline-step3 \
        --format json
      """
    Then all three commands exit with code 0
    And running "bp log --last 3" shows 3 ledger entries tagged pipeline-step1, pipeline-step2, pipeline-step3
    And all ledger entries record target "target.example.com"

  @happy @community
  Scenario: Sequential auth-bypass then headers-bypass on same endpoint without session clash
    Given an active session has been set with cookie "session=abc123"
    When I run:
      """
      bp check auth https://target.example.com \
        --endpoints /api/admin \
        --format json
      """
    And I run:
      """
      bp check headers https://target.example.com/api/admin \
        --format json
      """
    Then both commands exit with code 0
    And the auth-bypass JSON output contains 3 probe objects
    And the headers JSON output contains 16 probe objects

  @happy @community
  Scenario: Endpoints mass scan followed by CORS check for discovered endpoints
    Given the SQLite DB is initialised at ~/.burp-rest/burpdata
    And the proxy history contains 5 requests for host "target.example.com"
    When I run:
      """
      bp check endpoints target.example.com \
        --tests auth-bypass \
        --limit 5 \
        --format json
      """
    Then the exit code is 0
    And for each vulnerable endpoint in the output I can subsequently run:
      """
      bp check cors https://target.example.com<endpoint_path> \
        --format json
      """
    And each such cors scan exits with code 0
