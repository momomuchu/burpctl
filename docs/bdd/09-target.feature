# Feature: Target — sitemap + scope management (§6.8)
#
# Ground truth: SPEC.md §6.8 · 6 endpoints · Community (C) · scope in-memory (JVM heap).
#
# Kotlin types:
#   SetScopeRequest  { includes:List<String> (required), excludes:List<String>=[] }
#   AddScopeRequest  { url:String (required) }  — used for BOTH /add AND /remove
#   SitemapEntry     { url:String, method:String, statusCode:Int?, mimeType:String? }
#                     statusCode and mimeType are nullable → serialised as null (encodeDefaults=true)
#
# Key invariants (§6.8):
#   POST /target/scope         = FULL REPLACE: includes=[] WIPES all scope (destructive).
#   GET  /target/scope         = reads in-memory scope ONLY — does NOT reflect Burp UI scope.
#   GET  /target/scope/check   = authoritative Burp engine verdict — DOES reflect Burp UI scope.
#   GET  /target/scope/check without ?url= → INVALID_PARAM inside HTTP 200 envelope (not 4xx).
#   ScopeCheckRequest DTO is DEAD — handler reads url from query param only, never body.
#   POST /target/scope/remove uses SAME DTO as /target/scope/add (AddScopeRequest {url}).
#   GET  /target/sitemap accepts optional ?url= prefix filter; returns SitemapEntry list.
#   In-memory scope is reset on Burp/extension restart (not persisted to disk).
#
# Cross-cutting contracts proven ELSEWHERE — do NOT re-prove here:
#   Output rendering (--format/--fields/-w/--quiet): bdd/00-output.feature
#   CONNECTION_REFUSED, generic --id errors, ApiResponse unwrap, PRO_REQUIRED: bdd/00-common.feature
#
# Tags:
#   @happy     nominal success path
#   @error     error / edge / destructive path
#   @community all six target endpoints run under Community edition (no Pro required)
#   @ledger    exercises Run Ledger behaviour
#   @agent     JSON schema contract for AX/pipeline integration

Feature: Target — sitemap dump, scope management, and authoritative scope check via /target (§6.8)

  As a bug-bounty hunter using `bp`
  I want to dump the Burp sitemap, manage the in-memory scope, and verify scope membership
  so that I can enumerate discovered endpoints, control what is in scope for scanning,
  and get an authoritative verdict from the Burp engine — all with a traceable ledger.

  Background:
    Given the Burp extension is running and reachable at http://127.0.0.1:8089
    And GET /health returns {"success":true,"data":{"status":"ok"}}

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /target/sitemap — optional prefix filter; SitemapEntry list
  # SitemapEntry: { url, method, statusCode:Int?, mimeType:String? }
  # statusCode and mimeType are nullable → present as null (encodeDefaults=true)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Sitemap dump with no filter returns all discovered entries (table)
    Given Burp has discovered entries for multiple hosts
    When I run:
      """
      bp sitemap --format table
      """
    Then the exit code is 0
    And the output is a human-aligned table with columns url, method, statusCode, mimeType
    And at least one row is present

  @happy @community @agent
  Scenario: Sitemap dump in JSON mode — one compact object per line, nullable fields present as null
    Given Burp has entries for shop.internal.example.com
    When I run:
      """
      bp sitemap --format json
      """
    Then the exit code is 0
    And stdout is one compact JSON object per line, each matching:
      """
      {"url":"<string>","method":"<string>","statusCode":<int|null>,"mimeType":"<string|null>"}
      """
    And null fields are serialised as null (encodeDefaults=true), not omitted
    And the JSON schema is stable across invocations

  @happy @community
  Scenario: Sitemap entry with null statusCode serialised as null (not omitted)
    Given Burp has a sitemap entry for https://target.example.com/ws with no recorded status
    When I run:
      """
      bp sitemap https://target.example.com/ws --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"statusCode\":null"

  @happy @community
  Scenario: Sitemap entry with null mimeType serialised as null (not omitted)
    Given Burp has a sitemap entry for https://target.example.com/binary with no recorded MIME
    When I run:
      """
      bp sitemap https://target.example.com/binary --format json
      """
    Then the exit code is 0
    And the JSON line contains "\"mimeType\":null"

  @happy @community
  Scenario: Sitemap prefix filter returns only entries under that prefix — excludes other hosts
    Given Burp has entries for https://target.example.com/api and https://other.example.com
    When I run:
      """
      bp sitemap https://target.example.com --format json
      """
    Then the exit code is 0
    And every JSON line has "url" starting with "https://target.example.com"
    And no JSON line has "url" starting with "https://other.example.com"

  @happy @community
  Scenario: Sitemap deep path prefix filters to that subtree only
    Given Burp has entries for /api/users, /api/orders, /api/admin, and /health
    When I run:
      """
      bp sitemap https://target.example.com/api/v1 --format json
      """
    Then the exit code is 0
    And all returned entries have URLs beginning with "https://target.example.com/api/v1"
    And /api/v2/products does not appear

  @happy @community
  Scenario: Sitemap prefix filter that matches nothing returns empty output (graceful)
    Given Burp has no discovered entries under https://unknown.example.com
    When I run:
      """
      bp sitemap https://unknown.example.com --format json
      """
    Then the exit code is 0
    And stdout is an empty stream (0 JSON lines)
    And bp does NOT raise an error — an empty sitemap result is valid

  @happy @community
  Scenario: Sitemap with empty Burp history returns zero lines (not an error)
    Given Burp's sitemap is empty (no traffic proxied yet)
    When I run:
      """
      bp sitemap --format json
      """
    Then the exit code is 0
    And stdout is an empty stream (0 lines)

  @happy @community @ledger
  Scenario: Sitemap dump with --tag records a C4 ledger entry
    When I run:
      """
      bp sitemap https://target.example.com --tag recon-sitemap-phase1
      """
    Then the exit code is 0
    And running "bp log --tag recon-sitemap-phase1" returns 1 entry
    And the ledger entry records burp_op "GET /target/sitemap"
    And the ledger entry records target "target.example.com"

  @happy @community @ledger
  Scenario: Sitemap dump with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp sitemap https://target.example.com --no-ledger --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  @fuzz @community
  Scenario Outline: Sitemap prefix filter — only entries matching the prefix are returned
    When I run:
      """
      bp sitemap <prefix> --format json
      """
    Then the exit code is 0
    And every JSON line (if any) has "url" starting with "<prefix>"

    Examples:
      | prefix                                    |
      | https://target.example.com               |
      | https://target.example.com/api           |
      | https://target.example.com/api/v1        |
      | https://admin.target.example.com         |

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /target/scope — reads in-memory scope (NOT the Burp UI scope)
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Show scope returns current in-memory includes and excludes (table)
    Given the in-memory scope includes https://app.example.com and excludes https://app.example.com/logout
    When I run:
      """
      bp scope show --format table
      """
    Then the exit code is 0
    And the output table shows columns type, url
    And a row with type="include" and url="https://app.example.com" is present
    And a row with type="exclude" and url="https://app.example.com/logout" is present

  @happy @community @agent
  Scenario: Show scope in JSON mode — single compact object with includes and excludes arrays
    Given the in-memory scope has includes and excludes populated
    When I run:
      """
      bp scope show --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON is parseable by "jq .includes"
    And the JSON is parseable by "jq .excludes"

  @happy @community
  Scenario: Show scope returns empty lists when no scope has been set (fresh state)
    Given no scope has been configured via POST /target/scope
    When I run:
      """
      bp scope show --format json
      """
    Then the exit code is 0
    And the JSON output contains an empty "includes" list
    And the JSON output contains an empty "excludes" list

  @happy @community
  Scenario: Show scope does NOT reflect scope set only via the Burp UI
    Given the Burp UI scope contains "https://ui-only.example.com" (set via Burp GUI)
    And no POST /target/scope call has been made for "https://ui-only.example.com"
    When I run:
      """
      bp scope show --format json
      """
    Then the exit code is 0
    And the JSON output does NOT contain "https://ui-only.example.com"

  @happy @community
  Scenario: bp emits a note on scope show disclosing that output is in-memory state only
    Given Burp is running
    When I run:
      """
      bp scope show --format json
      """
    Then bp emits a note such as:
      """
      Note: GET /target/scope reads the bp in-memory scope, which does not reflect URLs added via the Burp Suite UI. Use 'bp scope check <url>' for the authoritative Burp engine verdict.
      """

  @happy @community @ledger
  Scenario: Show scope with --tag records ledger entry with burp_op GET /target/scope
    When I run:
      """
      bp scope show --tag scope-audit-start
      """
    Then the exit code is 0
    And running "bp log --tag scope-audit-start" returns 1 entry
    And the ledger entry records burp_op "GET /target/scope"

  @happy @community @ledger
  Scenario: Show scope with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp scope show --no-ledger --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /target/scope — SetScopeRequest { includes:List<String>, excludes:List<String>=[] }
  # FULL REPLACE: clear + set. includes=[] WIPES the entire scope. DESTRUCTIVE.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope set with one include replaces the entire previous scope
    Given the in-memory scope previously included "https://old.example.com"
    When I run:
      """
      bp scope set --include https://new.example.com --format json
      """
    Then the exit code is 0
    And the REST call sends POST /target/scope with {"includes":["https://new.example.com"],"excludes":[]}
    And bp scope show returns includes containing only "https://new.example.com"
    And "https://old.example.com" is no longer present

  @happy @community
  Scenario: Scope set with multiple includes sets all of them
    When I run:
      """
      bp scope set \
        --include https://target.example.com \
        --include https://api.target.example.com \
        --include https://staging.target.example.com \
        --format json
      """
    Then the exit code is 0
    And bp scope show returns exactly 3 include entries

  @happy @community
  Scenario: Scope set with excludes sets both includes and excludes
    When I run:
      """
      bp scope set \
        --include https://target.example.com \
        --exclude https://target.example.com/logout \
        --exclude https://target.example.com/static \
        --format json
      """
    Then the exit code is 0
    And the REST body contains "\"includes\":[\"https://target.example.com\"]"
    And the REST body contains "\"excludes\":[\"https://target.example.com/logout\",\"https://target.example.com/static\"]"

  @happy @community
  Scenario: Scope set with omitted --exclude sends excludes as empty list (default)
    When I run:
      """
      bp scope set --include https://target.example.com --format json
      """
    Then the exit code is 0
    And the POST /target/scope body sent to :8089 contains "\"excludes\":[]"

  @error @community
  Scenario: Scope set with no --include argument WIPES the entire scope (destructive full-replace)
    Given the in-memory scope previously included "https://target.example.com"
    When I run:
      """
      bp scope set --format json
      """
    Then the exit code is 0
    And the POST /target/scope body sent to :8089 contains "\"includes\":[]"
    And bp scope show returns an empty includes list
    And stderr contains a warning such as "WARNING: --include not provided; this will clear the entire scope"

  @error @community
  Scenario: Scope set wipe is surfaced as stderr warning even when exit code is 0
    When I run:
      """
      bp scope set
      """
    Then the exit code is 0
    And stderr contains a warning such as "WARNING: includes is empty — all scope entries will be wiped"
    And the POST /target/scope body sent to :8089 contains "\"includes\":[]"

  @happy @community @ledger
  Scenario: Scope set with --tag records the operation in C4 ledger
    When I run:
      """
      bp scope set --include https://target.example.com --tag scope-set-engagement-1
      """
    Then the exit code is 0
    And running "bp log --tag scope-set-engagement-1" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope"

  @happy @community @ledger
  Scenario: Scope set wipe with --tag records the destructive wipe in ledger for audit
    When I run:
      """
      bp scope set --tag scope-wipe-danger
      """
    Then the exit code is 0
    And running "bp log --tag scope-wipe-danger" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope"
    And the ledger entry status is "ok"

  @happy @community @ledger
  Scenario: Scope set with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp scope set --include https://target.example.com --no-ledger --format json
      """
    Then the exit code is 0
    And no Run Ledger entry is written for this operation

  @happy @community
  Scenario: bp warns that in-memory scope is lost on Burp/extension restart
    When I run:
      """
      bp scope set --include https://app.example.com --format json
      """
    Then stderr contains a notice such as:
      """
      Note: scope is stored in-memory (JVM heap) and will be reset on Burp/extension restart. Use 'bp scope set' to restore scope at the start of each session.
      """

  @fuzz @community
  Scenario Outline: Scope set fuzz — various include/exclude combinations all succeed
    When I run:
      """
      bp scope set <flags> --format json
      """
    Then the exit code is 0
    And the REST body sent matches {"includes":<includes_json>,"excludes":<excludes_json>}

    Examples:
      | flags                                                                                                              | includes_json                                               | excludes_json                                     |
      | --include https://a.example.com                                                                                    | ["https://a.example.com"]                                   | []                                                |
      | --include https://a.example.com --include https://b.example.com                                                    | ["https://a.example.com","https://b.example.com"]           | []                                                |
      | --include https://a.example.com --exclude https://a.example.com/logout                                            | ["https://a.example.com"]                                   | ["https://a.example.com/logout"]                  |
      | --include https://a.example.com --exclude https://a.example.com/logout --exclude https://a.example.com/register  | ["https://a.example.com"]                                   | ["https://a.example.com/logout","https://a.example.com/register"] |

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /target/scope/add — AddScopeRequest { url:String (required) }
  # Additive, not a replace. Does NOT clear existing scope entries.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope add appends one URL without removing existing entries (additive)
    Given the in-memory scope includes "https://target.example.com"
    When I run:
      """
      bp scope add https://api.target.example.com --format json
      """
    Then the exit code is 0
    And the REST call sends POST /target/scope/add with {"url":"https://api.target.example.com"}
    And bp scope show returns includes containing "https://target.example.com"
    And bp scope show returns includes containing "https://api.target.example.com"

  @happy @community
  Scenario: Scope add sends AddScopeRequest DTO to /target/scope/add (wire format)
    When I run:
      """
      bp scope add https://target.example.com/api --format json
      """
    Then the exit code is 0
    And the outgoing JSON body to POST /target/scope/add is exactly {"url":"https://target.example.com/api"}

  @happy @community
  Scenario: Scope add on a fresh in-memory scope populates includes from zero
    Given the in-memory scope is empty
    When I run:
      """
      bp scope add https://target.example.com/api --format json
      """
    Then the exit code is 0
    And bp scope show returns includes containing "https://target.example.com/api"

  @happy @community
  Scenario: Scope add of same URL twice is idempotent — no duplicate in includes list
    When I run:
      """
      bp scope add https://target.example.com --format json
      """
    And I run again:
      """
      bp scope add https://target.example.com --format json
      """
    Then both commands exit with code 0
    And bp scope show does not contain "https://target.example.com" more than once in the includes list

  @happy @community
  Scenario: Scope add accepts a URL with no scheme when Burp's engine is lenient (isLenient=true)
    When I run:
      """
      bp scope add not-a-url --format json
      """
    Then the REST call sends POST /target/scope/add with {"url":"not-a-url"}
    And the server response is HTTP 200 (Burp scope engine accepts the string as-is)
    And the exit code is 0

  @error @community
  Scenario: Scope add with missing URL argument returns INVALID_REQUEST
    When I run:
      """
      bp scope add --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST" or "url is required"

  @error @community
  Scenario: Scope add with empty url string returns INVALID_REQUEST
    When I run:
      """
      bp scope add "" --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @happy @community @ledger
  Scenario: Scope add with --tag records the URL addition in the C4 ledger
    When I run:
      """
      bp scope add https://target.example.com/api --tag scope-add-api
      """
    Then the exit code is 0
    And running "bp log --tag scope-add-api" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope/add"
    And the ledger entry records target "target.example.com"

  @happy @community @ledger
  Scenario: Scope add with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp scope add https://target.example.com/api --no-ledger --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  # ═══════════════════════════════════════════════════════════════════════════
  # POST /target/scope/remove — AddScopeRequest { url:String (required) }
  # SAME DTO as /scope/add. Removes/excludes a URL from the in-memory scope.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope remove uses AddScopeRequest DTO — same wire shape as scope add
    When I run:
      """
      bp scope remove https://target.example.com/logout --format json
      """
    Then the exit code is 0
    And the outgoing JSON body to POST /target/scope/remove is exactly {"url":"https://target.example.com/logout"}

  @happy @community
  Scenario: Scope remove excludes the URL from in-memory scope without affecting other entries
    Given the in-memory scope includes "https://target.example.com" and "https://api.target.example.com"
    When I run:
      """
      bp scope remove https://target.example.com/logout --format json
      """
    Then the exit code is 0
    And bp scope show returns excludes containing "https://target.example.com/logout"
    And bp scope show still includes "https://target.example.com"
    And bp scope show still includes "https://api.target.example.com"

  @happy @community
  Scenario: Scope remove of a URL that was never in scope is a graceful no-op
    Given "https://ghost.example.com" is NOT in the in-memory scope
    When I run:
      """
      bp scope remove https://ghost.example.com --format json
      """
    Then the exit code is 0
    And bp does NOT error — removing a non-existent URL is a graceful no-op
    And the in-memory scope is unchanged

  @error @community
  Scenario: Scope remove with missing URL argument returns INVALID_REQUEST
    When I run:
      """
      bp scope remove --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST" or "url is required"

  @error @community
  Scenario: Scope remove with empty url string returns INVALID_REQUEST
    When I run:
      """
      bp scope remove "" --format json
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @happy @community @ledger
  Scenario: Scope remove with --tag records the removal in the C4 ledger
    When I run:
      """
      bp scope remove https://target.example.com/logout --tag scope-remove-logout
      """
    Then the exit code is 0
    And running "bp log --tag scope-remove-logout" returns 1 entry
    And the ledger entry records burp_op "POST /target/scope/remove"

  # ═══════════════════════════════════════════════════════════════════════════
  # GET /target/scope/check — authoritative Burp engine verdict
  # query param: url:String (required) — NOT a body / NOT ScopeCheckRequest DTO
  # Reflects the Burp UI scope (unlike GET /target/scope which is in-memory only).
  # Missing url → INVALID_PARAM inside HTTP 200 envelope (NOT a 400 or 404).
  # ScopeCheckRequest DTO is DEAD — handler uses query param only.
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope check returns true for a URL in Burp engine scope (table)
    Given https://app.example.com is configured in the Burp Suite scope (UI or API)
    When I run:
      """
      bp scope check https://app.example.com/api/v1/users --format table
      """
    Then the exit code is 0
    And the output table shows columns url, inScope
    And the inScope column is "true"

  @happy @community @agent
  Scenario: Scope check in JSON mode — compact object with inScope boolean
    Given https://api.target.example.com is in the Burp Suite UI scope
    When I run:
      """
      bp scope check https://api.target.example.com/v2/orders --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON contains "\"inScope\":true"
    And the JSON field "url" matches "https://api.target.example.com/v2/orders"
    And the JSON schema is stable

  @happy @community
  Scenario: Scope check returns false for a URL not in Burp engine scope
    Given https://out-of-scope.example.com is NOT configured in the Burp Suite scope
    When I run:
      """
      bp scope check https://out-of-scope.example.com/login --format json
      """
    Then the exit code is 0
    And the JSON contains "\"inScope\":false"

  @happy @community
  Scenario: Scope check reflects Burp UI scope — URL set only via UI returns inScope=true
    Given "https://ui-configured.example.com" is set via the Burp GUI only (not via POST /target/scope)
    When I run:
      """
      bp scope check https://ui-configured.example.com/api --format json
      """
    Then the exit code is 0
    And the JSON contains "\"inScope\":true"

  @happy @community
  Scenario: bp discloses that scope check reflects Burp UI scope, not in-memory scope
    Given "https://ui-only.example.com" is added via Burp Suite UI only
    When I run:
      """
      bp scope check https://ui-only.example.com --format json
      """
    Then bp emits a note such as:
      """
      Note: scope check uses the Burp engine (reflects Burp UI scope). This may differ from 'bp scope show' which reads the bp in-memory scope only.
      """

  @happy @community
  Scenario: Scope check sends url as query param — NOT as JSON body (ScopeCheckRequest DTO is dead)
    Given https://api.example.com is in Burp's scope
    When I run:
      """
      bp scope check https://api.example.com --format json
      """
    Then the outgoing HTTP request is:
      """
      GET /target/scope/check?url=https%3A%2F%2Fapi.example.com
      """
    And the request has no body

  @error @community
  Scenario: Scope check without URL returns INVALID_PARAM wrapped in HTTP 200 (not a 4xx)
    When I run:
      """
      bp scope check --format json
      """
    Then the HTTP response from Burp at :8089 was 200 (not 400 or 422)
    And the exit code is non-zero (bp unwraps the envelope and translates INVALID_PARAM to non-zero exit)
    And stderr contains "INVALID_PARAM"
    And stdout is empty (error surfaced to stderr only)

  @error @community
  Scenario: Scope check with empty url string — server returns INVALID_PARAM in HTTP 200 envelope
    When bp sends:
      """
      GET /target/scope/check?url=
      """
    Then the server response body contains {"success":false,"error":{"code":"INVALID_PARAM",...}}
    And bp surfaces this as non-zero exit and prints the error message to stderr

  @happy @community @ledger
  Scenario: Scope check with --tag records verdict in the C4 ledger
    When I run:
      """
      bp scope check https://target.example.com/api --tag scope-check-api
      """
    Then the exit code is 0
    And running "bp log --tag scope-check-api" returns 1 entry
    And the ledger entry records burp_op "GET /target/scope/check"
    And the ledger entry records target "target.example.com"

  @happy @community @ledger
  Scenario: Scope check without --tag is still recorded in the Run Ledger with auto-generated id
    When I run:
      """
      bp scope check https://api.example.com --format json
      """
    Then the exit code is 0
    And a Run Ledger entry is created with burp_op "GET /target/scope/check"
    And the entry has an auto-generated id

  @happy @community @ledger
  Scenario: Scope check with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp scope check https://target.example.com/api --no-ledger --format json
      """
    Then the exit code is 0
    And no new ledger entry is created for this operation

  @ledger
  Scenario: --tag and --no-ledger are mutually exclusive — bp surfaces an error
    When I run:
      """
      bp scope check https://api.example.com --tag my-tag --no-ledger
      """
    Then the exit code is non-zero
    And stderr contains "--tag and --no-ledger cannot be used together"

  @fuzz @community
  Scenario Outline: Scope check across various URL patterns — always returns inScope boolean
    When I run:
      """
      bp scope check <url> --format json
      """
    Then the exit code is 0
    And the JSON contains "\"inScope\":" followed by true or false

    Examples:
      | url                                          |
      | https://app.example.com                      |
      | https://app.example.com/api/v1/users         |
      | https://app.example.com/admin                |
      | https://other.example.com                    |
      | http://app.example.com                       |
      | https://app.example.com:8443                 |
      | https://sub.app.example.com                  |

  # ═══════════════════════════════════════════════════════════════════════════
  # Key invariants: in-memory scope vs Burp engine scope
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Scope show vs scope check show different results when Burp UI scope differs from in-memory
    Given "https://ui-configured.example.com" is in the Burp Suite UI scope
    And the bp in-memory scope is empty (no bp scope commands have been run)
    When I run "bp scope show --format json"
    Then stdout shows includes=[] (in-memory is empty)
    When I run "bp scope check https://ui-configured.example.com --format json"
    Then the JSON contains "\"inScope\":true" (Burp engine sees the UI scope)
    And bp makes the divergence visible to the user

  @happy @community
  Scenario: After scope set, scope show reflects new in-memory state synchronously
    When I run:
      """
      bp scope set --include https://newscope.example.com --format json
      """
    And I run:
      """
      bp scope show --format json
      """
    Then the second command shows includes=["https://newscope.example.com"]
    And the state is updated synchronously (no eventual consistency lag)

  @happy @community
  Scenario: Add then remove a URL leaves in-memory scope unchanged from baseline
    Given the in-memory scope starts empty
    When I run:
      """
      bp scope add https://temp.example.com --format json
      """
    And then I run:
      """
      bp scope remove https://temp.example.com --format json
      """
    And then I run:
      """
      bp scope show --format json
      """
    Then the final scope show response shows includes=[]

  @happy @community
  Scenario: Scope set wipe then re-add restores scope correctly
    Given the in-memory scope includes "https://target.example.com"
    When I run the wipe step:
      """
      bp scope set --format json
      """
    Then bp scope show returns empty includes
    When I run the restore step:
      """
      bp scope add https://target.example.com --format json
      """
    Then bp scope show returns includes containing "https://target.example.com"

  # ═══════════════════════════════════════════════════════════════════════════
  # Community-edition confirmation — all 6 target endpoints require no Pro gate
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: All six target endpoints work under Burp Suite Community edition
    Given Burp Suite Community edition is running at :8089
    When I run each of the following commands:
      | bp sitemap --format json                                                |
      | bp scope show --format json                                             |
      | bp scope set --include https://target.example.com --format json         |
      | bp scope add https://target.example.com/api --format json               |
      | bp scope remove https://target.example.com/logout --format json         |
      | bp scope check https://target.example.com/api --format json             |
    Then all six commands exit with code 0
    And none of the outputs contains "requires Burp Suite Professional"
    And none of the outputs contains "SERVICE_UNAVAILABLE" due to Pro check

  # ═══════════════════════════════════════════════════════════════════════════
  # End-to-end / combined scenarios
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community @ledger
  Scenario: Full scope lifecycle — set, add, remove, verify, all tagged for audit trail
    When I run the set step:
      """
      bp scope set --include https://target.example.com --tag lifecycle-set
      """
    And I run the add step:
      """
      bp scope add https://api.target.example.com --tag lifecycle-add
      """
    And I run the remove step:
      """
      bp scope remove https://target.example.com/logout --tag lifecycle-remove
      """
    And I run the check step:
      """
      bp scope check https://target.example.com/api/users --tag lifecycle-check --format json
      """
    Then all four commands exit with code 0
    And running "bp log --last 4" shows 4 ledger entries tagged lifecycle-set, lifecycle-add, lifecycle-remove, lifecycle-check
    And the scope check JSON contains "\"inScope\":true"

  @happy @community
  Scenario: Sitemap-to-scope workflow — dump sitemap, add discovered hosts to scope
    Given Burp has sitemap entries for https://target.example.com and https://api.target.example.com
    When I run:
      """
      bp sitemap --format json
      """
    And I parse the unique hosts from the JSON output
    And I add each discovered host to scope:
      """
      bp scope add https://target.example.com --format json
      bp scope add https://api.target.example.com --format json
      """
    Then both scope add commands exit with code 0
    And bp scope show returns includes containing both hosts

  @ledger @community
  Scenario: Run Ledger records correct burp_op for all six target subcommands
    When I run "bp sitemap --tag op-sitemap"
    And I run "bp scope show --tag op-scope-show"
    And I run "bp scope set --include https://a.example.com --tag op-scope-set"
    And I run "bp scope add https://b.example.com --tag op-scope-add"
    And I run "bp scope remove https://b.example.com --tag op-scope-remove"
    And I run "bp scope check https://a.example.com --tag op-scope-check"
    Then "bp log --tag op-sitemap" shows burp_op="GET /target/sitemap"
    And "bp log --tag op-scope-show" shows burp_op="GET /target/scope"
    And "bp log --tag op-scope-set" shows burp_op="POST /target/scope"
    And "bp log --tag op-scope-add" shows burp_op="POST /target/scope/add"
    And "bp log --tag op-scope-remove" shows burp_op="POST /target/scope/remove"
    And "bp log --tag op-scope-check" shows burp_op="GET /target/scope/check"

  @ledger @community
  Scenario: --no-ledger suppresses Run Ledger recording for any target subcommand
    When I run "bp sitemap --no-ledger --format json"
    And I run "bp scope show --no-ledger --format json"
    And I run "bp scope check https://app.example.com --no-ledger --format json"
    Then the Run Ledger has no new entries from any of these three invocations
