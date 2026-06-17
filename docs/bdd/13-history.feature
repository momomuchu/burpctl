# =============================================================================
# Domain 13 · History  /history — 5 endpoints · C+DB
# Spec reference: SPEC.md §6.13
#
# CONDITIONAL GROUP: registered ONLY when historyDao != null && sitemapDao != null.
# If the SQLite DB at ~/.burp-rest/burpdata fails to init, ALL 5 endpoints return
# 404 (route absent, not a 4xx from handler). bp must probe + degrade gracefully.
#
# Endpoints covered:
#   GET    /history                  — paginated list with full HistoryFilter
#   GET    /history/{id}             — single entry (req + resp retrieval), id:Long
#   GET    /history/sitemap          — host+path+method tuples + hitCount
#   POST   /history/{id}/replay      — verbatim replay via Burp engine
#   DELETE /history                  — destructive wipe (history + sitemap)
#
# Key contracts from §6.13:
#   - HistoryEntryResponse.id          = Long  (not Int)
#   - HistoryPageResponse.total        = Long
#   - SitemapListResponse.total        = Int   (type inconsistency — assumed, not fixed)
#   - Entries sorted id DESC
#   - Bodies truncated to 1 MB at insert
#   - HistoryFilter query params: host, method, statusCode:Int?, source, search,
#       since, until, page:Int=0, pageSize:Int=50
#   - source enum values: proxy | repeater | replay | intruder
#   - ?search= = SQL LIKE unescaped (% and _ are wildcards)
#   - replay: NOT persisted (id=0, source='replay'), RepeaterService may re-insert
#   - DELETE: irreversible, no confirmation, non-transactional between the 2 tables
#   - DB-absent: 404 (route not registered)
#   - id non-Long / absent: INVALID_REQUEST 400
#
# Cross-cutting contracts (proven once, not repeated here):
#   - Output rendering (json/table/raw/quiet/--fields/-w): 00-output.feature
#   - CONNECTION_REFUSED, generic --id invalid, ApiResponse envelope: 00-common.feature
#
# Tags: @happy @error @fuzz @ledger @agent @community
# =============================================================================

@community
Feature: History — paginated traffic log, sitemap, single-entry retrieval, replay, and wipe

  As a bug-bounty hunter or AI security agent driving bp
  I want to query, inspect, replay, and manage the Burp history DB
  So that I can grep secrets, reconstruct request chains, replay verbatim traffic,
  and wipe the slate between engagements — all with full ledger traceability

  Background:
    Given the bp CLI is installed and on PATH
    And the Burp Suite REST extension is listening on http://127.0.0.1:8089
    And the SQLite DB at ~/.burp-rest/burpdata has been successfully initialised
    And historyDao and sitemapDao are non-null (all 5 /history endpoints are registered)
    And the history DB contains at least 20 entries across hosts:
      | host               | method | statusCode | source   |
      | api.acme.corp      | GET    | 200        | proxy    |
      | api.acme.corp      | POST   | 401        | proxy    |
      | api.acme.corp      | POST   | 200        | repeater |
      | admin.acme.corp    | GET    | 403        | proxy    |
      | admin.acme.corp    | DELETE | 200        | intruder |
      | staging.acme.corp  | GET    | 302        | proxy    |
    And the entry with the lowest Long id in the DB is referred to as FIRST_ID
    And the entry with the highest Long id in the DB is referred to as LAST_ID

  # ===========================================================================
  # GET /history — HistoryFilter contract
  # ===========================================================================

  @happy @community
  Scenario: List history with default pagination returns first page of 50 sorted id DESC
    When I run:
      """
      bp history --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON object matches: {"success":true,"data":{...}}
    And "data.total" is a Long integer >= 20
    And "data.entries" is an array with at most 50 elements
    And each element of "data.entries" has the field "id" of type Long
    And the entries are ordered by "id" descending (highest id first)
    And every element contains the fields: id, host, method, statusCode, source, timestamp

  @happy @community
  Scenario: Filter history by host returns only matching entries
    When I run:
      """
      bp history --host api.acme.corp --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "host" equal to "api.acme.corp"
    And no entry with host "admin.acme.corp" or "staging.acme.corp" appears

  @happy @community
  Scenario: Filter history by HTTP method returns only entries with that verb
    When I run:
      """
      bp history --method POST --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "method" equal to "POST"
    And no GET or DELETE entries appear

  @happy @community
  Scenario: Filter history by statusCode returns only entries with that exact status
    When I run:
      """
      bp history --status-code 401 --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "statusCode" equal to 401
    And "data.total" is a Long >= 1

  @happy @community
  Scenario Outline: Filter history by source returns only entries with that source value
    When I run:
      """
      bp history --source <source> --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "source" equal to "<source>"

    Examples:
      | source   |
      | proxy    |
      | repeater |
      | intruder |
      | replay   |

  @happy @community
  Scenario: Filter history by since returns only entries at or after the timestamp
    When I run:
      """
      bp history --since 2024-01-01T00:00:00Z --format json
      """
    Then the exit code is 0
    And every entry's "timestamp" is >= "2024-01-01T00:00:00Z"

  @happy @community
  Scenario: Filter history by until returns only entries at or before the timestamp
    When I run:
      """
      bp history --until 2024-12-31T23:59:59Z --format json
      """
    Then the exit code is 0
    And every entry's "timestamp" is <= "2024-12-31T23:59:59Z"

  @happy @community
  Scenario: Filter history by since and until range returns entries in the window
    When I run:
      """
      bp history \
        --since 2024-06-01T00:00:00Z \
        --until 2024-06-30T23:59:59Z \
        --format json
      """
    Then the exit code is 0
    And every entry's "timestamp" falls in the range [2024-06-01T00:00:00Z, 2024-06-30T23:59:59Z]

  @happy @community
  Scenario: Full HistoryFilter — all parameters combined in one call
    When I run:
      """
      bp history \
        --host api.acme.corp \
        --method POST \
        --status-code 200 \
        --source repeater \
        --since 2024-01-01T00:00:00Z \
        --until 2024-12-31T23:59:59Z \
        --page 0 \
        --page-size 10 \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And every entry has host="api.acme.corp", method="POST", statusCode=200, source="repeater"
    And "data.entries" has at most 10 elements (pageSize=10)
    And "data.total" reflects the total matching count before pagination (not just this page)

  @happy @community
  Scenario: Pagination — page 0 and page 1 return disjoint entry sets
    Given the history contains at least 6 entries for host api.acme.corp
    When I run:
      """
      bp history --host api.acme.corp --page 0 --page-size 3 --format json
      """
    And I store "data.entries[*].id" as PAGE0_IDS
    And I run:
      """
      bp history --host api.acme.corp --page 1 --page-size 3 --format json
      """
    And I store "data.entries[*].id" as PAGE1_IDS
    Then PAGE0_IDS and PAGE1_IDS share no common id values (disjoint pages)
    And entries in PAGE0_IDS have higher id values than entries in PAGE1_IDS (DESC order)

  @happy @community
  Scenario: pageSize=1 returns exactly one entry; total reflects full DB count
    When I run:
      """
      bp history --page 0 --page-size 1 --format json
      """
    Then the exit code is 0
    And "data.entries" has exactly 1 element
    And "data.total" is the full count of all history entries (not 1)

  @happy @community
  Scenario: Search with a plain string matches entries whose URL or body contains that string
    When I run:
      """
      bp history --search "Authorization" --format json
      """
    Then the exit code is 0
    And "data.entries" contains only entries where "Authorization" appears in the stored request or response

  @happy @community
  Scenario: Search with SQL LIKE wildcard percent matches any sequence of characters
    # ?search= is unescaped SQL LIKE — % is a real wildcard
    When I run:
      """
      bp history --search "Bearer %" --format json
      """
    Then the exit code is 0
    And every returned entry contains a "Bearer " token prefix in its stored data
    And the total count may be lower than without --search

  @happy @community @ledger
  Scenario: history list auto-records a LedgerEntry with burp_op GET /history
    When I run:
      """
      bp history --host api.acme.corp --format json --tag history-audit-june
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value              |
      | burp_op | GET /history       |
      | target  | api.acme.corp      |
      | status  | ok                 |
      | tag     | history-audit-june |

  @happy @community @ledger
  Scenario: history list with --no-ledger does not record a LedgerEntry
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp history --no-ledger --format json
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries (unchanged)

  # ===========================================================================
  # GET /history/{id} — single entry retrieval (id:Long)
  # ===========================================================================

  @happy @community
  Scenario: Retrieve a single history entry by Long id returns full req and resp with nullable fields always present
    # encodeDefaults=true: nullable fields are present even if null, never absent
    When I run:
      """
      bp history $LAST_ID --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches: {"success":true,"data":{...}}
    And "data.id" equals LAST_ID (Long)
    And "data" contains the fields: id, host, method, url, statusCode, source, timestamp
    And the JSON response always contains the key "reqBody"   (value may be null, never absent)
    And the JSON response always contains the key "resBody"   (value may be null, never absent)
    And the JSON response always contains the key "resHeaders" (value may be [], never absent)
    And the JSON response always contains the key "statusCode" (value may be null, never absent)

  @happy @community @ledger
  Scenario: history get auto-records a LedgerEntry with burp_op GET /history/{id}
    When I run:
      """
      bp history $LAST_ID --format json --tag single-entry-inspect
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value                |
      | burp_op | GET /history/{id}    |
      | status  | ok                   |
      | tag     | single-entry-inspect |

  @error @community
  Scenario: GET /history/{id} with a non-Long string id returns INVALID_REQUEST 400
    When I run:
      """
      bp history "not-a-long" --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains:
      """
      {"success":false,"error":{"code":"INVALID_REQUEST","message":"<any>"}}
      """

  @error @community
  Scenario: GET /history/{id} with a float id is rejected (Long contract)
    When I run:
      """
      bp history 3.14 --format json
      """
    Then the exit code is non-zero
    And stderr contains a validation error about id being a Long integer

  @error @community
  Scenario: GET /history/{id} with a negative Long id returns an error
    When I run:
      """
      bp history -1 --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"success":false' or a not-found error message

  @error @community
  Scenario: GET /history/{id} with a Long id that does not exist returns not-found error
    When I run:
      """
      bp history 9999999999 --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"success":false'
    And the error message indicates the entry was not found

  # ===========================================================================
  # GET /history/sitemap — host+path+method tuples + hitCount
  # ===========================================================================

  @happy @community
  Scenario: Retrieve sitemap without host filter returns all unique host+path+method tuples
    # SitemapListResponse.total is Int (not Long) per §6.13 — intentional type inconsistency
    When I run:
      """
      bp history sitemap --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches: {"success":true,"data":{...}}
    And "data.total" is a JSON number within Int range (32-bit signed, NOT Long)
    And "data.entries" is an array of sitemap tuple objects
    And each tuple contains the fields: host, path, method, hitCount
    And "data.total" equals the length of "data.entries"

  @happy @community
  Scenario: Retrieve sitemap filtered by host returns only tuples for that host
    When I run:
      """
      bp history sitemap --host api.acme.corp --format json
      """
    Then the exit code is 0
    And every entry in "data.entries" has "host" equal to "api.acme.corp"
    And no tuple with host "admin.acme.corp" or "staging.acme.corp" appears
    And each tuple has a non-negative integer "hitCount"

  @happy @community
  Scenario: Sitemap entries are unique host+path+method combinations with cumulative hitCount
    Given the history contains 3 GET requests to api.acme.corp/v1/users and 2 POST requests to the same path
    When I run:
      """
      bp history sitemap --host api.acme.corp --format json
      """
    Then the exit code is 0
    And the sitemap contains a tuple {host:"api.acme.corp", path:"/v1/users", method:"GET", hitCount:3}
    And the sitemap contains a tuple {host:"api.acme.corp", path:"/v1/users", method:"POST", hitCount:2}
    And each host+path+method combination appears exactly once (tuples are unique)

  @happy @community
  Scenario: Sitemap for a host with no history returns empty entries and total=0
    When I run:
      """
      bp history sitemap --host unknown.nevervisited.corp --format json
      """
    Then the exit code is 0
    And "data.total" is 0
    And "data.entries" is an empty array []

  @happy @community @ledger
  Scenario: history sitemap auto-records a LedgerEntry with burp_op GET /history/sitemap
    When I run:
      """
      bp history sitemap --host api.acme.corp --format json --tag sitemap-recon
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value                |
      | burp_op | GET /history/sitemap |
      | target  | api.acme.corp        |
      | status  | ok                   |
      | tag     | sitemap-recon        |

  @happy @community @agent
  Scenario: Agent uses sitemap in JSON mode to enumerate unique paths for a target (AX mode)
    When an AI agent runs:
      """
      bp history sitemap --host api.acme.corp --format json --fields path,method,hitCount
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And "data.entries" is an array of compact objects each with exactly path, method, hitCount
    And the agent can parse this to build a wordlist of discovered paths

  # ===========================================================================
  # POST /history/{id}/replay — verbatim replay via Burp engine
  # ===========================================================================

  @happy @community
  Scenario: Replay a history entry verbatim returns a live response with durationMs
    # Per §6.13: replay handler sets id=0, source='replay' — NOT persisted by the handler.
    # RepeaterService may re-insert as a side-effect, but the direct handler does not persist.
    When I run:
      """
      bp history replay $LAST_ID --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON matches: {"success":true,"data":{...}}
    And "data.statusCode" is a valid HTTP status code integer
    And "data.durationMs" is a positive integer (live network time, not 0)
    And "data.source" is "replay" (if returned in response)

  @happy @community
  Scenario: Replay result is NOT persisted by the /history/{id}/replay handler (source=replay contract)
    # The handler sets id=0 and source='replay'; any re-insertion comes from RepeaterService
    When I run:
      """
      bp history replay $LAST_ID --format json
      """
    Then the exit code is 0
    And calling "bp history --source replay --format json" immediately after shows
      that any re-inserted entry (if any) has source="replay" confirming the spec contract

  @happy @community @ledger
  Scenario: history replay auto-records a LedgerEntry with burp_op POST /history/{id}/replay
    When I run:
      """
      bp history replay $LAST_ID --format json --tag replay-evidence
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value                     |
      | burp_op | POST /history/{id}/replay |
      | status  | ok                        |
      | tag     | replay-evidence           |
    And the LedgerEntry's "command" field contains the value of LAST_ID

  @happy @community @ledger
  Scenario: history replay with --no-ledger executes the replay without recording in the ledger
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp history replay $LAST_ID --no-ledger --format json
      """
    Then the exit code is 0
    And the Burp engine executes the live replay (statusCode present in stdout)
    And the Run Ledger still has exactly N entries (no new row)

  @error @community
  Scenario: POST /history/{id}/replay with a non-Long id returns INVALID_REQUEST 400
    When I run:
      """
      bp history replay "abc" --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"code":"INVALID_REQUEST"'

  @error @community
  Scenario: POST /history/{id}/replay with an id that no longer exists returns an error
    When I run:
      """
      bp history replay 9999999999 --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains '"success":false'

  @happy @community @agent
  Scenario: Agent replays a history entry and parses live response for differential analysis
    When an AI agent runs:
      """
      bp history replay $LAST_ID --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And "data.statusCode" is an integer (parseable by the agent for differential analysis)
    And "data.durationMs" is a non-negative integer
    And the agent can compare this against the original stored statusCode to detect state drift

  # ===========================================================================
  # DELETE /history — destructive wipe with --confirm safety gate
  # ===========================================================================

  @happy @community
  Scenario: Delete all history with --confirm wipes both history and sitemap tables
    # DELETE is non-transactional between the 2 tables per §6.13 — both should be wiped
    # but if interrupted between the two, one table may still have data
    Given the history contains at least 10 entries
    When I run:
      """
      bp history clear --confirm --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line containing {"success":true,"data":{...}}
    And calling "bp history --format json" immediately after returns "data.total":0
    And calling "bp history sitemap --format json" immediately after returns "data.total":0

  @happy @community @ledger
  Scenario: history clear records a LedgerEntry even though Burp history is now gone
    # The Run Ledger (~/.bp/ledger.db) is independent of the Burp history DB (~/.burp-rest/burpdata)
    When I run:
      """
      bp history clear --confirm --format json --tag wipe-engagement-1
      """
    Then the exit code is 0
    And the most recent Run Ledger entry has:
      | field   | value             |
      | burp_op | DELETE /history   |
      | status  | ok                |
      | tag     | wipe-engagement-1 |
    And calling "bp history --format json" returns "data.total":0  (Burp history wiped)
    And calling "bp log --format json" returns an array with at least N+1 entries (ledger NOT wiped)

  @happy @community @ledger
  Scenario: history clear with --no-ledger wipes history but skips LedgerEntry
    Given the Run Ledger currently has N entries
    When I run:
      """
      bp history clear --confirm --no-ledger
      """
    Then the exit code is 0
    And calling "bp history --format json" returns "data.total":0
    And the Run Ledger still has exactly N entries (no new wipe-record row)

  @error @community
  Scenario: Delete history WITHOUT --confirm is rejected client-side before any REST call
    When I run:
      """
      bp history clear --format json
      """
    Then the exit code is 1
    And stderr contains a safety message referencing "--confirm" requirement
    And NO HTTP DELETE request is sent to http://127.0.0.1:8089/history
    And the history table remains unmodified

  @error @community
  Scenario: Delete history with --confirm=false is also rejected
    When I run:
      """
      bp history clear --confirm=false --format json
      """
    Then the exit code is 1
    And stderr contains the --confirm requirement message

  @error @community
  Scenario: Interactive TTY without --confirm prompts for explicit "yes" confirmation
    Given stdout IS a TTY (interactive terminal session)
    When I run "bp history clear" without the --confirm flag
    Then bp prompts: "This will irreversibly delete all history and sitemap data. Type 'yes' to confirm:"
    And if the user types anything other than "yes", the exit code is 1 and no REST call is made
    And if the user types "yes", bp proceeds with the DELETE /history call

  # ===========================================================================
  # DB-absent — reference scenario (full coverage in 00-common.feature)
  # ===========================================================================

  @error @community
  Scenario: All /history endpoints return graceful error when DB init failed (DB-absent reference)
    Given the SQLite DB at ~/.burp-rest/burpdata failed to initialise (historyDao is null)
    And therefore all 5 /history/* routes are NOT registered in the Ktor router
    When I run:
      """
      bp history --format json
      """
    Then the exit code is non-zero
    And stderr contains a message indicating history is unavailable (e.g. "history unavailable: DB not initialised")
    And NO entry is written to the Run Ledger (the operation did not succeed)

  # ===========================================================================
  # Fuzz / edge cases — HistoryFilter boundary and SQL LIKE injection
  # ===========================================================================

  @fuzz @community
  Scenario: statusCode filter with a non-integer value is handled gracefully
    # Per §6.13: statusCode=abc is ignored (Int? parsing returns null → no filter applied)
    When I run:
      """
      bp history --status-code abc --format json
      """
    Then the exit code is 0 or non-zero
    And if exit code is 0, "data.entries" is the unfiltered list (filter ignored)
    And stdout or stderr contains no unstructured panic output

  @fuzz @community
  Scenario: page=-1 (negative page) is sent and the server responds gracefully
    When I run:
      """
      bp history --page -1 --format json
      """
    Then the exit code is 0 or non-zero
    And stdout or stderr is valid JSON (no unstructured panic output)
    And if exit code is 0, "data.entries" is an array (may be empty)

  @fuzz @community
  Scenario: pageSize=0 is handled gracefully (returns all or is rejected)
    When I run:
      """
      bp history --page-size 0 --format json
      """
    Then the exit code is 0 or non-zero
    And stdout or stderr is valid JSON (no unstructured error)

  @fuzz @community
  Scenario: search with literal percent matches all rows (SQL LIKE wildcard contract)
    # % is an unescaped SQL LIKE wildcard — matches everything
    When I run:
      """
      bp history --search "%" --format json
      """
    Then the exit code is 0
    And "data.entries" is a non-empty array (% matches all rows in SQL LIKE)

  @fuzz @community
  Scenario: search with underscore wildcard matches any single character (SQL LIKE _ contract)
    # _ is an unescaped SQL LIKE wildcard — matches exactly one character
    When I run:
      """
      bp history --search "api_acme" --format json
      """
    Then the exit code is 0
    And "data.entries" may contain entries where _ matched any character in that position

  @fuzz @community
  Scenario: Very large pageSize does not crash — returns all available entries up to DB capacity
    When I run:
      """
      bp history --page-size 100000 --format json
      """
    Then the exit code is 0
    And "data.entries" contains all available entries (no crash, no 500)

  @fuzz @community
  Scenario: Response body resBody is truncated to 1 MB when original exceeded that size
    # Per §6.13: truncation happens at insert time, not at retrieval time
    Given a history entry was captured where the response body exceeded 1 048 576 bytes
    When I run:
      """
      bp history <that-entry-id> --format json
      """
    Then the exit code is 0
    And "data.resBody" is present and its length in bytes is at most 1 048 576

  # ===========================================================================
  # Agent mode (AX) — full JSON pipeline scenarios
  # ===========================================================================

  @happy @community @agent
  Scenario: Agent lists history in JSON mode with --fields for minimal schema (AX-friendly)
    When an AI agent runs:
      """
      bp history \
        --host api.acme.corp \
        --source proxy \
        --format json \
        --fields id,method,statusCode,host
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And each entry in "data.entries" contains exactly the keys: id, method, statusCode, host
    And each "id" is a Long integer (parseable as int64)
    And the agent can iterate the array to build a differential status map per endpoint

  @happy @community @agent
  Scenario: Agent retrieves a single entry in JSON to inspect raw request and response bodies
    When an AI agent runs:
      """
      bp history $LAST_ID --format json --fields id,method,url,reqBody,resBody,statusCode
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And "data" contains exactly the keys: id, method, url, reqBody, resBody, statusCode
    And "data.reqBody" and "data.resBody" are present (may be null — encodeDefaults=true)
    And the agent can scan "data.resBody" for secrets, JWTs, or API keys

  @happy @community @agent
  Scenario: Agent greps for JWT tokens across history using --search eyJ prefix
    When an AI agent runs:
      """
      bp history --search "eyJ" --format json --fields id,host,method,statusCode
      """
    Then the exit code is 0
    And "data.entries" contains entries whose stored request or response body contains "eyJ" (JWT header prefix)
    And each entry's id is a Long usable to retrieve the full entry via "bp history <id>"

  @happy @community @agent
  Scenario: Agent discovers suspicious path via sitemap then replays it for state-drift detection
    Given an AI agent has already run:
      """
      bp history sitemap --host api.acme.corp --format json --fields path,method,hitCount
      """
    And the agent identified path="/api/admin" method="GET" as suspicious (low hitCount)
    When the agent looks up a history entry for that path:
      """
      bp history --host api.acme.corp --method GET --search "/api/admin" --page-size 1 --format json --fields id
      """
    And extracts the id as ADMIN_ENTRY_ID and replays it:
      """
      bp history replay $ADMIN_ENTRY_ID --format json
      """
    Then the exit code is 0
    And "data.statusCode" is a valid HTTP status code
    And the agent can compare the live status against the stored status to detect state changes

  @happy @community @agent
  Scenario: Agent uses -w template to produce one line per entry for awk/jq pipeline processing
    When an AI agent runs:
      """
      bp history --host api.acme.corp -w "%{requestId} %{method} %{status}" --page-size 20
      """
    Then the exit code is 0
    And stdout contains at most 20 lines
    And each line matches: "<Long-id> <VERB> <3-digit-int>"
    And the output is suitable for awk/jq pipeline processing without further JSON parsing

  @happy @community @agent
  Scenario: Agent pipes --quiet history list IDs directly into history get for bulk inspection
    When an AI agent runs:
      """
      bp history --host api.acme.corp --quiet --page-size 5
      """
    Then stdout contains exactly 5 lines each containing a Long id
    And each id can be passed directly to "bp history <id>" without transformation

  @happy @community @agent
  Scenario: Agent relies on non-TTY default JSON output without explicit --format
    Given stdout is not a TTY (piped to another process)
    When an AI agent runs:
      """
      bp history --host api.acme.corp
      """
    Then stdout is compact JSON (default when not-TTY, no --format needed)
    And the JSON schema is stable: "success", "data.total", "data.entries" always present
