Feature: Fuzz Results Retrieval and Filtering
  As a security researcher or AI agent driving bp,
  I want to retrieve, filter, and summarize Intruder attack results
  so that I can triage anomalous responses and understand the shape of a fuzz run.

  # Output rendering (--format/--fields/-w/--quiet) is proven once in 00-output.feature.
  # Cross-cutting errors (CONNECTION_REFUSED, envelope unwrap, PRO_REQUIRED) are
  # proven once in 00-common.feature.
  # Ledger (--tag / --no-ledger) is proven once in 00-common.feature.
  # This file proves: results retrieval REST contract + pagination, anomalous/status/length
  # filters, summarization of large sets, attack status polling schema, partial-results
  # warnings from lifecycle operations, quick-fuzz inline results, community/pro boundary,
  # and endpoint-specific errors and mutual-exclusion rules.

  Background:
    Given Burp Suite is running and the REST API is reachable at http://127.0.0.1:8089
    And an attack was previously created with id "a1b2c3d4" against https://shop.example.com
    And the attack has completed with 50 results (indices 0-49)
    And results include:
      | index | payload                   | statusCode | length | durationMs | contentType      | anomalous | error |
      | 0     | admin                     | 200        | 4820   | 312        | application/json | false     | null  |
      | 1     | root                      | 200        | 4820   | 298        | application/json | false     | null  |
      | 7     | ' OR 1=1--                | 500        | 312    | 105        | text/html        | true      | null  |
      | 12    | <script>alert(1)</script> | 200        | 4820   | 290        | application/json | false     | null  |
      | 23    | ../../../etc/passwd       | 403        | 89     | 88         | text/plain       | true      | null  |
      | 31    | null                      | 200        | 9940   | 440        | application/json | true      | null  |
      | 45    | ../../../../windows       | 500        | 312    | 101        | text/html        | true      | null  |

  # ─────────────────────────────────────────────────────────────────────────
  # §1 — RESULTS RETRIEVAL: REST CONTRACT AND PAGINATION
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Retrieve all results — REST endpoint and row count
    When I run:
      """
      bp fuzz results a1b2c3d4
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/results
    And stdout contains a table with columns: index, payload, status, length, time, contentType, anomalous
    And the table has 50 rows

  @happy @fuzz @community
  Scenario: Pagination — offset and limit map to query parameters
    When I run:
      """
      bp fuzz results a1b2c3d4 --offset 10 --limit 5
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/results?offset=10&limit=5
    And stdout shows exactly 5 rows starting at index 10

  @happy @fuzz @community
  Scenario: limit=0 is the Burp API sentinel meaning "return all results"
    # Must pass limit=0 through unmodified — not treated as "no limit flag"
    When I run:
      """
      bp fuzz results a1b2c3d4 --offset 0 --limit 0
      """
    Then the exit code is 0
    And the REST call includes query param limit=0
    And all 50 results are returned

  # ─────────────────────────────────────────────────────────────────────────
  # §2 — ENDPOINT-SPECIFIC JSON SCHEMA
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: JSON output schema — stable key set and order for agent consumption
    # Proves the exact field contract for /intruder/attack/{id}/results; not re-proven per filter.
    When I run:
      """
      bp fuzz results a1b2c3d4 --format json
      """
    Then the exit code is 0
    And each stdout line is a compact single-line JSON object
    And line 0 matches exactly:
      """
      {"index":0,"payload":"admin","status":200,"length":4820,"time":312,"contentType":"application/json","anomalous":false,"location":null,"requestId":null}
      """
    And line 7 matches exactly:
      """
      {"index":7,"payload":"' OR 1=1--","status":500,"length":312,"time":105,"contentType":"text/html","anomalous":true,"location":null,"requestId":null}
      """
    And the schema is stable (same keys, same order) across all 50 lines

  # ─────────────────────────────────────────────────────────────────────────
  # §3 — --anomalous-only FILTER
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --anomalous-only returns only anomalous rows and passes limit=0 to API
    # 4 anomalous results in fixture: indices 7, 23, 31, 45
    When I run:
      """
      bp fuzz results a1b2c3d4 --anomalous-only
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/results?offset=0&limit=0
    And stdout shows exactly 4 rows
    And the displayed indices are 7, 23, 31, 45
    And every row has anomalous=true

  @happy @fuzz @community
  Scenario: --anomalous-only with zero anomalous results exits 0 with empty output
    Given the attack "a1b2c3d4" has 50 results all with anomalous=false
    When I run:
      """
      bp fuzz results a1b2c3d4 --anomalous-only
      """
    Then the exit code is 0
    And stdout is empty (or shows "0 anomalous results")
    And stderr is empty

  # ─────────────────────────────────────────────────────────────────────────
  # §4 — STATUS CODE FILTER
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --status filters to only rows with that HTTP status code
    When I run:
      """
      bp fuzz results a1b2c3d4 --status 500
      """
    Then the exit code is 0
    And every displayed row has status=500
    And rows 7 and 45 are shown
    And rows with status 200 or 403 are excluded

  @happy @fuzz @community
  Scenario: --status that matches no results returns exit 0 with empty output
    Given no result in attack "a1b2c3d4" has status 302
    When I run:
      """
      bp fuzz results a1b2c3d4 --status 302
      """
    Then the exit code is 0
    And stdout shows 0 rows

  # ─────────────────────────────────────────────────────────────────────────
  # §5 — LENGTH FILTER
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: Length filters — min, max, and combined range
    # Lengths in fixture: 89, 312, 4820, 9940
    When I run:
      """
      bp fuzz results a1b2c3d4 <flags>
      """
    Then the exit code is 0
    And only rows matching <description> are shown

    Examples:
      | flags                           | description                              |
      | --min-length 1000               | length >= 1000 (rows: 4820, 9940)        |
      | --max-length 500                | length <= 500  (rows: 89, 312)           |
      | --min-length 100 --max-length 400 | 100 <= length <= 400 (row: 312 only)   |

  # ─────────────────────────────────────────────────────────────────────────
  # §6 — COMBINED FILTERS
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --anomalous-only and --status combine with AND semantics
    # Anomalous indices: 7 (500), 23 (403), 31 (200), 45 (500)
    When I run:
      """
      bp fuzz results a1b2c3d4 --anomalous-only --status 500
      """
    Then the exit code is 0
    And only indices 7 and 45 are shown (anomalous=true AND status=500)

  # ─────────────────────────────────────────────────────────────────────────
  # §7 — SUMMARIZATION OF LARGE RESULT SETS
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: --summary emits status distribution and anomaly count — no individual rows
    Given the attack "z9x8y7w6" completed with 10000 results
    When I run:
      """
      bp fuzz results z9x8y7w6 --summary
      """
    Then the exit code is 0
    And stdout contains:
      """
      Attack:    z9x8y7w6
      Total:     10000
      Anomalous: 42
      Status distribution:
        200 → 9850
        403 → 108
        500 → 42
      Length range: 89 – 51200 bytes
      Duration range: 88 – 2450 ms
      Content-types:
        application/json → 9872
        text/html        → 128
      """
    And no individual result rows are printed

  @happy @fuzz @community
  Scenario: --summary --format json emits one summary object not N result lines
    Given the attack "z9x8y7w6" has 10000 results
    When I run:
      """
      bp fuzz results z9x8y7w6 --summary --format json
      """
    Then the exit code is 0
    And stdout is a single JSON object:
      """
      {"attackId":"z9x8y7w6","total":10000,"anomalousCount":42,"statusDistribution":{"200":9850,"403":108,"500":42},"lengthMin":89,"lengthMax":51200,"durationMin":88,"durationMax":2450,"contentTypes":{"application/json":9872,"text/html":128}}
      """

  @happy @fuzz @community
  Scenario: --summary --anomalous-only summarizes only the anomalous subset
    When I run:
      """
      bp fuzz results z9x8y7w6 --summary --anomalous-only
      """
    Then the exit code is 0
    And the summary totals reflect only the anomalous subset
    And the header shows "Anomalous subset: 42 of 10000"

  # ─────────────────────────────────────────────────────────────────────────
  # §8 — ATTACK STATUS POLLING SCHEMA
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Poll status — REST endpoint and human-readable output
    When I run:
      """
      bp fuzz status a1b2c3d4
      """
    Then the exit code is 0
    And the REST call is GET /intruder/attack/a1b2c3d4/status
    And stdout shows:
      """
      attackId:   a1b2c3d4
      status:     completed
      progress:   100
      isComplete: true
      """

  @happy @fuzz @community
  Scenario Outline: Status JSON schema reflects current attack state
    # Agent polls bp fuzz status <id> --format json until isComplete=true, then fetches results
    Given the attack "<attackId>" is in state "<state>" at <progress>% progress
    When I run:
      """
      bp fuzz status <attackId> --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"attackId":"<attackId>","status":"<state>","progress":<progress>,"isComplete":<done>}
      """

    Examples:
      | attackId | state     | progress | done  |
      | a1b2c3d4 | completed | 100      | true  |
      | b2c3d4e5 | running   | 60       | false |
      | c3d4e5f6 | paused    | 35       | false |

  # ─────────────────────────────────────────────────────────────────────────
  # §9 — PARTIAL RESULTS FROM LIFECYCLE OPERATIONS
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Pause attack then retrieve partial results — warning on stderr, data on stdout
    Given the attack "b2c3d4e5" is running with 30 results at 60% progress
    When I run:
      """
      bp fuzz pause b2c3d4e5
      """
    Then the exit code is 0
    And the REST call is POST /intruder/attack/b2c3d4e5/pause
    When I run:
      """
      bp fuzz results b2c3d4e5 --format json
      """
    Then the exit code is 0
    And stdout has 30 JSON lines
    And stderr contains "attack is paused — results are partial"

  @happy @fuzz @community
  Scenario: Stop attack then retrieve results collected before stop
    Given the attack "b2c3d4e5" is running with 30 results
    When I run:
      """
      bp fuzz stop b2c3d4e5
      """
    Then the exit code is 0
    And the REST call is POST /intruder/attack/b2c3d4e5/stop
    When I run:
      """
      bp fuzz results b2c3d4e5 --format json
      """
    Then the exit code is 0
    And stdout has 30 JSON lines (results collected before stop)

  @happy @fuzz @community
  Scenario: Resume a paused attack
    Given the attack "b2c3d4e5" is paused at 60%
    When I run:
      """
      bp fuzz resume b2c3d4e5
      """
    Then the exit code is 0
    And the REST call is POST /intruder/attack/b2c3d4e5/resume
    And stdout shows:
      """
      attack b2c3d4e5 resumed
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §10 — QUICK-FUZZ INLINE RESULTS (synchronous, no poll)
  # ─────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: Quick-fuzz returns results inline — REST body and row schema
    Given proxy history entry 3 is a POST to https://api.shop.example.com/login
    When I run:
      """
      bp fuzz 3 --param username --payloads admin,root,"' OR 1=1--"
      """
    Then the exit code is 0
    And the REST call is POST /intruder/quick-fuzz with body:
      """
      {"requestId":3,"param":"username","payloads":["admin","root","' OR 1=1--"],"options":{"throttleMs":0}}
      """
    And stdout is a table with columns: index, payload, status, length, time, contentType, anomalous
    And the table has 3 rows (one per payload)
    And anomalous=true appears for the SQLi payload if its status/length diverges from baseline

  @happy @fuzz @community
  Scenario: Quick-fuzz JSON schema for agent analysis
    When I run:
      """
      bp fuzz 3 --param q --payloads "<script>alert(1)</script>","' OR '1'='1" --format json
      """
    Then the exit code is 0
    And stdout has 2 JSON lines
    And each line has keys: index, payload, status, length, time, contentType, anomalous, error

  @happy @fuzz @community
  Scenario: Quick-fuzz --anomalous-only shows only divergent probes
    When I run:
      """
      bp fuzz 3 --param id --payloads 1,2,999999,"1 OR 1=1" --anomalous-only
      """
    Then the exit code is 0
    And only results where anomalous=true are shown
    # anomalous = statusCode differs OR |Δlength| > max(length*0.2, 20) OR contentType differs

  # ─────────────────────────────────────────────────────────────────────────
  # §11 — COMMUNITY vs PRO BOUNDARY
  # ─────────────────────────────────────────────────────────────────────────

  @community @fuzz
  Scenario: Intruder results work in Community edition (Repeater-backed engine, not Pro-gated)
    Given Burp Suite Community Edition is running at :8089
    And the attack "a1b2c3d4" was executed using RepeaterService
    When I run:
      """
      bp fuzz results a1b2c3d4 --format json
      """
    Then the exit code is 0
    And results are returned without a PRO_REQUIRED error

  @community @fuzz
  Scenario: Cluster-bomb attack executed as sniper server-side — warning surfaced in results
    Given an attack was created with type "cluster-bomb" but only sniper is implemented server-side
    When I run:
      """
      bp fuzz results a1b2c3d4 --format json
      """
    Then the exit code is 0
    And results are present
    And stderr contains:
      """
      warning: attack type 'cluster-bomb' was requested but only 'sniper' is implemented server-side. Results reflect sniper execution. Full cluster-bomb expansion must be done client-side.
      """

  # ─────────────────────────────────────────────────────────────────────────
  # §12 — ENDPOINT-SPECIFIC ERRORS
  # ─────────────────────────────────────────────────────────────────────────

  @error @fuzz @community
  Scenario: Attack id not found — in-memory state hint in error message
    # Burp's attack state is in-memory and lost on restart per §6.4; message must say so
    Given no attack with id "deadbeef" exists (Burp may have restarted)
    When I run:
      """
      bp fuzz results deadbeef
      """
    Then the exit code is non-zero
    And stderr contains "attack 'deadbeef' not found"
    And stderr contains "lost state after a Burp restart" or "Re-run the attack"

  @error @fuzz @community
  Scenario: Missing attack id argument — usage error exit 2
    When I run:
      """
      bp fuzz results
      """
    Then the exit code is 2
    And stderr contains a usage hint for bp fuzz results

  @error @fuzz @community
  Scenario: Attack id with path traversal characters is sanitized before HTTP call
    When I run:
      """
      bp fuzz results "../../etc"
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: invalid attack id '../../etc'
      """

  @error @fuzz @community
  Scenario: Invalid --offset (non-integer) is a usage error
    When I run:
      """
      bp fuzz results a1b2c3d4 --offset abc
      """
    Then the exit code is 2
    And stderr contains:
      """
      error: --offset must be a non-negative integer
      """

  @error @fuzz @community
  Scenario: Negative --limit is a usage error
    When I run:
      """
      bp fuzz results a1b2c3d4 --limit -5
      """
    Then the exit code is 2
    And stderr contains:
      """
      error: --limit must be a non-negative integer (use 0 for all results)
      """

  @error @fuzz @community
  Scenario: Unknown field name in --fields lists valid fields in error
    When I run:
      """
      bp fuzz results a1b2c3d4 --fields index,nonexistent,status
      """
    Then the exit code is 2
    And stderr contains:
      """
      error: unknown field 'nonexistent'. Valid fields: index,payload,status,length,time,contentType,anomalous,location,requestId
      """

  @error @fuzz @community
  Scenario: --summary and --index are mutually exclusive
    When I run:
      """
      bp fuzz results a1b2c3d4 --summary --index 7
      """
    Then the exit code is 2
    And stderr contains:
      """
      error: --summary and --index are mutually exclusive
      """

  @error @fuzz @community
  Scenario: Status call for an unknown attack id returns not-found error
    When I run:
      """
      bp fuzz status unknownXX
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: attack 'unknownXX' not found
      """

  @error @fuzz @community
  Scenario: All results have statusCode=0 — unreachable target warning on stderr
    Given the attack "f1f2f3f4" completed but all 10 results have statusCode=0 and error set
    When I run:
      """
      bp fuzz results f1f2f3f4
      """
    Then the exit code is 0
    And stdout shows 10 rows with status=0
    And stderr contains:
      """
      warning: all results have statusCode=0 — the target may have been unreachable during the attack
      """

  @error @fuzz @community
  Scenario: Quick-fuzz with blank --param is rejected
    When I run:
      """
      bp fuzz 3 --param "" --payloads admin,root
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --param must not be blank (Burp API rejects empty param names)
      """

  @error @fuzz @community
  Scenario: Quick-fuzz without --payloads is rejected
    When I run:
      """
      bp fuzz 3 --param username
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: --payloads must not be empty (provide at least one payload value)
      """

  @error @fuzz @community
  Scenario: Quick-fuzz requestId out of bounds — Burp 500 surfaced with context
    Given proxy history has only 5 entries (indices 0-4)
    When I run:
      """
      bp fuzz 999 --param q --payloads test
      """
    Then the exit code is non-zero
    And stderr contains:
      """
      error: Burp returned 500 INTERNAL_ERROR — requestId 999 may be out of bounds (proxy history has fewer entries)
      """
