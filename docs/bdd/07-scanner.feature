# ============================================================
# Feature: 07-scanner — §6.6 /scanner/* (9 endpoints)
#
# Ground-truth: SPEC.md §6.6 only.
# Pro required: POST /scanner/crawl | /audit | /crawl-and-audit
#               GET  /scanner/{id}/status
#               GET  /scanner/{id}/issues
#               POST /scanner/{id}/pause  (STUB — returns status, does NOT pause)
#               POST /scanner/{id}/resume (STUB — returns nothing useful)
#               POST /scanner/{id}/stop   (removes from map; Burp task continues)
# Community-safe: GET /scanner/issue-definitions (reads sitemap; empty list on unavail)
#
# Kotlin types (source-of-truth):
#   ScanRequest    { url:String, config:ScanConfig=() }
#   ScanConfig     { /* fields passed through */ }
#   ScanStatus     { issueCount:Int, crawlProgress:Int=0, auditProgress:Int=0 }
#   ScanIssue      { name:String, url:String,
#                    severity:  HIGH|MEDIUM|LOW|INFORMATION|FALSE_POSITIVE,
#                    confidence: CERTAIN|FIRM|TENTATIVE }
#   scanId         : 8-char String (UUID prefix)
#   ApiResponse<T> : { success:Boolean, data:T?, error:ApiError? }
#   ApiError       : { code:String, message:String }
#
# Spec caveats (must be disclosed by bp CLI):
#   - audit: url field is IGNORED — scope is taken from Burp project scope
#   - pause/resume: STUBS — handler returns scan status; no actual pause in Burp engine
#   - stop: removes scan from in-memory map; underlying Burp task is NOT interrupted
#   - crawlProgress / auditProgress: ALWAYS 0 (stub in current extension)
#   - typeIndex: always 0L
#   - Entire /scanner group is ABSENT from /docs (OpenAPI 0.2.0)
#   - Community: crawl/audit/crawl-and-audit raise IllegalStateException → HTTP 500
#     with message "requires Burp Suite Professional"
#   - issue-definitions: reads sitemap → empty list if unavailable (graceful, Community-safe)
#
# Output/format/ledger contract: proven once in 00-output.feature and 00-common.feature.
# Cross-cutting errors (CONNECTION_REFUSED, PRO_REQUIRED envelope, generic --id invalid):
#   proven once in 00-common.feature — not repeated here.
# Only endpoint-specific schemas and endpoint-specific error contracts appear below.
# ============================================================

@scanner
Feature: Scanner — §6.6 /scanner/* Pro lifecycle (crawl/audit/all),
         status/issues/control (pause/resume/stop) and Community defs

  Background:
    Given the Burp Suite REST extension is listening on http://127.0.0.1:8089
    And the bp CLI is installed and on PATH
    And the default base URL is http://127.0.0.1:8089

  # ═══════════════════════════════════════════════════════════
  # §1  bp scan crawl <url>  — POST /scanner/crawl  (Pro)
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Crawl — happy path returns 8-char scanId and records to ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop
      """
    Then the exit code is 0
    And stdout is a table row containing "SCAN_ID" with an 8-character alphanumeric value
    And the C4 Run Ledger records an entry with:
      | field   | value                    |
      | burp_op | POST /scanner/crawl      |
      | target  | https://ginandjuice.shop |
      | status  | ok                       |

  @happy @pro
  Scenario: Crawl — --format json schema: ApiResponse wrapping {scanId:<8-char>}
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout is exactly one line
    And that line is valid JSON matching:
      """
      {"success":true,"data":{"scanId":"<8-char-alphanum>"},"error":null}
      """
    And the JSON field "data.scanId" has length 8

  @happy @pro
  Scenario: Crawl — passes ScanConfig fields through to the server
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop --config '{"maximumCrawlLinks":200}'
      """
    Then the exit code is 0
    And stdout or stderr contains a scanId

  @happy @pro @ledger
  Scenario: Crawl — --tag labels the C4 ledger entry
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop --tag gin-crawl-01
      """
    Then the exit code is 0
    And the C4 ledger entry has tag="gin-crawl-01"
    And the C4 ledger entry has burp_op="POST /scanner/crawl"

  @happy @pro @ledger
  Scenario: Crawl — --no-ledger suppresses C4 recording entirely
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop --no-ledger
      """
    Then the exit code is 0
    And no new C4 ledger entry is created for this invocation

  @error @community
  Scenario: Crawl on Community — server raises IllegalStateException → HTTP 500 with Pro-required message
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop --format json
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"
    And the HTTP response code from Burp was 500
    And the JSON error envelope has "success":false and "error.code" one of "SERVICE_UNAVAILABLE" or "INTERNAL_ERROR"

  @ledger @community
  Scenario: Crawl on Community — failed scan-start records ledger entry with status=err
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan crawl https://ginandjuice.shop
      """
    Then the exit code is non-zero
    And the C4 ledger entry has status="err" and burp_op="POST /scanner/crawl"

  @error
  Scenario: Crawl — missing positional URL is rejected before any HTTP call
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl
      """
    Then the exit code is 2
    And stderr contains "url" and "required"
    And no request is sent to http://127.0.0.1:8089

  @error
  Scenario: Crawl — empty URL string is rejected with a clear error
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl ""
      """
    Then the exit code is non-zero
    And stderr contains a user-readable error about the empty URL value

  @fuzz
  Scenario: Crawl — non-URL string does not cause bp to panic; error is structured
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan crawl "not-a-url-at-all"
      """
    Then bp does not crash with an unhandled exception
    And any error output is a structured JSON envelope or a clean stderr message
    And stdout does not contain a raw Java/Kotlin stack trace

  @fuzz
  Scenario: Crawl — very long URL (1000 chars) does not cause bp to hang
    Given Burp Suite Professional is active
    When I run with a 1000-character URL value:
      """
      bp scan crawl <1000-char-url>
      """
    Then the command completes within 10 seconds
    And stdout or stderr is a structured response (not silence)

  # ═══════════════════════════════════════════════════════════
  # §2  bp scan audit [<url>]  — POST /scanner/audit  (Pro)
  #     SPEC CAVEAT: url field is IGNORED — scope = Burp project scope
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Audit — url accepted but silently ignored; bp warns on stderr; scanId returned
    Given Burp Suite Professional is active
    And the Burp Suite project scope includes "https://ginandjuice.shop"
    When I run:
      """
      bp scan audit https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout matches:
      """
      {"success":true,"data":{"scanId":"[0-9a-f]{8}"},"error":null}
      """
    And bp emits a warning on stderr: "Note: url is ignored for audit; scope is taken from Burp project scope"

  @happy @pro
  Scenario: Audit — omitting url still starts the scan (url is ignored server-side anyway)
    Given Burp Suite Professional is active
    And the Burp Suite project scope includes "https://ginandjuice.shop"
    When I run:
      """
      bp scan audit --format json
      """
    Then the exit code is 0
    And stdout contains the key "scanId"

  @happy @pro @ledger
  Scenario: Audit — tagged operation records correct burp_op in ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan audit https://ginandjuice.shop --tag audit-run-01 --format json
      """
    Then the exit code is 0
    And the C4 ledger entry has burp_op="POST /scanner/audit" and tag="audit-run-01"

  @error @community
  Scenario: Audit on Community — Pro-required error surfaced to user; HTTP 500 from server
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan audit https://ginandjuice.shop --format json
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"
    And the HTTP response code from Burp was 500

  # ═══════════════════════════════════════════════════════════
  # §3  bp scan all <url>  — POST /scanner/crawl-and-audit  (Pro)
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: All (crawl-and-audit) — happy path returns scanId and records to ledger
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan all https://ginandjuice.shop --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line:
      """
      {"success":true,"data":{"scanId":"<8-char-alphanum>"},"error":null}
      """
    And the C4 ledger records burp_op="POST /scanner/crawl-and-audit"

  @error @community
  Scenario: All (crawl-and-audit) on Community — fails with Pro-required message
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan all https://ginandjuice.shop
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"

  # ═══════════════════════════════════════════════════════════
  # §4  Community gate: all three scan-start subcommands fail; defs does not
  # ═══════════════════════════════════════════════════════════

  @error @community
  Scenario Outline: All three scan-start subcommands fail on Community; no scan tracking created
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan <subcommand> https://ginandjuice.shop --format json
      """
    Then the exit code is non-zero
    And stderr contains "requires Burp Suite Professional"
    And stdout is empty or is a JSON error envelope with "success":false
    And no scan tracking entry is created in bp

    Examples:
      | subcommand |
      | crawl      |
      | audit      |
      | all        |

  @happy @community
  Scenario: Community-safe: defs is NOT gated by Pro check
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan defs --format json
      """
    Then the exit code is 0
    And bp does NOT emit "requires Burp Suite Professional"

  # ═══════════════════════════════════════════════════════════
  # §5  Full Pro lifecycle: all → status → issues → stop
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Full scanner lifecycle — create, poll status, list issues, then stop
    Given Burp Suite Professional is active

    When I run step 1 (start scan):
      """
      bp scan all https://ginandjuice.shop --format json --tag lifecycle-01
      """
    Then step 1 exits 0
    And I capture the JSON field "data.scanId" into $SID
    And $SID has length 8

    When I run step 2 (poll status immediately after start):
      """
      bp scan status $SID --format json
      """
    Then step 2 exits 0
    And stdout is a single compact JSON line
    And the JSON contains key "issueCount" with a non-negative integer value
    And the JSON field "crawlProgress" equals 0
    And the JSON field "auditProgress" equals 0

    When I run step 3 (list issues after scan completes):
      """
      bp scan issues $SID --format json
      """
    Then step 3 exits 0
    And stdout is valid JSON with "success":true
    And the "data" field is a JSON array
    And each element in the array contains keys "name", "url", "severity", "confidence"

    When I run step 4 (stop tracking):
      """
      bp scan stop $SID --quiet
      """
    Then step 4 exits 0

    When I run step 5 (status after stop — scan removed from map):
      """
      bp scan status $SID --format json
      """
    Then step 5 exits non-zero or stdout has "success":false
    And the response indicates scan $SID is no longer tracked

  # ═══════════════════════════════════════════════════════════
  # §6  bp scan status <scanId>  — GET /scanner/{id}/status  (Pro)
  #     ScanStatus { issueCount:Int, crawlProgress:Int, auditProgress:Int }
  #     SPEC CAVEAT: crawlProgress and auditProgress are ALWAYS 0 (stub)
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Status — default table output shows all three ScanStatus fields
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" was started
    When I run:
      """
      bp scan status a1b2c3d4
      """
    Then the exit code is 0
    And stdout is a table with column headers including "ISSUE_COUNT", "CRAWL_PROGRESS", "AUDIT_PROGRESS"
    And the CRAWL_PROGRESS value is 0
    And the AUDIT_PROGRESS value is 0
    And the ISSUE_COUNT value is a non-negative integer

  @happy @pro
  Scenario: Status — --format json schema: ScanStatus object with all three keys always present
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scan status a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is exactly one line
    And that line parses as JSON matching:
      """
      {"success":true,"data":{"issueCount":<int>,"crawlProgress":0,"auditProgress":0},"error":null}
      """
    And "crawlProgress" is 0
    And "auditProgress" is 0

  @happy @pro
  Scenario: Status — crawlProgress and auditProgress are always 0 regardless of actual Burp progress (spec stub)
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has been running for 60 seconds
    When I run:
      """
      bp scan status a1b2c3d4 --format json
      """
    Then the JSON field "data.crawlProgress" is 0
    And the JSON field "data.auditProgress" is 0
    And bp emits a note (once per session): "crawlProgress and auditProgress are stub values — always 0 in current extension"

  @error @pro
  Scenario: Status — unknown scanId returns structured error (exceptions swallowed as HTTP 200 with error body)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan status zzzzzzzz --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains one of: "not found", "error", "unknown scan"

  @fuzz
  Scenario: Status — path-traversal-shaped scan id is sanitised before sending
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan status "../../../etc/passwd"
      """
    Then bp does not construct a path-traversal URL to http://127.0.0.1:8089
    And the exit code is non-zero
    And stderr contains a validation error about the scan id format

  # ═══════════════════════════════════════════════════════════
  # §7  bp scan issues <scanId>  — GET /scanner/{id}/issues  (Pro)
  #     ScanIssue { name, url, severity, confidence }
  #     severity:    HIGH|MEDIUM|LOW|INFORMATION|FALSE_POSITIVE
  #     confidence:  CERTAIN|FIRM|TENTATIVE
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Issues — default table output shows all four ScanIssue fields with correct row count
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has 3 issues
    When I run:
      """
      bp scan issues a1b2c3d4
      """
    Then the exit code is 0
    And stdout is a table with column headers: "NAME", "URL", "SEVERITY", "CONFIDENCE"
    And the table has 3 data rows

  @happy @pro
  Scenario: Issues — --format json schema: array of ScanIssue objects in data field
    Given Burp Suite Professional is active
    And a completed scan with id "a1b2c3d4" has 2 issues
    When I run:
      """
      bp scan issues a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And stdout matches:
      """
      {"success":true,"data":[<issue_object>,<issue_object>],"error":null}
      """
    And each issue object contains keys "name", "url", "severity", "confidence"

  @happy @pro
  Scenario: Issues — empty list returned when scan found zero vulnerabilities (not an error)
    Given Burp Suite Professional is active
    And a completed scan with id "b9c8d7e6" found 0 issues
    When I run:
      """
      bp scan issues b9c8d7e6 --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[],"error":null}
      """
    And bp does not emit any error

  @happy @pro
  Scenario: Issues — unknown scanId returns empty list (exceptions swallowed to HTTP 200 per spec)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan issues zzzzzzzz --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[],"error":null}
      """

  @happy @pro
  Scenario Outline: Issues — all severity × confidence enum combinations are valid in response
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" has an issue with severity <severity> and confidence <confidence>
    When I run:
      """
      bp scan issues a1b2c3d4 --format json
      """
    Then the exit code is 0
    And the response JSON contains an issue with "severity":"<severity>" and "confidence":"<confidence>"

    Examples:
      | severity       | confidence |
      | HIGH           | CERTAIN    |
      | HIGH           | FIRM       |
      | HIGH           | TENTATIVE  |
      | MEDIUM         | CERTAIN    |
      | MEDIUM         | FIRM       |
      | MEDIUM         | TENTATIVE  |
      | LOW            | CERTAIN    |
      | LOW            | FIRM       |
      | LOW            | TENTATIVE  |
      | INFORMATION    | CERTAIN    |
      | INFORMATION    | FIRM       |
      | INFORMATION    | TENTATIVE  |
      | FALSE_POSITIVE | CERTAIN    |
      | FALSE_POSITIVE | FIRM       |
      | FALSE_POSITIVE | TENTATIVE  |

  @fuzz
  Scenario: Issues — 64-character scan id handled gracefully (no unhandled exception)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan issues aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      """
    Then the exit code is 0 or non-zero
    And stdout is valid JSON or stderr is a clean error message
    And no unhandled exception stack trace appears in output

  # ═══════════════════════════════════════════════════════════
  # §8  bp scan pause <scanId>  — POST /scanner/{id}/pause  (Pro; STUB)
  #     SPEC CAVEAT: returns current ScanStatus — does NOT pause the Burp engine
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Pause — stub returns current ScanStatus body (not a "paused" confirmation); bp warns
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scan pause a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line containing "issueCount"
    And the response body is a ScanStatus object (not a "paused" confirmation)
    And bp emits a warning: "pause is a stub — the Burp scan engine continues running"

  @happy @pro
  Scenario: Pause then status — scan is still running, confirming the stub caveat
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run pause:
      """
      bp scan pause a1b2c3d4 --quiet
      """
    And then immediately run status:
      """
      bp scan status a1b2c3d4 --format json
      """
    Then the status response does not contain "paused" as the scan state
    And the scan is still actively running in Burp

  # ═══════════════════════════════════════════════════════════
  # §9  bp scan resume <scanId>  — POST /scanner/{id}/resume  (Pro; STUB)
  #     SPEC CAVEAT: does not resume anything; returns no useful body
  # ═══════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Resume — stub succeeds with HTTP 200; does not resume any paused Burp scan; bp warns
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is in any state
    When I run:
      """
      bp scan resume a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout contains "success":true
    And bp emits a warning: "resume is a stub — no actual pause was in effect, no action taken"

  # ═══════════════════════════════════════════════════════════
  # §10  bp scan stop <scanId>  — POST /scanner/{id}/stop  (Pro)
  #      Removes scanId from in-memory map.
  #      SPEC CAVEAT: underlying Burp task is NOT interrupted.
  # ═══════════════════════════════════════════════════════════

  @happy @pro @ledger
  Scenario: Stop — removes scan from tracking map, warns about Burp task continuity, records to ledger
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scan stop a1b2c3d4 --tag stop-manual-01
      """
    Then the exit code is 0
    And stdout confirms that scan "a1b2c3d4" was removed from bp tracking
    And bp emits a note: "the underlying Burp scan task is not interrupted — only bp tracking is removed"
    And the C4 ledger entry has burp_op="POST /scanner/a1b2c3d4/stop" and tag="stop-manual-01"

  @happy @pro
  Scenario: Stop — --format json returns compact confirmation envelope with success:true
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run:
      """
      bp scan stop a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line with "success":true

  @happy @pro
  Scenario: Stop then status — scan no longer tracked; status returns error or not-found
    Given Burp Suite Professional is active
    And a scan with id "a1b2c3d4" is running
    When I run stop:
      """
      bp scan stop a1b2c3d4 --quiet
      """
    And then I run status:
      """
      bp scan status a1b2c3d4 --format json
      """
    Then the stop command exits 0
    And the status command exits non-zero or returns "success":false
    And the status response indicates scan "a1b2c3d4" is not tracked

  @error @pro
  Scenario: Stop — unknown scanId emits clear diagnostic (not-found or already-stopped)
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan stop zzzzzzzz --format json
      """
    Then bp emits a clear diagnostic indicating "zzzzzzzz" was not found or already stopped

  @error
  Scenario: Stop — blank scan id is rejected before any HTTP call
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan stop "" --format json
      """
    Then the exit code is non-zero
    And stderr contains a user-readable error about the invalid or empty scan id

  # ═══════════════════════════════════════════════════════════
  # §11  bp scan defs  — GET /scanner/issue-definitions  (Community-safe)
  #      Reads sitemap; graceful empty list on unavailability
  # ═══════════════════════════════════════════════════════════

  @happy @community
  Scenario: Defs on Community — returns empty list (graceful degradation, not an error)
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan defs --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[],"error":null}
      """
    And bp does not emit any Pro-required error

  @happy @community
  Scenario: Defs — empty list when sitemap is unavailable is displayed as empty table (not error)
    Given Burp Suite Community edition is active
    And the sitemap service is unavailable
    When I run:
      """
      bp scan defs --format table
      """
    Then the exit code is 0
    And stdout shows an empty table or "no results" indicator

  @happy @pro
  Scenario: Defs on Pro with populated sitemap — returns non-empty array of definition objects
    Given Burp Suite Professional is active
    And the Burp sitemap contains issue definitions
    When I run:
      """
      bp scan defs --format json
      """
    Then the exit code is 0
    And stdout is valid JSON with "success":true
    And the "data" field is a non-empty array of issue definition objects

  @happy @pro @ledger
  Scenario: Defs — --tag records the call in the C4 ledger with correct burp_op
    Given Burp Suite Professional is active
    When I run:
      """
      bp scan defs --tag defn-audit-01
      """
    Then the exit code is 0
    And the C4 ledger entry has burp_op="GET /scanner/issue-definitions" and tag="defn-audit-01"

  @happy @community @ledger
  Scenario: Defs — --no-ledger suppresses C4 recording even on Community
    Given Burp Suite Community edition is active
    When I run:
      """
      bp scan defs --no-ledger --format json
      """
    Then the exit code is 0
    And no new C4 ledger entry is created for this invocation

  @fuzz
  Scenario: Defs — sitemap unavailable on Pro returns graceful empty list (not a crash)
    Given Burp Suite Professional is active
    And the sitemap service is unavailable
    When I run:
      """
      bp scan defs --format json
      """
    Then the exit code is 0
    And stdout equals:
      """
      {"success":true,"data":[],"error":null}
      """
    And no error or stack trace is emitted
