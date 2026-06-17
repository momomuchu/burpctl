# Feature: Run Ledger — auto-record, query, tag, and replay every bp operation (§9)
#
# Ground truth: SPEC.md §9 — C4 Run Ledger (SQLite at ~/.bp/ledger.db)
#
# LedgerEntry fields:
#   id, name, tag, timestamp (ISO-8601), target (host/url), command (raw bp argv),
#   request_ref, response_ref, status (ok|err), burp_op
#
# Critical behavioural contracts:
#   - EVERY bp operation is auto-recorded unless --no-ledger is given.
#   - Failed operations (Burp REST error, target unreachable) are ALSO recorded with status=err.
#   - --no-ledger suppresses recording; --tag is silently ignored when --no-ledger is set.
#   - --no-ledger does NOT suppress normal stdout output.
#   - Ledger is SQLite-backed and persists across process restarts.
#   - If ledger DB is unavailable, bp prints a warning but still executes the op.
#   - request_ref and response_ref are non-null for completed operations (chain traceability).
#   - command field stores the verbatim bp argv for forensic replay.
#   - name and tag are independent fields; name gives a human-readable run identity.
#   - No-match filters return exit 0 with empty result (not an error).
#
# Command surface (CLI.md):
#   bp log [--tag T] [--target H] [--since ISO] [--until ISO] [--status ok|err]
#          [--burp-op OP] [--name N] [--limit N]
#   bp tag <opId> <label>
#
# NOTE: bp show and bp replay are NOT in CLI.md and are excluded from this file.
#   Scenarios referencing those commands have been removed.
#
# Output rendering (--format/--fields/-w/--quiet) proven once in 00-output.feature.
# Cross-cutting errors (CONNECTION_REFUSED, PRO_REQUIRED) proven once in 00-common.feature.
#
# Tags:
#   @happy    — nominal success path
#   @error    — error / rejection path
#   @community — ledger is a local SQLite; no Burp Pro required

@ledger
Feature: Run Ledger — every bp operation is recorded, queryable, and taggable

  As a bug-bounty hunter or security auditor
  I want every bp operation automatically recorded in a local SQLite ledger
  So that I can prove, date, and replay every action taken against a target (ISO traceability)

  Background:
    Given the bp CLI is installed and on PATH
    And the Burp Suite REST extension is listening on http://127.0.0.1:8089
    And the Run Ledger DB has been initialised at ~/.bp/ledger.db
    And the proxy history contains at least one entry with requestId 7 targeting api.acme.corp

  # ═══════════════════════════════════════════════════════════════════════════
  # AUTO-RECORDING — every op writes a LedgerEntry
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Repeater send auto-records LedgerEntry with status ok, command, target, timestamp
    Given no prior ledger entries exist for tag "baseline-check"
    When I run:
      """
      bp send 7 --tag baseline-check
      """
    Then the exit code is 0
    And a new entry appears in "bp log" with fields:
      | field   | value               |
      | tag     | baseline-check      |
      | target  | api.acme.corp       |
      | burp_op | POST /repeater/send |
      | status  | ok                  |
    And the entry's "command" field contains the exact string "bp send 7 --tag baseline-check"
    And the entry's "timestamp" is an ISO-8601 datetime within the last 60 seconds

  @happy @community
  Scenario: Quick-fuzz auto-records LedgerEntry with correct burp_op
    When I run:
      """
      bp fuzz 12 --param q --payloads q=payloads.txt --tag xss-sqli-lfi
      """
    Then the exit code is 0
    And "bp log --tag xss-sqli-lfi" returns exactly 1 entry
    And that entry's "burp_op" is "POST /intruder/quick-fuzz"
    And that entry's "status" is "ok"
    And that entry's "target" matches "api.acme.corp"

  @happy @community
  Scenario: Full intruder attack (create+start) auto-records one LedgerEntry per phase
    When I run:
      """
      bp fuzz 3 \
        --pos body:username \
        --payloads username=usernames.txt \
        --type sniper \
        --throttle-ms 200 \
        --tag enum-users-2024
      """
    Then the exit code is 0
    And "bp log --tag enum-users-2024" returns at least 2 entries
    And one entry has "burp_op" = "POST /intruder/attack/create"
    And one entry has "burp_op" = "POST /intruder/attack/{id}/start"
    And all entries have "status" = "ok"

  @happy @community
  Scenario: Session send auto-records even when no --tag is provided (tag is null/empty)
    When I run:
      """
      bp session send --url https://api.acme.corp/v1/profile --method GET
      """
    Then the exit code is 0
    And "bp log --target api.acme.corp" shows a new entry for this operation
    And the entry's "tag" field is empty or null
    And the entry's "burp_op" is "POST /session/send"

  @happy @community
  Scenario: Security scan (auth-bypass) auto-records with full command stored verbatim
    When I run:
      """
      bp check auth https://api.acme.corp \
        --endpoints /api/admin,/api/users \
        --method GET \
        --tag auth-bypass-sprint42
      """
    Then the exit code is 0
    And "bp log --tag auth-bypass-sprint42" returns 1 entry
    And the entry's "burp_op" is "POST /scan/auth-bypass"
    And the entry's "command" starts with "bp check auth"

  # ═══════════════════════════════════════════════════════════════════════════
  # bp log — list and filter
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: bp log with no filter lists all entries sorted newest first
    Given the ledger contains 5 entries recorded in the last hour
    When I run:
      """
      bp log
      """
    Then the exit code is 0
    And the output table has at least 5 rows
    And the rows are ordered by timestamp descending

  @happy @community
  Scenario: bp log JSON schema contract — all LedgerEntry fields present in each element
    # One JSON schema assertion kept; --format rendering proven in 00-output.feature
    Given the ledger contains entries for target "api.acme.corp"
    When I run:
      """
      bp log --target api.acme.corp --format json
      """
    Then the exit code is 0
    And stdout is a JSON array where each element contains keys:
      | id | name | tag | timestamp | target | command | request_ref | response_ref | status | burp_op |
    And each JSON object is on a single line (compact, not pretty-printed)
    And the array is ordered by timestamp descending
    And no key is conditionally absent (all fields always present, null when empty)

  @happy @community
  Scenario: bp log --tag filters to only matching entries
    Given the ledger contains entries tagged "sprint-42" and entries tagged "sprint-43"
    When I run:
      """
      bp log --tag sprint-42
      """
    Then the exit code is 0
    And every row in the output has tag = "sprint-42"
    And no row with tag = "sprint-43" appears

  @happy @community
  Scenario: bp log --target filters entries by hostname
    Given the ledger contains entries targeting "api.acme.corp" and "staging.acme.corp"
    When I run:
      """
      bp log --target api.acme.corp
      """
    Then every returned entry's target contains "api.acme.corp"
    And no entry targeting "staging.acme.corp" appears

  @happy @community
  Scenario: bp log --since and --until filter entries by time window
    Given the ledger contains entries from today and from 2 days ago
    When I run:
      """
      bp log --since 2024-06-01T00:00:00Z --until 2024-06-01T23:59:59Z
      """
    Then the exit code is 0
    And every returned entry's timestamp falls within the range 2024-06-01T00:00:00Z to 2024-06-01T23:59:59Z

  @happy @community
  Scenario: bp log --status err shows only failed operations (burp_op and command populated even on failure)
    Given the ledger contains both successful and failed entries
    When I run:
      """
      bp log --status err --format json
      """
    Then the exit code is 0
    And every entry in the JSON array has "status": "err"
    And each entry's "burp_op" and "command" fields are populated even for failed ops

  @happy @community
  Scenario: bp log --burp-op filters by the REST endpoint called
    When I run:
      """
      bp log --burp-op "POST /repeater/send" --format json
      """
    Then every returned entry has "burp_op": "POST /repeater/send"

  @happy @community
  Scenario: bp log --limit caps the number of rows returned
    Given the ledger contains 200 entries
    When I run:
      """
      bp log --limit 10
      """
    Then the output contains at most 10 rows

  @happy @community
  Scenario: bp log --name filters entries by run name
    Given a ledger entry named "header-bypass-round2"
    When I run:
      """
      bp log --name "header-bypass-round2" --format json
      """
    Then the exit code is 0
    And every returned entry has "name": "header-bypass-round2"

  @happy @community
  Scenario: bp log returns empty JSON array (not an error) when no entries match the filter
    When I run:
      """
      bp log --tag nonexistent-tag-xyz --format json
      """
    Then the exit code is 0
    And stdout is "[]"

  @happy @community
  Scenario: Ledger entries from different domains (fuzz, scan, session) coexist and are queryable together
    Given the ledger contains one entry from "bp fuzz", one from "bp check cors", one from "bp session send"
    When I run:
      """
      bp log --target api.acme.corp --format json
      """
    Then the exit code is 0
    And the returned array contains entries with burp_op values:
      | POST /intruder/quick-fuzz |
      | POST /scan/cors           |
      | POST /session/send        |

  # ═══════════════════════════════════════════════════════════════════════════
  # bp tag <opId> <label> — annotate a posteriori
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: bp tag adds a label to an existing entry by ID; other fields unchanged
    Given a ledger entry with id "42" and no tag
    When I run:
      """
      bp tag 42 "confirmed-xss-bounty"
      """
    Then the exit code is 0
    And "bp log --tag confirmed-xss-bounty --format json" returns 1 entry with id 42
    And the entry's other fields (timestamp, command, burp_op, target) are unchanged

  @happy @community
  Scenario: bp tag overwrites a previous tag on an entry
    Given a ledger entry with id "17" and tag "triage"
    When I run:
      """
      bp tag 17 "escalated-p1"
      """
    Then the exit code is 0
    And "bp log --tag escalated-p1 --format json" returns entry id 17 where "tag" is "escalated-p1"
    And the old value "triage" no longer appears in the tag field

  @happy @community
  Scenario: bp tag JSON schema contract — response is {id, tag, status}
    When I run:
      """
      bp tag 99 "idor-confirmed" --format json
      """
    Then the exit code is 0
    And stdout is a single JSON object:
      """
      {"id":99,"tag":"idor-confirmed","status":"ok"}
      """

  @error @community
  Scenario: bp tag on a non-existent entry ID exits non-zero with clear message
    When I run:
      """
      bp tag 99999 "ghost"
      """
    Then the exit code is 1
    And stderr contains "entry 99999 not found in ledger"

  @error @community
  Scenario: bp tag with an empty label is rejected
    When I run:
      """
      bp tag 42 ""
      """
    Then the exit code is 1
    And stderr contains "tag label must not be empty"

  # ═══════════════════════════════════════════════════════════════════════════
  # --tag global flag — tag at operation time
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: --tag on a fuzz command writes the tag into the LedgerEntry immediately
    When I run:
      """
      bp fuzz 7 --param role --payloads role=roles.txt --tag role-escalation-test
      """
    Then the exit code is 0
    And "bp log --tag role-escalation-test --format json" returns a non-empty array
    And the first element has "tag": "role-escalation-test"

  @happy @community
  Scenario: --tag on a security scan command writes the tag into the LedgerEntry
    When I run:
      """
      bp check cors https://api.acme.corp/data --tag cors-check-june
      """
    Then the exit code is 0
    And "bp log --tag cors-check-june --format json" returns 1 entry
    And that entry's "burp_op" is "POST /scan/cors"

  @happy @community
  Scenario: Multiple sequential operations sharing the same --tag all appear under that tag
    When I run:
      """
      bp send 1 --tag recon-wave-1
      bp send 2 --tag recon-wave-1
      bp send 3 --tag recon-wave-1
      """
    Then "bp log --tag recon-wave-1" returns exactly 3 entries
    And all 3 entries have "tag": "recon-wave-1"

  @happy @community
  Scenario: --name gives the LedgerEntry a human-readable identifier (independent of --tag)
    When I run:
      """
      bp fuzz 3 --param username --payloads username=names.txt \
        --name "username-enum-sprint-7" \
        --tag sprint-7
      """
    Then "bp log --tag sprint-7 --format json" contains an entry where "name" is "username-enum-sprint-7"
    And the entry also has "tag": "sprint-7"

  # ═══════════════════════════════════════════════════════════════════════════
  # --no-ledger opt-out
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: --no-ledger suppresses recording; operation still executes and N stays the same
    Given the current ledger entry count for target "api.acme.corp" is N
    When I run:
      """
      bp send 7 --no-ledger
      """
    Then the exit code is 0
    And the Burp REST call to POST /repeater/send completes successfully
    And "bp log --target api.acme.corp" still returns exactly N entries (no new row)

  @happy @community
  Scenario: --no-ledger on a fuzz run suppresses all entries for that operation
    When I run:
      """
      bp fuzz 12 --param q --payloads q=payloads.txt --no-ledger
      """
    Then the exit code is 0
    And "bp log --burp-op 'POST /intruder/quick-fuzz'" returns the same count as before

  @happy @community
  Scenario: --no-ledger does NOT suppress stdout output — only disables recording
    When I run:
      """
      bp send 7 --no-ledger --format json
      """
    Then the exit code is 0
    And stdout is a valid JSON object containing "success": true
    And no entry is written to the ledger DB

  @happy @community
  Scenario: --no-ledger and --tag together — --tag is silently ignored (no entry created)
    When I run:
      """
      bp session send --url https://api.acme.corp/v1/me \
        --tag this-tag-will-be-ignored \
        --no-ledger
      """
    Then the exit code is 0
    And "bp log --tag this-tag-will-be-ignored" returns 0 entries

  # ═══════════════════════════════════════════════════════════════════════════
  # Failure / error path — ledger records failures too
  # ═══════════════════════════════════════════════════════════════════════════

  @error @community
  Scenario: A failed Burp REST call still creates a LedgerEntry with status err
    Given Burp Suite is running but proxy history entry 9999 does not exist
    When I run:
      """
      bp send 9999 --tag failed-send
      """
    Then the exit code is 1
    And "bp log --tag failed-send --format json" returns 1 entry
    And that entry has "status": "err"
    And that entry has a non-null "command" field

  @error @community
  Scenario: When Burp is unreachable, bp still creates a LedgerEntry with status err
    Given Burp Suite REST extension is NOT reachable at http://127.0.0.1:8089
    When I run:
      """
      bp send 7 --tag burp-down-test
      """
    Then the exit code is 1
    And stderr contains a connection error message referencing 127.0.0.1:8089
    And "bp log --tag burp-down-test --format json" returns 1 entry with "status": "err"

  @error @community
  Scenario: When ledger DB is unavailable, bp prints a warning but still executes the op
    Given the ledger DB at ~/.bp/ledger.db is locked or missing
    When I run:
      """
      bp send 7
      """
    Then the exit code is 0
    And the Burp REST call to POST /repeater/send succeeds
    And stderr contains a warning: "ledger unavailable — operation not recorded"

  # ═══════════════════════════════════════════════════════════════════════════
  # Filter edge cases and validation
  # ═══════════════════════════════════════════════════════════════════════════

  @error @community
  Scenario: bp log --since with invalid datetime format exits with usage error
    When I run:
      """
      bp log --since "not-a-date"
      """
    Then the exit code is 1
    And stderr contains "invalid datetime format for --since"
    And the error message shows the expected format: ISO-8601 (e.g. 2024-06-01T00:00:00Z)

  @error @community
  Scenario: bp log --status with an invalid value exits with usage error
    When I run:
      """
      bp log --status unknown
      """
    Then the exit code is 1
    And stderr contains "invalid --status value: must be ok or err"

  # ═══════════════════════════════════════════════════════════════════════════
  # Traceability guarantees — ISO / audit evidence
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: command field stores verbatim bp argv — enables forensic replay
    When I run:
      """
      bp check headers https://api.acme.corp/admin --method POST --tag forensic-evidence-001
      """
    Then "bp log --tag forensic-evidence-001 --format json" returns 1 entry
    And the entry's "command" field is verbatim:
      """
      bp check headers https://api.acme.corp/admin --method POST --tag forensic-evidence-001
      """
    And the "burp_op" is "POST /scan/headers"
    And the "timestamp" is a stable ISO-8601 value that does not change on subsequent reads

  @happy @community
  Scenario: Ledger persists across process restarts (SQLite durability)
    Given a ledger entry with tag "pre-restart-op" was created in a previous bp process
    When I start a new bp process and run:
      """
      bp log --tag pre-restart-op --format json
      """
    Then the exit code is 0
    And the same entry (command, burp_op, tag, timestamp) is returned as before the restart

  @happy @community
  Scenario: Fuzz LedgerEntry has non-null request_ref and response_ref (chain traceability)
    When I run:
      """
      bp fuzz 7 --param role --payloads role=roles.txt --tag idor-chain-trace
      """
    Then "bp log --tag idor-chain-trace --format json" returns the ledger entry
    And the entry's "request_ref" is non-null
    And the entry's "response_ref" is non-null

  # ═══════════════════════════════════════════════════════════════════════════
  # Integration — ledger + fuzz output fields are independent
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Fuzz stdout (per-payload results) and ledger entry are independently accessible with different schemas
    When I run:
      """
      bp fuzz 7 --param role --payloads role=roles.txt \
        --tag xref-test \
        --format json \
        --fields index,payload,status,length,anomalous
      """
    Then the exit code is 0
    And the fuzz result stdout is a JSON array where each element has keys: index, payload, status, length, anomalous
    And "bp log --tag xref-test --format json" returns the ledger entry for this operation
    And the ledger entry's "burp_op" is "POST /intruder/quick-fuzz"
    And the two outputs are independent (fuzz result schema ≠ ledger entry schema)

  @happy @community
  Scenario: Fuzz with -w prints one line per payload result; ledger records the whole op as a single entry
    When I run:
      """
      bp fuzz 7 --param role --payloads role=roles.txt \
        -w "%{status} %{payload}" \
        --tag wtemplate-ledger-test
      """
    Then stdout contains one line per payload result
    And each line matches "<status_code> <payload>"
    And "bp log --tag wtemplate-ledger-test --format json" returns exactly 1 ledger entry (not one per payload)
    And that ledger entry's "command" contains '-w "%{status} %{payload}"'

  # ═══════════════════════════════════════════════════════════════════════════
  # Agent (AX) — JSON-mode queries for programmatic ledger access
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @community
  Scenario: Agent queries failed operations in JSON mode with field selection
    When an AI agent runs:
      """
      bp log --target api.acme.corp --status err --format json --fields id,tag,burp_op,timestamp,command
      """
    Then the exit code is 0
    And stdout is a JSON array (possibly empty)
    And each element is a compact single-line JSON object
    And each element contains exactly the keys: id, tag, burp_op, timestamp, command

  @happy @community
  Scenario: Agent tags an entry then queries to confirm, all in JSON mode
    When an AI agent runs in sequence:
      """
      bp tag 55 "escalated-idor" --format json
      bp log --tag escalated-idor --format json
      """
    Then the first command's stdout is:
      """
      {"id":55,"tag":"escalated-idor","status":"ok"}
      """
    And the second command's stdout is a JSON array where the entry with id 55 has "tag" = "escalated-idor"
