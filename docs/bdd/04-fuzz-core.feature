# Domain: 04-fuzz-core
# Ground truth: SPEC.md §5 (--pos grammar) + §6.4 (intruder endpoints)
# API base: http://127.0.0.1:8089
# All endpoints: POST /intruder/attack/create+start (via bp fuzz <id> --async)
#                GET  /intruder/attack/{id}/status  GET /intruder/attack/{id}/results
#                POST /intruder/attack/{id}/pause   POST /intruder/attack/{id}/resume
#                POST /intruder/attack/{id}/stop    POST /intruder/quick-fuzz
# Key invariants:
#   - attackId = 8-char UUID prefix (String)
#   - requestId = Int (history index, 0-based)
#   - Server only executes sniper; battering-ram/pitchfork/cluster-bomb are client-side in bp
#   - payloads Map<String,List<String>> — ALL values flattened (keys irrelevant at server)
#   - positions[0].name only consumed in sniper
#   - PayloadPosition { start:Int, end:Int, name:String } — ALL required, no defaults
#   - throttleMs active; followRedirects/maxRetries accepted but NOT wired
#   - attack status enum: created | running | paused | stopped | completed | error
#   - Community: intruder runs (delegates to RepeaterService, not Burp Pro Intruder)
#   - quick-fuzz: baseline = first result with error==null; anomalous if statusCode diff
#     OR |Δlength| > max(length*0.2, 20) OR contentType diff

Feature: bp fuzz — core fuzzing lifecycle with --pos grammar and 4 attack types
  As a security researcher (human DX) or an AI agent (AX),
  I want to drive Burp's Intruder engine via `bp fuzz` using semantic position selectors,
  multiple attack types, payload sets, throttle control, and a full attack lifecycle,
  so that I can automate targeted payload injection and triage anomalous responses
  with machine-readable output at every stage.

  Background:
    Given Burp Suite is running and listening on http://127.0.0.1:8089
    And the extension REST API is healthy (GET /health returns status "ok")
    And proxy history contains at least one captured request at index 3
      with URL "https://api.target.com/login" method POST
      and raw body "username=admin&password=secret"

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 1 · quick-fuzz (POST /intruder/quick-fuzz) — synchronous, 1 param
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: quick-fuzz a single param — table output with baseline row first
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz 3 --param username \
        --payloads 'admin,root,"'"'"' OR '"'"'1'"'"'='"'"'1","admin'"'"'--"' \
        --throttle-ms 100 \
        --format table
      """
    Then the exit code is 0
    And stdout contains a table with headers:
      | index | payload       | status | length | time | contentType      | anomalous |
    And a baseline row is printed first (the first request with no error)
    And at least one row has anomalous "true"

  @happy @fuzz @community
  Scenario: quick-fuzz JSON schema — endpoint-specific field contract
    # Proves the exact JSON fields emitted by POST /intruder/quick-fuzz (not generic output)
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz 3 --param username \
        --payloads 'admin,root,"'"'"' OR 1=1--"' \
        --format json
      """
    Then the exit code is 0
    And each stdout line is a valid compact JSON object
    And each JSON object contains exactly the fields:
      | index | payload | statusCode | length | durationMs | error | contentType | bodyPreview | anomalous |

  @happy @fuzz @ledger @community
  Scenario: quick-fuzz is recorded in the Run Ledger by default
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz 3 --param username \
        --payloads 'admin,root' \
        --tag sqli-login-test
      """
    Then the exit code is 0
    And running "bp log --tag sqli-login-test --format json" shows an entry with:
      | field     | value                       |
      | tag       | sqli-login-test             |
      | burp_op   | POST /intruder/quick-fuzz   |
      | status    | ok                          |

  @happy @fuzz @ledger @community
  Scenario: quick-fuzz --no-ledger is NOT recorded in the Run Ledger
    Given request at history index 3 has param "username" in the body
    When I run:
      """
      bp fuzz 3 --param username \
        --payloads admin \
        --no-ledger
      """
    Then the exit code is 0
    And running "bp log --format json" shows no new entry for this run

  @error @fuzz @community
  Scenario: quick-fuzz with blank param is rejected — INVALID_REQUEST
    When I run:
      """
      bp fuzz 3 --param "" --payloads 'admin,root'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr explains that param must not be blank

  @error @fuzz @community
  Scenario: quick-fuzz with empty payloads list is rejected — INVALID_REQUEST
    When I run:
      """
      bp fuzz 3 --param username --payloads ""
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr explains that payloads must be non-empty

  @error @fuzz @community
  Scenario: quick-fuzz without positional id raises usage error before any API call
    # --param alone is ambiguous without a request id
    When I run:
      """
      bp fuzz --param username --payloads admin
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr explains that exactly one of --id or --request is required

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 2 · SNIPER — 1 position, 1 payload set, sequential per payload
  # Endpoints: bp fuzz <id> --async (create+start) → status → results
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: sniper on body:username — offset auto-resolved from raw request bytes
    # bp must parse the raw request bytes and compute start/end for the field value
    # Raw POST body: "username=admin&password=secret"
    # "admin" sits at bytes 9-14 → PayloadPosition{start:9,end:14,name:"username"}
    Given request at history index 3 has raw body "username=admin&password=secret"
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/usernames.txt \
        --throttle-ms 0 \
        --async \
        --format json
      """
    Then the exit code is 0
    And the resolved PayloadPosition sent to POST /intruder/attack/create matches:
      | name     | start | end |
      | username | 9     | 14  |

  @happy @fuzz @community
  Scenario: sniper on offset:42-52 — raw byte-range passed through directly, no resolution
    Given request at history index 3 exists
    When I run:
      """
      bp fuzz 3 \
        --pos 'offset:42-52' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt \
        --async \
        --format json
      """
    Then the exit code is 0
    And the PayloadPosition sent is exactly: start=42, end=52, name="offset:42-52"
    And no byte-resolution parsing is performed (offsets are passed through directly)

  @happy @fuzz @community
  Scenario: sniper results pagination — offset and limit applied server-side
    Given an attack "a1b2c3d4" exists with 50 results
    When I run:
      """
      bp fuzz results a1b2c3d4 \
        --offset 20 --limit 10 \
        --format json
      """
    Then the exit code is 0
    And stdout contains exactly 10 JSON result objects
    And the first object has "index": 20

  @happy @fuzz @community
  Scenario: results --limit 0 returns ALL results (SPEC §6.4: limit=0 means unbounded)
    Given attack "a1b2c3d4" has 200 results
    When I run:
      """
      bp fuzz results a1b2c3d4 --offset 0 --limit 0 --format json
      """
    Then the exit code is 0
    And stdout contains exactly 200 JSON result objects

  @happy @fuzz @community
  Scenario: empty results for a created-but-not-started attack
    Given attack "a1b2c3d4" has status "created" and has not been started
    When I run:
      """
      bp fuzz results a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is an empty JSON array "[]" or zero result lines

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 3 · LIFECYCLE — --async (create+start) → status → pause/resume → stop
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: full async lifecycle — launch with --async, poll to complete, fetch results
    # Canonical --async round-trip: bp fuzz <id> --async creates+starts in one call,
    # prints attackId immediately, then poll with status/results/pause/resume/stop.
    Given a file "/tmp/tokens.txt" with content:
      """
      Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
      Bearer invalid-token
      Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.fake
      """
    When I run:
      """
      bp fuzz 3 \
        --pos 'header:Authorization' \
        --type sniper \
        --payloads Authorization=/tmp/tokens.txt \
        --throttle-ms 200 \
        --async \
        --format json
      """
    Then the exit code is 0
    And stdout is a JSON object with field "attackId" matching pattern "[a-f0-9]{8}"
    And stdout JSON contains "status": "running"

    When I poll:
      """
      bp fuzz status <attackId> --format json
      """
    Then eventually stdout JSON contains "isComplete": true
    And stdout JSON contains "progress": 100

    When I run:
      """
      bp fuzz results <attackId> --format json
      """
    Then the exit code is 0
    And stdout contains 3 JSON result objects (one per payload)
    And each result has fields: index, payload, statusCode, length, durationMs, error, contentType, anomalous

  @happy @fuzz @community
  Scenario: pause a running attack and then resume it
    Given an attack "a1b2c3d4" is in status "running"
    When I run:
      """
      bp fuzz pause a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "paused"

    When I run:
      """
      bp fuzz resume a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "running"

  @happy @fuzz @community
  Scenario: stop a running attack — stopped is a terminal state
    Given an attack "a1b2c3d4" is in status "running"
    When I run:
      """
      bp fuzz stop a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout JSON contains "status": "stopped"
    And isComplete is true

  @happy @fuzz @community
  Scenario: results on a stopped attack returns partial results collected before stop
    Given attack "a1b2c3d4" ran 15 out of 50 payloads then was stopped
    When I run:
      """
      bp fuzz results a1b2c3d4 --limit 0 --format json
      """
    Then the exit code is 0
    And stdout contains exactly 15 JSON result objects (results collected before stop)

  @happy @fuzz @community
  Scenario: poll status — progress transitions 0→100, status running→completed
    Given an attack "a1b2c3d4" was just started
    When I run "bp fuzz status a1b2c3d4 --format json" repeatedly
    Then each response JSON contains "progress" between 0 and 100
    And eventually "isComplete": true appears
    And "status" transitions through: running → completed

  @error @fuzz @community
  Scenario: resume a non-paused running attack — bp warns it is already running
    # Guard against redundant resume on an already-running attack
    Given an attack "a1b2c3d4" is in status "running"
    When I run:
      """
      bp fuzz resume a1b2c3d4 --format json
      """
    Then the exit code is 0
    And bp warns: "attack is already running — resume has no effect"

  @error @fuzz @community
  Scenario: status of unknown attackId returns not-found error
    When I run:
      """
      bp fuzz status 00000000 --format json
      """
    Then the exit code is non-zero
    And stderr contains "not found" or an appropriate error message
    And no crash traceback is shown

  @error @fuzz @community
  Scenario: --async with a non-existent requestId — validation deferred to server-side start
    # SPEC §6.4: the create step does NOT validate requestId; error surfaces when the
    # underlying /start executes. With --async, bp fuzz returns an error once the server
    # rejects the deferred start (attackId is printed, then an async error follows).
    When I run:
      """
      bp fuzz 9999 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/usernames.txt \
        --async \
        --format json
      """
    Then the exit code is non-zero
    And stderr contains an error about invalid requestId 9999

  @happy @fuzz @ledger @community
  Scenario: fuzz attack is tagged and retrievable from Run Ledger
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --async \
        --tag sqli-enumeration-phase1
      """
    And I poll until the attack completes
    Then "bp log --tag sqli-enumeration-phase1 --format json" returns an entry with:
      | field     | value                          |
      | tag       | sqli-enumeration-phase1        |
      | burp_op   | POST /intruder/attack/create   |
      | status    | ok                             |
      | target    | https://api.target.com/login   |

  @happy @fuzz @ledger @community
  Scenario: results fetch step is independently recorded in the ledger
    Given attack "a1b2c3d4" is tagged "sqli-enum"
    When I run:
      """
      bp fuzz results a1b2c3d4 --tag sqli-enum-results --format json
      """
    Then "bp log --tag sqli-enum-results" shows an entry with:
      | burp_op | GET /intruder/attack/a1b2c3d4/results |

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 4 · BATTERING-RAM — same payload into ALL positions simultaneously
  # Client-side expansion; total requests = len(payloads)
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: battering-ram — same payload injected into username AND password simultaneously
    # Each payload replaces BOTH positions simultaneously → total = len(payloads) requests
    Given a file "/tmp/creds.txt" with lines: admin, root, administrator, test
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type battering-ram \
        --payloads shared=/tmp/creds.txt \
        --throttle-ms 150 \
        --async \
        --format json
      """
    Then the exit code is 0
    And bp expands client-side into 4 sniper-style requests (one per payload)
    And each request has the SAME payload in both body:username and body:password positions

    When the attack completes
    Then "bp fuzz results <attackId> --format json" returns 4 result objects

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 5 · PITCHFORK — N payload sets in lockstep (truncated to min length)
  # Client-side expansion; pairs set[i] ↔ position[i]
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: pitchfork 2 positions — lockstep truncates to min(len) of the two sets
    # username.txt: admin, user1, operator  (3 entries)
    # password.txt: pass1, pass2            (2 entries)
    # lock-step → min(3,2) = 2 requests total
    # Request 1: username=admin,  password=pass1
    # Request 2: username=user1,  password=pass2
    Given a file "/tmp/username.txt" with lines: admin, user1, operator
    And a file "/tmp/password.txt" with lines: pass1, pass2
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type pitchfork \
        --payloads username=/tmp/username.txt \
        --payloads password=/tmp/password.txt \
        --throttle-ms 100 \
        --async \
        --format json
      """
    Then the exit code is 0
    And bp computes lock-step count: min(3, 2) = 2
    And the attack is expanded client-side into 2 requests

    When the attack completes
    Then "bp fuzz results <attackId> --format json" returns exactly 2 result objects
    And result at index 0 has payload pair: username="admin", password="pass1"
    And result at index 1 has payload pair: username="user1", password="pass2"

  @happy @fuzz @community
  Scenario: pitchfork 3 positions — lockstep min enforced across all three sets
    # users.txt: alice, bob, carol     (3)
    # roles.txt: admin, viewer         (2)
    # actions.txt: read, write, delete (3)
    # lock-step → min(3,2,3) = 2 requests
    Given files "/tmp/users.txt" (alice,bob,carol), "/tmp/roles.txt" (admin,viewer), "/tmp/actions.txt" (read,write,delete)
    When I run:
      """
      bp fuzz 3 \
        --pos 'header:X-User-ID' \
        --pos 'cookie:role' \
        --pos 'query:action' \
        --type pitchfork \
        --payloads X-User-ID=/tmp/users.txt \
        --payloads role=/tmp/roles.txt \
        --payloads action=/tmp/actions.txt \
        --throttle-ms 0 \
        --async \
        --format json
      """
    Then the exit code is 0
    And bp client-side expansion yields exactly 2 requests (min of 3,2,3)
    And result at index 0 has: X-User-ID=alice, role=admin, action=read
    And result at index 1 has: X-User-ID=bob,   role=viewer, action=write

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 6 · CLUSTER-BOMB — Cartesian product (N-dimensional matrix)
  # Client-side expansion; every combination of all sets
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: cluster-bomb 2D matrix — header × cookie = a×b requests
    # ips.txt: 127.0.0.1, 10.0.0.1   (a=2)
    # roles.txt: admin, user, guest   (b=3)
    # Total: 2 × 3 = 6 requests
    Given a file "/tmp/ips.txt" with lines: 127.0.0.1, 10.0.0.1
    And a file "/tmp/roles.txt" with lines: admin, user, guest
    When I run:
      """
      bp fuzz 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 200 \
        --async \
        --format json
      """
    Then the exit code is 0
    And bp client-side expansion yields 2 × 3 = 6 request combinations
    And the attack is created with "attackType": "cluster-bomb"

    When the attack completes
    Then "bp fuzz results <attackId> --format json" returns exactly 6 result objects
    And the combination matrix covers every pair:
      | X-Forwarded-For | role  |
      | 127.0.0.1       | admin |
      | 127.0.0.1       | user  |
      | 127.0.0.1       | guest |
      | 10.0.0.1        | admin |
      | 10.0.0.1        | user  |
      | 10.0.0.1        | guest |

  @happy @fuzz @community
  Scenario: cluster-bomb 3D matrix — 2 headers + 1 cookie = a×b×c requests
    # X-Forwarded-For: 127.0.0.1, 10.0.0.1  (a=2)
    # X-Real-IP:       127.0.0.1, 10.0.0.1  (b=2)
    # role:            admin, user           (c=2)
    # Total: 2 × 2 × 2 = 8 requests
    Given a file "/tmp/ips.txt" with lines: 127.0.0.1, 10.0.0.1
    And a file "/tmp/roles.txt" with lines: admin, user
    When I run:
      """
      bp fuzz 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'header:X-Real-IP' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads X-Real-IP=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 500 \
        --async \
        --format json
      """
    Then the exit code is 0
    And bp client-side expansion yields 2 × 2 × 2 = 8 request combinations
    And all 8 combinations of (X-Forwarded-For, X-Real-IP, role) are scheduled

    When the attack completes
    Then "bp fuzz results <attackId> --format json" returns exactly 8 result objects

  @happy @fuzz @community
  Scenario: cluster-bomb 3D — --anomalous-only filter reduces output to matching rows only
    Given the 3D cluster-bomb attack "cb3d1234" has completed with 8 results
    And only 2 results have anomalous=true
    When I run:
      """
      bp fuzz results cb3d1234 \
        --anomalous-only \
        --format table
      """
    Then the exit code is 0
    And the table contains exactly 2 rows

  @happy @fuzz @community
  Scenario: cluster-bomb full SPEC §5 example — --throttle-ms 500 with --anomalous-only
    # Exact example from SPEC.md §5 "Fuzz matriciel" — tests combined throttle + filter
    Given a file "/tmp/ips.txt" and "/tmp/roles.txt" populated
    When I run:
      """
      bp fuzz 42 \
        --pos 'header:X-Forwarded-For' \
        --pos 'header:X-Real-IP' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads X-Real-IP=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 500 \
        --anomalous-only \
        --format table
      """
    Then the exit code is 0
    And bp waits 500ms between each of the a×b×c requests
    And only rows with anomalous=true are displayed

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 7 · --pos SELECTOR RESOLUTION — all 6 selector types
  # header:NAME  cookie:NAME  body:FIELD  query:NAME  path:INDEX  offset:START-END
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: --pos selector types each resolve to correct byte offsets
    Given request at history index <history_id> has the given structure
    When I run:
      """
      bp fuzz <history_id> \
        --pos '<selector>' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt \
        --async \
        --format json
      """
    Then the exit code is 0
    And the PayloadPosition name is "<expected_name>"
    And the PayloadPosition start and end offsets correspond to "<target_value>" in the raw request

    Examples:
      | history_id | selector              | expected_name   | target_value |
      | 3          | header:Authorization  | Authorization   | admin        |
      | 3          | cookie:session        | session         | sess123      |
      | 3          | body:username         | username        | admin        |
      | 7          | query:id              | id              | 1001         |
      | 5          | path:1                | path:1          | 42           |
      | 3          | offset:9-14           | offset:9-14     | admin        |

  @happy @fuzz @community
  Scenario: multiple --pos flags for sniper — positions fuzzed sequentially, not in parallel
    # sniper with 2 positions: fuzzes position[0] fully, then position[1]
    # SPEC caveat: only positions[0].name is consumed by the server in sniper mode
    Given request at history index 3 has body "username=admin&password=secret"
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type sniper \
        --payloads set1=/tmp/wordlist.txt \
        --async \
        --format json
      """
    Then the exit code is 0
    And 2 PayloadPositions are sent to POST /intruder/attack/create
    And bp sends payloads through position 0 (username) first, then position 1 (password)
    And SPEC caveat is respected: only positions[0].name is consumed by the server in sniper mode

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 8 · ATTACK TYPE CONTRACT — server executes only sniper; bp expands others
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: all 4 attack types accepted — bp handles client-side expansion
    # SPEC §5 caveat: server only implements sniper; bp expands others client-side
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type <attack_type> \
        --payloads username=/tmp/payloads.txt \
        --async \
        --format json
      """
    Then the exit code is 0
    And the CreateAttackRequest contains "attackType": "<attack_type>"
    And <client_side_note>

    Examples:
      | attack_type   | client_side_note                                                   |
      | sniper        | bp delegates directly to the server                                |
      | battering-ram | bp expands client-side (same payload to all positions per request) |
      | pitchfork     | bp expands client-side (lock-step pairing across sets)             |
      | cluster-bomb  | bp expands client-side (full Cartesian product)                    |

  @happy @fuzz @community
  Scenario: bp emits client-side expansion notice for non-sniper types
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type cluster-bomb \
        --payloads username=/tmp/usernames.txt \
        --payloads password=/tmp/passwords.txt \
        --async \
        --format json
      """
    Then the exit code is 0
    And stderr or stdout contains:
      """
      Note: cluster-bomb is expanded client-side by bp (server implements sniper only)
      """

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 9 · THROTTLE & UNIMPLEMENTED OPTIONS
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario Outline: --throttle-ms value is forwarded in CreateAttackRequest.throttleMs
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --throttle-ms <ms> \
        --async \
        --format json
      """
    Then the exit code is 0
    And the CreateAttackRequest sent contains "throttleMs": <ms>

    Examples:
      | ms   |
      | 0    |
      | 1000 |

  @happy @fuzz @community
  Scenario: --follow-redirects accepted but bp warns it is not wired server-side
    # SPEC §6.4 caveat: followRedirects accepted but NOT wired
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/payloads.txt \
        --follow-redirects \
        --async \
        --format json
      """
    Then the exit code is 0
    And bp emits a warning: "followRedirects is accepted by the server but not currently wired"
    And the AttackOptions contains "followRedirects": true

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 10 · PAYLOAD LOADING — file, inline, multi-set, server flattening
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: payload file with 100 entries produces exactly 100 results in sniper
    Given a file "/tmp/big_list.txt" with 100 unique string entries
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/big_list.txt \
        --throttle-ms 0 \
        --async \
        --format json
      """
    And I poll until the attack completes
    Then "bp fuzz results <attackId> --limit 0 --format json" returns exactly 100 result objects

  @happy @fuzz @community
  Scenario: inline payloads via comma-separated --payloads name=val1,val2,val3
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads 'username=admin,root,administrator' \
        --async \
        --format json
      """
    Then the exit code is 0
    And the CreateAttackRequest payloads map has key "username" with list ["admin","root","administrator"]

  @happy @fuzz @community
  Scenario: SPEC caveat — server flattens all payload map values regardless of key names
    # All Map<String,List<String>> values are flattened; keys have no functional role at server
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads 'set1=admin,root' \
        --payloads 'set2=administrator' \
        --async \
        --format json
      """
    Then the exit code is 0
    And the payloads sent to the server have key "set1" with ["admin","root"] and "set2" with ["administrator"]
    And bp warns: "server flattens all payload sets — key names (set1,set2) have no functional role in sniper"

  @error @fuzz @community
  Scenario: payload file does not exist — error raised before attack is created
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --type sniper \
        --payloads username=/tmp/nonexistent_file.txt \
        --async
      """
    Then the exit code is non-zero
    And stderr contains "file not found: /tmp/nonexistent_file.txt"
    And no request is sent to POST /intruder/attack/create

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 11 · COMMUNITY EDITION — intruder available without Pro
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: fuzz attack succeeds on Community — delegates to RepeaterService, not Burp Pro Intruder
    # SPEC §6.4 + §7: intruder delegates to RepeaterService on Community
    # bp must NOT emit a PRO_REQUIRED error or warning for intruder commands
    Given Burp Suite Community Edition is running on port 8089
    When I run:
      """
      bp fuzz 3 --param username \
        --payloads 'admin,root' \
        --format json
      """
    Then the exit code is 0
    And the attack succeeds without a 503 or "Pro required" error
    And stderr does NOT contain "Pro required" or "SERVICE_UNAVAILABLE"

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 12 · ANOMALOUS DETECTION — endpoint-specific logic from SPEC §6.4
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: anomalous=true when payload response statusCode differs from baseline
    # SPEC §6.4: anomalous if statusCode ≠ baseline
    Given baseline response for history id 3 returns HTTP 200
    When quick-fuzz sends payload "' OR 1=1--" and receives HTTP 302
    Then the result has anomalous=true

  @happy @fuzz @community
  Scenario: anomalous threshold — |Δlength| > max(length*0.2, 20) triggers anomalous
    # SPEC §6.4: anomalous if |Δlength| > max(baseline_length*0.2, 20)
    # Case A: baseline=500, response=560 → delta=60, threshold=max(100,20)=100 → NOT anomalous
    # Case B: baseline=100, response=130 → delta=30, threshold=max(20,20)=20  → anomalous
    Given baseline response length is 500 bytes
    When a payload causes response length 560 bytes
    Then that result has anomalous=false (delta 60 < threshold 100)

    Given baseline response length is 100 bytes
    When a payload causes response length 130 bytes
    Then that result has anomalous=true (delta 30 > threshold 20)

  @happy @fuzz @community
  Scenario: anomalous=true when response Content-Type differs from baseline
    # SPEC §6.4: anomalous if contentType ≠ baseline
    Given baseline response has Content-Type "application/json"
    When a payload causes Content-Type "text/html"
    Then the result has anomalous=true

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 13 · INPUT VALIDATION — endpoint-specific usage errors
  # ─────────────────────────────────────────────────────────────────────────────

  @error @fuzz @community
  Scenario: missing --pos raises usage error before any API call
    When I run:
      """
      bp fuzz 3 \
        --type sniper \
        --payloads username=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "at least one --pos is required"
    And no HTTP request is sent to :8089

  @error @fuzz @community
  Scenario: cluster-bomb with fewer --payloads sets than --pos count raises error
    # cluster-bomb requires exactly one payload set per position
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --type cluster-bomb \
        --payloads username=/tmp/usernames.txt
      """
    Then the exit code is non-zero
    And stderr contains "cluster-bomb requires one payload set per position (got 1 sets for 2 positions)"

  @error @fuzz @community
  Scenario: pitchfork with fewer payload sets than positions raises error
    # pitchfork requires one set per position (cannot proceed with missing set)
    When I run:
      """
      bp fuzz 3 \
        --pos 'body:username' \
        --pos 'body:password' \
        --pos 'query:action' \
        --type pitchfork \
        --payloads username=/tmp/u.txt \
        --payloads password=/tmp/p.txt
      """
    Then the exit code is non-zero
    And stderr contains "pitchfork requires one payload set per position (got 2 sets for 3 positions)"

  @error @fuzz @community
  Scenario: invalid --pos selector type raises descriptive parse error
    When I run:
      """
      bp fuzz 3 \
        --pos 'unknown:foo' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "unknown position selector type: 'unknown'"
    And stderr lists valid selector types: header, cookie, body, query, path, offset

  @error @fuzz @community
  Scenario: offset selector with invalid range format raises descriptive error
    When I run:
      """
      bp fuzz 3 \
        --pos 'offset:not-a-range' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "invalid offset format: 'not-a-range' — expected 'offset:START-END' with integer start and end"

  @error @fuzz @community
  Scenario: header selector for a header absent from the captured request raises error
    Given request at history index 3 does NOT have header "X-Missing-Header"
    When I run:
      """
      bp fuzz 3 \
        --pos 'header:X-Missing-Header' \
        --type sniper \
        --payloads set1=/tmp/payloads.txt
      """
    Then the exit code is non-zero
    And stderr contains "header 'X-Missing-Header' not found in request at index 3"

  # ─────────────────────────────────────────────────────────────────────────────
  # SECTION 14 · AGENT MODE (AX) — machine-readable end-to-end cluster-bomb
  # Proves stable JSON schema throughout the full lifecycle for AI consumers
  # ─────────────────────────────────────────────────────────────────────────────

  @happy @fuzz @community
  Scenario: agent drives full cluster-bomb lifecycle via JSON — non-TTY environment
    # An AI agent pipes every command; stable JSON schema required at each step
    Given stdout is a pipe (non-TTY agent environment)
    When the agent runs:
      """
      bp fuzz 3 \
        --pos 'header:X-Forwarded-For' \
        --pos 'cookie:role' \
        --type cluster-bomb \
        --payloads X-Forwarded-For=/tmp/ips.txt \
        --payloads role=/tmp/roles.txt \
        --throttle-ms 200 \
        --async \
        --format json
      """
    Then stdout is a single compact JSON line like:
      """
      {"success":true,"data":{"attackId":"a1b2c3d4","status":"running"},"error":null}
      """
    When the agent polls:
      """
      bp fuzz status a1b2c3d4 --format json
      """
    Until stdout contains "isComplete":true
    When the agent runs:
      """
      bp fuzz results a1b2c3d4 --format json
      """
    Then each stdout line is a compact JSON object with stable schema:
      """
      {"index":<int>,"payload":"<str>","statusCode":<int>,"length":<int>,"durationMs":<int>,"error":null,"contentType":"<str>","bodyPreview":"<str>","anomalous":<bool>}
      """
    And the agent can filter anomalous results by parsing "anomalous":true
