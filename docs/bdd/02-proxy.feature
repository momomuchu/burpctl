Feature: Proxy — history list/filter/pagination, single request, WebSocket, intercept
  As a security researcher or AI agent driving Burp via bp,
  I want to list, filter, and inspect captured proxy traffic,
  browse WebSocket messages, and toggle intercept on/off,
  so that I can triage captured requests and control what Burp intercepts
  without leaving the terminal.

  # Command surface (CLI.md):
  #   bp proxy [--host H --limit N --offset N]   → GET /proxy/history (list)
  #   bp req <id>                                 → GET /proxy/history/{id}
  #   bp ws                                       → GET /proxy/websocket/history
  #   bp intercept on|off|forward|drop            → POST /proxy/intercept/*
  # Output format/fields flags are cross-cutting (proven in 00-output.feature).
  # Cross-cutting errors (CONNECTION_REFUSED, generic --id, envelope) → 00-common.feature.

  Background:
    Given Burp Suite is running and the bp extension is loaded at http://127.0.0.1:8089
    And the proxy listener is active on 127.0.0.1:8080

  # ─────────────────────────────────────────────────────────────
  # GET /proxy/history — list + filter + pagination
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: List proxy history with default pagination returns first 50 entries
    Given the proxy has captured at least 3 HTTP requests
    When I run:
      """
      bp proxy
      """
    Then the exit code is 0
    And the output is a table with columns: id, method, host, path, status, length
    And the table contains at most 50 rows
    And each row has a non-empty "host" value

  @happy @community
  Scenario: List proxy history JSON schema for agent consumption
    # One --format json assertion for the list endpoint (agent-mode schema contract).
    Given the proxy has captured requests to "api.example.com"
    When I run:
      """
      bp proxy --format json
      """
    Then the exit code is 0
    And stdout is compact JSON (one object per line) with the envelope:
      """
      {"success":true,"data":{"items":[...],"total":<Int>,"limit":<Int>,"offset":<Int>}}
      """
    And each item in "data.items" contains the fields: id, method, host, path, statusCode, length
    And no pretty-printing whitespace is present (compact, AX-stable schema)

  @happy @community
  Scenario: Filter proxy history by host excludes other hosts and reflects filtered total
    Given the proxy has captured requests to "api.example.com" and "login.evil.com"
    When I run:
      """
      bp proxy --host api.example.com --format json
      """
    Then the exit code is 0
    And every item in "data.items" has host equal to "api.example.com"
    And no item has host equal to "login.evil.com"
    And "data.total" reflects the filtered count, not the total history size

  @happy @community
  Scenario: Paginate proxy history — two consecutive pages contain no duplicates
    Given the proxy has captured at least 10 requests to "shop.target.com"
    When I run:
      """
      bp proxy --host shop.target.com --limit 3 --offset 0 --format json
      """
    Then the exit code is 0
    And "data.items" contains exactly 3 entries
    And "data.limit" is 3
    And "data.offset" is 0
    When I run:
      """
      bp proxy --host shop.target.com --limit 3 --offset 3 --format json
      """
    Then the exit code is 0
    And "data.items" contains the next 3 entries (none duplicated from the previous page)
    And "data.offset" is 3

  @happy @community @ledger
  Scenario: Proxy history list operation is recorded in the Run Ledger by default
    Given no prior ledger entry for this operation
    When I run:
      """
      bp proxy --host api.example.com --tag recon-phase1
      """
    Then the exit code is 0
    And a ledger entry is created with:
      | field   | value              |
      | tag     | recon-phase1       |
      | burp_op | GET /proxy/history |
      | target  | api.example.com    |
      | status  | ok                 |

  @happy @community @ledger
  Scenario: --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp proxy --limit 5 --no-ledger
      """
    Then the exit code is 0
    And no new ledger entry is created for this invocation

  @error @community
  Scenario: History list when proxy has captured zero requests returns empty result
    Given the proxy history is empty
    When I run:
      """
      bp proxy --format json
      """
    Then the exit code is 0
    And "data.items" is an empty array []
    And "data.total" is 0

  @error @community
  Scenario: History list filtered by unknown host returns empty result
    Given the proxy has captured requests but none to "nevervisited.internal"
    When I run:
      """
      bp proxy --host nevervisited.internal --format json
      """
    Then the exit code is 0
    And "data.items" is an empty array []
    And "data.total" is 0

  @error @community
  Scenario Outline: bp proxy handles invalid query parameter values gracefully
    When I run:
      """
      bp proxy <args> --format json
      """
    Then the exit code is <exit_code>
    And the output or error contains <expected_message_fragment>

    Examples:
      | args         | exit_code | expected_message_fragment       |
      | --limit -1   | non-zero  | "invalid value for --limit"     |
      | --offset -5  | non-zero  | "invalid value for --offset"    |
      | --limit abc  | non-zero  | "invalid value for --limit"     |
      | --limit 0    | 0         | "data.items"                    |

  @happy @community
  Scenario Outline: Proxy history pagination boundary combinations
    # Distinct boundary behaviors: mid-page, partial last page, exact end, over-end, limit>total.
    Given the proxy has captured <total> requests to "<host>"
    When I run:
      """
      bp proxy --host <host> --limit <limit> --offset <offset> --format json
      """
    Then the exit code is 0
    And "data.items" contains exactly <expected_count> entries
    And "data.total" is <total>

    Examples:
      | host            | total | limit | offset | expected_count |
      | api.example.com | 10    | 5     | 5      | 5              |
      | api.example.com | 10    | 5     | 8      | 2              |
      | api.example.com | 10    | 5     | 10     | 0              |
      | api.example.com | 10    | 100   | 0      | 10             |
      | shop.target.com | 3     | 1     | 2      | 1              |

  # ─────────────────────────────────────────────────────────────
  # GET /proxy/history/{id} — single request by absolute id
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Get a single proxy history entry by its absolute index
    # encodeDefaults=true: null fields always present in output (not absent).
    Given the proxy has captured at least 1 request and its id is known as 0
    When I run:
      """
      bp req 0 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON envelope:
      """
      {"success":true,"data":{"id":0,"method":"GET","host":"api.example.com","path":"/v1/users","statusCode":200,"length":<Int>,"listenerInterface":null,"clientIp":null,"timestamp":null}}
      """
    And the response always includes all declared fields (encodeDefaults=true), even if null

  @happy @community
  Scenario: Proxy history entries always have null listenerInterface, clientIp, and HTTP timestamp
    # Per spec: listenerInterface, clientIp, timestamp (HTTP) always null.
    # encodeDefaults=true means these null fields ARE present in JSON output (not absent).
    Given proxy history entry with id 0 exists
    When I run:
      """
      bp req 0 --format json
      """
    Then the exit code is 0
    And "data.listenerInterface" is explicitly present and null (not absent)
    And "data.clientIp" is explicitly present and null (not absent)
    And "data.timestamp" is explicitly present and null (not absent)

  @error @community
  Scenario: Get proxy history entry with non-integer id returns INVALID_PARAM error
    # Server parses id via toIntOrNull; non-integer → INVALID_PARAM (not 404).
    When I run:
      """
      bp req abc --format json
      """
    Then the exit code is non-zero
    And stdout or stderr contains:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_PARAM","message":"<any>"}}
      """

  @error @community
  Scenario: Get proxy history entry with out-of-bounds id triggers a server 500
    # Per spec: out-of-bounds id → 500 Ktor (unmapped — endpoint-specific behavior).
    Given the proxy history has 3 entries (ids 0, 1, 2)
    When I run:
      """
      bp req 9999 --format json
      """
    Then the exit code is non-zero
    And bp surfaces the error with a message indicating the entry was not found or an internal server error occurred
    And stdout or stderr contains "INTERNAL_ERROR" or "not found" or a non-zero HTTP status code hint

  @error @community
  Scenario: Offset-relative id instability warning is surfaced by bp
    # Per spec: id = start+idx (offset-relative → unstable between offsets).
    # bp must warn users to use absolute ids via bp req <id>, not relative page ids.
    Given the proxy has captured 20 requests
    When I run:
      """
      bp proxy --limit 5 --offset 10 --format json
      """
    Then the exit code is 0
    And bp emits a warning on stderr:
      """
      Warning: item ids in paginated results are offset-relative and unstable. Use 'bp req <id>' with the absolute index for stable access.
      """

  @error @community
  Scenario: bp req with missing id argument shows usage error
    When I run:
      """
      bp req
      """
    Then the exit code is non-zero
    And stderr contains "missing required argument: <id>"

  # ─────────────────────────────────────────────────────────────
  # GET /proxy/websocket/history — WebSocket message history
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: List WebSocket history shows direction enum, payload, and query-time timestamp
    # Per spec: direction = Montoya enum .name (CLIENT_TO_SERVER | SERVER_TO_CLIENT).
    # Per spec: timestamp = Instant.now() at query time (not capture time).
    Given the proxy has captured WebSocket messages on "wss://realtime.app.com/socket"
    When I run:
      """
      bp ws --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON envelope:
      """
      {"success":true,"data":{"items":[...],"total":<Int>}}
      """
    And each item contains the fields: direction, payload, timestamp
    And "direction" is one of CLIENT_TO_SERVER or SERVER_TO_CLIENT (Montoya enum .name)
    And "timestamp" is the Instant.now() at query time (not capture time — per spec)

  @happy @community
  Scenario: WebSocket history timestamp reflects query time not capture time
    # Per spec: WS timestamp = Instant.now() at call time (not when traffic was captured).
    # bp must document this in --help and not mislead users.
    Given the proxy has captured WebSocket messages at 10:00:00
    When I run at 10:05:00:
      """
      bp ws --format json
      """
    Then each item's "timestamp" reflects approximately 10:05:00 (query time)
    And bp emits a note on stderr:
      """
      Note: WebSocket history timestamps reflect query time, not capture time.
      """

  @error @community
  Scenario: WebSocket history when no WebSocket traffic was captured returns empty list
    Given the proxy has captured only HTTP traffic (no WebSocket connections)
    When I run:
      """
      bp ws --format json
      """
    Then the exit code is 0
    And "data.items" is an empty array []
    And "data.total" is 0

  # ─────────────────────────────────────────────────────────────
  # POST /proxy/intercept/* — intercept control
  # GET /proxy/intercept — STUB always {enabled:false}
  # ─────────────────────────────────────────────────────────────

  @community
  Scenario: GET intercept status always returns enabled=false (stub — unreliable)
    # Per spec: GET /proxy/intercept is a STUB — always returns {enabled:false}.
    # bp must surface this caveat rather than silently report false status.
    Given intercept has been enabled via bp intercept on
    When I run:
      """
      bp intercept status --format json
      """
    Then the exit code is 0
    And stdout contains:
      """
      {"enabled":false}
      """
    And bp emits a warning on stderr:
      """
      Warning: GET /proxy/intercept is a stub and always returns {enabled:false}. This does not reflect actual intercept state.
      """

  @happy @community
  Scenario Outline: Intercept toggle commands produce correct JSON response
    When I run:
      """
      bp intercept <action> --format json
      """
    Then the exit code is 0
    And stdout contains:
      """
      {"success":true,"data":{"enabled":<enabled_value>},"error":null}
      """

    Examples:
      | action | enabled_value |
      | on     | true          |
      | off    | false         |

  @happy @community @ledger
  Scenario: Enable intercept is tagged and recorded in the Run Ledger
    When I run:
      """
      bp intercept on --tag pre-manual-browse --format json
      """
    Then the exit code is 0
    And a ledger entry is created with:
      | field   | value                        |
      | tag     | pre-manual-browse            |
      | burp_op | POST /proxy/intercept/enable |
      | status  | ok                           |

  @happy @community @ledger
  Scenario: Disable intercept with --no-ledger suppresses Run Ledger recording
    When I run:
      """
      bp intercept off --no-ledger
      """
    Then the exit code is 0
    And no new ledger entry is created

  @community
  Scenario: Forward intercepted request is a stub no-op that returns {forwarded:true}
    # Per spec: POST /proxy/intercept/forward is a stub — {forwarded:true} no-op.
    # Per spec: forward/drop absent from /docs (OpenAPI). bp must NOT rely on /docs for discovery.
    # bp must surface the caveat rather than imply real forwarding happened.
    When I run:
      """
      bp intercept forward --format json
      """
    Then the exit code is 0
    And stdout body (from Burp) is:
      """
      {"forwarded":true}
      """
    And bp emits a warning on stderr:
      """
      Warning: POST /proxy/intercept/forward is a stub. No request was actually forwarded by this call.
      """

  @community
  Scenario: Drop intercepted request is a stub no-op that returns {dropped:true}
    # Per spec: POST /proxy/intercept/drop is a stub — {dropped:true} no-op.
    # Per spec: forward/drop absent from /docs (OpenAPI). bp must NOT rely on /docs for discovery.
    When I run:
      """
      bp intercept drop --format json
      """
    Then the exit code is 0
    And stdout body (from Burp) is:
      """
      {"dropped":true}
      """
    And bp emits a warning on stderr:
      """
      Warning: POST /proxy/intercept/drop is a stub. No request was actually dropped by this call.
      """

  # ─────────────────────────────────────────────────────────────
  # Intercept lifecycle (DX integration scenario)
  # ─────────────────────────────────────────────────────────────

  @happy @community
  Scenario: Intercept lifecycle — enable, capture, disable in sequence
    When I run:
      """
      bp intercept on --quiet
      """
    Then stdout is "enabled" and exit code is 0
    # (user browses manually to trigger capture)
    When I run:
      """
      bp proxy --limit 1 --format json
      """
    Then exit code is 0 and "data.total" is at least 1
    When I run:
      """
      bp intercept off --quiet
      """
    Then stdout is "disabled" and exit code is 0
