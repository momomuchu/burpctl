Feature: 01-health — health, version, and docs endpoint contracts
  As a human operator or AI agent driving bp against a local Burp Suite extension on :8089
  I want bp to confirm the server is alive, report its version, and expose the embedded OpenAPI —
  so that every downstream operation starts from a known, trusted baseline.

  Background:
    Given the bp binary is installed and on PATH
    And the default Burp REST URL is "http://127.0.0.1:8089" (BURP_REST_URL env)

  # ---------------------------------------------------------------------------
  # §1 bp health — GET /health
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: health check returns status ok with expected fields in table format
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health
      """
    Then the exit code is 0
    And stdout contains a table with columns: status  version  uptime  burpVersion
    And the "status" cell equals "ok"
    And the "version" cell equals "0.1.0"
    And the "burpVersion" cell equals "null"
    And stderr is empty

  @happy @community
  Scenario: health --format json returns stable ApiResponse schema for agent consumers
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.status" equals "ok"
    And the JSON field "data.version" equals "0.1.0"
    And the JSON field "data.uptime" is a positive integer
    And the JSON field "data.burpVersion" is null
    And the JSON field "error" is null
    And stderr is empty

  @happy @community
  Scenario: burpVersion is always null in health response — bp does NOT use it for edition detection
    # Known flag: burpVersion is never populated; edition probe uses a separate mechanism.
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "data.burpVersion" is null
    And bp does NOT attempt to interpret burpVersion for edition detection

  @happy @community
  Scenario: health is resilient to large uptime values without integer overflow
    Given Burp Suite is running and has been up for 9007199254740991 milliseconds
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "data.uptime" equals 9007199254740991
    And bp renders the uptime without integer overflow or truncation

  @happy @community
  Scenario: health records a Run Ledger entry with correct burp_op and target
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp health --tag health-check-001
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value                            |
      | tag     | health-check-001                 |
      | burp_op | GET /health                      |
      | target  | http://127.0.0.1:8089            |
      | status  | ok                               |
      | command | bp health --tag health-check-001 |

  @error
  Scenario: a failed health call is still recorded in the ledger with status=error
    # Cross-cutting CONNECTION_REFUSED envelope is proven in 00-common.feature;
    # this scenario asserts the health-specific ledger behaviour on failure.
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run:
      """
      bp health --tag failed-probe
      """
    Then the exit code is non-zero
    And running "bp log --format json" shows a ledger entry where:
      | field  | value        |
      | tag    | failed-probe |
      | status | error        |

  @error
  Scenario: health respects BURP_REST_URL and surfaces the wrong URL in the error message
    Given Burp Suite is running on port 8089
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:9999"
    When I run:
      """
      bp health
      """
    Then the exit code is non-zero
    And stderr contains "http://127.0.0.1:9999"
    And stderr does NOT contain "8089"

  @error
  Scenario: health with legacy port 9876 produces an actionable error with a hint for port 8089
    # Specifically tests that bp guides users migrating from the old spec.md default port.
    Given Burp Suite is running on port 8089 only
    And environment variable BURP_REST_URL is set to "http://127.0.0.1:9876"
    When I run:
      """
      bp health
      """
    Then the exit code is non-zero
    And stderr contains "9876"
    And stderr contains a hint suggesting "http://127.0.0.1:8089"

  @error
  Scenario: health returns non-zero when the extension returns HTTP 500
    Given Burp Suite extension returns HTTP 500 with body:
      """
      {"success":false,"data":null,"error":{"code":"INTERNAL_ERROR","message":"unexpected Throwable"}}
      """
    When I run:
      """
      bp health --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stdout JSON field "error.code" equals "INTERNAL_ERROR"

  @happy @community
  Scenario Outline: health succeeds for valid BURP_REST_URL forms (trailing slash, localhost alias)
    Given Burp Suite is running and reachable at "<host>:<port>"
    And environment variable BURP_REST_URL is set to "<url>"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true

    Examples:
      | url                       | host      | port |
      | http://127.0.0.1:8089/    | 127.0.0.1 | 8089 |
      | http://localhost:8089      | localhost | 8089 |

  @error
  Scenario Outline: health fails cleanly for unreachable BURP_REST_URL and surfaces the URL
    Given no service is listening at "<url>"
    And environment variable BURP_REST_URL is set to "<url>"
    When I run:
      """
      bp health --format json
      """
    Then the exit code is non-zero
    And stdout JSON field "success" is false
    And stderr contains "<url>"

    Examples:
      | url                    |
      | http://127.0.0.1:9876  |
      | http://192.0.2.1:8089  |

  # ---------------------------------------------------------------------------
  # §2 bp version — GET /version
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: version returns the deployed extension version string
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version
      """
    Then the exit code is 0
    And stdout contains "0.1.0"
    And stderr is empty

  @happy @community
  Scenario: version --format json returns stable schema with version and burpVersion fields
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.version" equals "0.1.0"
    And the JSON field "data.burpVersion" is null

  @happy @community
  Scenario: version records a Run Ledger entry with burp_op GET /version
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp version --tag pre-flight
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value        |
      | tag     | pre-flight   |
      | burp_op | GET /version |
      | status  | ok           |

  # ---------------------------------------------------------------------------
  # §3 bp docs — GET /docs  (non-enveloped OpenAPI response)
  # ---------------------------------------------------------------------------

  @happy @community
  Scenario: docs --format raw returns the raw OpenAPI JSON — not wrapped in ApiResponse
    # /docs is the only endpoint that returns raw bytes, not an ApiResponse envelope.
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs --format raw
      """
    Then the exit code is 0
    And stdout is valid JSON
    And the JSON root object contains key "openapi" or "swagger"
    And the JSON field "info.version" equals "0.2.0"
    And stdout does NOT begin with '{"success"'

  @happy @community
  Scenario: docs --format json normalises the raw bytes into an ApiResponse envelope
    # bp wraps the non-enveloped /docs response for consistency in agent mode.
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs --format json
      """
    Then the exit code is 0
    And stdout is valid JSON
    And the JSON field "success" is true
    And the raw OpenAPI bytes are accessible under the "data" field

  @happy @community
  Scenario: docs surfaces the version discrepancy between /docs (0.2.0) and /health (0.1.0)
    # /docs reports info.version 0.2.0 while /health reports version 0.1.0 — a known mismatch.
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs --format json
      """
    Then the exit code is 0
    And the JSON field "info.version" in the OpenAPI payload equals "0.2.0"
    And stderr contains a warning about version mismatch between /docs (0.2.0) and /health (0.1.0)

  @happy @community
  Scenario: docs warns that /session, /scan, /scanner-start are absent from the embedded OpenAPI
    # /docs is known-incomplete: three endpoint groups are undocumented.
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp docs
      """
    Then the exit code is 0
    And stderr contains a warning that /docs is known-incomplete
    And stderr mentions that /session, /scan, /scanner groups are absent from the embedded OpenAPI
