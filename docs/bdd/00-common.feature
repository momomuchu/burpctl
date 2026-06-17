Feature: Cross-Cutting Contracts
  As a security engineer or AI agent driving bp against Burp Suite,
  I need the CLI to behave consistently on every cross-cutting concern —
  connection failures, exit codes, invalid identifiers, ApiResponse envelope
  unwrapping, PRO_REQUIRED degradation, Run Ledger recording, and JSON
  leniency — so that every pipeline can rely on one stable contract regardless
  of which endpoint it calls.

  These scenarios are proven ONCE here and are NOT repeated in endpoint files.
  See 00-output.feature for output-rendering contracts (--format/--fields/-w/--quiet).

  Background:
    Given the bp CLI is installed and on PATH
    And the default Burp REST URL is "http://127.0.0.1:8089"

  # ─────────────────────────────────────────────
  # §1  EXIT-CODE TABLE (reference contract)
  # Proves the mapping once; every other feature relies on it.
  # ─────────────────────────────────────────────

  @contract @community
  Scenario: Exit-code 0 on a successful call
    Given Burp Suite is running on port 8089
    When I run: bp health
    Then bp exits with exit code 0

  @contract @community
  Scenario: Exit-code 3 when Burp is unreachable (CONNECTION_REFUSED)
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health
    Then bp exits with exit code 3

  @contract @community @pro
  Scenario: Exit-code 4 when a Pro-only command is run against Community edition (PRO_REQUIRED)
    Given Burp Suite is running in Community edition on port 8089
    When I run: bp collab new --format json
    Then bp exits with exit code 4

  @contract @community
  Scenario: Exit-code 2 on bad CLI usage (missing required positional argument)
    Given Burp Suite is running on port 8089
    When I run: bp send --format json
    Then bp exits with exit code 2
    And stderr contains a usage hint (e.g. "Usage:" or "required argument")

  @contract @community
  Scenario: Exit-code 1 on a generic API error (non-connection, non-Pro, non-usage)
    Given Burp Suite is running on port 8089
    And the proxy history contains fewer than 9999 entries
    When I run: bp send 9999 --format json
    Then bp exits with exit code 1
    And stdout contains JSON with "success" equal to false

  # ─────────────────────────────────────────────
  # §2  BURP UNREACHABLE — CONNECTION_REFUSED
  # ─────────────────────────────────────────────

  @error @community
  Scenario: Health check when Burp is not running returns exit 3 and a clear connection error
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health
    Then bp exits with exit code 3
    And stderr contains "connection refused" or "could not connect" and the target URL "http://127.0.0.1:8089"
    And stdout is empty

  @error @community
  Scenario: Burp unreachable with --format json emits a machine-readable CONNECTION_REFUSED envelope on stdout
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health --format json
    Then bp exits with exit code 3
    And stdout is a single compact JSON line matching:
      """
      {"success":false,"data":null,"error":{"code":"CONNECTION_REFUSED","message":"<non-empty>"}}
      """
    And stderr contains the target URL so the operator knows what was tried

  @error @community
  Scenario: Any subcommand when Burp is unreachable fails fast within 5 seconds (no hang)
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp proxy --format json
    Then bp exits with exit code 3
    And stdout contains JSON with "error.code" equal to "CONNECTION_REFUSED"
    And bp fails within 5 seconds

  @error @community
  Scenario: Wrong --url host (typo in hostname) produces CONNECTION_REFUSED with the attempted URL in the error
    Given no host is listening at "http://burp.local:8089"
    When I run: bp health --url http://burp.local:8089 --format json
    Then bp exits with exit code 3
    And the error message references "http://burp.local:8089" so the operator can spot the misconfiguration

  @error @community
  Scenario: Wrong --url port (Burp on 8089 but CLI told 9999) produces CONNECTION_REFUSED
    Given Burp Suite is running on port 8089 but NOT on port 9999
    When I run: bp health --url http://127.0.0.1:9999 --format json
    Then bp exits with exit code 3
    And stdout contains JSON with "error.code" equal to "CONNECTION_REFUSED"
    And the error message contains port "9999" (not "8089") so the operator sees the configured address

  # ─────────────────────────────────────────────
  # §3  INVALID / MISSING --id
  # Proves the client-side validation contract once for any command that
  # accepts an integer requestId positional or --id flag.
  # ─────────────────────────────────────────────

  @error @community
  Scenario: --id with a non-integer string is rejected client-side before any HTTP call (exit 2)
    Given Burp Suite is running on port 8089
    When I run: bp send abc --format json
    Then bp exits with exit code 2
    And stderr contains an error indicating the id must be an integer
    And no HTTP request is made to Burp

  @error @community
  Scenario: --id with a negative integer is rejected (exit 1 or 2, success:false)
    Given Burp Suite is running on port 8089
    When I run: bp send -1 --format json
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "success" equal to false
    And the error message identifies the invalid id value

  @error @community
  Scenario: --id that does not exist in Burp returns INVALID_REQUEST (exit 1, HTTP 200 unwrapped)
    Given Burp Suite is running on port 8089
    And the proxy history contains fewer than 9999 entries
    When I run: bp send 9999 --format json
    Then bp exits with exit code 1
    And stdout contains JSON matching:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"<non-empty>"}}
      """

  @error @community
  Scenario Outline: Boundary id values are all rejected with a non-zero exit code
    Given Burp Suite is running on port 8089
    When I run: bp send <value> --format json
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "success" equal to false

    Examples:
      | value       |
      | 0           |
      | 2147483648  |
      | 1.5         |

  # ─────────────────────────────────────────────
  # §4  ApiResponse ENVELOPE UNWRAP
  # The server wraps errors in HTTP 200 {"success":false,...}.
  # bp must unwrap and propagate a non-zero exit code.
  # ─────────────────────────────────────────────

  @contract @community
  Scenario: bp unwraps an HTTP 200 body with success:false and exits non-zero (envelope contract)
    Given Burp Suite is running on port 8089
    When I send a raw GET to "/target/scope/check" with no "url" query parameter
    Then the server responds with HTTP 200
    And the response JSON has "success" equal to false
    And the response JSON has "error.code" equal to "INVALID_PARAM"

  @contract @community
  Scenario: bp scope check without a URL argument exits non-zero despite the HTTP 200 from the server
    Given Burp Suite is running on port 8089
    When I run: bp scope check --format json
    Then bp exits with a non-zero exit code
    And stdout contains JSON with "error.code" equal to "INVALID_PARAM"
    And bp does NOT exit 0 (the HTTP 200 must not mask the error)

  @contract @community
  Scenario: AI agent calling bp in json mode receives the stable ApiResponse schema on both success and error
    Given Burp Suite is running on port 8089
    When I run: bp health --format json
    Then stdout is a single compact JSON line (no pretty-print, no embedded newlines)
    And the JSON has the keys "success", "data", and "error" at the top level
    And there is no trailing comma or unquoted key in the output

  # ─────────────────────────────────────────────
  # §5  PRO_REQUIRED — Community edition graceful degradation (exit 4)
  # Covers: early pre-flight warning + correct exit code.
  # Endpoint-specific Pro error messages live in each endpoint's feature file.
  # ─────────────────────────────────────────────

  @error @community @pro
  Scenario: bp detects Community edition before dispatching a Pro-only command and warns on stderr (exit 4)
    Given Burp Suite is running in Community edition on port 8089
    When I run: bp collab new --format json
    Then bp exits with exit code 4
    And stderr contains a pre-flight warning such as "requires Burp Suite Professional"
    And stdout contains JSON with "error.code" equal to "PRO_REQUIRED"

  @error @community @pro
  Scenario: bp scan crawl on Community exits 4 with PRO_REQUIRED (not 1 / INTERNAL_ERROR)
    Given Burp Suite is running in Community edition on port 8089
    When I run: bp scan crawl https://app.example.com --format json
    Then bp exits with exit code 4
    And stdout contains JSON with "error.code" equal to "PRO_REQUIRED"
    And the error message contains "Professional"

  @error @community @pro
  Scenario: bp collab poll on Community exits 4 with PRO_REQUIRED
    Given Burp Suite is running in Community edition on port 8089
    When I run: bp collab poll --format json
    Then bp exits with exit code 4
    And stdout contains JSON with "error.code" equal to "PRO_REQUIRED"

  # ─────────────────────────────────────────────
  # §6  RUN LEDGER — auto-record, --tag, --no-ledger
  # ─────────────────────────────────────────────

  @contract @community @ledger
  Scenario: Every successful operation is auto-recorded in the Run Ledger by default
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run: bp send 1 --format json
    Then bp exits with exit code 0
    And running "bp log --format json" afterwards shows an entry whose "command" matches "bp send 1"
    And the ledger entry contains a "timestamp" and "target" field

  @contract @community @ledger
  Scenario: --no-ledger flag suppresses the Run Ledger entry for that operation
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run: bp send 1 --no-ledger --format json
    Then bp exits with exit code 0
    And running "bp log --format json" afterwards does NOT contain an entry for this operation

  @contract @community @ledger
  Scenario: --tag records the label in the Run Ledger entry for the operation
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I run: bp send 1 --tag "auth-bypass-probe-1" --format json
    Then bp exits with exit code 0
    And running "bp log --format json" shows an entry with "tag" equal to "auth-bypass-probe-1"
    And that ledger entry includes the exact bp command, timestamp, and target URL

  @contract @community @ledger
  Scenario: Failed operations (non-zero exit) are NOT recorded in the Run Ledger
    Given Burp Suite is running on port 8089
    When I run: bp send 9999 --format json
    Then bp exits with a non-zero exit code
    And running "bp log --format json" does NOT show an entry for this failed operation

  # ─────────────────────────────────────────────
  # §7  JSON LENIENCY (server-side isLenient=true)
  # Proves that Gson's lenient mode is scoped to the server; bp CLI output
  # is always strict JSON.
  # ─────────────────────────────────────────────

  @contract @community
  Scenario: Server accepts JSON with trailing comma (isLenient=true) and unknown keys are silently dropped
    Given Burp Suite is running on port 8089
    And proxy history entry 1 exists
    When I send a raw POST to "/repeater/send" with body:
      """
      {"requestId":1,"unknownField":"ignored",}
      """
    Then the server responds with HTTP 200
    And the response JSON has "success" equal to true
    And the "unknownField" key is NOT reflected back in any response field

  @contract @community
  Scenario: Server accepts JSON with unquoted keys (isLenient=true Gson quirk)
    Given Burp Suite is running on port 8089
    And proxy history entry 2 exists
    When I send a raw POST to "/repeater/send" with body:
      """
      {requestId:2}
      """
    Then the server responds with HTTP 200
    And the response JSON has "success" equal to true

  @error @community
  Scenario: Sending completely invalid JSON (not even an object) returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      not-json-at-all
      """
    Then the server responds with HTTP 400
    And the response JSON matches:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"<non-empty>"}}
      """

  @error @community
  Scenario: Sending a JSON array at the top level (not an object) returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      ["requestId",1]
      """
    Then the server responds with HTTP 400
    And the response JSON has "error.code" equal to "INVALID_REQUEST"

  @error @community
  Scenario: Sending a typed mismatch (requestId as String instead of Int) returns INVALID_REQUEST 400
    Given Burp Suite is running on port 8089
    When I send a raw POST to "/repeater/send" with body:
      """
      {"requestId":"seven"}
      """
    Then the server responds with HTTP 400
    And the response JSON has "error.code" equal to "INVALID_REQUEST"
    And the message references the type mismatch (requestId must be Int)

  @contract @community
  Scenario: bp CLI stdout is always strict JSON (no trailing comma, no unquoted key) even though server accepts lenient JSON
    Given Burp Suite is NOT running (port 8089 is closed)
    When I run: bp health --format json
    Then bp exits with exit code 3
    And stdout is valid strict JSON (passes a strict JSON parser without errors)
    And stdout contains no trailing comma and no unquoted key
