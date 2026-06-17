Feature: Output rendering contract — shared across all bp commands
  # Proves the four-format model, -w grammar, --fields selection, TTY auto-detection,
  # encodeDefaults null emission, quiet semantics, exit-code / stream split, and
  # NDJSON agent-mode schema stability ONCE for the whole CLI.
  #
  # Representative command: `bp fuzz results <attackId>` (multi-record, richest field catalog).
  # Single-record command: `bp send <id>` (status★ + raw).
  # Scope check: `bp scope check <url>` (quiet shell-composition pattern).
  #
  # This file REPLACES all per-endpoint format-variation scenarios (CLI.md §Décisions #5).
  # Per-endpoint files keep AT MOST one --format json scenario asserting endpoint-specific schema.
  #
  # Sources: CLI.md (global flags), OUTPUT.md §0–§6.

  Background:
    # Burp is running at :8089; attack a1b2c3d4 has two results (index 0 and 1).
    Given Burp Suite is reachable at "http://127.0.0.1:8089"
    And attack "a1b2c3d4" has two quick-fuzz results:
      | index | payload       | status | length | time | contentType      | anomalous | requestId |
      | 0     | admin         | 200    | 1487   | 42   | application/json | false     | 318       |
      | 1     | ' OR 1=1--    | 500    | 622    | 58   | text/html        | true      | 319       |

  # ─────────────────────────────────────────────────────────────
  # §1  FOUR FORMATS (OUTPUT.md §1)
  # ─────────────────────────────────────────────────────────────

  Scenario Outline: --format flag selects rendering shape for the same data
    # Proves F-JSON, F-TABLE, F-RAW (single-record), F-QUIET in one outline.
    # Rows are genuinely distinct shapes — not data variation.
    When I run "bp fuzz results a1b2c3d4 <extra_args>"
    Then stdout matches the <expected_shape> contract
    And stderr is empty
    And exit code is 0

    Examples:
      | extra_args                   | expected_shape                                                       |
      | --format json                | NDJSON: two lines, each a valid JSON object, no outer array          |
      | --format table               | header row + two data rows, columns aligned, no JSON syntax          |
      | --format quiet               | two bare lines containing only "200" then "500", no keys             |

  Scenario: --format raw requires a single-record scope; multi-record raises usage error
    # R-RAW-SINGLE: concatenated raw HTTP is ambiguous.
    When I run "bp fuzz results a1b2c3d4 --format raw"
    Then exit code is 2
    And stderr contains "raw requires a single record"
    And stdout is empty

  Scenario: --format raw on a single-record command emits verbatim HTTP bytes
    # F-RAW: no field selection, no wrapper.
    When I run "bp send 42 --format raw"
    Then stdout starts with "HTTP/1.1"
    And stdout contains no JSON syntax
    And stderr is empty
    And exit code is 0

  # ─────────────────────────────────────────────────────────────
  # §2  TTY AUTO-DETECTION (OUTPUT.md A4)
  # ─────────────────────────────────────────────────────────────

  Scenario: table is the default format when stdout is a TTY
    Given stdout is a TTY
    When I run "bp fuzz results a1b2c3d4"
    Then stdout contains a header row with column names
    And stdout contains no JSON syntax

  Scenario: json is the default format when stdout is piped
    Given stdout is a pipe (not a TTY)
    When I run "bp fuzz results a1b2c3d4"
    Then stdout line 1 is a valid JSON object
    And stdout line 2 is a valid JSON object
    And stdout contains no outer JSON array

  Scenario: BP_AGENT=1 forces json format regardless of TTY
    Given stdout is a TTY
    And env var "BP_AGENT" is "1"
    When I run "bp fuzz results a1b2c3d4"
    Then stdout line 1 is a valid JSON object
    And human niceties (color, spinners, progress bars) are absent from stdout

  # ─────────────────────────────────────────────────────────────
  # §3  encodeDefaults — null fields always present (OUTPUT.md A3, AX-SCHEMA)
  # ─────────────────────────────────────────────────────────────

  Scenario: json output includes null-valued fields as explicit nulls, never omits them
    # encodeDefaults=true parity: agents rely on key presence.
    # attack a1b2c3d4 result index 0 has no redirect → location is null.
    When I run "bp fuzz results a1b2c3d4 --format json"
    Then each stdout line contains the key "location"
    And the value of "location" in line 1 is JSON null, not an absent key
    And the value of "anomalous" in line 1 is false (bool, not string)
    And the value of "anomalous" in line 2 is true (bool)

  Scenario: anomalous field is null for full attack results (not quick-fuzz)
    # R-ANOM: server only sets anomalous in quick-fuzz. For /intruder/attack/results
    # (non-quick-fuzz) the field renders as null, not false, to avoid a fake signal.
    Given attack "b9c8d7e6" has standard (non-quick-fuzz) attack results
    When I run "bp fuzz results b9c8d7e6 --format json"
    Then each stdout line contains the key "anomalous"
    And the value of "anomalous" is JSON null in every line

  # ─────────────────────────────────────────────────────────────
  # §4  --quiet SEMANTICS (OUTPUT.md §1.4, E-QUIET)
  # ─────────────────────────────────────────────────────────────

  Scenario: --quiet prints only the essential value per record, one per line
    # F-QUIET: no header, no key, no alignment — designed for shell composition.
    When I run "bp fuzz results a1b2c3d4 --quiet"
    Then stdout is exactly:
      """
      200
      500
      """
    And stderr is empty
    And exit code is 0

  Scenario: --quiet on success with empty essential value prints empty line and exits 0
    # E-QUIET-EMPTY / OPEN-Q1: presence of the record is success; empty line, exit 0.
    Given "bp scope check https://example.com" returns an in-scope result with no extra value
    When I run "bp scope check https://example.com --quiet"
    Then stdout is a single line containing "in-scope"
    And exit code is 0

  Scenario: --quiet on failure emits nothing to stdout; error goes to stderr
    # E-QUIET: --quiet affects stdout only; errors still go to stderr with exit code.
    Given Burp is unreachable
    When I run "bp scope check https://example.com --quiet"
    Then stdout is empty
    And stderr contains an error message
    And exit code is 3

  Scenario: --quiet and -w together are a usage error
    # R-PREC: mutually exclusive; supplying both → exit 2.
    When I run "bp fuzz results a1b2c3d4 --quiet -w '%{status}'"
    Then exit code is 2
    And stderr contains a usage error message
    And stdout is empty

  # ─────────────────────────────────────────────────────────────
  # §5  -w / --write-out TOKEN SUBSTITUTION (OUTPUT.md §3)
  # ─────────────────────────────────────────────────────────────

  Scenario: -w template with all core tokens substitutes correctly per record
    # R-WTOK: 11 core tokens guaranteed on every family.
    When I run "bp fuzz results a1b2c3d4 -w '%{index} %{status} %{length} %{time} %{payload} %{location} %{anomalous} %{contentType} %{requestId} %{host} %{method}'"
    Then stdout line 1 is "0 200 1487 42 admin  false application/json 318  "
    And stdout line 2 is "1 500 622 58 ' OR 1=1--  true text/html 319  "
    # tokens absent for this family (location, host, method) render as empty string

  Scenario: -w headline example — status and payload only, one line per record
    # Founder headline example (OUTPUT.md §3.1): curl-style triage, no decoration.
    When I run "bp fuzz results a1b2c3d4 -w '%{status} %{payload}'"
    Then stdout is exactly:
      """
      200 admin
      500 ' OR 1=1--
      """
    And exit code is 0

  Scenario: -w template with escape sequences renders \n \t \\ correctly
    # R-WESC: \n → newline, \t → tab, \\ → backslash in template literals.
    When I run "bp fuzz results a1b2c3d4 -w '%{status}\t%{length}'"
    Then stdout line 1 is "200<TAB>1487"
    And stdout line 2 is "500<TAB>622"

  Scenario: -w with a payload containing a newline character escapes it to \n
    # R-WSAFE: raw \n inside a token value is escaped so one record = one stdout line.
    Given attack "c3d4e5f6" has a result where payload contains an embedded newline
    When I run "bp fuzz results c3d4e5f6 -w '%{payload}'"
    Then stdout has exactly one line per result record
    And the embedded newline appears as the two-character sequence "\n" in that line

  Scenario: -w with an unknown token is a usage error (fail loud)
    # R-WUNKNOWN: unknown token must not silently pass through as literal text.
    When I run "bp fuzz results a1b2c3d4 -w '%{nonexistent}'"
    Then exit code is 2
    And stderr contains "unknown token"
    And stdout is empty

  Scenario: -w owns stdout — --format and --fields are ignored for row rendering
    # R-PREC: when -w is present it OWNS stdout; --format is simply ignored for rows.
    When I run "bp fuzz results a1b2c3d4 -w '%{status}' --format table --fields payload,status"
    Then stdout contains only the two status codes (200 then 500), one per line
    And stdout contains no column headers
    And exit code is 0

  # ─────────────────────────────────────────────────────────────
  # §6  --fields COLUMN RESTRICTION (OUTPUT.md §2)
  # ─────────────────────────────────────────────────────────────

  Scenario: --fields restricts and orders json output columns
    # R-FIELDS: given order is honored; omitted fields absent from each line.
    When I run "bp fuzz results a1b2c3d4 --format json --fields status,payload"
    Then each stdout line is a JSON object with exactly two keys: "status" and "payload"
    And "status" appears before "payload" in each line

  Scenario: --fields with an unknown field name is a usage error
    # R-FIELDS: unknown field → exit 2, stderr lists valid fields.
    When I run "bp fuzz results a1b2c3d4 --fields bogusField"
    Then exit code is 2
    And stderr contains "bogusField"
    And stderr lists valid field names

  Scenario: --fields with --format raw is a usage error
    # R-FIELDS + F-RAW: raw has no columns; combining them is semantically invalid.
    When I run "bp send 42 --format raw --fields status"
    Then exit code is 2
    And stderr contains a usage error message

  # ─────────────────────────────────────────────────────────────
  # §7  EXIT CODES & STDERR vs STDOUT SPLIT (OUTPUT.md §5)
  # ─────────────────────────────────────────────────────────────

  Scenario: successful command with target HTTP 500 exits 0 — exit code reflects bp+Burp, not target
    # E-TARGET: a fuzz result containing status 500 is a successful bp operation.
    When I run "bp fuzz results a1b2c3d4 --format json"
    Then exit code is 0
    And stdout line 2 contains "\"status\":500"

  Scenario: on any failure stdout is completely empty and error is a single JSON object on stderr
    # E-STREAMS: fail = empty stdout; AX-STDERR-JSON: in agent mode errors on stderr are JSON.
    Given stdout is a pipe (not a TTY)
    And attack "zzzzzzzz" does not exist (server returns 404 INVALID_REQUEST)
    When I run "bp fuzz results zzzzzzzz --format json"
    Then stdout is empty
    And stderr is exactly one JSON line with keys "error.code" and "error.message"
    And exit code is 1

  Scenario: human-mode error on stderr is prose, not JSON
    # E-SHAPE: in human mode (TTY) stderr errors are plain prose, not JSON.
    Given stdout is a TTY
    And attack "zzzzzzzz" does not exist
    When I run "bp fuzz results zzzzzzzz"
    Then stderr is a plain prose line containing "error:"
    And stderr does not start with "{"

  # ─────────────────────────────────────────────────────────────
  # §8  NDJSON AGENT-MODE SCHEMA STABILITY (OUTPUT.md §4)
  # ─────────────────────────────────────────────────────────────

  Scenario: NDJSON schema is stable — field names, types, order, and null presence are frozen
    # AX-SCHEMA: additive-only evolution. Agents may rely on key presence and type.
    When I run "bp fuzz results a1b2c3d4 --format json"
    Then stdout line 1 matches the schema:
      | field       | type        | nullable |
      | index       | integer     | false    |
      | payload     | string      | false    |
      | status      | integer     | false    |
      | length      | integer     | false    |
      | time        | integer     | false    |
      | contentType | string      | true     |
      | anomalous   | boolean     | true     |
      | error       | string      | true     |
      | location    | string      | true     |
      | requestId   | integer     | true     |
    And fields appear in exactly the catalog order listed above
    And no field is absent (all nullables present as JSON null when empty)

  Scenario: bp version --format json reports schema integer for agent pinning
    # AX-VERSION: agents pin schema to detect breaking changes.
    When I run "bp version --format json"
    Then stdout is one JSON object
    And it contains key "bp" (string, semver)
    And it contains key "schema" (integer)
    And exit code is 0

  Scenario: --no-ledger suppresses the ledger write without affecting stdout, stderr, or exit code
    # L-NOLEDGER: orthogonal to output. Zero trace in ~/.bp/ for this invocation.
    Given the ledger entry count is N before the command
    When I run "bp fuzz results a1b2c3d4 --format json --no-ledger"
    Then stdout is valid NDJSON with two records
    And stderr is empty
    And exit code is 0
    And the ledger entry count is still N after the command
