# =============================================================================
# Domain 12 · Config (/config and /extensions)
# Spec reference: SPEC.md §6.10 — 5 endpoints, Community tier (C)
#
# LOAD-BEARING CAVEATS (all scenarios must honour these):
#   1. GET /config/project  → hardcoded stub: always returns {"type":"project"}
#   2. PUT /config/project  → echo stub: reflects the sent payload, no durable write
#   3. GET /config/user     → hardcoded stub: always returns {"type":"user"}
#   4. PUT /config/user     → echo stub: reflects the sent payload, no durable write
#   5. GET /extensions      → self-metadata only; total is ALWAYS 1 (Montoya limit)
#   6. /extensions is mounted at the ROOT (/extensions), NOT at /config/extensions
#
# Kotlin request model for PUT endpoints:
#   ConfigUpdateRequest { config: Map<String,String> }
#
# Command spellings (canonical — CLI.md §command-map):
#   bp config get project    GET  /config/project
#   bp config set project    PUT  /config/project
#   bp config get user       GET  /config/user
#   bp config set user       PUT  /config/user
#   bp ext                   GET  /extensions          (root mount, NOT /config/extensions)
#
# Output/error cross-cutting contracts NOT re-proved here:
#   --format json|table|raw|quiet  · --fields · -w/--write-out  → 00-output.feature
#   CONNECTION_REFUSED · envelope unwrap · generic --id errors  → 00-common.feature
# =============================================================================

@config
Feature: 12-config — project config, user config, and extension metadata (§6.10)

  As a bug-bounty hunter or AI agent driving bp against Burp Suite on :8089
  I want to read and write project/user configuration and inspect loaded extensions
  So that I can confirm Burp state, script config probes, and surface stub-caveat warnings
  that prevent me from treating echo responses as proof of durable writes.

  Background:
    Given the bp binary is installed and on PATH
    And the Burp REST extension is listening on http://127.0.0.1:8089

  # ===========================================================================
  # GET /config/project — hardcoded stub, always {"type":"project"}
  # ===========================================================================

  @happy @community
  Scenario: GET project config returns the hardcoded stub value and emits stub-caveat warning
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config get project
      """
    Then the exit code is 0
    And stdout contains a table with at least the column "type"
    And the "type" cell equals "project"
    And stderr contains a warning matching "stub" or "hardcoded" or "not the live Burp config"

  @happy @community
  Scenario: GET project config --format json returns stable agent-mode envelope with endpoint-specific schema
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config get project --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line matching:
      """
      {"success":true,"data":{"type":"project"},"error":null}
      """
    And the JSON field "data.type" equals "project"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: GET project config --quiet suppresses both table output and stub-caveat warning
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config get project --quiet
      """
    Then the exit code is 0
    And stdout is exactly "project"
    And stderr is empty

  @fuzz @community
  Scenario: GET project config is idempotent — repeated calls always return {"type":"project"}
    Given Burp Suite is running with the REST extension active on port 8089
    When I run "bp config get project --format json" three times in sequence
    Then all three runs exit 0
    And all three stdout lines are identical: {"success":true,"data":{"type":"project"},"error":null}

  # ===========================================================================
  # PUT /config/project — echo stub, ConfigUpdateRequest{config:Map<String,String>}
  # ===========================================================================

  @happy @community
  Scenario: PUT project config echoes the sent payload and warns of no durable write
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"proxy.intercept":"disabled","scanner.enabled":"false"}'
      """
    Then the exit code is 0
    And stdout contains "proxy.intercept"
    And stdout contains "disabled"
    And stderr contains a warning matching "echo" or "stub" or "not persisted" or "no durable write"

  @happy @community
  Scenario: PUT project config --format json returns echoed config inside data.config field
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"proxy.intercept":"disabled"}' --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.config.proxy.intercept" equals "disabled"
    And the JSON field "error" is null
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT project config does NOT make a subsequent GET to verify persistence
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"any.key":"any.value"}' --format json
      """
    Then the exit code is 0
    And bp does NOT make a subsequent GET /config/project call to verify the write
    And the JSON field "data.config.any.key" equals "any.value"

  @happy @community
  Scenario: PUT project config --quiet suppresses normal output but caveat warning still emits on stderr
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"k":"v"}' --quiet
      """
    Then the exit code is 0
    And stdout is empty or contains only "ok"
    And stderr contains a stub-caveat warning

  @error @community
  Scenario: PUT project config with malformed JSON exits non-zero with parse error
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config 'not-valid-json'
      """
    Then the exit code is non-zero (1 or 2)
    And stderr contains "invalid JSON" or "malformed config" or "parse error"
    And stdout is empty

  @error @community
  Scenario: PUT project config with empty config map is rejected or warns of no-op
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{}'
      """
    Then the exit code is non-zero OR stderr contains "empty config map has no effect"

  # ===========================================================================
  # GET /config/user — hardcoded stub, always {"type":"user"}
  # ===========================================================================

  @happy @community
  Scenario: GET user config returns the hardcoded stub value and emits stub-caveat warning
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config get user
      """
    Then the exit code is 0
    And stdout contains a table with at least the column "type"
    And the "type" cell equals "user"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: GET user config --format json returns stable agent-mode envelope with endpoint-specific schema
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config get user --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line matching:
      """
      {"success":true,"data":{"type":"user"},"error":null}
      """
    And the JSON field "data.type" equals "user"
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: GET user config --quiet suppresses both output and stub-caveat warning
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config get user --quiet
      """
    Then the exit code is 0
    And stdout is exactly "user"
    And stderr is empty

  @happy @community
  Scenario: GET user config stub-caveat warning pattern is consistent with project config caveat
    Given Burp Suite is running with the REST extension active on port 8089
    When I run both:
      """
      bp config get project 2>&1
      bp config get user 2>&1
      """
    Then both commands emit a matching stub-caveat warning pattern on stderr
    And the warning in each case is not empty and does not differ in severity level

  @fuzz @community
  Scenario: GET user config is idempotent — repeated calls always return {"type":"user"}
    Given Burp Suite is running with the REST extension active on port 8089
    When I run "bp config get user --format json" three times in sequence
    Then all three runs exit 0
    And all three stdout lines are identical: {"success":true,"data":{"type":"user"},"error":null}

  # ===========================================================================
  # PUT /config/user — echo stub, ConfigUpdateRequest{config:Map<String,String>}
  # ===========================================================================

  @happy @community
  Scenario: PUT user config echoes the sent payload and warns of no durable write
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set user --config '{"theme":"dark","shortcuts.enabled":"true"}'
      """
    Then the exit code is 0
    And stdout contains "theme"
    And stdout contains "dark"
    And stderr contains a warning matching "echo" or "stub" or "not persisted" or "no durable write"

  @happy @community
  Scenario: PUT user config --format json returns echoed payload in data.config field
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set user --config '{"theme":"dark","font.size":"14"}' --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.config.theme" equals "dark"
    And the JSON field "data.config.font.size" equals "14"
    And the JSON field "error" is null
    And stderr contains a stub-caveat warning

  @happy @community
  Scenario: PUT user config --quiet suppresses normal output but caveat warning still emits on stderr
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set user --config '{"k":"v"}' --quiet
      """
    Then the exit code is 0
    And stdout is empty or contains only "ok"
    And stderr contains a stub-caveat warning

  @error @community
  Scenario: PUT user config with malformed JSON exits non-zero with parse error
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set user --config '{bad-json'
      """
    Then the exit code is non-zero
    And stderr contains "invalid JSON" or "parse error" or "malformed config"
    And stdout is empty

  @error @community
  Scenario: PUT user config without --config argument exits with usage error (exit 2)
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set user
      """
    Then the exit code is 2
    And stderr contains "required" or "missing" or "--config"

  # ===========================================================================
  # Scenario Outline: PUT echo-stub reflects exactly the sent keys for both resources
  # (Distinct rows: project vs user scope; proxy/scanner/timeout vs theme/font/shortcuts keys)
  # ===========================================================================

  @happy @community
  Scenario Outline: PUT config echo stub reflects exactly the sent keys for both resources
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set <resource> --config '{"<key>":"<value>"}' --format json --no-ledger
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.config.<key>" equals "<value>"
    And stderr contains a stub-caveat warning

    Examples:
      | resource | key             | value    |
      | project  | proxy.intercept | disabled |
      | project  | scanner.enabled | false    |
      | project  | timeout.ms      | 3000     |
      | user     | theme           | dark     |
      | user     | font.size       | 14       |
      | user     | shortcuts       | true     |

  # ===========================================================================
  # Echo-stub divergence — write then read proves no durable side effect
  # (Load-bearing: confirms CAVEAT #2 and #4 — distinguishes echo from real write)
  # ===========================================================================

  @happy @community
  Scenario: PUT project config followed immediately by GET project config shows stub divergence
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"foo":"bar"}' --format json --no-ledger
      """
    And then I run:
      """
      bp config get project --format json --no-ledger
      """
    Then the first command's data.config.foo equals "bar"
    And the second command returns JSON where "data.type" equals "project"
    And the second command response does NOT contain "foo" (proving no durable write occurred)
    And this divergence confirms the PUT is an echo stub with no durable side effect

  # ===========================================================================
  # GET /extensions — mounted at ROOT /extensions (NOT /config/extensions)
  #   total is ALWAYS 1; returns self-metadata (filename of the active extension)
  # ===========================================================================

  @happy @community
  Scenario: GET extensions returns total=1 and the active extension filename
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp ext
      """
    Then the exit code is 0
    And stdout contains a table with columns: total, filename (or name)
    And the "total" cell equals "1"
    And the "filename" or "name" cell is a non-empty string ending with ".jar" or containing "burp"
    And stderr is empty

  @happy @community
  Scenario: GET extensions --format json returns stable agent-mode envelope with endpoint-specific schema
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp ext --format json
      """
    Then the exit code is 0
    And stdout is exactly one JSON line
    And the JSON field "success" is true
    And the JSON field "data.total" equals 1
    And the JSON field "data.extensions" is an array of length 1
    And the JSON field "error" is null
    And stderr is empty

  @happy @community
  Scenario: GET extensions total is always exactly 1 regardless of how many extensions Burp has loaded (Montoya invariant)
    Given Burp Suite is running with multiple extensions loaded
    When I run:
      """
      bp ext --format json
      """
    Then the exit code is 0
    And the JSON field "data.total" equals 1
    And the JSON array "data.extensions" has exactly 1 element
    And stderr contains a caveat matching "Montoya" or "self-metadata" or "total always 1" or "active extension only"

  @happy @community
  Scenario: GET extensions --quiet prints only the filename of the active extension
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp ext --quiet
      """
    Then the exit code is 0
    And stdout is a single non-empty string (the extension filename or name)
    And stderr is empty

  @happy @community
  Scenario: GET extensions Montoya caveat is surfaced to the caller on stderr
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp ext
      """
    Then the exit code is 0
    And stderr contains a warning matching "only the active extension" or "total always 1" or "Montoya limit"

  @happy @community
  Scenario: bp ext routes to /extensions (root path) not /config/extensions
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp ext --format json
      """
    Then the exit code is 0
    And the HTTP request made by bp targets the path "/extensions" (not "/config/extensions")
    And the JSON field "data.total" equals 1
    And stdout does NOT contain any reference to "/config/extensions"

  @error @community
  Scenario: Accessing /config/extensions (wrong path) returns 404 or error
    # Guard: bp must not silently fall back to the wrong path if a user bypasses via --url override
    Given Burp Suite is running with the REST extension active on port 8089
    When bp is instructed to request the path "/config/extensions" directly
    Then the exit code is non-zero OR stderr contains "not found" or "404"
    And the response does NOT contain "total":1 on a successful 200

  @fuzz @community
  Scenario: GET extensions is idempotent — total is always 1 on every call
    Given Burp Suite is running with the REST extension active on port 8089
    When I run "bp ext --format json" three times in sequence
    Then all three runs exit 0
    And all three stdout lines contain "\"total\":1"

  # ===========================================================================
  # Run Ledger — --tag records correct burp_op per endpoint
  # ===========================================================================

  @ledger @happy @community
  Scenario Outline: --tag records a LedgerEntry with correct burp_op for each config endpoint
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      <command> --tag <tag>
      """
    Then the exit code is 0
    And running "bp log --format json" shows a ledger entry where:
      | field   | value     |
      | tag     | <tag>     |
      | burp_op | <burp_op> |
      | status  | ok        |

    Examples:
      | command                                              | tag               | burp_op             |
      | bp config get project                                | config-probe-001  | GET /config/project |
      | bp config set project --config '{"k":"v"}'           | config-write-001  | PUT /config/project |
      | bp config get user                                   | user-config-read  | GET /config/user    |
      | bp config set user --config '{"k":"v"}'              | user-config-write | PUT /config/user    |
      | bp ext                                               | ext-probe-001     | GET /extensions     |

  @ledger @happy @community
  Scenario: --no-ledger suppresses Run Ledger recording for config operations
    Given Burp Suite is running with the REST extension active on port 8089
    And the Run Ledger currently has N entries
    When I run:
      """
      bp config get project --no-ledger
      """
    Then the exit code is 0
    And the Run Ledger still has exactly N entries

  # ===========================================================================
  # Fuzz / edge cases — echo-stub correctness under abnormal input
  # ===========================================================================

  @fuzz @community
  Scenario: PUT project config with a very long string value is echoed without truncation
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"long.key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.config.long.key" has length 199

  @fuzz @community
  Scenario: PUT project config with special characters in map values is echoed correctly
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"inject.test":"<script>alert(1)</script>","sql.test":"'\'' OR '\''1'\''='\''1"}' --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON field "data.config.inject.test" equals "<script>alert(1)</script>"
    And the JSON field "data.config.sql.test" equals "' OR '1'='1"

  @fuzz @community
  Scenario: PUT user config with Unicode values is echoed without corruption
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set user --config '{"locale":"日本語","emoji":"🔒"}' --format json
      """
    Then the exit code is 0
    And the JSON field "data.config.locale" equals "日本語"
    And the JSON field "data.config.emoji" equals "🔒"

  @fuzz @community
  Scenario: PUT project config with a large number of keys in the map is echoed in full
    Given Burp Suite is running with the REST extension active on port 8089
    When I run:
      """
      bp config set project --config '{"k1":"v1","k2":"v2","k3":"v3","k4":"v4","k5":"v5","k6":"v6","k7":"v7","k8":"v8","k9":"v9","k10":"v10"}' --format json
      """
    Then the exit code is 0
    And the JSON field "success" is true
    And the JSON object "data.config" contains all 10 keys
