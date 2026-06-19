# Feature: Decoder & Utils — encode / decode / hash / smart-decode / diff / extract-endpoints
#
# Domain: §6.9 /decoder  (4 endpoints · Community · pure JVM — offline capable)
#         §6.12 /utils   (2 endpoints · Community · requires Burp HTTP engine)
#
# CLI surface (canonical — CLI.md):
#   bp encode <data> --enc <enc>           POST /decoder/encode
#   bp decode <data> --enc <enc>           POST /decoder/decode
#   bp decode <data> --smart                    POST /decoder/smart-decode
#   bp hash   <data> --algo <alg>          POST /decoder/hash
#   bp diff   <A> <B> [--method --header --body flags]  POST /utils/diff
#   bp endpoints <url>                          POST /utils/extract-endpoints
#
# Encoding values: base64 | url | hex | html  (exactly 4 — anything else → INVALID_REQUEST)
# Hash algorithms: md5 | sha1 | sha256 | sha384 | sha512
#
# Cross-cutting contracts proven elsewhere (NOT re-proven here):
#   00-output.feature  : --format / --fields / --format quiet / -w / --write-out rendering
#   00-common.feature  : CONNECTION_REFUSED / generic --id / ApiResponse unwrap / PRO_REQUIRED
#
# What IS proven here:
#   • Encode/decode/hash/smart-decode happy paths with endpoint-specific response fields
#   • Smart-decode step-trace contract (steps[], final, layer cap)
#   • Diff response-field contract (statusA/B, lengthA/B, headersChanged, bodySummary)
#   • Extract-endpoints field contract + JS-bundle cap + filter rules
#   • Endpoint-specific errors (wrong encoding, wrong algorithm, input mismatch, bad URL)
#   • Decoder offline-capability (no Burp needed — distinct architectural property)
#   • Round-trip encode → decode invariant
#   • AX end-to-end pipelines that exercise multi-command chaining

Feature: Decoder & Utils — encode, decode, hash, smart-decode, diff, extract-endpoints

  As a security researcher using bp (burpctl),
  I want to encode/decode/hash payloads, peel multi-layer encodings, diff two live HTTP
  responses, and extract API endpoints from HTML/JS — decoder is offline-capable,
  utils requires Burp's HTTP engine —
  so that I can craft and analyse payloads precisely without leaving the terminal.

  Background:
    Given the Burp REST extension is listening on http://127.0.0.1:8089
    And the bp CLI is installed and on PATH

  # ───────────────────────────────────────────────────────────────────────────
  # ENCODE  (POST /decoder/encode)
  # Supported encodings: base64 | url | hex | html
  # Response fields: data.encoding, data.result
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Encode a XSS payload to base64
    When I run:
      """
      bp encode '<script>alert(1)</script>' --enc base64
      """
    Then the exit code is 0
    And the data.encoding field equals "base64"
    And the data.result field equals "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="

  @happy @community @decoder
  Scenario: Encode a payload to URL encoding
    When I run:
      """
      bp encode 'admin OR 1=1--' --enc url
      """
    Then the exit code is 0
    And the data.encoding field equals "url"
    And the data.result field equals "admin+OR+1%3D1--"

  @happy @community @decoder
  Scenario: Encode a payload to hex
    When I run:
      """
      bp encode 'SELECT * FROM users' --enc hex
      """
    Then the exit code is 0
    And the data.encoding field equals "hex"
    And the data.result field equals "53454c454354202a2046524f4d207573657273"

  @happy @community @decoder
  Scenario: Encode special HTML entities (only 5 entities covered — & < > " ')
    # SPEC FLAG: html encoding covers only: & < > " '
    When I run:
      """
      bp encode '<img src="x" onerror='"'"'alert(1)'"'"'>' --enc html
      """
    Then the exit code is 0
    And the data.encoding field equals "html"
    And the data.result field equals "&lt;img src=&quot;x&quot; onerror=&#x27;alert(1)&#x27;&gt;"

  @happy @community @decoder @ax
  Scenario: Encode in JSON mode — endpoint-specific schema (AX agent mode)
    # Proves the exact schema shape for encode; --format json contract per 00-output.feature
    When I run:
      """
      bp encode 'Bearer eyJhbGci' --enc url --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema is: {"success":true,"data":{"encoding":"<str>","result":"<str>"},"error":null}

  @error @community @decoder
  Scenario: Encode with unsupported encoding returns 400 INVALID_REQUEST
    # Supported set: base64 | url | hex | html — anything else → INVALID_REQUEST
    When I run:
      """
      bp encode 'test' --enc rot13
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"
    And stderr contains "encoding"

  @error @community @decoder
  Scenario: Encode with missing data argument returns usage error
    When I run:
      """
      bp encode --enc base64
      """
    Then the exit code is non-zero
    And stderr contains "required" or "missing"

  # ───────────────────────────────────────────────────────────────────────────
  # DECODE  (POST /decoder/decode)
  # Response fields: data.encoding, data.result
  # Auto-detect: encoding flag optional; SPEC FLAG: may mis-identify short inputs
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Decode a base64-encoded JWT header with explicit encoding
    When I run:
      """
      bp decode 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' --enc base64
      """
    Then the exit code is 0
    And the data.result field equals '{"alg":"HS256","typ":"JWT"}'
    And the data.encoding field equals "base64"

  @happy @community @decoder
  Scenario: Decode a URL-encoded query parameter with explicit encoding
    When I run:
      """
      bp decode 'admin%40example.com%3Fref%3Dhome' --enc url
      """
    Then the exit code is 0
    And the data.result field equals "admin@example.com?ref=home"

  @happy @community @decoder
  Scenario: Decode a hex-encoded payload with explicit encoding
    When I run:
      """
      bp decode '53454c454354202a2046524f4d207573657273' --enc hex
      """
    Then the exit code is 0
    And the data.result field equals "SELECT * FROM users"

  @happy @community @decoder
  Scenario: Decode HTML entities with explicit encoding
    When I run:
      """
      bp decode '&lt;script&gt;alert(1)&lt;/script&gt;' --enc html
      """
    Then the exit code is 0
    And the data.result field equals "<script>alert(1)</script>"

  @happy @community @decoder
  Scenario: Decode with auto-detect (encoding omitted) — base64 input
    # SPEC FLAG: auto-detect may mis-identify short/ambiguous inputs
    When I run:
      """
      bp decode 'cGFzc3dvcmQxMjM='
      """
    Then the exit code is 0
    And the data.result field equals "password123"
    And the data.encoding field is one of "base64", "auto"

  @happy @community @decoder
  Scenario: Decode with auto-detect — URL-encoded input
    When I run:
      """
      bp decode 'hello%20world%21'
      """
    Then the exit code is 0
    And the data.result field equals "hello world!"

  @happy @community @decoder
  Scenario: Auto-detect on ambiguous short input — bp optionally warns low confidence
    # SPEC FLAG: "YQ==" is valid base64 for "a" but also a valid string — confidence is low
    When I run:
      """
      bp decode 'YQ==' --format json
      """
    Then the exit code is 0
    And if data.encoding is "base64" then data.result is "a"
    And bp optionally surfaces a "low-confidence auto-detect" warning in the envelope

  @happy @community @decoder @ax
  Scenario: Decode in JSON mode — endpoint-specific schema (AX agent mode)
    When I run:
      """
      bp decode 'dXNlcjpwYXNz' --enc base64 --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema is: {"success":true,"data":{"encoding":"<str>","result":"<str>"},"error":null}

  @error @community @decoder
  Scenario: Decode invalid base64 (odd padding) returns 400 INVALID_REQUEST
    When I run:
      """
      bp decode 'not-valid-base64!!!' --enc base64
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Decode odd-length hex string returns 400 INVALID_REQUEST
    # SPEC: hex with odd number of characters → INVALID_REQUEST
    When I run:
      """
      bp decode 'abc' --enc hex
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Decode with unsupported explicit encoding returns 400 INVALID_REQUEST
    When I run:
      """
      bp decode 'dGVzdA==' --enc base32
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Decode with malformed input type (non-string data) returns 400 INVALID_REQUEST
    When I run:
      """
      bp decode --raw-json '{"data":42,"encoding":"base64"}'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  # ───────────────────────────────────────────────────────────────────────────
  # HASH  (POST /decoder/hash)
  # Supported algorithms: md5 | sha1 | sha256 | sha384 | sha512
  # Response fields: data.algorithm, data.result (lowercase hex)
  # SPEC FLAG: algorithm echoed as-is (not JVM-normalized)
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Hash a password with MD5 — verify exact digest and response field
    When I run:
      """
      bp hash 'password123' --algo md5
      """
    Then the exit code is 0
    And the data.result field equals "482c811da5d5b4bc6d497ffa98491e38"
    And the data.algorithm field equals "md5"

  @happy @community @decoder
  Scenario: Hash a token with SHA-256 — verify exact digest and response field
    When I run:
      """
      bp hash 'supersecret' --algo sha256
      """
    Then the exit code is 0
    And the data.result field equals "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
    And the data.algorithm field equals "sha256"

  @happy @community @decoder
  Scenario: Hash with SHA-1 — verify 40-character hex output
    When I run:
      """
      bp hash 'admin' --algo sha1
      """
    Then the exit code is 0
    And the data.result is a 40-character hex string
    And the data.algorithm field equals "sha1"

  @happy @community @decoder
  Scenario: Hash with SHA-384 — verify 96-character hex output
    When I run:
      """
      bp hash 'test-payload' --algo sha384
      """
    Then the exit code is 0
    And the data.result is a 96-character hex string
    And the data.algorithm field equals "sha384"

  @happy @community @decoder
  Scenario: Hash with SHA-512 — verify 128-character hex output
    When I run:
      """
      bp hash 'api-secret-key-v2' --algo sha512
      """
    Then the exit code is 0
    And the data.result is a 128-character hex string
    And the data.algorithm field equals "sha512"

  @happy @community @decoder
  Scenario: Hash echoes the algorithm name exactly as given (not JVM-normalized)
    # SPEC FLAG: "sha-1" may be accepted by JVM but echoed as "sha-1" not "SHA-1" or "sha1"
    When I run:
      """
      bp hash 'test' --algo sha-1 --format json
      """
    Then the exit code is 0 or non-zero depending on JVM alias acceptance
    And if successful $.data.algorithm equals "sha-1" (not "SHA-1" or "sha1")

  @error @community @decoder
  Scenario: Hash with unsupported algorithm returns 400 INVALID_REQUEST
    # SPEC: unsupported JVM MessageDigest → INVALID_REQUEST; algorithm echoed as-is
    When I run:
      """
      bp hash 'test' --algo bcrypt
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST"

  @error @community @decoder
  Scenario: Hash with missing --algo returns usage error
    When I run:
      """
      bp hash 'test'
      """
    Then the exit code is non-zero
    And stderr contains "required" or "algorithm"

  # ───────────────────────────────────────────────────────────────────────────
  # SMART-DECODE  (POST /decoder/smart-decode)  — bp decode <data> --smart
  # Response contract: data.steps[] (array of {encoding, result}), data.final
  # SPEC: peels up to 10 layers; ignores --enc if provided
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Smart-decode peels a single base64 layer and returns step trace
    When I run:
      """
      bp decode 'dXNlcjpwYXNz' --smart
      """
    Then the exit code is 0
    And the data.steps array has 1 entry
    And steps[0].encoding equals "base64"
    And steps[0].result equals "user:pass"
    And the data.final field equals "user:pass"

  @happy @community @decoder
  Scenario: Smart-decode peels double-encoded base64 (base64 of base64)
    # "ZFhObGNqcHdZWE56" is base64(base64("user:pass"))
    When I run:
      """
      bp decode 'ZFhObGNqcHdZWE56' --smart
      """
    Then the exit code is 0
    And the data.steps array has at least 2 entries
    And the data.final field equals "user:pass"

  @happy @community @decoder
  Scenario: Smart-decode peels URL-then-base64 layered encoding
    # Cookie value: URL-encoded base64 of "admin:secret" → "YWRtaW46c2VjcmV0%3D"
    When I run:
      """
      bp decode 'YWRtaW46c2VjcmV0%3D' --smart
      """
    Then the exit code is 0
    And the data.steps array has at least 2 entries
    And the data.final field contains "admin:secret"

  @happy @community @decoder
  Scenario: Smart-decode ignores the --enc flag (spec-mandated behaviour)
    # SPEC FLAG: --enc is silently ignored when --smart is used
    When I run:
      """
      bp decode 'dXNlcjpwYXNz' --smart --enc hex
      """
    Then the exit code is 0
    And the data.final field equals "user:pass"
    And no error is returned for the ignored --enc flag

  @happy @community @decoder
  Scenario: Smart-decode stops at plain text (0 layers detected)
    When I run:
      """
      bp decode 'hello world' --smart
      """
    Then the exit code is 0
    And the data.steps array has 0 entries
    And the data.final field equals "hello world"

  @happy @community @decoder
  Scenario: Smart-decode respects the 10-layer cap
    # SPEC: peels at most 10 layers; output metadata must reflect the cap
    Given a pathologically nested encoding with more than 10 layers
    When I run:
      """
      bp decode '<deeply-nested-payload>' --smart
      """
    Then the exit code is 0
    And the data.steps array has at most 10 entries
    And the data.final field is the result after at most 10 peeling rounds

  @happy @community @decoder @ax
  Scenario: Smart-decode in JSON mode — endpoint-specific schema (AX agent mode)
    # AX: agent reads steps[] to understand the full encoding chain
    When I run:
      """
      bp decode 'YWRtaW46c2VjcmV0' --smart --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema is:
      """
      {
        "success": true,
        "data": {
          "steps": [{"encoding": "<str>", "result": "<str>"}],
          "final": "<str>"
        },
        "error": null
      }
      """

  @error @community @decoder
  Scenario: Smart-decode with empty data string behaves gracefully (no 500)
    When I run:
      """
      bp decode '' --smart
      """
    Then the exit code is 0 or non-zero (implementation-defined)
    And no panic or 500 INTERNAL_ERROR is returned
    And if successful the data.final field is an empty string

  # ───────────────────────────────────────────────────────────────────────────
  # DIFF  (POST /utils/diff) — bp diff <A> <B> [flags]
  # Requires Burp HTTP engine running; issues 2 live requests.
  # Response fields: data.statusA, data.statusB, data.lengthA, data.lengthB,
  #                  data.headersChanged, data.bodySummary (set-based, NOT unified diff)
  # SPEC FLAG: /utils/diff absent from OpenAPI /docs
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @utils
  Scenario: Diff two GET endpoints — verify core response field contract
    Given Burp's HTTP engine is running
    When I run:
      """
      bp diff 'https://api.example.com/orders/123' 'https://api.example.com/orders/456'
      """
    Then the exit code is 0
    And the data.statusA and data.statusB fields are present integers
    And the data.lengthA and data.lengthB fields are present integers
    And the data.headersChanged field lists any differing response headers

  @happy @community @utils
  Scenario: Diff authenticated vs unauthenticated request to detect IDOR
    # Extra per-target headers via --a-header / --b-header distinguish auth contexts
    When I run:
      """
      bp diff 'https://api.example.com/profile/me' 'https://api.example.com/profile/me' \
        --a-header 'Authorization: Bearer eyJhbGci.victim-token' \
        --b-header 'Authorization: Bearer eyJhbGci.attacker-token'
      """
    Then the exit code is 0
    And data.statusA and data.statusB are present
    And bp prints a warning if data.lengthA and data.lengthB differ by more than 20 bytes

  @happy @community @utils
  Scenario: Diff a POST endpoint body with different payloads — bodySummary field
    When I run:
      """
      bp diff 'https://api.example.com/search' 'https://api.example.com/search' \
        --a-method POST --a-body '{"q":"normal"}' \
        --b-method POST --b-body '{"q":"'"'"' OR 1=1--'"'"'}'
      """
    Then the exit code is 0
    And data.statusA and data.statusB are present
    And data.bodySummary contains a set-based summary of body differences (not a unified diff)

  @happy @community @utils @ax
  Scenario: Diff in JSON mode — endpoint-specific schema (AX agent mode)
    # AX: agent uses diff to detect privilege escalation; schema must be stable
    When I run:
      """
      bp diff 'https://staging.corp.internal/api/admin/users' \
              'https://staging.corp.internal/api/users' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema contains: success, data.statusA, data.statusB, data.lengthA, data.lengthB, data.headersChanged, data.bodySummary

  @error @community @utils
  Scenario: Diff with missing second URL argument returns usage error
    When I run:
      """
      bp diff 'https://example.com/a'
      """
    Then the exit code is non-zero
    And stderr contains "required" or "missing"

  @error @community @utils
  Scenario: Diff with malformed URL returns INVALID_REQUEST
    When I run:
      """
      bp diff 'not-a-url' 'https://example.com/b'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST" or "invalid URL"

  @error @community @utils
  Scenario: Diff surfaces a human-readable error when Burp is down (no raw stacktrace)
    # Distinct from 00-common CONNECTION_REFUSED: asserts message quality (no Java stacktrace)
    Given Burp REST is NOT listening on :8089
    When I run:
      """
      bp diff 'https://example.com/a' 'https://example.com/b'
      """
    Then the exit code is non-zero
    And stderr contains a human-readable message (not a Java stacktrace)
    And the message references "Burp" or "8089" or "connection"

  # ───────────────────────────────────────────────────────────────────────────
  # EXTRACT-ENDPOINTS  (POST /utils/extract-endpoints) — bp endpoints <url>
  # Fetches target URL + up to 10 JS bundles (cap); per-bundle errors swallowed.
  # Filters: static assets (.png, .jpg, .css, .woff), w3.org, schemas.xmlsoap.org.
  # Response fields: data.endpoints[{path, method}], data.bundlesScanned
  # SPEC FLAG: /utils/extract-endpoints absent from OpenAPI /docs
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @utils
  Scenario: Extract API endpoints from a web app home page — core field contract
    Given the URL "https://app.example.com" returns HTML with embedded API references
    When I run:
      """
      bp endpoints 'https://app.example.com'
      """
    Then the exit code is 0
    And data.endpoints is a non-empty list
    And each endpoint entry has a path field
    And static assets (.png, .jpg, .css, .woff) are NOT included in the list
    And data.bundlesScanned is an integer

  @happy @community @utils
  Scenario: Extract endpoints includes API paths found in linked JS bundles
    Given "https://spa.example.com" loads a React app with a bundle at /static/js/main.chunk.js
    When I run:
      """
      bp endpoints 'https://spa.example.com'
      """
    Then the exit code is 0
    And data.endpoints includes paths like "/api/v1/users", "/api/v1/auth/login"
    And data.bundlesScanned is at most 10

  @happy @community @utils
  Scenario: Extract endpoints caps JS bundle fetching at exactly 10
    # SPEC: extract-endpoints fetches at most 10 JS bundles; errors per bundle swallowed
    Given "https://large-spa.example.com" references 15 distinct JS bundles
    When I run:
      """
      bp endpoints 'https://large-spa.example.com'
      """
    Then the exit code is 0
    And data.bundlesScanned is exactly 10
    And data.bundlesCapped is true or data.bundlesSkipped is 5

  @happy @community @utils
  Scenario: Extract endpoints filters w3.org and xmlsoap.org schema URLs
    # SPEC FLAG: w3.org and schemas.xmlsoap.org URLs are explicitly filtered out
    When I run:
      """
      bp endpoints 'https://app.example.com' --format json
      """
    Then the exit code is 0
    And no element in $.data.endpoints[*].path contains "w3.org"
    And no element in $.data.endpoints[*].path contains "schemas.xmlsoap.org"

  @happy @community @utils
  Scenario: Extract endpoints returns empty list when app has no JS or API refs
    Given the URL "https://empty.example.com" returns minimal HTML with no JS or API refs
    When I run:
      """
      bp endpoints 'https://empty.example.com'
      """
    Then the exit code is 0
    And data.endpoints is an empty list []
    And no error is returned

  @happy @community @utils @ax
  Scenario: Extract endpoints in JSON mode — endpoint-specific schema (AX agent mode)
    # AX: agent feeds extracted endpoints into a fuzz loop; schema must be stable
    When I run:
      """
      bp endpoints 'https://api.target.io' --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the JSON schema is:
      """
      {
        "success": true,
        "data": {
          "endpoints": [{"path": "<str>", "method": "<str|null>"}],
          "bundlesScanned": "<int>"
        },
        "error": null
      }
      """

  @happy @community @utils
  Scenario: Extract endpoints when a JS bundle fetch fails — error is swallowed silently
    # SPEC FLAG: per-bundle fetch errors are silently swallowed; overall call succeeds
    Given "https://flaky.example.com" has one JS bundle returning 500
    When I run:
      """
      bp endpoints 'https://flaky.example.com'
      """
    Then the exit code is 0
    And data.endpoints lists all endpoints found in bundles that succeeded
    And no error is surfaced for the failed bundle

  @happy @community @utils
  Scenario: Extract endpoints when target URL returns non-200 — handled gracefully
    Given "https://gone.example.com" returns HTTP 404
    When I run:
      """
      bp endpoints 'https://gone.example.com'
      """
    Then the exit code is 0 or non-zero (implementation-defined)
    And if successful data.endpoints is an empty list
    And no 500 INTERNAL_ERROR is propagated to the user

  @error @community @utils
  Scenario: Extract endpoints with missing URL argument returns usage error
    When I run:
      """
      bp endpoints
      """
    Then the exit code is non-zero
    And stderr contains "required" or "url"

  @error @community @utils
  Scenario: Extract endpoints with malformed URL returns INVALID_REQUEST
    When I run:
      """
      bp endpoints 'javascript:alert(1)'
      """
    Then the exit code is non-zero
    And stderr contains "INVALID_REQUEST" or "invalid URL"

  # ───────────────────────────────────────────────────────────────────────────
  # DECODER OFFLINE CAPABILITY  (distinct architectural property)
  # Decoder = pure JVM (Base64/URL/hex/HTML + MessageDigest) — no Burp REST needed.
  # Utils endpoints DO require Burp HTTP engine.
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario: Decoder encode works when Burp REST is down (pure JVM — offline capable)
    # SPEC: decoder endpoints use only local JVM — no Montoya, no Pro, no HTTP engine
    Given Burp REST is NOT listening on :8089
    When I run:
      """
      bp encode 'offline-test' --enc base64
      """
    Then the exit code is 0
    And the data.result field equals "b2ZmbGluZS10ZXN0"

  # ───────────────────────────────────────────────────────────────────────────
  # ROUND-TRIP INVARIANT  encode → decode produces original value
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder
  Scenario Outline: Encode then decode produces the original value (round-trip)
    When I run encode:
      """
      bp encode '<original>' --enc <encoding> --format quiet
      """
    And I capture the encoded output as $ENCODED
    And I run decode:
      """
      bp decode '$ENCODED' --enc <encoding> --format quiet
      """
    Then the decoded output equals "<original>"

    Examples:
      | original                        | encoding |
      | hello world                     | base64   |
      | <script>alert(1)</script>       | base64   |
      | admin OR 1=1                    | url      |
      | SELECT * FROM users WHERE id=1  | hex      |
      | <img src="x" onerror="alert()"> | html     |

  # ───────────────────────────────────────────────────────────────────────────
  # AX END-TO-END PIPELINES  (multi-command chaining across decoder + utils)
  # ───────────────────────────────────────────────────────────────────────────

  @happy @community @decoder @ax
  Scenario: AX agent uses smart-decode to analyse an unknown token from a response cookie
    # Full AX pipeline: capture cookie → smart-decode → inspect steps → report encoding chain
    Given an AX agent has captured a cookie "X-Auth=YWRtaW4lM0FzZWNyZXQ%3D" from a response
    When the agent runs:
      """
      bp decode 'YWRtaW4lM0FzZWNyZXQ%3D' --smart --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And the agent can read $.data.steps[] to identify the encoding chain
    And $.data.final contains plaintext credential material

  @happy @community @decoder @ax
  Scenario: AX agent hashes a candidate password to compare against a leaked MD5 digest
    # AX: --format quiet returns raw digest; agent compares without parsing JSON wrapper
    Given a leaked hash "5f4dcc3b5aa765d61d8327deb882cf99" (MD5 of "password")
    When the agent runs:
      """
      bp hash 'password' --algo md5 --format quiet
      """
    Then the exit code is 0
    And stdout equals "5f4dcc3b5aa765d61d8327deb882cf99"

  @happy @community @utils @ax
  Scenario: AX agent extracts endpoints then feeds them into a diff comparison
    # Two-step AX recon: bp endpoints → bp diff selected pair
    Given the agent has extracted endpoints from "https://api.example.com" including
      "/api/v1/users/me" and "/api/v1/users/other"
    When the agent runs:
      """
      bp diff 'https://api.example.com/api/v1/users/me' \
              'https://api.example.com/api/v1/users/other' \
        --format json
      """
    Then the exit code is 0
    And stdout is a single compact JSON line
    And $.data.statusA and $.data.statusB are integers
    And the agent determines IDOR risk if statusB == 200 and lengthB differs from lengthA
