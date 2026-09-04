# Proof ceilings

`burpctl` can support only the claim its treatment and controls distinguish. A negative closes the
tested axis only when those controls held. If a required control cannot be constructed, the result is
**inconclusive with a named reason**, not clean.

This document records limits of the evidence, not product defects. A successful request, a 2xx, or a
classifier field cannot raise an observation above these ceilings.

## PC-01 — A bounded no-response is not a timeout diagnosis

**Question `burpctl` cannot answer.** Did an individual security-check probe receive no response
because its response budget elapsed, rather than because name resolution or connection establishment
failed quickly?

**Mechanical boundary.** The pinned Montoya 2025.3 API accepts
`RequestOptions.withResponseTimeout(long)`, with zero disabling the timeout, but exposes no public
timeout-specific exception or result. Its send result exposes only whether a response exists. The
bounded-send path consequently maps a response-less exchange to one cause-neutral state. An elapsed
budget, DNS failure, and connection refusal can present that same state; duration does not identify the
cause.

**What the tool can say.** The probe is inconclusive with `status: null` and the reason
`probe produced no response within the configured N ms response budget`. This wording is deliberate.
It does not say that a timeout occurred. `--probe-timeout-ms` configures the budget; its name does not
turn a missing response into a timeout diagnosis.

**If you need the answer.** Repeat against a known-responsive same-origin control and use an
independent transport observation that separates DNS, connect, TLS, and response-wait failures. A
larger budget can test whether a later response arrives, but it cannot retrospectively classify the
first absence. Preserve the `burpctl` result as inconclusive.

Evidence anchors: `SessionService.boundedRequestSender`, `SessionService.requireResponse`,
`SecurityScanService.sendWithBudget`, and campaign record D61.

## PC-02 — `COOKIE_ONLY` cannot decide most single-factor auth topologies

**Question `burpctl` cannot answer from the three credential arms alone.** Does anonymous access bypass
a single authentication factor when the only discriminator is the `FULL`, `NONE`, and `COOKIE_ONLY`
response tuple?

**Mechanical boundary.** In a status/body-only experiment, the cookie arm contributes negative evidence
only when `FULL` and `NONE` return the same substantive 2xx representation while `COOKIE_ONLY` returns
401 or 403. The configured cookies must therefore be insufficient to authenticate on their own. Three
blind categories produce the same missed bypass for different reasons:

| Category | Authentication topology | Why the arm comparison cannot decide it | Result of a real bypass (`FULL` / `NONE` / `COOKIE_ONLY`) |
|---|---|---|---|
| `COOKIE_ONLY` collapses onto `NONE` | Configured header or API key only; captured cookie-jar cookie only | The arm carries neither configured headers nor cookie-jar cookies, so it adds no credential state. | 2xx / 2xx / 2xx |
| `COOKIE_ONLY` is distinct but cannot deny | Configured-cookie-only; header **or** configured cookie is sufficient | The configured cookie still authenticates, so the negative control required by the arm oracle can never occur. | 2xx / 2xx / 2xx |
| The external factor is identical in every arm | Ambient session handling, mTLS, or query authentication | No arm removes or varies the effective factor, so no credential-free comparison is constructed. | Indistinguishable across the three arms |

The arm comparison remains capable of producing its 2xx / 2xx / 401-or-403 tuple only when configured
cookies deny on their own—for example, composite authentication requiring a configured cookie **and** a
header, or a stale, invalid, or low-privilege configured cookie paired with another valid `FULL` factor.
Even then, PC-03 limits what that tuple proves.

**What the tool can say.** An identical effective credential state or an all-2xx tuple establishes no
bypass and does not close this axis. Without a marker, interpreting such a result as clean means only
“no bypass was distinguished, **or** authentication has one of the blind shapes above”; it does not mean
“not vulnerable.” Conversely, 2xx / 2xx / 401-or-403 establishes only a credential-sensitive response
difference: an intentionally public endpoint plus a cookie that independently causes denial produces
the same tuple. Changes to classifier wording do not remove either ambiguity.

**If you need the answer.** Supply the server-held marker required by PC-03; that independent oracle can
prove a protected read even when `COOKIE_ONLY` is not a negative state. Make the credential sets
explicit on the wire, and remove ambient session handling, client certificates, and query credentials
rather than assuming `NONE` removed them. If the question is specifically which factor gates access,
run a separate experiment with a proved authenticated principal, a proved credential-free request, and
an independently invalid or lower-privilege credential state.

Evidence anchors: `SessionService.cookieOnlyDiffersFromNone`,
`SessionService.applyAuthentication`, `SessionService.disallowedHeaders`, and the three credential modes
collected by `SecurityScanService`.

## PC-03 — A 2xx auth result does not prove a protected read

**Question `burpctl` cannot answer.** Did the `NONE` arm read a protected representation, rather than a
benign public representation that happens to return 2xx and match the authenticated body?

**Mechanical boundary.** Body equality proves equality, not protection. A protected read requires a marker that the server held, the acting principal never supplied in the finalized request or in a supported equivalent representation, and policy withholds from the tested principal. `burpctl` can enforce only the request-provenance half; server-held origin and policy remain caller preconditions. PC-08 defines the transformations the provenance check can and cannot recognize. When no eligible marker is supplied, status, length, duration, and body equality provide no protected-read oracle. The positive three-arm tuple is also consistent with a public endpoint whose configured cookie independently triggers a denial.

**What the tool can say.** A substantive `NONE` response containing an eligible configured marker can prove that representation was read without credentials; it does not prove by itself that the marker was server-held or policy-protected. A marker found in the finalized acting request, or request provenance that cannot be read consistently, makes the result inconclusive. Without marker evidence, the evidence reaches only 2xx/body equivalence and, where the cookie arm is denied, a credential-sensitive response difference. It cannot support the statement "anonymous users can read protected data."

**If you need the answer.** First obtain a fresh, inert, high-entropy marker from an authorized response and independently establish that it pre-existed the probe, is server-held, and is policy-protected. Do not place it, or an equivalent form recognized by the target's parsers, in any treatment request. Compare equivalent `FULL`, credential-free, and negative-control requests, and require the literal configured marker in the unauthorized response. If no eligible marker can be constructed, report only unauthenticated 2xx/body equivalence and leave the protected-read question inconclusive.

Evidence anchors: the `protectedContentMarker` request field, `ObservedAuthenticatedSend.requestMaterial`, `SecurityScanService.observedMarkerProvenance`, and PC-08.

## PC-04 — A scanner task cannot be recovered after its handle is lost

**Question `burpctl` cannot answer.** Which underlying Burp Scanner task existed, or what state it is
in, after the extension-owned `ScanTask` handle and its registry entry are gone?

**Mechanical boundary.** Starting a crawl or audit returns a locally generated short ID and stores its
Montoya `ScanTask` handle in an extension-owned in-memory map. That live map is mechanically enumerable,
so loss of only the caller's copy of an ID is not an inherent limit. The ceiling begins when the map
entry or registry itself is lost—for example, on extension reload. Pinned Montoya 2025.3 exposes task
start and per-handle operations but no primitive that lists existing scanner tasks, so the extension
cannot rediscover the underlying handle from Burp.

No REST or service enumeration of the still-live private registry exists. Implementing the deferred
enumeration feature would create the only product-level recovery path for a discarded task handle, and
only while that registry survives; after an extension reload, the pinned Montoya API exposes no
task-list primitive, so a lost handle cannot be recovered at all.

The campaign recorded six tasks with unknown final state, not six lost IDs: five IDs were recorded and
one was hidden when its output was discarded. Unknown state is not evidence of continued execution,
completion, stopping, or deletion.

**What the tool can say.** A known but absent ID produces `NOT_FOUND`. With no ID there is no status,
issues, or stop request to make, so the task remains `unknown`; elapsed time, low CPU, or absent target
traffic does not settle it.

**If you need the answer.** Capture every start result in a prevalidated JSON-capable output mode,
persist the returned ID outside the extension, and stop or settle the task before reloading the
extension. If a handle is already lost, use Burp's own UI to inspect or control the task if possible;
`burpctl` cannot recover it. Do not guess IDs and do not report the task as stopped.

Evidence anchors: `ScannerService.scans`, `ScannerService.registerOrDelete`,
`ScannerService.requireScan`, `scannerRoutes`, campaign records D24 and D55, and ADR-0014.

## PC-05 — A long scope-check URL can be rejected before the route runs

**Question `burpctl` cannot answer.** Is an exact, very long URL in Burp target scope when that URL
cannot fit in the request line for `GET /target/scope/check?url=...`?

**Mechanical boundary.** The CLI accepts the URL and httpx percent-encodes it as a query parameter. The
extension uses Ktor 2.3.12 on Netty without overriding the HTTP decoder. That pinned decoder's bytecode
defaults `maxInitialLineLength` to 4096 bytes, including the method, route, encoded query, and HTTP
version. The usable target-URL length is therefore smaller and depends on percent-encoding. Rejection
happens in the HTTP decoder before Ktor dispatches `TargetRoutes`; route validation and the normal typed
error envelope never run.

The campaign tested an 8,291-character URL and received a bare HTTP 400. That observation is consistent
with the configured 4096-byte default, but it did not bisect or measure the exact target-URL threshold.
“About 8 KiB” is not an established limit.

**What the tool can say.** The CLI reports a non-JSON/invalid-response failure for the bare HTTP 400. It
does not produce `inScope: true` or `inScope: false`, and the 400 must not be interpreted as
out-of-scope.

**If you need the answer.** Use Burp's UI or another trusted interface that carries the URL outside an
HTTP request line. No body-carried `burpctl` scope-check route exists. Shorten the URL only when you can
independently show the shorter value asks the same scope-rule question; otherwise leave the exact URL's
scope state unknown. Do not substitute scope add/remove for an independent read oracle.

Evidence anchors: `target.scope_check`, `BurpClient._request`, `TargetRoutes`, `RestServer.start`, the
pinned Ktor `NettyApplicationEngine.Configuration`, and campaign record D51.

## PC-06 — CLI/extension version pairing is required but not runtime-enforced

**Question `burpctl` cannot answer automatically.** Is the loaded extension the exact release expected
by this CLI invocation?

**Mechanical boundary.** The 2.1.0 CLI and extension are a required pair, but there is no runtime
version handshake. Repository tests assert that declared CLI, Gradle, extension, and OpenAPI versions
match within one source tree; they do not constrain which JAR is loaded in Burp. `BurpClient` does not
preflight `/version` or `/health` before commands.

The only automatic mismatch hint is reactive and narrow: if a request containing `probeTimeoutMs`,
`bodyBase64`, or `protectedContentMarker` receives one specific generic `INVALID_REQUEST`, the CLI
suggests that the extension may be older. That hint applies only to those fields and cannot establish
compatibility elsewhere.

**What the tool can say.** There is no general mismatch message. A mismatched pair runs until a
particular request succeeds or fails according to the loaded extension; the failure may resemble target
or input behavior rather than a version problem. Success of one command is not proof that the rest of
the pair is compatible.

**If you need the answer.** Before consequential work, compare local `bp --version` with the extension
version returned by `bp --format json health` (or `bp --format json version`). Require exact equality.
On mismatch, stop, load the matching extension JAR, and repeat the identity check before trusting new
results. Treat results gathered before the check as unverified for version-sensitive behavior.

Evidence anchors: `test_every_published_version_is_the_same_release`, `healthRoutes`,
`BurpClient._compatibility_message`, and `BurpClient._request`.

## PC-07 — Text response models cannot preserve arbitrary response bytes

**Question `burpctl` cannot answer.** What exact raw bytes did a session, repeater, or persisted-history response contain when its body was not valid UTF-8?

**Mechanical boundary.** `SessionService` reads Montoya's exact `BurpByteArray.getBytes()` and decodes those bytes as UTF-8. This preserves valid UTF-8 exactly and repairs session request persistence and replay because session request bodies originate as text and are sent as UTF-8. The response and history models, however, expose only a nullable `body` string and no authoritative `bodyBase64`. Kotlin's text decoding replaces malformed UTF-8 sequences with U+FFFD. For example, the response bytes `41 80 ff 42` become `A��B`; UTF-8-encoding that text produces `41 ef bf bd ef bf bd 42`, not the original bytes. Persistence, replay, raw rendering, or later consumers cannot reconstruct bytes that were replaced at this boundary.

**What the tool can say.** A valid UTF-8 response body is represented faithfully as text. For a body containing invalid UTF-8, `body` is only a lossy Unicode projection: neither exact byte identity nor exact raw-byte length is established. A successful target send proves that a response was received, not that its arbitrary body bytes were preserved.

**If you need the answer.** Capture or export the response through a Burp interface that exposes the original bytes, or add and consume an end-to-end Base64 response field before interpreting the body as text. Do not UTF-8-encode the returned `body` string and describe the result as the original raw response.

Evidence anchors: `SessionService.toUtf8TextOrNull`, `AuthenticatedResponse.body`, `HttpResponseData.body`, `HistoryEntry.resBody`, and the `non-UTF-8 response bytes have only a lossy text representation` regression.

## PC-08 — Marker provenance cannot invert arbitrary target transformations

**Question `burpctl` cannot answer.** Could a response marker have been derived from actor-supplied request material through a target-specific or unbounded transformation that the provenance classifier does not model?

**Mechanical boundary.** Before a marker can support any auth-bypass verdict, `burpctl` checks the actual post-override request material recorded from the request handed to Montoya: method, URL/authority/path/query/request target, UTF-8 body, final header names, values and lines (including session and per-request headers), parsed cookie pairs, and the exact serialized `Cookie` header. A parsed-cookie disagreement with the wire string and unavailable observed material both fail closed as inconclusive. The checker independently explores the configured marker and each request component, then compares their canonical forms. For the marker and for each component it processes at most 128 distinct candidate representations. Each candidate examines at most 128 Base64-looking tokens and tries both the standard and URL-safe decoder, so the marker and each individual component can each cause at most 16,384 Base64-token examinations and 32,768 Base64 decode attempts; decoded outputs still enter that item's same 128-representation exploration ceiling. On both sides of the comparison it recognizes literal text; recursive UTF-8 percent decoding (including double encoding and form `+`-as-space); numeric HTML entities and `amp`, `lt`, `gt`, `quot`, `apos`, and `nbsp`; JSON escapes and `\uXXXX` Unicode escapes including surrogate pairs; standard and URL-safe Base64 that decodes as valid UTF-8; Unicode NFKC normalization; locale-neutral lowercase comparison; and whitespace collapse.

The checker deliberately does not claim generic provenance across hexadecimal/application codecs, non-UTF-8 charset transcoding, compression, hashes, encryption, transliteration or confusable mapping, the full HTML5 named-entity catalogue, application-specific parsing/templates/concatenation, or transform chains beyond the stated bounds. Some are non-invertible; others require parser context that the request does not carry. Treating every coincidental decoding as provenance would suppress genuine findings, while pretending arbitrary transformation is enumerable would fabricate them.

**What the tool can say.** A recognized actor-supplied equivalent makes the affected probe inconclusive and can never produce `vulnerable`. No recognized equivalent means only "not derived under PC-08's bounded model"; it does not establish that the server held the marker. That origin remains the caller precondition in PC-03.

**If you need the answer.** Use a fresh, high-entropy, inert marker already observed in authorized server state, keep it and all target-equivalent forms absent from the acting request, and avoid marker values that the target derives through an unsupported codec or canonicalization. If the application uses an unsupported transformation, inspect the finalized request and parser chain independently; do not use that marker to certify a protected read.

Evidence anchors: `SessionService.sendPreservingHeadersObserved`, `ObservedAuthenticatedSend.requestMaterial`, `SecurityScanService.observedMarkerProvenance`, `SecurityScanService.transformedMaterialContainsMarker`, and the representation-specific tests in `SecurityScanServiceTest`.
