# `bp` output contract

This document describes the implemented v2.1.0 serializer and process-exit behavior. It is a source
contract, not a claim that the incomplete real-Burp acceptance pass succeeded. See
[`quality/README.md`](../quality/README.md), [ADR-0014](adr/0014-state-preserving-reportable-operations.md),
and [`PROOF-CEILINGS.md`](PROOF-CEILINGS.md).

## Selection and ordering

The root option `--format` accepts `table`, `json`, `raw`, or `quiet`; table is the ordinary default and
`BP_AGENT=1` selects JSON when no format is explicit. `--fields` is supported for table and JSON and is
incompatible with raw and quiet.

For commands routed through the shared `run()` helper, the implementation checks the selected format
and static field names before loading configuration, opening the Run Ledger, constructing the REST
client, or invoking the supplied REST callback. Local Typer callback work—argument parsing and, for
some commands, local file reading—can occur before that chokepoint. Local `log` and `tag` commands call
the same preflight before opening or mutating their ledger.

This protects known incompatible selections from target, Burp-state, configuration-import, task, and
one-use-poll effects. It does not make the static catalog an oracle for every later wrapper or optional
field: current `scan issues --fields severity`, `sitemap --fields url`, and
`req --fields listenerPort` selections pass preflight but can fail after their GET because the returned
top-level shape does not contain that projected leaf. That is an implementation defect to fix, not a
reason to document universal pre-effect safety.

Unknown static fields and incompatible format/field combinations exit 2. Matching is
case-insensitive; requested spelling/order controls projected JSON/table output. `all` and `*` disable
projection and return the actual response shape rather than synthesizing a fixed full schema.

## JSON

- A dictionary or scalar becomes one compact JSON value.
- A list becomes compact NDJSON: one independently parseable value per line, no outer array.
- Empty lists produce zero stdout bytes.
- The renderer preserves actual returned keys and their order. It does not synthesize every field in a
  model or promise that absent keys are always present as `null`.
- Runtime JSON errors use `{"error":{"code":...,"message":...}}`; when known, `status`,
  `http_status`, and `op` are additional keys.

Data goes to stdout and diagnostics to stderr. Most local validation and parser failures honor JSON
mode. Confirmation refusals in `history clear` and `scope set` remain human diagnostics at the current
source boundary; they still leave stdout empty and exit 2.

## Table

Table output uses uppercase headers/keys, two spaces between columns, blank text for null, lowercase
JSON spelling for booleans, and compact JSON for nested values. Values are not width-capped or
right-aligned by the serializer. Empty lists produce zero stdout bytes.

## Reconstructed raw HTTP

Raw output is supported only for:

- `bp req ID` — request and optional response;
- `bp send ID` — returned response;
- `bp history get ID` — stored request and optional response;
- `bp history replay ID` — replayed record.

When both request and response are present, the separator is `\r\n\x1e\r\n`. A valid Base64 body is
used where supplied; otherwise the text projection is UTF-8 encoded. Missing `Host` and reason text are
reconstructed from structured values.

This is deterministic rendering of the extension's structured representation, not proof of the
original request or response wire bytes. See PC-07 and the transport boundary in
[`ALGORITHMS.md`](ALGORITHMS.md).

## Quiet

Quiet output is allowlisted. It never guesses an essential value from dictionary order. The
implemented allowlist is:

```text
health
proxy
req
fuzz
send
collab new
collab poll
scan issues
scope check
history list
history get
log
tag
check auth
check idor
check headers
check cors
check endpoints
```

| Command | Quiet projection |
|---|---|
| `health` | successful response `status` |
| `proxy`, `req`, `history list|get`, `log`, `tag` | record `id` |
| `fuzz`, `send` | response/status value; fuzz error rows use sentinel `0` because no HTTP status exists |
| `collab new` | each payload host |
| `collab poll` | each interaction id, or `none` when there are no interactions |
| `scan issues` | issue severity |
| `scope check` | `in-scope` or `out-of-scope` |
| `check *` | `vulnerable`, `clean`, or `inconclusive` |

A command outside the allowlist emits zero quiet stdout bytes. An absent single essential value also
emits zero bytes, not a fabricated value or a guaranteed blank line. Request failure does not
synthesize `down`; it follows the ordinary error path.

## Field shapes that matter to automation

These are renderer/input shapes, not a promise that every server key always appears.

### Client-side fuzz rows

```text
index, payloads, status, length, duration_ms, anomalous, baseline, error, error_code
```

The baseline has index `-1`. `payloads` may contain strings or a `{"b64":"..."}` member for a binary
payload. Error rows are retained under `--anomalous-only`. A baseline error stops all payload shots;
`CONNECTION_REFUSED`, `TRANSPORT_ERROR`, `NO_RESPONSE`, and `INVALID_RESPONSE` stop the remaining
prepared corpus after the triggering row. `NO_RESPONSE` is terminal and maps to exit 3.

Fuzz `length` uses exact decoded response bytes when the response model carries them. Text-only models
cannot preserve arbitrary malformed UTF-8; PC-07 states that proof ceiling.

### Proxy list

```text
id, method, url, status
```

`id` remains the absolute Burp proxy-history index after filtering/pagination.

### Extension history

List rows are:

```text
id, method, url, statusCode
```

A `history get` record may expose:

```text
id, source, method, url, host, reqHeaders, reqBody,
statusCode, resHeaders, resBody, durationMs, timestamp
```

`history replay` returns `original`, nullable `replayed`, and `persistence`. A null replayed row means
the target send completed but optional history recording produced no row; inspect persistence and do
not retry merely to obtain an ID. The list, detail, and replay shapes are intentionally distinct. The
output layer does not rename `statusCode` to `status`, invent `reqLength`/`length`, or flatten absent
server fields.

### Repeater send

The returned top-level shape is:

```text
request, response, durationMs, hasResponse, persistence
```

Raw mode derives its response representation from that wrapper. The ordinary serializer does not
replace it with invented top-level `status`, `length`, `time`, or `requestId` fields.

### Scanner issues

The current server result remains a wrapper containing `scanId`, `issues`, and `total`. Accepted issue
leaves include `name`, `url`, `severity`, `confidence`, `detail`, and `remediation`; the generic output
layer does not add `host` or `typeIndex` and does not promise issue sorting. The nested field-projection
ordering defect described above remains a code issue.

### Collaborator

Generation wrapper fields are `payloads`; payload leaves are `id`, `payload`, and `interactionId`.
Polling wrapper fields are `found`, `interactions`, and `queriedPayloadId`; interaction leaves are
`id`/`interactionId`, `type`, `clientIp`, `timestamp`, `details`, and `clientPort`.

For explicit record-field projection, the output layer materializes all declared leaves before
rendering and aliases poll `id` to `interactionId`. An optional leaf absent from every returned record
therefore becomes JSON `null` or a blank table cell instead of an unknown-field failure after a
one-use poll.

### Configuration

`config get` returns `config` and `excludedPaths`. `config set` returns
`applied, config, excludedPaths, warning`. A non-null top-level `warning` is copied to stderr before
quiet or field projection can hide it. Do not retry an applied operation merely because its resulting
state could not be exported.

### Run Ledger

`log`/`tag` rows expose local control-plane metadata such as `id`, `ts`, `command`, `burp_op`,
`target`, `program`, `tag`, `status`, `exit_code`, error/response metadata, and request/response hashes.
Raw target bodies are not stored. A REST call normally gets one row, but ledger construction is
fail-open: if local storage cannot be opened, the call proceeds after a warning and has no row.
`--no-ledger` disables the required data source for `log`/`tag`, so those commands exit 1.

## Redaction

Redaction is enabled by default and is intended to run on structured data before serialization.
Recognized paths include secret keys, authorization/cookie forms, URL userinfo, sensitive query values,
nested header/cookie structures, and matching Base64 duplicates. Safe cookie name/domain/path identifiers
remain visible while values are masked.

This release does **not yet claim redaction completeness**. Concurrent release review found paths in
which utility diff output could expose authorization/Set-Cookie material and uncaught tracebacks could
reach stderr without the ordinary redaction boundary; corrective work and final regression results are
still being integrated. Until that work is settled, treat `--no-redact` as an explicit opt-out but do
not infer that its absence proves every secret-bearing representation was masked.

Redaction is also not the same as omission: a nested request/response wrapper may appear in default
output even when recognized secrets are masked. Select a narrow field set when even redacted structure
is not needed.

## Exit codes

The complete implemented numeric set is **0–5**; no other application-defined exit code exists.

| Exit | Meaning and reachable examples |
|---:|---|
| 0 | successful operation, clean check, help/version, or zero records |
| 1 | default/unmapped runtime error, `UNSUPPORTED`, `SERVICE_UNAVAILABLE`, invalid response/render shape, unavailable required ledger, or a check whose observations are only inconclusive |
| 2 | Click/Typer syntax, callback/config/field/selector validation, or missing destructive confirmation |
| 3 | `CONNECTION_REFUSED`, `TRANSPORT_ERROR`, or fuzz `NO_RESPONSE` |
| 4 | `PRO_REQUIRED` |
| 5 | a `check` result with classifier findings |

A target HTTP 403/500 can still be a successful bp operation and exit 0: target status is data. A
structured inconclusive check exits 1 and retains its result on stdout. If findings and inconclusive
observations coexist, findings select exit 5.

A partial fuzz failure emits all attempted evidence rows first, emits its diagnostic to stderr, and
then uses the highest applicable stable category. It does not label absence of a target response as an
anomaly.

## Not implemented

This release has no write-out template, standalone `--quiet`, meta line, fixed generated output schema,
row/body cap options, schema command, pretty mode, strict empty-essential mode, raw-write mode,
per-result index selector, or fuzz-summary command. Historical Gherkin and earlier output-design prose
that name those surfaces are not executable contracts.
