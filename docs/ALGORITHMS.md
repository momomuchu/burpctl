# `bp` load-bearing algorithms

This document specifies the implemented client-side positional fuzzer. It does not claim end-to-end
wire identity or completed live verification. See [`PROOF-CEILINGS.md`](PROOF-CEILINGS.md) and the
v2.1.0 status in the root [`README.md`](../README.md).

## A1: selector to byte range

```text
resolve_pos(raw_request: bytes, selector: str) -> Position(start, end, name)
```

`start` is inclusive and `end` exclusive. The selected bytes are exactly
`raw_request[start:end]`. The parser accepts HTTP/1 request text with CRLF or LF line endings.

| Selector | Implemented selection |
|---|---|
| `offset:A-B` | literal byte range after `0 <= A < B <= len(raw)` validation |
| `header:NAME` | value of the first case-insensitive matching header |
| `cookie:NAME` | first exact cookie-name match across all `Cookie` header fields |
| `query:NAME` | first exact query member value before any fragment |
| `path:INDEX` | 1-based non-empty path segment, before query/fragment |
| `body:FIELD` | top-level JSON member or form member value |

For JSON, the resolver recognizes `application/json` and a content-type-free body beginning with `{`
or `[`. Only a top-level object member can be selected; keys are matched by their decoded JSON name,
strings select bytes inside their quotes, compound values select their complete literal, and primitives
select the token. A top-level array is not addressable by `body:FIELD`.

For form data, it recognizes `application/x-www-form-urlencoded` and a content-type-free body containing
`=`. It selects the exact member's encoded value after leading body whitespace. Multipart form data and
dot-path JSON selectors are not implemented.

Errors are typed local usage failures:

- malformed selector/range/path index: `BAD_SELECTOR`;
- absent member or out-of-range offset: `POS_NOT_FOUND`;
- unsupported body shape/media type: `UNSUPPORTED_BODY`;
- overlapping positions: `POS_OVERLAP`.

Repeated members use the first match. There is no `[k]` selector extension. Positions are validated as
non-overlapping half-open ranges; adjacent ranges are valid, while equal starts are ambiguous and
rejected.

## A2: bounded attack expansion

The extension's server-side Intruder surface is not the engine used by `bp fuzz`. `bp` resolves ranges,
expands one of four modes, substitutes locally, and sends each concrete structured request through
`POST /repeater/send`.

For positions `p1..pn` and payload lists `s1..sn`:

| Type | Accepted payload-list layout | Generated shots |
|---|---|---|
| `sniper` | one shared list, or one named list per position | one position changed at a time; `n * |S|` shared or `sum(|si|)` named |
| `battering-ram` | exactly one shared list | every position receives the same value; `|S|` |
| `pitchfork` | exactly one list per position | lockstep to the shortest list; `min(|si|)` |
| `cluster-bomb` | exactly one list per position | Cartesian product; `product(|si|)` |

The plan is snapshotted, restartable, and capped at 10,000 payload shots before target traffic. Empty
plans and incompatible list counts fail before sends. Expansion materializes only the current concrete
request rather than retaining the complete expanded corpus.

### Substitution

For each concrete request:

1. validate all ranges and payload byte types;
2. reject CR, LF, or NUL insertion outside the body;
3. apply substitutions in descending `start` order so a later byte-length change cannot shift an
   unresolved earlier range;
4. if any substitution touches the body, recalculate the byte `Content-Length`, collapse duplicates,
   or add one when absent.

Payloads are bytes. After substitution, the wire bridge parses the reconstructed HTTP request into
method, URL, ordered headers, and body. Binary bodies travel through the `bodyBase64` request member;
text bodies travel as UTF-8. The extension supplies exact body bytes to Montoya where the request model
carries them. Montoya still builds the outbound request.

Therefore byte-precise selection/substitution is **not** raw-framing transport. It does not preserve the
request-line HTTP version, conflicting length fields, transfer-coding/trailers, connection-level
framing, or arbitrary malformed request structure end to end. Do not use `bp send`/`fuzz` where those
bytes are the oracle.

## Payload files

A file whose first line is not the magic line uses legacy behavior: split on LF, strip one trailing CR
from each line, and discard blank/whitespace-only lines.

A byte-safe file begins exactly:

```text
#!bp-payloads-json-v1
```

The remainder is UTF-8 JSON containing an array. Each member is either:

- a JSON string, encoded as UTF-8 bytes; or
- exactly `{"b64":"CANONICAL_BASE64"}` for arbitrary bytes.

The versioned form can represent empty, whitespace-only, embedded-line-break, NUL, and arbitrary byte
payloads. Duplicate object members, extra keys, noncanonical/malformed Base64, non-array documents, and
other member types are usage errors before sending.

## Execution, control, and errors

A valid invocation sends one fresh unmodified baseline first, then each concrete payload request. Each
attempt produces one row:

```text
index, payloads, status, length, duration_ms,
anomalous, baseline, error, error_code
```

The baseline has `index=-1`, empty payloads, `baseline=true`, and `anomalous=false`. Successful payload
rows are anomalous when their target status or response-byte length differs from the baseline under the
implemented threshold. A request failure has status and length sentinels of zero, `anomalous=false`,
and typed error fields; an infrastructure failure is not a target-response anomaly.

`--anomalous-only` retains the baseline and every error row. A baseline failure stops before payload
shots. `CONNECTION_REFUSED`, `TRANSPORT_ERROR`, `NO_RESPONSE`, and `INVALID_RESPONSE` stop the remaining
prepared corpus after their row. `NO_RESPONSE` is terminal and exits 3. Other per-shot server failures
may allow later attempts. JSON mode emits the retained rows to stdout and a typed summary diagnostic to
stderr before the nonzero exit.

The response body text is decoded from exact response bytes. Malformed UTF-8 is still non-injective in
text output; when exact response bytes are the oracle, use an original-byte capture as required by
PC-07.

## Release evidence

The source and local regression suite implement the behavior above, but the corrective campaign has
not completed a retained live acceptance run against the final redeployed v2.1.0 pair. No ledger record
is `verified`. The destroyed unversioned acceptance harness and the non-clean retained results from its
in-repository replacement are described in the root README and ROADMAP; do not infer live proof from
this algorithm specification.
