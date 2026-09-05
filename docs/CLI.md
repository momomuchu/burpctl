# `bp` CLI contract

This document enumerates the implemented v2.1.0 Python command surface. `bp` is primary;
`burpctl` is an equivalent installed entry point. An operation named here is not thereby proved against
real Burp: the release-evidence status and limits are in
[`quality/README.md`](../quality/README.md), [ADR-0014](adr/0014-state-preserving-reportable-operations.md),
and [`PROOF-CEILINGS.md`](PROOF-CEILINGS.md).

## Root options

| Option | Meaning |
|---|---|
| `--url U` | Burp REST origin; precedence is option, `BURP_REST_URL`, `~/.bp/config`, default `http://127.0.0.1:8089` |
| `--format json\|table\|raw\|quiet` | output representation; default table, or JSON when `BP_AGENT=1` |
| `--fields A,B,…` | case-insensitive field projection for JSON/table; incompatible with raw/quiet |
| `--no-ledger` | suppress the ordinary operation-ledger write; local `log`/`tag` then fail because their required ledger is disabled |
| `--no-redact` | disable output redaction for this invocation |
| `--version` | print the local CLI version; root position only |
| `-h`, `--help` | help |

The first five options are position-tolerant before or after a command until the literal `--`. They are
not separate command-local flags. `--version` is not hoisted. No `-w`/`--write-out`, standalone
`--quiet`, invocation-time `--tag`, schema, pretty, strict, meta, raw-part, or async-result option is
implemented.

## Implemented leaf commands

There are **50** leaf commands. Arguments shown in capitals are positional. `…` means the option may
repeat.

### Flat commands

```text
bp health
bp version
bp proxy [--host H] [--limit N] [--offset N]
bp req ID
bp ws
bp intercept on|off|forward|drop
bp send ID [--set-header 'N: V']… [--body STR|@FILE] [--method M] [--path P]
bp tab ID [--name N]
bp fuzz ID --pos SELECTOR… --payloads NAME=FILE…
             [--type sniper|battering-ram|pitchfork|cluster-bomb] [--anomalous-only]
bp sitemap [PREFIX]
bp encode DATA --enc ENCODING
bp decode DATA [--enc ENCODING] [--smart]
bp hash DATA --algo ALGORITHM
bp ext
bp diff A B [--method-a M] [--method-b M] [--body-a STR] [--body-b STR]
bp endpoints DATA
bp log [--since T] [--until T] [--target H] [--tag X] [--status S] [--limit N]
bp tag OP_ID NAME
```

`bp version` calls `/version`; `bp --version` is local. `intercept forward|drop` remain discoverable
commands but return `UNSUPPORTED` because pinned Montoya cannot perform them. `fuzz` is synchronous and
client-side; there are no `fuzz status|results|pause|resume|stop|summary` leaves. There is no
`fuzz --throttle-ms` or request `--id` option.

### Collaborator

```text
bp collab new [--count 1..100]
bp collab poll [ID]
```

Collaborator requires Burp Suite Professional. Polling may consume one-use provider state, so statically
invalid output selections are rejected before the REST call. Optional interaction leaves render as
`null`/blank rather than becoming a post-poll unknown-field error.

### Scanner

```text
bp scan crawl URL
bp scan audit URL
bp scan all URL
bp scan status SCAN_ID
bp scan issues SCAN_ID
bp scan defs
```

Starting a scan requires Pro. Server pause/resume/stop routes are not CLI leaves; pause/resume and the
linked crawl-and-audit capability are unavailable through pinned Montoya and return `UNSUPPORTED` where
exposed.

### Bounded checks

Every check accepts `--probe-timeout-ms N` and `--deadline-ms N`.

```text
bp check auth URL [--endpoint PATH]… [--method M] [--marker TEXT] [timeouts]
bp check idor URL --param NAME --own VALUE… --target VALUE…
                  [--method M] [--body STR] [--header 'N: V']… [timeouts]
bp check headers URL [--method M] [--body STR] [--marker TEXT] [timeouts]
bp check cors URL [--method M] [timeouts]
bp check endpoints HOST [--test NAME]… [--limit 1..1000] [timeouts]
```

`check headers` is a header-bypass probe, not a general response-security-header audit.
`check endpoints` reads extension-owned Repeater/session history, not ordinary proxy-listener history.
A no-response result reports only an inconclusive bounded observation; it cannot distinguish a slow
server, refused connection, and resolution failure (PC-01).

`--marker` supplies a candidate protected-content marker. The classifier refuses a finding when a
supported equivalent appears in supplied method/URL/body or in the observed final headers/cookies. The
method, URL, and body are not re-read from the `HttpRequest` handed to Montoya, so their post-override
provenance is not established. This bounded rejection check also does not prove server-held marker
origin or authorization policy. The relevant proof-ceiling sections are being corrected and must be
re-verified before release; use the current limitation stated here in the meantime.

A check exit 5 means the implemented classifier emitted a finding. For example, the IDOR check compares
responses for caller-labelled values; it does not establish two principals, ownership, or a
cross-principal protected read by itself.

### Scope

```text
bp scope show
bp scope set [--include URL]… [--exclude URL]… [--confirm|--no-confirm]
bp scope add URL
bp scope remove URL
bp scope check URL
```

Complete scope `show`/`set` remain discoverable but unsupported through pinned Montoya. Add/remove/check
operate on the available engine classification. Very long accepted mutation values may not fit through
the GET check path; see PC-05.

### Configuration

```text
bp config get project|user
bp config set project|user --json JSON
```

A successful import reports its observed post-import representation when available. User-configuration
import excludes `user_options.extender.extensions`—the path that can reload the serving extension—and
returns that omission in `excludedPaths` while applying safe siblings. Do not retry an
applied-but-unverifiable import after a returned warning.

### Session

```text
bp session set --json JSON
bp session get
bp session clear
bp session send URL [--method M|-X M] [--body STR] [--set-header 'N: V']…
bp session cookies
```

`session clear` clears configured cookies/headers/origin **and** the captured cookie jar. The session is
a singleton origin-bound credential snapshot, not a named multi-principal store.

### History

```text
bp history list [--host H] [--method M] [--status N] [--source S]
                [--search TEXT] [--since T] [--until T]
                [--page P] [--page-size 1..1000]
bp history get ID
bp history sitemap [--host H]
bp history replay ID
bp history clear [--confirm|--no-confirm]
```

This is the extension's conditional H2 history, distinct from `bp proxy` (live Burp proxy history) and
`bp log` (the local Python Run Ledger).

## Fuzz selector grammar

```text
header:NAME   cookie:NAME   body:FIELD   query:NAME   path:INDEX   offset:START-END
```

Positions are resolved to byte offsets in the reconstructed request and substitutions are applied from
right to left. The subsequent structured REST/Montoya bridge is not a raw HTTP framing transport; do
not use `send` or `fuzz` for an oracle that depends on request-line version, conflicting length fields,
trailers, or exact wire framing.

## Output and exit contract

`--format raw` is registered only for `req`, `send`, `history get`, and `history replay`; other commands
reject it before their REST or state effect. Exact reconstructed shapes and quiet projections are in
[`OUTPUT.md`](OUTPUT.md).

| Exit | Reachable meaning |
|---:|---|
| 0 | successful command or clean check; target HTTP failure statuses remain data, not CLI failure |
| 1 | runtime/unsupported/service error, invalid response/render shape, unavailable local ledger, or check with only inconclusive probes |
| 2 | invocation, option, local validation, field, selector, or confirmation error |
| 3 | REST transport failure or fuzz `CONNECTION_REFUSED`, `TRANSPORT_ERROR`, or `NO_RESPONSE` |
| 4 | `PRO_REQUIRED` |
| 5 | security-check classifier finding |

Fuzz retains the attempted baseline/error row. A terminal `NO_RESPONSE` stops remaining shots and exits
3. Findings outrank simultaneous inconclusive check results for process-exit selection.

## Surface diff rule

The list above is generated by static inspection of Typer registrations, not by the historical
`docs/bdd/*.feature` corpus. Those feature files have no runner and remain design history. A release
must fail documentation review if the registered 50-leaf set or any option changes without updating
this inventory.
