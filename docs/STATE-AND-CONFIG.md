# State and configuration contract

This document separates the Python CLI's local state from the Kotlin extension's state. It describes
the v2.1.0 source contract, not completed live-release proof. See
[`quality/README.md`](../quality/README.md), [ADR-0014](adr/0014-state-preserving-reportable-operations.md),
and [`PROOF-CEILINGS.md`](PROOF-CEILINGS.md).

## Python configuration

Configuration precedence is explicit option, environment, `~/.bp/config`, then built-in default. The
path is resolved at invocation time, so a changed `HOME` selects a different file.

Recognized file keys and environment names are:

| Key | Environment | Default | Current runtime use |
|---|---|---|---|
| `burp_rest_url` | `BURP_REST_URL` | `http://127.0.0.1:8089` | REST client origin |
| `redact` | `BP_REDACT` | `on` | output and diagnostic redaction |
| `ledger` | inverse `BP_NO_LEDGER` | `on` | local Run Ledger |
| `enforce_scope` | `BP_ENFORCE_SCOPE` | `warn` | parsed/validated, not consumed by commands |
| `envelope` | `BP_ENVELOPE` | `off` | parsed, not consumed by commands |
| `throttle_ms` | `BP_THROTTLE_MS` | `0` | parsed/validated, not consumed by commands |
| `anomaly_pct` | `BP_ANOMALY_PCT` | `5` | parsed/validated, not consumed by commands |

The file syntax is `key=value`. URL values must be HTTP(S) origins with no userinfo, query, fragment,
control/whitespace, or non-root path. Scope mode, booleans, nonnegative throttle, and anomaly percentage
0–100 are validated.

Only `--url`, `--no-redact`, and `--no-ledger` provide relevant root-option overrides. There are no
implemented `--enforce-scope`, `--envelope`, `--redact`, or `--throttle-ms` root options. `BP_AGENT=1`
is interpreted by output selection rather than this configuration object.

## Python Run Ledger

The Run Ledger is SQLite at `BP_LEDGER_PATH` or `~/.bp/ledger.db`. It is enabled by default and can be
disabled per invocation with `--no-ledger` or by configured precedence.

Each successful attempt to record a bp-to-extension REST operation stores local control-plane metadata:

```text
id, ts, command, burp_op, target, program, tag, status, exit_code,
req_sha256, resp_sha256, resp_status, resp_len, duration_ms,
error_code, req_ref, resp_ref
```

Request/response bodies are used only to calculate SHA-256 values and are not stored. `target` is reduced
to the REST listener's `host[:port]`; `burp_op` drops raw query/authority content; command text is the
subcommand path rather than full target/payload arguments. Current `req_ref`/`resp_ref` values are null.

Granularity is one row per REST call, not one row per CLI invocation or target send. Browser, curl,
proxy-listener, and other non-`bp` traffic produces no row. The ledger is operational evidence, not an
exact target-request capture or proof that a target effect occurred.

Ledger opening/record/update failures are nonfatal for ordinary REST commands: the operation can proceed
with a warning and no complete row. `exit_code` is backfilled after rendering/exit selection, and
`bp tag` mutates the tag; rows are therefore not immutable after insertion. `bp log` and `bp tag` are
local and normally do not record themselves, but they require the ledger and exit 1 when it is disabled
or unavailable.

`bp send` does not append a workspace `requests.jsonl` row. Exact target evidence remains caller-owned;
a returned URL may itself contain a credential and a hash cannot replace a safe exact representation.

## Extension H2 persistence

The extension uses H2/MVStore at `~/.burp-rest/burpdata`, not the Python SQLite ledger. The database
manager rejects unsafe symbolic-link locations and tightens directory/file modes to owner-only where
the filesystem supports POSIX permissions.

Connections are scoped to top-level operations. Nested DAO work on one thread joins the same
transaction. Session replacement/clear and combined history+sitemap clear are transactional in the
exercised source paths. History routes stay registered if database initialization fails and report
service unavailability rather than becoming an apparent empty success or silently disappearing.

Repeater and session target sends populate extension history/sitemap when those stores are available.
Persistence is secondary to the target send: responses report persisted/partial/failed/not-configured
state rather than pretending a completed send did not occur or inviting an unsafe retry.

## Session state

The configured session is one immutable, origin-bound credential snapshot. It is not a named
multi-principal session store. Configured headers/cookies and automatically captured response cookies
are distinct stores.

`session set` validates then replaces configured fields under `sessionMutationLock`. A send snapshots
its credential state and captured-cookie epoch atomically under the fixed order
`sessionMutationLock -> cookieMutationLock`. Batched sends preflight every target origin and hold the
session mutation lock across their sequential execution so a concurrent replacement cannot make a
later item fail only after earlier target effects.

`session clear`:

1. clears persisted/configured cookies, headers, name/origin state;
2. increments the captured-cookie epoch;
3. empties the captured cookie jar; and
4. publishes the empty session before returning.

The explicit cookie-jar clear uses the same lock order and epoch invalidation while leaving configured
session credentials/origin unchanged. An older in-flight response cannot repopulate cookies after
either clear. A clear does not retroactively cancel a target request that already snapshotted and sent
old credentials; callers needing that stronger boundary must quiesce sends first.

Cookie-jar output includes domain, name, redacted value by default, path, `secure`, `httpOnly`, expiry,
and host-only state. The in-memory jar is lost on extension reload.

## Burp project and user configuration

`GET /config/project` and `GET /config/user` export Burp's nested JSON object. Imports require a JSON
object and validate every supplied node against the exported structure and JSON kind; unknown options,
wrong kinds, and uncheckable nonempty arrays are rejected before import.

Project import applies the validated subset. User import first excludes only
`user_options.extender.extensions`, because re-importing extension inventory can reload the responder
mid-request. Safe siblings remain importable and the returned `excludedPaths` identifies the omission.

After an import, the extension re-exports the resulting state. If that observation succeeds, the
response includes `applied=true`, the observed `config`, exclusions, and no warning. If the primary
import completed but re-export fails, `applied` remains true, `config` is null, and a do-not-retry
warning is returned and logged. Retrying an effect merely because its secondary observation failed is
unsafe.

`GET /extensions` can inspect only the current extension through pinned Montoya. It returns exactly that
one record and must not be interpreted as an inventory of every loaded extension.

## Scanner state and recovery

Scanner task handles live in an extension-owned in-memory registry while underlying work belongs to
Burp. Status/count values that Montoya cannot provide are nullable rather than fabricated. Stop reports
completion only after the deletion primitive succeeds; pause/resume and linked crawl-and-audit remain
unsupported.

No API enumerates Scanner task handles. A handle discarded by a caller or lost on extension reload
cannot be rediscovered through pinned Montoya. Such task state remains unknown until an authoritative
oracle settles it; elapsed time, low CPU, or absent fixture traffic is not proof of deletion or
completion. See PC-04.

## Evidence status

No defect record is `verified`. Live verification against the final redeployed v2.1.0 pair remains
incomplete. The previous unversioned harness was destroyed before its repaired cases ran; its
in-repository replacement has produced non-clean retained runs, not release proof. Source tests
establish the local transaction, lock, shape-validation, and reporting mechanisms above; they do not
substitute for the receipt-bearing release gate.
