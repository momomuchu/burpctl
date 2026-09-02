# ADR-0005 — C4 Run Ledger on by default; SQLite `~/.bp/`; `--no-ledger` opt-out

**Status:** accepted — 2026-06-16
**Criticality:** [HIGH][BLOCKS:high]

---

## Decision

Every attempted HTTP operation from `bp` to `:8089` writes one **LedgerEntry** to a SQLite database
at `~/.bp/` automatically. One CLI invocation may perform several REST operations and therefore
write several rows. The ledger is **on by default**. To suppress recording for a single invocation,
pass `--no-ledger`.

### LedgerEntry schema

| Field | Type | Notes |
|---|---|---|
| `id` | string | time-prefixed local operation key |
| `tag` | string nullable | retroactive label set by `bp tag`; global run-time `--tag` is not shipped |
| `ts` | ISO-8601 string | time of the REST operation |
| `target` | string nullable | Burp REST listener host and optional port |
| `command` | string | `bp` subcommand name, not full arguments |
| `burp_op` | string | REST method/path (for example `POST /repeater/send`) |
| `req_sha256` / `resp_sha256` | string nullable | REST-envelope fingerprints; no raw bodies |
| `resp_status` / `resp_len` / `duration_ms` | integer nullable | REST exchange metadata |
| `status` / `exit_code` / `error_code` | mixed | operation and process outcome |
| `req_ref` / `resp_ref` | string nullable | reserved; current operations leave them null |

### Ledger subcommands

```
bp log [--target H] [--tag T] [--since ISO] [--until ISO] [--status S] [--limit N]
bp tag <opId> <label>
```

No `bp show` or stored-result replay command is shipped; hashes are not reversible request/response
references.

---

## Rationale

Decision 2026-06-16. `docs/SPEC.md §9` and §4 (C4 component) establish the ledger as
the primary differentiator of `bp` vs a raw `curl` script:

The ledger supplies timestamped, queryable evidence that a bp-to-extension operation was attempted
and records whether it resolved or failed in transport. It does not by itself prove what reached a
target, identify the application host in `target`, or enable replay from hashes. `bp send` can
additionally produce the active-workspace request row defined by ADR-0013.

On by default because opt-in observability is not observability — it only captures the runs the
user remembered to flag.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Opt-in via `--ledger` flag | Would record nothing by default, defeating the ISO-traceability goal. Hunters forget flags; the ledger must be passive. |
| Log to a file (plain text) | Not queryable. `bp log --target 127.0.0.1:8089` and `bp tag` require a structured store. SQLite is the lightest structured option with zero network dependency. |
| Store in the extension's DB (`~/.burp-rest/burpdata`) | The ledger is a `bp` client concern, not a server concern. Mixing them creates coupling; the extension DB may be absent (init failure). `~/.bp/` is owned by the CLI. |
| One row per CLI invocation | Requires buffering and synthesising multiple REST outcomes, while the shipped client observes and records at the HTTP boundary. Target-request cardinality belongs to the separate workspace ledger (ADR-0013). |
| Global disable flag instead of `--no-ledger` | A global disable buried in config would make the ledger silently absent for all ops. `--no-ledger` is per-invocation, explicit, and visible in the command history. |

---

## Consequences

- `~/.bp/` must be created on first run if it does not exist.
- Ledger writes must be non-blocking relative to the main operation (write failure is logged to
  stderr, never propagated as a `bp` error — the operation succeeded regardless).
- `--no-ledger` is documented prominently as the escape hatch for health polls and dry-runs that
  should not appear in audit logs.
- C4 is the observability component (`docs/SPEC.md §4`) and is orthogonal to any future adapter work — do not couple them at implementation time.
