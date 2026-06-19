# ADR-0005 — C4 Run Ledger on by default; SQLite `~/.bp/`; `--no-ledger` opt-out

**Status:** accepted — 2026-06-16
**Criticality:** [HIGH][BLOCKS:high]

---

## Decision

Every `bp` operation that calls `:8089` writes one **LedgerEntry** to a SQLite database at
`~/.bp/` automatically. The ledger is **on by default**. To suppress recording for a single
invocation, pass `--no-ledger`.

### LedgerEntry schema

| Field | Type | Notes |
|---|---|---|
| `id` | int (autoincrement) | local ledger key |
| `tag` / `name` | string nullable | user label, set via `--tag NAME` |
| `timestamp` | ISO8601 string | time of the `bp` invocation |
| `target` | string nullable | host or URL targeted |
| `command` | string | the full `bp` command line as typed |
| `burpOp` | string | REST endpoint called (e.g. `POST /intruder/attack/create`) |
| `requestRef` | string nullable | pointer to stored request bytes |
| `responseRef` | string nullable | pointer to stored result set |
| `status` | string | `ok` or `err` |

### Ledger subcommands

```
bp log [--host H] [--tag T] [--since ISO] [--limit N]   — list/filter entries
bp tag <opId> <label>                                    — annotate an entry after the fact
bp show <opId> [--format json|table|raw|quiet] [-w TPL]  — re-render a stored result
```

---

## Rationale

Decision 2026-06-16. `docs/SPEC.md §9` and §4 (C4 component) establish the ledger as
the primary differentiator of `bp` vs a raw `curl` script:

- A security engagement may require ISO-level proof of actions taken against a target (what was
  sent, when, by whom). `curl` provides no such record. `bp` does by default.
- The ledger enables replay: `bp show <id> -w '%{status} %{payload}'` re-renders any past attack
  in any format, from stored refs, without re-running.
- `--tag` lets a hunter annotate operations with engagement context at run time or retroactively,
  enabling grep-able audit trails (`bp log --tag ssrf-probe`).
- One entry per invocation (not per result row) keeps the ledger compact even for attacks with
  thousands of payload rows.

On by default because opt-in observability is not observability — it only captures the runs the
user remembered to flag.

---

## Alternatives Considered

| Alternative | Rejection reason |
|---|---|
| Opt-in via `--ledger` flag | Would record nothing by default, defeating the ISO-traceability goal. Hunters forget flags; the ledger must be passive. |
| Log to a file (plain text) | Not queryable. `bp log --host t.com` and `bp tag` require a structured store. SQLite is the lightest structured option with zero network dependency. |
| Store in the extension's DB (`~/.burp-rest/burpdata`) | The ledger is a `bp` client concern, not a server concern. Mixing them creates coupling; the extension DB may be absent (init failure). `~/.bp/` is owned by the CLI. |
| Per-result-row entries for fuzz attacks | A 10 000-payload cluster-bomb would write 10 000 rows. The ledger would explode in size. One entry per invocation with a responseRef preserves the ability to re-render without bloat. |
| Global disable flag instead of `--no-ledger` | A global disable buried in config would make the ledger silently absent for all ops. `--no-ledger` is per-invocation, explicit, and visible in the command history. |

---

## Consequences

- `~/.bp/` must be created on first run if it does not exist.
- Ledger writes must be non-blocking relative to the main operation (write failure is logged to
  stderr, never propagated as a `bp` error — the operation succeeded regardless).
- `--no-ledger` is documented prominently as the escape hatch for health polls and dry-runs that
  should not appear in audit logs.
- C4 is the observability component (`docs/SPEC.md §4`) and is orthogonal to any future adapter work — do not couple them at implementation time.
