# `bp` — Canonical CLI Grammar (contract)

# Current CLI contract

This section documents version 2.1.0 of the `bp` CLI and Burp REST extension contract. Historical v2.0.0 deviations are named as such below; confirmed defects are tracked in `quality/confirmed-defects.yaml`.

- `bp` is primary and `burpctl` is an equivalent installed alias.
- Global `--url`, `--format`, `--fields`, `--no-ledger`, and `--no-redact` may appear before or after a command, but option hoisting stops at `--`.
- `-h` and `--help` are accepted. `BP_AGENT=1` selects JSON for successful output unless `--format` is explicit.
- `--format` accepts `json`, `table`, `raw`, and `quiet`. `raw` is valid only for the single-record `req`, `send`, `history get`, and `history replay` commands, which reconstruct deterministic HTTP/1.1 bytes from structured fields; other commands reject it before execution.
- Runtime/server failures and local usage/parser failures honor JSON mode. Exit codes are 0 success, 1 runtime/unsupported, 2 local usage, 3 transport, 4 Pro capability, and 5 confirmed security-check finding; fuzz `NO_RESPONSE` preserves its evidence row, stops remaining shots, and exits 3.
- Output-mode and field compatibility are resolved at the shared command-execution chokepoint before config loading, ledger creation, client construction, or the REST callback. Invalid output options cannot cause a mutation, one-use poll, target request, configuration import, or task creation.
- `--format quiet` emits only an essential value explicitly declared in `OUTPUT.md §1.5`; every other command emits no quiet stdout rather than inferring meaning from response key order. Those missing declarations remain a documented contract gap.
- `history list` exposes only `--host`, `--method`, `--status`, and `--page` in v2.0.0. Although `GET /history` accepts `source`, `search`, `since`, `until`, and `pageSize`, the corresponding CLI options are absent (D25).
- `scan audit URL` creates a task for that URL, and `scan all` reaches the discoverable HTTP 501 linked operation. Real task status, issues, and audit stop return HTTP 503 in v2.0.0 (D55). The CLI intentionally exposes `crawl|audit|all|status|issues|defs`; `start|stop|pause|resume|crawl-and-audit` were not promised spellings (D54 rejected).
- `intercept forward|drop` and complete scope `show|set` are discoverable but unsupported, never acknowledged as completed. v2.0.0 scope help incorrectly describes `show|set` as usable (D52).
- `config get|set` exports/imports nested Burp project/user JSON. A successful import reports `applied=true`; if the post-import export cannot verify resulting state, `config` is null and a do-not-retry warning is returned and always copied to stderr even under quiet or field-projected output. Wrong-typed or unknown nested settings are not an exact validated import contract (D49–D50), and `config set user` reloads the serving extension and destroys its in-memory state (D53).
- `session clear` removes configured cookies/headers/origin but, in v2.0.0, leaves the captured cookie jar active and offers no CLI jar-clear command (D29). `session set --help` omits the accepted `origin` field (D32).
- `check endpoints` reads extension-owned Repeater/session H2 history, not ordinary proxy-listener history. In v2.0.0, `check auth` marks three identical public 200 representations as vulnerable (D58); auth/headers/CORS/endpoints quiet output does not emit the promised word (D59); structured inconclusive results exit 0 (D60); and probes have no per-probe timeout below the aggregate REST-client deadline (D61).
- Without a server-held marker, `check auth` cannot distinguish a cookie-only bypass where FULL, COOKIES_ONLY, and NONE all return the same representation from an intentionally public route; that case is not confirmed. The optional `--marker TEXT` modifier serializes that exact value as `protectedContentMarker` on the `/scan/auth-bypass` request; omitting it leaves the field absent.
- A bounded check probe that returns no response is inconclusive and names only the budget it was given. Pinned Montoya signals a slow target, refused connection, and resolution failure identically as an absent response and exposes no timeout-specific type, so the extension cannot distinguish them.

See [ADR-0013](adr/0013-truthful-executable-contracts.md), [ADR-0014](adr/0014-state-preserving-reportable-operations.md), and the current-contract section of [SPEC.md](SPEC.md).

---


> Single source of truth for the command surface.
> All BDD scenarios must conform to it. Resolves divergences detected during the audit
> (`--id` vs `--request-id`, `bp fuzz` vs `bp intruder`, `--url` vs positional).
> See also: `SPEC.md` (API), `OUTPUT.md` (output formats).

## Principle

`bp <command> [subject] [flags]` — **POSIX sh**, ultra-short.
- **Subject = positional argument** (id, url, data) — fast to type.
- **Modifiers = flags**.
- One spelling per concept. No synonyms.

## Global flags (on ALL commands)  `[CRITICAL][BLOCKS:critical]`

| Flag | Role | Default |
|---|---|---|
| `--url U` | Burp REST base URL | `$BURP_REST_URL` or `http://127.0.0.1:8089` |
| `--format json\|table\|raw\|quiet` | rendering | `table` (all streams; pass `--format json` for agents/pipes) |
| `--fields a,b,c` | column selection/order | all |
| `-w, --write-out 'TPL'` | curl-style template (`%{status} %{payload}`…) | — _(historical design only; not shipped and has no target release)_ |
| `--tag NAME` | tags the operation in the Run Ledger | — _(global invocation-time flag not shipped; use the shipped retroactive `bp tag` command)_ |
| `--no-ledger` | do not record this operation in the Run Ledger | off — **shipped** (ADR-0005); env equivalent `BP_NO_LEDGER=1` |
| `--no-redact` | do not mask secrets in output (e.g. to read a JWT you decode) | off — **shipped**; env equivalent `BP_REDACT=off` |
| `--version` | print the bp CLI version and exit | — **shipped** |
| `-h, --help` | help | — |

> **NOTE — global flag placement (ADR-0009):** `--url`/`--format`/`--fields`/`--no-ledger` now work in **either** position — `bp health --format json` and `bp --format json health` are equivalent (a small argv pre-processor hoists them ahead of the subcommand).

## `--pos` grammar (fuzzing)  `[CRITICAL][BLOCKS:high]`

Selectors (the CLI resolves to byte-offset from the base request):

```
header:NAME   cookie:NAME   body:FIELD   query:NAME   path:INDEX   offset:START-END
```

`--type` = `sniper` | `battering-ram` | `pitchfork` | `cluster-bomb`
(`cluster-bomb` = Cartesian product = N-D matrix; `pitchfork` = lockstep).
`--payloads NAME=FILE` binds a list to the named position `NAME` (≥1 per position for pitchfork/cluster-bomb).

`--pos` is byte-precise only while selecting and replacing bytes in `bp`'s reconstructed HTTP/1
request. It is **not raw-framing transport**: a substitution that touches the body recalculates
`Content-Length` and collapses duplicate `Content-Length` fields; the REST bridge converts the result
to structured method/URL/headers/body data; and Burp's Montoya client builds the outbound request.
Consequently the original request-line HTTP version, conflicting length fields, transfer-coding and
trailers, and non-UTF-8 body bytes are not preserved end to end. Do not use `bp send` or `bp fuzz`
for request-smuggling, desynchronization, or any experiment whose oracle depends on exact wire
framing.

## Command map (1 verb → actual endpoints)

| Command | REST endpoint(s) | Group |
|---|---|---|
| `bp health` · `bp version` | `GET /health` · `/version` | health |
| `bp proxy [--host H --limit N --offset N]` | `GET /proxy/history` | proxy |
| `bp req <id>` | `GET /proxy/history/{id}` | proxy |
| `bp ws` | `GET /proxy/websocket/history` | proxy |
| `bp intercept on\|off\|forward\|drop` | `POST /proxy/intercept/*` | proxy |
| `bp send <id> [--set-header 'N: V']… [--body @f\|STR] [--method M] [--path P]` | `POST /repeater/send` | repeater |
| `bp send --batch @file` | `POST /repeater/send/batch` | repeater | _(historical design only; not shipped and has no target release)_ |
| `bp tab <id>` | `POST /repeater/tab/create` | repeater |
| `bp fuzz <id> --pos SEL… [--payloads N=F]… [--type T] [--throttle-ms N] [--anomalous-only]` | client-side fire via `POST /repeater/send` (synchronous) | intruder |
| `bp fuzz <id> --param NAME --payloads @f` | `POST /intruder/quick-fuzz` (1-param shortcut) | intruder | _(historical design only; not shipped and has no target release)_ |
| `bp fuzz status\|results\|pause\|resume\|stop <attackId>` _(historical async design; not shipped and no target release is assigned)_ | `/intruder/attack/{id}/*` | intruder |
| `bp collab new [--count N]` | `POST /collaborator/generate[/batch]` | collaborator (Pro) |
| `bp collab poll [id]` | `GET /collaborator/poll[/{id}]` | collaborator (Pro) |
| `bp scan crawl\|audit\|all <url>` | `POST /scanner/{crawl,audit,crawl-and-audit}` | scanner (Pro) |
| `bp scan status\|issues <scanId>` · `bp scan defs` | `/scanner/{id}/*` · `/scanner/issue-definitions` | scanner (Pro); server pause/resume/stop routes are not CLI commands and are `UNSUPPORTED` on pinned Montoya |
| `bp check auth <url> [--endpoint PATH]… [--method M] [--marker TEXT]` · `bp check idor\|headers\|cors\|endpoints <url>` | `POST /scan/*` | securityscan |
| `bp scope show\|set\|add\|remove\|check [url]` | `GET/POST /target/scope*`; add/remove/check manage or classify Burp scope; complete `show`/`set` return HTTP 501 `UNSUPPORTED` | target |
| `bp sitemap [prefix]` | `GET /target/sitemap` | target |
| `bp encode\|decode\|hash <data> [--smart]` | `POST /decoder/*` | decoder |
| `bp config get\|set project\|user` · `bp ext` | `GET/PUT /config/*` · `GET /extensions` | config |
| `bp session set\|get\|clear` · `bp session send` · `bp session cookies` | `/session/*` | session |
| `bp diff A B` · `bp endpoints <data>` | `POST /utils/{diff,extract-endpoints}` | utils |
| `bp history list [--host --method --status --page]` · `bp history get <id>` · `bp history sitemap` · `bp history replay <id>` · `bp history clear --confirm` | `/history/*` (conditional DB); server-side `source/search/since/until/pageSize` list filters have no v2.0.0 CLI options | history |
| `bp log [filters]` · `bp tag <opId> <name>` | Run Ledger (C4, local DB `~/.bp/`) | — observability |

## Naming decisions (resolve the audit)  `[HIGH][BLOCKS:high]`

1. **`--id` everywhere** for a requestId (never `--request-id`).
2. **`bp fuzz`** = the single Intruder verb (never `bp intruder`). Lifecycle as subcommands `bp fuzz status|results|…`.
3. **Positional subject**: `bp scope add <url>`, `bp fuzz <id>`, `bp check idor <url>` (never `--url` for the primary subject). `--url` is reserved for the global flag (REST base URL).
4. **3 distinct "history" concepts, 3 names**: `bp proxy` (live capture) · `bp history` (server DB /history) · `bp log` (Run Ledger C4, our observability).
5. **Output**: a single global model (§ Global flags + `OUTPUT.md`), never re-specified per endpoint.

## Output convention & errors (factored)  `[HIGH][BLOCKS:high]`

- **Rendering** (json/table/raw/quiet/`-w`/`--fields`) is a **cross-cutting contract** proved **once** (`bdd/00-output.feature`), not per endpoint.
- **Cross-cutting errors** (Burp unreachable → `CONNECTION_REFUSED`, invalid `--id`, unpacked `ApiResponse` envelope, `PRO_REQUIRED` on Community) are proved **once** (`bdd/00-common.feature`).
- Each endpoint feature tests only its **distinct logic** + its **own contract** (specific pre/post/error conditions).
- Exit codes: `0` ok · `1` generic error · `2` bad usage · `3` transport (`CONNECTION_REFUSED`, `TRANSPORT_ERROR`, fuzz `NO_RESPONSE`) · `4` `PRO_REQUIRED` · `5` confirmed findings (`bp check …` only, ADR-0010). Errors go to stderr; stdout remains parsable.
