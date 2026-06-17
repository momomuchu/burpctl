# `bp` — Canonical CLI Grammar (contract)

> **DRAFT — proposed, to be validated.** Single source of truth for the command surface.
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
| `--format json\|table\|raw\|quiet` | rendering | `table` if TTY, otherwise `json` |
| `--fields a,b,c` | column selection/order | all |
| `-w, --write-out 'TPL'` | curl-style template (`%{status} %{payload}`…) | — |
| `--tag NAME` | tags the operation in the Run Ledger | — |
| `--no-ledger` | do not record the operation | (records by default) |
| `-h, --help` | help | — |

## `--pos` grammar (fuzzing)  `[CRITICAL][BLOCKS:high]`

Selectors (the CLI resolves to byte-offset from the base request):

```
header:NAME   cookie:NAME   body:FIELD   query:NAME   path:INDEX   offset:START-END
```

`--type` = `sniper` | `battering-ram` | `pitchfork` | `cluster-bomb`
(`cluster-bomb` = Cartesian product = N-D matrix; `pitchfork` = lockstep).
`--payloads NAME=FILE` binds a list to the named position `NAME` (≥1 per position for pitchfork/cluster-bomb).

## Command map (1 verb → actual endpoints)

| Command | REST endpoint(s) | Group |
|---|---|---|
| `bp health` · `bp version` | `GET /health` · `/version` | health |
| `bp proxy [--host H --limit N --offset N]` | `GET /proxy/history` | proxy |
| `bp req <id>` | `GET /proxy/history/{id}` | proxy |
| `bp ws` | `GET /proxy/websocket/history` | proxy |
| `bp intercept on\|off\|forward\|drop` | `POST /proxy/intercept/*` | proxy |
| `bp send <id> [--set-header 'N: V']… [--body @f\|STR] [--method M] [--path P]` | `POST /repeater/send` | repeater |
| `bp send --batch @file` | `POST /repeater/send/batch` | repeater |
| `bp tab <id>` | `POST /repeater/tab/create` | repeater |
| `bp fuzz <id> --pos SEL… [--payloads N=F]… [--type T] [--throttle-ms N] [--anomalous-only]` | client-side fire via `POST /repeater/send` (v1: synchronous) | intruder |
| `bp fuzz <id> --param NAME --payloads @f` | `POST /intruder/quick-fuzz` (1-param shortcut) | intruder |
| `bp fuzz status\|results\|pause\|resume\|stop <attackId>` _(v1.1 — async lifecycle, not shipped in v1)_ | `/intruder/attack/{id}/*` | intruder |
| `bp collab new [--count N]` | `POST /collaborator/generate[/batch]` | collaborator (Pro) |
| `bp collab poll [id]` | `GET /collaborator/poll[/{id}]` | collaborator (Pro) |
| `bp scan crawl\|audit\|all <url>` | `POST /scanner/{crawl,audit,crawl-and-audit}` | scanner (Pro) |
| `bp scan status\|issues\|pause\|resume\|stop <scanId>` · `bp scan defs` | `/scanner/{id}/*` · `/scanner/issue-definitions` | scanner (Pro) |
| `bp check auth\|idor\|headers\|cors\|endpoints <url>` | `POST /scan/*` | securityscan |
| `bp scope show\|set\|add\|remove\|check [url]` | `GET/POST /target/scope*` | target |
| `bp sitemap [prefix]` | `GET /target/sitemap` | target |
| `bp encode\|decode\|hash <data> [--smart]` | `POST /decoder/*` | decoder |
| `bp config get\|set project\|user` · `bp ext` | `GET/PUT /config/*` · `GET /extensions` | config |
| `bp session set\|get\|clear` · `bp session send` · `bp session cookies` | `/session/*` | session |
| `bp diff A B` · `bp endpoints <data>` | `POST /utils/{diff,extract-endpoints}` | utils |
| `bp history list [filters]` · `bp history get <id>` · `bp history sitemap` · `bp history replay <id>` · `bp history clear --confirm` | `/history/*` (conditional DB) | history |
| `bp log [filters]` · `bp tag <opId> <name>` | Run Ledger (C4, local DB `~/.bp/`) | — observability |

## Naming decisions (resolve the audit)  `[HIGH][BLOCKS:high]`

1. **`--id` everywhere** for a requestId (never `--request-id`).
2. **`bp fuzz`** = the single Intruder verb (never `bp intruder`). Lifecycle as subcommands `bp fuzz status|results|…`.
3. **Positional subject**: `bp scope add <url>`, `bp fuzz <id>`, `bp check idor <url>` (never `--url` for the primary subject). `--url` is reserved for the global flag (REST base URL).
4. **3 distinct "history" concepts, 3 names**: `bp proxy` (live capture) · `bp history` (server DB /history) · `bp log` (Run Ledger C4, our observability).
5. **Output**: a single global model (§ Global flags + `OUTPUT.md`), never re-specified per endpoint.

## Output convention & errors (factored — anti-Goodhart)  `[HIGH][BLOCKS:high]`

- **Rendering** (json/table/raw/quiet/`-w`/`--fields`) is a **cross-cutting contract** proved **once** (`bdd/00-output.feature`), not per endpoint.
- **Cross-cutting errors** (Burp unreachable → `CONNECTION_REFUSED`, invalid `--id`, unpacked `ApiResponse` envelope, `PRO_REQUIRED` on Community) are proved **once** (`bdd/00-common.feature`).
- Each endpoint feature tests only its **distinct logic** + its **own contract** (specific pre/post/error conditions).
- Exit codes: `0` ok · `1` generic error · `2` bad usage · `3` `CONNECTION_REFUSED` · `4` `PRO_REQUIRED`. Errors on stderr; stdout remains parsable.
