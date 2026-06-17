# `bp` — Canonical CLI Grammar (contrat)

> **DRAFT — proposed, à valider.** Source de vérité unique de la surface de commande.
> Tout scénario BDD doit s'y conformer. Résout les divergences détectées à l'audit
> (`--id` vs `--request-id`, `bp fuzz` vs `bp intruder`, `--url` vs positionnel).
> Voir aussi : `SPEC.md` (API), `OUTPUT.md` (formats de sortie).

## Principe

`bp <command> [subject] [flags]` — **POSIX sh**, ultra-court.
- **Sujet = argument positionnel** (id, url, data) — rapide à taper.
- **Modificateurs = flags**.
- Une seule orthographe par concept. Pas de synonyme.

## Flags globaux (sur TOUTE commande)  `[CRITICAL][BLOCKS:critical]`

| Flag | Rôle | Défaut |
|---|---|---|
| `--url U` | base REST Burp | `$BURP_REST_URL` ou `http://127.0.0.1:8089` |
| `--format json\|table\|raw\|quiet` | rendu | `table` si TTY, sinon `json` |
| `--fields a,b,c` | sélection/ordre des colonnes | toutes |
| `-w, --write-out 'TPL'` | template curl-style (`%{status} %{payload}`…) | — |
| `--tag NAME` | tague l'op dans le Run Ledger | — |
| `--no-ledger` | ne pas enregistrer l'op | (enregistre) |
| `-h, --help` | aide | — |

## Grammaire `--pos` (fuzzing)  `[CRITICAL][BLOCKS:high]`

Sélecteurs (le CLI résout en byte-offset depuis la requête de base) :

```
header:NAME   cookie:NAME   body:FIELD   query:NAME   path:INDEX   offset:START-END
```

`--type` = `sniper` | `battering-ram` | `pitchfork` | `cluster-bomb`
(`cluster-bomb` = produit cartésien = matrice N-D ; `pitchfork` = lockstep).
`--payloads NAME=FILE` lie une liste à la position nommée `NAME` (≥1 par position pour pitchfork/cluster-bomb).

## Command map (1 verbe → endpoints réels)

| Commande | Endpoint(s) REST | Groupe |
|---|---|---|
| `bp health` · `bp version` | `GET /health` · `/version` | health |
| `bp proxy [--host H --limit N --offset N]` | `GET /proxy/history` | proxy |
| `bp req <id>` | `GET /proxy/history/{id}` | proxy |
| `bp ws` | `GET /proxy/websocket/history` | proxy |
| `bp intercept on\|off\|forward\|drop` | `POST /proxy/intercept/*` | proxy |
| `bp send <id> [--set-header 'N: V']… [--body @f\|STR] [--method M] [--path P]` | `POST /repeater/send` | repeater |
| `bp send --batch @file` | `POST /repeater/send/batch` | repeater |
| `bp tab <id>` | `POST /repeater/tab/create` | repeater |
| `bp fuzz <id> --pos SEL… [--payloads N=F]… [--type T] [--throttle-ms N] [--anomalous-only]` | client-side fire via `POST /repeater/send` (v1: synchrone) | intruder |
| `bp fuzz <id> --param NAME --payloads @f` | `POST /intruder/quick-fuzz` (raccourci 1-param) | intruder |
| `bp fuzz status\|results\|pause\|resume\|stop <attackId>` _(v1.1 — lifecycle async, non livré en v1)_ | `/intruder/attack/{id}/*` | intruder |
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
| `bp history list [filters]` · `bp history get <id>` · `bp history sitemap` · `bp history replay <id>` · `bp history clear --confirm` | `/history/*` (conditionnel DB) | history |
| `bp log [filters]` · `bp tag <opId> <name>` | Run Ledger (C4, DB locale `~/.bp/`) | — observabilité |

## Décisions de nommage (résolvent l'audit)  `[HIGH][BLOCKS:high]`

1. **`--id` partout** pour un requestId (jamais `--request-id`).
2. **`bp fuzz`** = le verbe Intruder unique (jamais `bp intruder`). Lifecycle en sous-commandes `bp fuzz status|results|…`.
3. **Sujet positionnel** : `bp scope add <url>`, `bp fuzz <id>`, `bp check idor <url>` (jamais `--url` pour le sujet principal). `--url` est réservé au flag global (base REST).
4. **3 « history » distincts, 3 noms** : `bp proxy` (capture live) · `bp history` (DB serveur /history) · `bp log` (Run Ledger C4, notre observabilité).
5. **Sortie** : un seul modèle global (§ Flags globaux + `OUTPUT.md`), jamais re-spécifié par endpoint.

## Convention de sortie & erreurs (factorisée — anti-Goodhart)  `[HIGH][BLOCKS:high]`

- Le **rendu** (json/table/raw/quiet/`-w`/`--fields`) est un **contrat transversal** prouvé **une fois** (`bdd/00-output.feature`), pas par endpoint.
- Les **erreurs transversales** (Burp injoignable → `CONNECTION_REFUSED`, `--id` invalide, envelope `ApiResponse` dépaquetée, `PRO_REQUIRED` en Community) sont prouvées **une fois** (`bdd/00-common.feature`).
- Chaque feature d'endpoint ne teste que sa **logique distincte** + son **contrat propre** (pré/post/erreur spécifiques).
- Codes de sortie : `0` ok · `1` erreur générique · `2` mauvais usage · `3` `CONNECTION_REFUSED` · `4` `PRO_REQUIRED`. Erreurs sur stderr ; stdout reste parsable.
