# Research — Bug bounty business concepts vs `bp` spec

> **DRAFT — spec context, not execution.** Manual synthesis (the API crashed the auto-synthesis
> lanes; the 3 successful research lanes — hunt-lifecycle, scope, bb-mini — are the source).
> Sourced from HackerOne/Bugcrowd/Intigriti/PortSwigger/VRT + repo bug-bounty-mini.

## Finding

`bp` maps faithfully to the **69 endpoints** but **models the API, not the business domain**. A
real bug bounty workflow relies on **concepts** that the spec does not carry. **35 gaps**:
**5 CRITICAL · 14 HIGH · 10 MEDIUM · 6 LOW**.

## Missing concept layers

| Layer | Concepts | In bp? |
|---|---|---|
| **Program** | program (platform, payout, safe-harbor, ROE), state | ❌ no program context |
| **Scope-ROE** | typed scope, wildcard `*.x`, OOS first-class, platform import, **pre-fire guard** | ⚠️ raw Burp list only |
| **Inventory** | asset/host, endpoint, param — with persistent **tested/untested state** | ❌ traffic-driven, stateless |
| **Finding** | promotion signal→candidate→confirmed→reported, notes, confidence | ❌ just `anomalous:Boolean` |
| **Evidence/Report** | PoC, repro, curl, diff, per-finding package; `bp report`, submission state | ❌ per-op, not per-finding |
| **Classification** | CWE / VRT / OWASP / CVSS, severity | ❌ no model |
| **Session/Auth** | **multi-context** (user A vs B) for IDOR/privesc/auth-bypass | ❌ singleton |
| **OOB/OAST** | payload↔collaborator interaction correlation | ⚠️ poll without correlation |
| **Floor bb-mini** | I6 anti-injection envelope, I7 secret redaction, sole-egress, cert SHA-256 | ❌ none |

## The 5 CRITICALs

1. **Scope = missing pre-fire guard** — nothing specifies that `bp fuzz/send/scan/check` checks scope **before** firing (anti-OOS, related to I6/G006).
2. **Wildcard suffix-match** — `*.example.com` semantics unspecified (the trap that bb-fetch had to fix).
3. **Scope ≠ program** — modeled as a Burp list, not as ROE tied to a program.
4. **Candidate Finding** — no "finding" entity or lifecycle.
5. **Session/Auth singleton** — no multi-context for access-control testing.

## Gaps mapped by product tier

> Each gap = which **tier** absorbs it. The decision = how far `bp` goes.

**T2 · Security floor (SAFETY/scope items):**
- `[C]` Scope pre-fire guard · `[C]` Wildcard suffix-match · `[C]` Scope-ROE program-linked
- `[H]` I6 anti-injection envelope · `[H]` I7 secret redaction · `[H]` requests log resp_sha256 (never raw body)
- `[H]` Typed scope + per-asset metadata · `[H]` Intigriti/HackerOne scope import · `[H]` In-mem vs UI divergence
- `[C]` Session/Auth multi-context · `[M]` sole-egress · `[M]` CIDR · `[M]` path-scope · `[M]` preflight/authz gate

**T3 · Hunt workspace (WORKFLOW value, on top of T2):**
- `[C]` Candidate Finding + lifecycle · `[H]` Evidence/PoC per-finding · `[H]` Report/submission + state
- `[H]` Asset inventory · `[H]` Endpoint inventory (tested state) · `[H]` OOB correlation
- `[M]` Param discovery · `[M]` Vuln-class CWE/VRT · `[M]` Impact/CVSS · `[M]` certification · `[M]` maturity · `[M]` observability query
- `[L]` dedup · `[L]` report-lifecycle · `[L]` audit-log · `[L]` non-web asset types

## The fork (founder decision)

- **T1 · Pure driver** — current spec; concepts live elsewhere (bug-bounty-mini). Risk: not safe/useful on its own.
- **T2 · Driver + security floor** — the *responsible* minimum: scope-guard, wildcards, I6/I7, multi-session. Workspace = roadmap.
- **T3 · Full workspace** — everything: program/inventory/finding/evidence/report. The vision, but ×3-4 the surface area.

## Incomplete (due to API outage)

- **burp-workflow** lane (fuzz strategy by bug class, match-replace, chaining) — not captured. Retryable when the API is stable.
- **Completeness critique** — not run. Possibly uncovered categories: recon/asset-discovery (intentionally outside Burp), program-rules/rate-limit.
