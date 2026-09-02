# ADR-0013 — Mirror completed replay sends into an active workspace request ledger

**Status:** accepted — 2026-09-02
**Criticality:** [HIGH]

## Context

The local Run Ledger records the control-plane call from `bp` to Burp REST, for example
`POST /repeater/send` against `127.0.0.1:8089`. It does not record the target request in a
workspace's `requests.jsonl`. A replay can therefore reach the target successfully while the
workspace ledger receives no row. Burp proxy history cannot close this gap because Montoya sends
do not pass through the proxy listener.

## Decision

After a successful `bp send`, mirror the completed target request into `requests.jsonl` when an
active workspace is identifiable:

- the current directory contains `SCOPE.md` or an existing `requests.jsonl`; and
- `BP_REQUEST_TAG` or `CLAUDE_CODE_SESSION_ID` supplies a non-empty tag.

Write exactly one compact JSON object with string keys `tag`, `request`, `status`, and `fact`:

```json
{"tag":"<tag>","request":"<METHOD> <absolute-url>","status":"<three-digits>","fact":"decision:len=<response-body-utf8-bytes>"}
```

Append the encoded row in one operating-system write to a single regular, non-symlink file. Refuse
recognizable credential-bearing URLs (userinfo; credential-named query parameters; opaque OAuth
codes and recovery/invitation path tokens) with a visible warning and no row rather than persisting
a transformed URL as though it were the request sent. A row failure warns on stderr after the target
result exists; it never changes or hides that result. An unsuccessful REST operation and an operation
without a completed target response append nothing. `BP_REQUEST_TAG` permits a generic
caller-supplied attempt identity; a blank value falls through to the Claude session identity used by
an existing workspace.

This workspace row and `~/.bp/ledger.db` have different purposes. `--no-ledger` continues to disable
only the local Run Ledger and does not suppress required request evidence in an active workspace.
Outside an identified workspace, `bp` retains its standalone behavior and creates no
`requests.jsonl`.

## Consequences

- One `bp send` target request now has one workspace row without shell-side receipt construction.
- The row contains no target body, response body, headers, cookies, or recognized credential-bearing
  URL. URL secret detection is intentionally conservative and non-exhaustive; callers must still
  keep secrets out of request URLs.
- Other effect-bearing commands need their own request/result bijection before they can use this
  writer. This decision does not falsely treat one control-plane Run Ledger row as target evidence.

## Alternatives rejected

- **Treat the SQLite Run Ledger row as sufficient.** It identifies the REST operation and hashes its
  envelope, not the target request row required by the workspace.
- **Rely on Burp proxy history.** Montoya `sendRequest` does not create a proxy-history entry.
- **Always create `requests.jsonl`.** That would add an unexpected project file for standalone `bp`
  users who have no workspace ledger contract.
- **Require a new command-line flag on every replay.** That restores the bookkeeping burden the
  recording layer exists to remove.
