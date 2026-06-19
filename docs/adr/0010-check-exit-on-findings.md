# ADR-0010 — `bp check` exits 5 when vulnerabilities are found

- **Status:** accepted — 2026-06-19
- **Criticality:** `[HIGH]` (CLI exit-code contract / public interface)
- **Supersedes:** none. Refines ADR-0009 area (CLI contract) and `docs/CLI.md §Output convention`.
- **Trigger:** UltraQA loop finding **[12]** (`check-detectors` lane) — `bp check auth|idor|cors|headers`
  exited `0` even when `vulnerableCount > 0`, so a CI/CD pipeline or shell script could not gate on
  findings without parsing output.

## Context

Every security CLI in common use (`nmap`, `nikto`, `nuclei`, `trivy`, `gitleaks`) returns a
**non-zero exit code when it finds something**, so that `bp check … && deploy` and CI gates work
without scraping stdout. `bp check` returned `0` regardless of `vulnerableCount` / `anomalousCount`,
making the four `check` verbs unusable as a pipeline gate.

The existing exit-code contract is `0` ok · `1` generic · `2` usage · `3` connection · `4` PRO.
None of those carry "the scan ran fine **and** found a finding", which is a distinct, expected
outcome for a scanner — not an error.

## Decision

Add **exit code `5` (`EXIT_VULN`)**: emitted by `bp check auth|idor|cors|headers|endpoints` when the
scan **completed successfully** and reported at least one finding (`vulnerableCount > 0`, or
`anomalousCount > 0` for `headers`). The normal rendered output is still written to stdout first;
only the process exit code changes.

- `0` — scan ran, **no** findings.
- `5` — scan ran, **findings present** (output still on stdout, parsable).
- `1/2/3/4` — unchanged (error / usage / connection / Pro-only), and take precedence over `5`
  (a connection failure is exit 3, not 5).

`EXIT_VULN` is additive: it never changes the meaning of `0/1/2/3/4` for any pre-existing case, and
only the `check` group can emit it.

## Rationale

- **Product evidence:** `bp` is a security tool used in local bug-bounty / pentest workflows
  (`disciplines.md §Community vs Pro`, the realistic-scenario campaign). Pipeline-gating on findings
  is the single most common way such tools are scripted.
- No existing test asserts `check` exits `0` on findings, so the change breaks no frozen contract.
- Convention alignment lowers operator surprise (matches `nuclei`/`trivy`).

## Alternatives considered

1. **Keep exit 0, require parsing `vulnerableCount`.** Rejected: forces every caller to parse JSON to
   gate, defeats `&&`/CI use, diverges from every comparable tool.
2. **Reuse exit 1 (generic error).** Rejected: a finding is not an error; conflating them means a
   real connection/usage failure is indistinguishable from "found an issue".
3. **Make it opt-in behind `--exit-on-findings`.** Rejected for v1 default: the scanner convention is
   strong enough to be the default; a future `--no-fail` flag can opt out if a user needs exit 0.

## Consequences

- `docs/CLI.md §Output convention` exit-code list gains `5 vulnerabilities found`.
- Implemented in `bp/src/bp/commands/securityscan.py` (post-render inspection of the response),
  with `EXIT_VULN = 5` defined in `bp/src/bp/cliutil.py`. `run()` semantics are unchanged — the
  command inspects the captured response after a successful `run()` and raises `typer.Exit(5)`.
