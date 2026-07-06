# Security Policy

`burpctl` is offensive-security tooling: a CLI and a Burp extension that drive a security proxy.
We take the security **of the tool itself** seriously, and we expect users to apply it ethically.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately via **[GitHub Security Advisories](https://github.com/momomuchu/burpctl/security/advisories/new)**
("Report a vulnerability"). If you can't use that, open a minimal issue asking a maintainer to contact
you — without details — and we'll move it to a private channel.

Please include:

- affected component (`bp` CLI / the Kotlin extension) and version (`bp --version`, or commit),
- a clear description and the impact,
- a minimal reproduction, and
- any suggested fix.

**What to expect:** we aim to acknowledge within a few days, agree on a fix and a disclosure timeline,
credit you (unless you prefer otherwise), and publish an advisory once a fix is released. We follow
coordinated disclosure — please give us a reasonable window before going public.

### In scope

- The `bp` client and the Burp REST extension in this repo: e.g. a secret leaking to disk/stdout
  despite redaction, the Run Ledger storing raw bodies, the REST server leaking internals, command
  injection, path traversal, an auth/scope bypass in the tooling, or RCE.

### Out of scope

- Vulnerabilities you find **in a target** *using* this tool — report those to that target's program.
- Burp Suite itself — report to [PortSwigger](https://portswigger.net/).
- Findings that require an already-compromised local machine, or misuse against systems you don't own.

## Supported versions

The latest release on `main` receives security fixes. Older tags are not maintained.

| Version | Supported |
|---|---|
| 1.1.x | ✅ |
| 1.0.x | ⚠️ upgrade recommended |

## Responsible / authorized use

This tool exists for **authorized** testing only — systems you own, a lab, or an in-scope bug-bounty /
pentest engagement. Using it against systems you are not authorized to test may be illegal. By using
`burpctl` you accept responsibility for staying within scope and the law. The maintainers are not
liable for misuse.
