# MYT-R02 — Source/Component Exposure Recon (Rules of Engagement)

MYT-R02 performs **active external reconnaissance** for leaked mainframe
source/components. Because it queries third-party services with client
identifiers, it is **off by default** and hard-gated.

## Authorization gate (all must be true before any external query)

1. `--recon` passed (or `recon.enabled: true` in config) — recon attempted.
2. `--authorized-recon` passed (or `recon.authorized: true`) — operator affirms
   they are authorized to reconnoiter the supplied identifiers.
3. At least one `--recon-id <org|domain>` (or `recon.identifiers: [...]`).

If any gate fails, the check returns **Skipped** with the reason — never an
error, and never a silent external call.

## Behavior

- Backend: GitHub code-search for mainframe source signatures
  (COBOL `IDENTIFICATION DIVISION`, JCL `EXEC PGM=`, REXX `ADDRESS TSO`,
  `EXEC CICS`, …) scoped to each identifier.
- **Scoped, not global**: a bare identifier (e.g. `acme-corp`) is searched with
  GitHub's `user:` qualifier (the account's own repos), not as a free-text term;
  a domain-style identifier (e.g. `acme.example`) falls back to a free-text
  search. This keeps results precise and low-noise.
- Token: `GITHUB_TOKEN` env var or `recon.github_token`. **A token is effectively
  required** — GitHub code search is rate-limited to ~10 requests/minute even when
  authenticated.
- **Rate-limit aware**: honours `x-ratelimit-reset` (waits only if the reset is
  near, capped at 30s — otherwise returns what it has rather than stalling the
  scan), with a bounded request budget. One failing backend never aborts the rest.
- Evidence is **redaction-safe**: only source, title, and URL are recorded —
  never response bodies or secrets.
- Validated live (2026-05-23): authorization gate + scoped GitHub query confirmed
  end-to-end; a clean account correctly returns **no exposure**.

## Operator responsibilities

Only run recon against identifiers you are explicitly authorized to assess
(engagement scope / signed ROE). Respect each source's Terms of Service and
rate limits. Recon findings indicate *potential* exposure and require human
validation before reporting to a client.

## Example

```bash
znextscan scan --profile mythos --mock tests/fixtures \
  --recon --authorized-recon --recon-id acme-corp --recon-id acme.example
```
