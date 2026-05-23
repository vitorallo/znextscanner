# MYT-R02 — Source/Component Exposure Recon (Rules of Engagement)

MYT-R02 performs **active external reconnaissance** for leaked mainframe
source/components. Because it queries third-party services with client
identifiers, it is **off by default** and hard-gated.

## Goal — why scan *outside* the mainframe?

A frontier-AI ("Mythos"-class) adversary is strongest against **readable source**
and weakest against opaque load modules. So the single biggest risk multiplier
isn't a setting on the LPAR — it's whether your **mainframe source has leaked**
into places an attacker's model can read it: public GitHub repos, contractor or
ex-employee accounts, AI-modernization uploads. (This is the "source/component
exposure amplifier" in [`../MYTHOS.md`](../MYTHOS.md) §2.)

MYT-R02 is the one control that looks at that surface: it searches public code
for *your* mainframe artifacts (COBOL/JCL/REXX/CICS signatures) so you can find
and pull leaked source **before** an adversary's AI weaponizes it. Every other
zNextScan check looks *inward* at the system; this one looks *outward* at your
exposure — which is why it is separate, opt-in, and authorization-gated.

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

## Scope

**In scope**
- **Public** source code on **GitHub** (code-search API).
- Matched against a fixed set of **mainframe-source signatures** (COBOL
  `IDENTIFICATION DIVISION`, JCL `EXEC PGM=` / `//SYSIN DD`, REXX `ADDRESS TSO`,
  CICS `EXEC CICS`).
- Scoped to the **GitHub accounts/orgs you supply** (`user:` qualifier); a
  domain identifier is a best-effort free-text search.

**Out of scope (by design)**
- The mainframe itself — MYT-R02 issues **no z/OS command** and reads nothing on
  the LPAR; it is purely an external lookup.
- **Private** repositories beyond what the supplied token can already see; the
  tool never authenticates *as* anyone but the operator's own token.
- Non-GitHub sources (paste sites, GitLab, S3, etc.). The backend layer is
  pluggable for future sources, but only GitHub ships today.
- Binaries/load modules and non-signature code (the goal is *source* exposure).

**Limitations / how to read results**
- Findings are **indicative, point-in-time, and require human validation** — a
  match means "code resembling mainframe source mentioning your identifier is
  public," not a confirmed breach.
- Coverage is bounded by GitHub's index, the signature set, and code-search
  rate limits (~10 req/min). Absence of findings is **not** proof of no exposure.

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
