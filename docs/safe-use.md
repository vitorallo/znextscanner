# Running zNextScan Safely in Production

zNextScan is built to be run against **production IBM Z systems with confidence**.
It is a **read-only** assessment tool: it collects security-configuration data and
evaluates it — it never changes anything on the mainframe. This page is the
"can we trust it in prod?" brief for your security and systems-programming teams.

## The five guarantees

1. **Read-only.** Every command is a *display/query* (`LISTUSER`, `SETROPTS LIST`,
   `RLIST`, `D …`). The tool issues **no** `ADDUSER`/`ALTUSER`/`PERMIT`/`RDEFINE`/
   `SET`/`MODIFY`/`START`/`STOP`/`DELETE` — no mutating verbs exist in the code
   path. The full allow-list is published in
   [`command-reference.md`](command-reference.md), including an explicit
   "Commands NOT used" table.
2. **No agent, nothing installed.** zNextScan runs entirely on *your* workstation
   or jump host. It installs no software, no started task, no exit, and leaves no
   persistent footprint on z/OS. Remove the tool and the only trace is the SMF/RACF
   log of the read-only queries it ran.
3. **z/OSMF-API-only option.** With `--method zosmf` the tool talks **only** to the
   z/OSMF REST API over TLS — no SSH, no USS shell, no TN3270, no dataset access.
   Connections are **outbound** from your host; nothing listens for inbound.
4. **Least privilege.** It runs as a dedicated, **read-only** user with **no**
   SPECIAL / OPERATIONS / AUDITOR-write authority (see below). The user can be
   locked down so it can't even open a shell.
5. **Auditable & bounded.** Every action is one of the published commands, attributed
   to the dedicated userid in SMF type-80/RACF logs, with structured local logs and
   an evidence bundle. Commands are scoped (no `find` over `/`, no unbounded scans),
   and unsupported/forbidden operations degrade to *Skipped*, never silently retry.

## z/OSMF-only mode (most locked-down)

For maximum assurance in production, run z/OSMF-only:

```bash
znextscan scan --profile mrra --method zosmf -H zos.example.com -P 10443 -u ZNSCAN
```

In this mode the tool uses two z/OSMF REST services:
- **TSO API** — RACF query commands (`LISTUSER`, `SETROPTS LIST`, `RLIST`)
- **Console API** — MVS *display* commands (`D PROG,APF`, `D SMF,O`, `D ICSF`, …)

USS-based checks simply report **Skipped** (no SSH, no shell). z/OSMF Console API
requires z/OS V2.3+; on V1R13 use SSH for the console-equivalent checks.

> The Mythos profile's external **source-exposure recon (MYT-R02)** is the only
> feature that reaches outside your network, and it is **off by default** and
> triple-gated (`--recon --authorized-recon --recon-id`). The MRRA profile never
> makes any external call.

## Minimum-privilege read-only user

Create a dedicated user. The example below is the **z/OSMF-only, read-only,
no-shell** variant — adapt resource names to your site with your security team.

```text
/* 1. Dedicated, restricted user — NO SPECIAL/OPERATIONS/AUDITOR, NO OMVS segment */
ADDUSER  ZNSCAN  NAME('ZNEXTSCAN READ-ONLY')        +
   DFLTGRP(SYS1)  PASSWORD(xxxxxxxx)  RESTRICTED      +
   TSO(ACCTNUM(IZUACCT) PROC(IZUFPROC) SIZE(4096))

/* 2. z/OSMF access (basic user role is enough — NOT IZUADMIN) */
CONNECT  ZNSCAN  GROUP(IZUUSER)

/* 3. READ-ONLY RACF query authority via the RADMIN interface
      (no SPECIAL needed). Skip any profile your site doesn't define. */
PERMIT IRR.RADMIN.LISTUSER  CLASS(FACILITY) ID(ZNSCAN) ACCESS(READ)
PERMIT IRR.RADMIN.RLIST     CLASS(FACILITY) ID(ZNSCAN) ACCESS(READ)
PERMIT IRR.RADMIN.SETROPTS  CLASS(FACILITY) ID(ZNSCAN) ACCESS(READ)
SETROPTS RACLIST(FACILITY) REFRESH

/* 4. READ to display-only MVS console commands (z/OSMF Console API) */
PERMIT MVS.DISPLAY.**  CLASS(OPERCMDS) ID(ZNSCAN) ACCESS(READ)
SETROPTS RACLIST(OPERCMDS) REFRESH
```

Key hardening choices:
- **`RESTRICTED`** — the user gets access *only* where explicitly permitted; it
  never benefits from a global/UACC grant.
- **No `OMVS` segment** — without a UID the user **cannot SSH or get a USS shell**.
  (Add a read-only OMVS segment only if you want the USS/hybrid checks.)
- **`IRR.RADMIN.*` READ** — the RACF read-only administrative path: it authorizes
  `LISTUSER`/`RLIST`/`SETROPTS LIST` **without** granting SPECIAL or AUDITOR.
  *Alternative:* grant the **`ROAUDIT`** attribute (read-only auditor, z/OS V2R4+),
  which cleanly covers the audit/SETROPTS reads with no write capability.
- **`MVS.DISPLAY.**` READ** — only `D` (display) operator commands; no `MVS.MODIFY`,
  `MVS.SET`, `MVS.START/STOP`.

### Authorities deliberately NOT granted

| Authority | Why it's not needed |
|-----------|---------------------|
| SPECIAL | Only reads RACF — never alters profiles |
| OPERATIONS | Never accesses datasets by bypassing security |
| AUDITOR (write) | `ROAUDIT` / `IRR.RADMIN` READ is enough |
| ALTER/UPDATE on datasets | Never writes datasets |
| ADDUSER / ALTUSER / PERMIT / RALTER | No admin verbs in the tool |
| MVS.MODIFY / SET / START / STOP | Display-only operator commands |
| Started-task authority | Runs as a TSO/REST user, not an STC |

## Defense in depth (optional)

- **Network**: restrict the z/OSMF port (e.g. 10443) to the scanner host's source
  IP at the firewall. Connections are outbound-only; no inbound to your host.
- **Credentials**: prefer the interactive prompt or `MRRA_PASSWORD` env var over a
  config file; consider a **PassTicket** or a short-lived, rotated password.
  Passwords never appear in reports, evidence, or logs.
- **Data minimization**: enable userid **redaction** (`redact_userids: true`) so
  evidence bundles are safe to share with auditors.
- **Scope**: limit a run with `scan.checks` / `scan.skip_checks`.
- **Change control**: because it's read-only and installs nothing, a run typically
  fits a standard read-only change (or no change record), not a configuration change.

## Production checklist

- [ ] Dedicated `RESTRICTED` read-only user created (no SPECIAL/OPERATIONS)
- [ ] `--method zosmf` (or hybrid with a read-only OMVS segment if USS checks needed)
- [ ] z/OSMF port reachable from the scanner host (outbound) only
- [ ] Credentials via prompt/env (not committed); rotated after the engagement
- [ ] `redact_userids` enabled if evidence will be shared
- [ ] Reviewed the command allow-list in [`command-reference.md`](command-reference.md)
- [ ] (Mythos) external recon left **off** unless separately authorized

zNextScan is read-only, agent-less, least-privilege, and fully auditable — designed
to be safe to point at production IBM Z from day one.
