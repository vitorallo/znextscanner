# Checks — Reference & Interpretation Guide

Every control is a check class extending `BaseCheck` with a three-phase lifecycle:

1. **execute(connection)** — run command(s), return raw output
2. **parse(output)** — extract structured data
3. **evaluate(data)** — apply criteria, return a `CheckResult`

zNextScan runs under a selectable **profile** (`--profile`):

| Profile | Catalog | Checks | Default |
|---------|---------|--------|---------|
| `mrra` | Mainframe Ransomware Readiness Assessment | 32 | ✅ |
| `mythos` | Frontier-AI readiness (`MYTHOS.md`) | 42 controls, ~37 checks | — |

The Mythos-native checks have their own guide: [`mythos-checks.md`](mythos-checks.md).
Framework background: [`mythos-framework.md`](mythos-framework.md).

## How to interpret a result

A check returns one **status** — read it like this:

| Status | What it means | What to do |
|--------|---------------|------------|
| **Pass** | Control verified in place | Nothing — keep evidence |
| **Partial** | Partially in place, or only partly observable from z/OS | Review the findings; finish assessment in the **questionnaire** (esp. Hybrid controls) |
| **Fail** | Control missing/misconfigured — a real gap | Remediate; prioritize P0 then P1 |
| **Skipped** | Could **not** be assessed (command unavailable on this z/OS version, connection method, or feature not installed) | Not a failure — re-run with SSH/hybrid, or answer in the questionnaire |
| **Error** | Unexpected command/parse failure | Investigate; report (should be rare — most unsupported paths degrade to Skipped) |

Key principles:
- **Skipped ≠ Fail.** It means "no evidence either way" — e.g. a USS check over a z/OSMF-only connection, or ICSF not installed. Graceful degradation is intentional (see [`compatibility.md`](compatibility.md)).
- **Partial often means "human follow-up".** Many Mythos controls are *Hybrid*: the scanner captures what z/OS exposes and defers the rest to the questionnaire.
- **Priority** drives remediation order: **P0** critical → **P1** high → **P2** medium. The readiness score weights P0×3, P1×2, P2×1.
- Findings are the *why*. Always read the `findings` list, not just the status.

---

## MRRA profile — 32 checks

### Identify (asset inventory & exposure)

| ID | Check | Pri | Command | What it checks → how to interpret |
|----|-------|-----|---------|-----------------------------------|
| ID-002 | Privileged User Inventory | P0 | `LISTUSER *` (TSO) | Counts users with SPECIAL/OPERATIONS/AUDITOR. **Pass** ≤5 SPECIAL · **Partial** 6–10 (review) · **Fail** >10 (excessive privileged surface). |
| ID-003 | APF Library Inventory | P0 | `D PROG,APF` (console) | Lists APF-authorized libraries. Informational **Pass**; flags **non-IBM** APF libs — APF code runs authorized, so each is a privilege-escalation target to justify. |
| EXT-011 | USS Network Listeners | P2 | `netstat -a` (USS) | Inventories USS listening sockets = network attack surface. Review unexpected listeners. |
| EXT-012 | USS Running Processes | P2 | `ps -ef` (USS) | Inventories USS processes. Review unexpected/long-running daemons. |
| EXT-014 | TCP/IP Stack Summary | P2 | `D TCPIP,,N,CONN` (console) | Inventories TCP connections/listeners = exposed services. |
| EXT-015 | RACF Class Status | P2 | `SETROPTS LIST` (TSO) | Active RACF classes. **Flags** critical classes inactive (PROGRAM, CSFSERV, CSFKEYS) — inactive ⇒ that protection is off. |

### Protect (hardening)

| ID | Check | Pri | Command | What it checks → how to interpret |
|----|-------|-----|---------|-----------------------------------|
| IAM-002 | Strong Password Policy | P0 | `SETROPTS LIST` | **Pass** = len ≥8, history ≥5, revoke ≤5, mixed-case, KDFAES. **Fail/Partial** = weak (short, no history, MASKED/no modern encryption) ⇒ credential attacks easier. |
| IAM-003 | Default Account Removal | P0 | `LISTUSER IBMUSER` / `SYS1` | **Fail** = IBMUSER active and not PROTECTED/revoked (well-known default account). **Pass** = protected or revoked. |
| IAM-004 | SPECIAL Attribute Restriction | P0 | `LISTUSER *` | **Pass** ≤5 · **Partial** 6–10 · **Fail** >10 users with SPECIAL. |
| IAM-005 | Started Task Security | P1 | `RLIST STARTED * ALL` | Flags STCs with **TRUSTED=YES** (bypass RACF) and `=MEMBER` (runs under its own name). Over-privileged STCs are lateral-movement targets. |
| ENC-002 | ICSF Key Management | P0 | `D ICSF` (console) | **Pass** = ICSF active. **Skipped** = ICSF not installed/active (can't assess crypto). |
| ENC-005 | Crypto Hardware Utilization | P1 | `D ICSF,CARDS` (console) | **Pass** = crypto cards online · **Partial** = none (software crypto only). **Skipped** if ICSF inactive. |
| SCI-001 | APF Library Integrity | P0 | `D PROG,APF` + `RLIST DATASET SYS1` | **Pass** = APF libs covered by RACF profiles with UACC(NONE). **Partial/Fail** = unprotected APF libs ⇒ anyone able to write them can run authorized code (privesc). |
| SCI-004 | Program Control Status | P1 | `SETROPTS LIST` | **Pass** = WHEN(PROGRAM) in effect **and** PROGRAM class active · **Partial** = one · **Fail** = neither (no program control). |
| EXT-001 | FTP Status | P2 | `NETSTAT CONN` | **Fail** = FTP listening on port 21 (cleartext, often unneeded). Else **Pass**. |
| EXT-004 | Session Timeout | P2 | `SETROPTS LIST` | **Pass** ≤15 min · **Partial** ≤30 · **Fail** >30 or unset (idle sessions hijackable). |
| EXT-005 | VTAM Security | P2 | `RLIST APPL * ALL` | Flags APPL profiles with **UACC ≠ NONE** (open application access). |
| EXT-006 | Console Security | P2 | `RLIST CONSOLE * ALL` | **Fail** = no CONSOLE class profiles ⇒ console (operator) access uncontrolled. |
| EXT-009 | PROTECTALL Status | P2 | `SETROPTS LIST` | **Fail** = PROTECTALL not in effect ⇒ datasets without a profile are accessible by default. |
| EXT-010 | ERASE Status | P2 | `SETROPTS LIST` | **Partial** = ERASE-ON-SCRATCH off ⇒ deleted data recoverable from disk. |
| EXT-013 | Dataset Encryption | P2 | `LISTDS 'SYS1.PARMLIB' LABEL` | Pervasive-encryption readiness (DATACLAS / key label). |
| EXT-002 | Java Version | P2 | `java -version` (USS) | Java runtime inventory (informational; CVE matching is Mythos MYT-V02). |
| EXT-021 | Backup Storage Infrastructure | P1 | `D SMS,SG(ALL)` + `D A,L` | **Pass** = COPY-type storage groups + DFHSM/CSM. **Fail/Partial** = no FlashCopy/Safeguarded Copy infra ⇒ ransomware can encrypt backups. |
| EXT-022 | Backup Automation Processes | P1 | `ps -ef` (USS) | **Pass** = backup processes (DFHSM/CSM/GDPS…) running · **Partial** = none found. |
| EXT-023 | Batch Job RACF Enforcement | P2 | `SETROPTS LIST` | **Fail** = BATCHALLRACF off ⇒ batch jobs can run without RACF identity (Health Checker `RACF_BATCHALLRACF`). |
| EXT-024 | RACF Database Protection | P1 | `RLIST DATASET SYS1.RACF[B]` | **Fail** = RACF DB datasets UACC ≠ NONE ⇒ the security database itself is exposed. **Partial** = no profile found. |
| EXT-025 | ICHAUTAB Authorization Bypass | P1 | `SETROPTS LIST` | Flags ICHAUTAB (authorization-bypass table) references — programs should not bypass RACF. |

### Detect (monitoring & audit)

| ID | Check | Pri | Command | What it checks → how to interpret |
|----|-------|-----|---------|-----------------------------------|
| MON-001 | SMF Recording Status | P0 | `D SMF,O` (console) | **Pass** = SMF active with types 30/80/83 · **Partial** = missing critical types (gaps in the audit trail). |
| MON-003 | RACF Audit Logging | P0 | `SETROPTS LIST` | **Pass** = AUDIT + SAUDIT + logon-failure logging · **Fail** = audit off (no forensic trail for an intrusion). |
| EXT-003 | USS Syslog Config | P2 | `cat /etc/syslog.conf` (USS) | **Fail** = no `/etc/syslog.conf` ⇒ USS logging unconfigured. |
| EXT-007 | OPERAUDIT Status | P2 | `SETROPTS LIST` | **Fail** = OPERAUDIT off ⇒ OPERATIONS-user commands unaudited. |
| EXT-008 | LOGOPTIONS Status | P2 | `SETROPTS LIST` | **Fail** = logon failures not logged ⇒ brute-force attempts invisible. |

> **Connection note:** Console checks (ID-003, ENC-*, MON-001, SCI-001, EXT-014/021) need the z/OSMF Console API (z/OS V2.3+) or SSH `opercmd`. USS checks (EXT-002/003/011/012/022) need SSH or hybrid. On a z/OSMF-only V1R13 system the unavailable ones return **Skipped**, not Error. Full matrix: [`compatibility.md`](compatibility.md).

---

## Mythos profile

The `mythos` profile reuses ~20 of the checks above (re-tagged with a Mythos
dimension) and adds frontier-AI-specific native checks (operational-code
surface, source-exposure recon, JRE CVE sweep, USS/OSS currency, immutable
backup, MFA framework, API glass-box, USS file-perm hardening, SMF→SIEM
readiness). Non-scriptable controls become the **questionnaire** deliverable.

See **[`mythos-checks.md`](mythos-checks.md)** for the per-check guide and
interpretation, and **[`MYTHOS.md`](../MYTHOS.md)** for the full 42-control
catalog and threat model.

## Error handling

`BaseCheck.run()` maps `CommandNotSupportedError`/`RACFPermissionError` →
**Skipped**, `TimeoutError` → **Error**, and any other exception → **Error**.
Checks are written so absent features/fields degrade to Skipped or Partial
rather than Error (data-driven parsers, no version branching).
