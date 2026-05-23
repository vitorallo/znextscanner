# Mythos-Native Scriptable Checks

`znextscan/checks/mythos_checks.py` adds checks the legacy MRRA registry has no
equivalent for. They use `MYT-*` control IDs, run only under `--profile mythos`,
and target the frontier-AI exposure surface (readable code, leaked source,
patch currency, recovery, API glass-box). See [`MYTHOS.md`](../MYTHOS.md) for the
threat model and the full 42-control catalog; this doc covers the 10 native
scriptable checks and **how to read each result**.

## Checks & commands

| ID | Check | Command(s) | Validation | Dim |
|----|-------|-----------|-----------|-----|
| MYT-R01 | Operational-code surface | `LISTA STATUS` (TSO) + `$D PROCLIB` (JES2) | Scanner | R |
| MYT-R02 | Source-exposure recon | external recon engine (GitHub/paste) | Scanner | R |
| MYT-R05 | z/OS Connect / API glass-box | `D A,L` + `D TCPIP,,N,CONN` (console) | Scanner | R |
| MYT-V01 | Maintenance currency | `D IPLINFO` (console) | Hybrid | V |
| MYT-V02 | Known-CVE exposure (JREs) | USS sweep of `/usr/lpp/java/*` (+ PATH) | Hybrid | V |
| MYT-V07 | USS/OSS patch currency | USS `ssh -V`/`openssl`/`python3`/`zoaversion` | Hybrid | V |
| MYT-C10 | MFA framework coverage | `SETROPTS LIST` + `RLIST MFADEF * ALL` (TSO) | Hybrid | C |
| MYT-C12 | USS file-permission hardening | one USS `find` probe | Scanner | C |
| MYT-X01 | Immutable backup presence | `D SMS,SG(ALL)` (console) | Hybrid | X |
| MYT-X08 | SMF→SIEM real-time readiness | `D SMF,O` (console) | Hybrid | X |

## How to interpret each check

- **MYT-R01** — *Readable operational-code surface.* **Pass** ≤15 distinct REXX/CLIST/PROCLIB libraries · **Partial** >15 (large AI-legible surface → tighten source-egress MYT-C11). SYSEXEC/SYSPROC reflect the connected TSO env (rich via z/OSMF, minimal via bare SSH); PROCLIB is connection-independent.
- **MYT-R02** — *Source/component exposure recon.* **Skipped** unless `--recon --authorized-recon --recon-id …` (authorization gate). **Pass** = no leaked code found · **Fail** = potential exposure(s) listed (verify each). See [`mythos-recon.md`](mythos-recon.md).
- **MYT-R05** — *API glass-box.* **Pass** = no API/web servers · **Partial** = API/modernization address spaces present (z/OSMF/Liberty/z-OS-Connect) and/or jobs LISTENing on web ports. Caught by name **and** by listening port (e.g. ZOSCSRV:9443). More exposed readable API surface = higher Mythos risk.
- **MYT-V01** — *Maintenance currency (proxy).* **Partial** with the z/OS release + last-IPL recency (`D IPLINFO`); deep SMP/E PTF/RSU currency is deferred to the questionnaire. **Skipped** if IPLINFO unparseable.
- **MYT-V02** — *JRE CVE exposure.* **Pass** = all detected JREs clean · **Fail** = any JRE matches the offline CVE map (per-major). **Skipped** = no JRE found or map unavailable. Read the per-JRE clean/VULNERABLE lines. Map is illustrative — curate `data/cve_map.json` against a live feed.
- **MYT-V07** — *USS/OSS currency.* **Pass** = all detected components ≥ minimum · **Fail** = any outdated (e.g. openssh < 9.8). **Skipped** = none detected. Absent components are omitted, not failed.
- **MYT-C10** — *MFA framework.* **Fail** = MFADEF class not active (password-only privileged access — high Mythos risk) · **Partial** = framework present (confirm per-user enrollment in questionnaire).
- **MYT-C12** — *USS file-perm hardening.* **Fail (CRITICAL)** = world/group-writable setuid/setgid file (trivial privesc) · **Fail** = world-writable file in /etc /var · **Pass** = none (setuid inventory reported) · **Skipped** = probe produced no output.
- **MYT-X01** — *Immutable backup* (first Recover check). **Pass** = COPY-type storage group present (FlashCopy/Safeguarded Copy infra) · **Partial** = storage groups but no COPY-type (backups encryptable — confirm air-gap/immutability in questionnaire) · **Skipped** = no SMS groups.
- **MYT-X08** — *SMF→SIEM readiness.* **Partial** = LOGSTREAM recording (real-time forwarding-capable; confirm SIEM ingestion in questionnaire) · **Fail** = DATASET recording (batch only, not real-time) · **Skipped** = method undetermined.

## Patterns

- Standard `execute → parse → evaluate` lifecycle; **Hybrid** checks degrade to
  **Skipped** (via `CommandNotSupportedError`) and then surface in the
  questionnaire (Hybrid = scriptable + questionnaire fallback).
- Reuse over re-implementation: X01 uses `parse_sms_storage_groups`, R05 uses
  `parse_netstat_conn`, X08 uses `parse_smf_status`, C10/SCI-004 use
  `parse_active_classes`.
- `data/cve_map.json` — offline, deterministic, refreshable
  (`component → [{max_vulnerable_version, cves}]`); java keyed by IBM build/Semeru
  quad, matched within the same major.
- Mock fixtures `tests/fixtures/MYT-*.txt`; authentic captures in
  `tests/fixtures/real_zos/` drive `TestRealZosCaptures` (skip if absent).

## Live validation (z/OS 3.1 via z/OSMF + hybrid, 2026-05-22 — 0 errors)

| Check | Live result |
|-------|-------------|
| MYT-R01 | 7 distinct libraries (SYSEXEC/SYSPROC + PROCLIB) |
| MYT-R02 | Skipped (auth gate not affirmed) |
| MYT-R05 | PARTIAL — 4 glass-box servers incl ZOSCSRV:9443 (z/OS Connect) caught by port |
| MYT-V01 | PARTIAL — z/OS 03.01.00, IPL date parsed |
| MYT-V02 | FAIL — 3 JREs; java 11.0.22.0 + 17.0.9.0 flagged, java 8.0.8.15 clean |
| MYT-V07 | FAIL — openssh 8.4 + libressl 3.0.2 outdated; python 3.11.5 current |
| MYT-C10 | FAIL — MFADEF not active (no MFA framework) |
| MYT-C12 | FAIL — /etc/ipnodes world-writable; 29 setuid, none writable |
| MYT-X01 | PARTIAL — 11 SMS storage groups, no COPY-type (no Safeguarded infra) |
| MYT-X08 | PARTIAL — SMF via LOGSTREAM (real-time forwarding-capable) |

V02/V07/C12 (USS) require SSH or hybrid; under a z/OSMF-only connection they
return **Skipped**. Console checks need z/OSMF Console API (V2.3+) or SSH
`opercmd`. See [`compatibility.md`](compatibility.md).
