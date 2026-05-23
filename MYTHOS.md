# MYTHOS — Frontier-AI Mainframe Readiness Assessment Framework

> Companion to `MRRA.md`. MRRA models a human ransomware attacker; **MYTHOS** models a
> frontier-AI ("Claude Mythos"-class, April 2026) adversary with autonomous vulnerability
> discovery and exploit development. This framework drives the **zNextScan** scanner.

## 1. Why MYTHOS

**The threat shifted in 2026.** Frontier AI crossed from research-accelerator to autonomous
offensive-research engine: it discovers zero-days *and* writes working exploits with little
human input.

- Target → working exploit compressed from **weeks to hours**.
- M-Trends 2026: mean-time-to-exploit ≈ **−7 days** — exploitation now precedes patch
  availability on average.
- The skilled-researcher bottleneck that protected mainframes is gone.

**Why mainframes are specifically exposed:**

- **Complexity is no longer a control.** Frontier AI cuts through legacy complexity at machine
  speed; "security through obscurity" fails.
- **The exposed surface is the readable operational/procedural layer**, not the proprietary
  core: REXX, CLIST, JCL, PROCs, USS, Python-for-z/OS, and accessible COBOL/PL-I/CICS/DB2.
- **Static RACF/config controls (MRRA's focus) are not where the new risk lives** — it lives
  in automation glue code.
- **MRRA has zero Respond/Recover controls.** Machine-speed intrusion demands them.

## 2. Central Amplifier — Source & Component Exposure

Frontier AI is weak on opaque binaries, strong when source/artifacts are legible. The dominant
risk multiplier is therefore **whether your mainframe code has leaked or been made AI-legible**:

- **AI-modernization pipelines** — COBOL/PL-I uploaded to LLM/cloud modernization tooling
  (largest emerging leak channel).
- **Public SCM** — REXX/JCL/CLIST/copybooks on GitHub/GitLab, contractor/ex-employee repos.
- **ISV / third-party breaches** — leaked vendor source for security exits, CICS user exits,
  scheduler/automation products (supply-chain-grade exposure).
- **Modernization glass-boxing** — z/OS Connect / USS containers exposing readable code paths.
- **Breach-dump & training corpora** — prior incident data, runbooks ingestible by an
  adversary's model.

Exposure reconnaissance is a first-class, **authorization-gated** control class (MYT-R02).

## 3. Threat Actor Profiles

| ID | Actor | AI capability | Motivation |
|----|-------|---------------|------------|
| TA-1 | Nation-state | Direct frontier-model access, agentic orchestration | Disruption, espionage, pre-positioning |
| TA-2 | Ransomware crew | Jailbroken / open-weight frontier-equivalent | Extortion, max downtime |
| TA-3 | AI-augmented insider | Tooling + legitimate access | Sabotage, theft, coercion |
| TA-4 | Supply-chain adversary | AI review of leaked ISV/vendor code | Backdoor / 0-day in trusted component |

## 4. Threat Scenarios (STRIDE / DREAD)

DREAD = mean of Damage, Reproducibility, Exploitability, Affected-users, Discoverability
(1–10), consistent with MRRA methodology.

| # | Scenario | STRIDE | Precondition | DREAD | Risk |
|---|----------|--------|--------------|-------|------|
| M1 | Autonomous logic-flaw exploitation in operational automation (REXX/CLIST/JCL/PROC/USS/Python) | Elevation, Tampering | Automation source legible/leaked | 8.8 | CRITICAL |
| M2 | AI-accelerated zero-day discovery in leaked application source (COBOL/PL-I/CICS/DB2) | Tampering, Info Disclosure, Elevation | App source leaked / in AI-modernization pipeline | 8.6 | CRITICAL |
| M3 | AI-orchestrated multi-stage intrusion & privilege chaining (recon→APF/RACF→exfil) | All | Foothold + leaked recon material | 8.5 | CRITICAL |
| M4 | Frontier-AI auth bypass / credential synthesis vs. legacy TSO/passphrase | Spoofing | Auth-path code/config exposed | 8.0 | CRITICAL |
| M5 | Mainframe ISV / third-party component compromise (0-day or implant in trusted component) | Tampering, Elevation | Vendor/ISV source breach | 7.9 | HIGH |
| M6 | AI-generated environment-adaptive ransomware batch payload (disables backups, tampers SMF) | DoS, Repudiation | Foothold + topology inferred | 7.8 | HIGH |
| M7 | Machine-speed anti-forensics / SMF & audit tampering | Repudiation | Foothold with audit-write reach | 7.4 | HIGH |
| M8 | AI-augmented insider (skill ceiling removed for deep sabotage) | All | Privileged insider | 7.6 | HIGH |

## 5. The Four Dimensions

The framework organizes all controls into four dimensions mapped to NIST CSF:

1. **Preparedness / Readiness** (Identify) — exposure recon, attack-surface legibility,
   inventory, classification.
2. **Controls to Add** (Protect) — hardening of the procedural periphery + reused RACF/ENC/SCI
   controls + source-egress/MFA/segmentation.
3. **Vulnerability Patching** (Identify/Protect) — currency vs. the hours-SLA reality, CVE
   exposure, virtual patching.
4. **Response & Recovery** (Respond/Recover) — immutable/air-gapped backup, Cyber Vault,
   recovery drills, AI-intrusion IR, SIEM forwarding. *(MRRA had none of these.)*

## 6. Control Catalog (42)

ID scheme `MYT-<D><nn>`: `R` Readiness, `C` Controls, `V` Vuln-patching, `X`
response/recovery. Validation: Scanner | Interview | Document | Hybrid. "Reuse" = existing
zNextScan/MRRA check class re-registered or reframed.

### Dimension R — Preparedness / Readiness

| ID | Name | Pri | NIST | Validation | Reuse |
|----|------|-----|------|-----------|-------|
| MYT-R01 | Readable operational-code surface inventory | P1 | Identify | Scanner | new |
| MYT-R02 | Source/component exposure recon (SCM + paste leak) | P0 | Identify | Scanner | new |
| MYT-R03 | AI-modernization pipeline data governance | P0 | Identify | Interview | — |
| MYT-R04 | ISV/vendor source-breach exposure mapping | P1 | Identify | Document | — |
| MYT-R05 | z/OS Connect / API glass-box inventory | P1 | Identify | Scanner | native (D A,L) |
| MYT-R06 | Privileged-user inventory (amplification context) | P0 | Identify | Scanner | ID-002 |
| MYT-R07 | APF library inventory (exploit-target enum) | P0 | Identify | Scanner | ID-003 |
| MYT-R08 | Crown-jewel data classification & LPAR criticality | P0 | Identify | Interview | — |
| MYT-R09 | Mainframe component & version inventory (SBOM) | P1 | Identify | Hybrid | EXT-002 |

### Dimension C — Controls to Add

| ID | Name | Pri | NIST | Validation | Reuse |
|----|------|-----|------|-----------|-------|
| MYT-C01 | Strong password/passphrase policy | P0 | Protect | Scanner | IAM-002 |
| MYT-C02 | Default/dormant account elimination | P0 | Protect | Scanner | IAM-003 |
| MYT-C03 | SPECIAL attribute restriction | P0 | Protect | Scanner | IAM-004 |
| MYT-C04 | Started-task / batch RACF enforcement | P1 | Protect | Scanner | IAM-005/EXT-023 |
| MYT-C05 | Program control / APF / ICHAUTAB integrity | P0 | Protect | Scanner | SCI-001/004/EXT-025/EXT-015 |
| MYT-C06 | RACF database & catalog protection | P1 | Protect | Scanner | EXT-024 |
| MYT-C07 | ICSF key management & crypto-hardware use | P1 | Protect | Scanner | ENC-002/005 |
| MYT-C08 | Dataset / pervasive encryption coverage | P1 | Protect | Scanner | EXT-021 |
| MYT-C09 | Network exposure reduction (FTP/Telnet/TCPIP) | P1 | Protect | Scanner | EXT-001/014 |
| MYT-C10 | MFA coverage for privileged & vendor access | P0 | Protect | Hybrid | native (MFADEF) |
| MYT-C11 | Source-egress / DLP for mainframe code | P0 | Protect | Interview | — |
| MYT-C12 | USS hardening (file permissions) | P1 | Protect | Scanner | native (USS perms) |
| MYT-C13 | Session timeout / console security | P2 | Protect | Scanner | EXT-004/006 |
| MYT-C14 | AI-attack network containment / segmentation | P1 | Protect | Interview | — |
| MYT-C15 | RACF dataset-protection hardening (PROTECTALL/ERASE) | P1 | Protect | Scanner | EXT-009/010 |

### Dimension V — Vulnerability Patching

| ID | Name | Pri | NIST | Validation | Reuse |
|----|------|-----|------|-----------|-------|
| MYT-V01 | SMP/E maintenance currency vs. hours-SLA | P0 | Identify | Hybrid | new |
| MYT-V02 | Known-CVE exposure for installed middleware | P0 | Identify | Hybrid | new |
| MYT-V03 | Vulnerability scanning coverage of estate | P1 | Identify | Interview | — |
| MYT-V04 | Patch-SLA shift to hours (process maturity) | P0 | Protect | Interview | — |
| MYT-V05 | Virtual / compensating-control patching | P1 | Protect | Interview | — |
| MYT-V06 | ISV product patch currency | P1 | Identify | Document | — |
| MYT-V07 | USS / open-source component patch currency | P1 | Identify | Hybrid | EXT-002 |

### Dimension X — Response & Recovery

| ID | Name | Pri | NIST | Validation | Reuse |
|----|------|-----|------|-----------|-------|
| MYT-X01 | Immutable backup / Safeguarded Copy presence | P0 | Recover | Hybrid | native (D SMS,SG) |
| MYT-X02 | Air-gapped / isolated backup copy | P0 | Recover | Interview | EXT-014 |
| MYT-X03 | RACF coverage of backup datasets & catalogs | P0 | Protect | Scanner | EXT-024 |
| MYT-X04 | IBM Z Cyber Vault presence & validation cadence | P1 | Recover | Interview | — |
| MYT-X05 | Recovery drill recency & RTO/RPO per workload | P0 | Recover | Interview | — |
| MYT-X06 | AI-intrusion mainframe IR playbook | P1 | Respond | Document | — |
| MYT-X07 | Break-glass credentials & LPAR isolation procedures | P1 | Respond | Interview | — |
| MYT-X08 | SMF/audit forwarding to SIEM (real-time) | P1 | Detect | Hybrid | native (D SMF,O) |
| MYT-X09 | 24/7 SOC coverage & mainframe detection content | P1 | Respond | Interview | — |
| MYT-X10 | RACF audit logging coverage | P0 | Detect | Scanner | MON-003/EXT-007/008 |
| MYT-X11 | Backup infrastructure & automation | P1 | Recover | Hybrid | EXT-021/022 |

**Totals:** 42 controls — ~27 scriptable (running 37 reused+native checks),
~15 Interview/Document-only → questionnaire deliverable. Composite controls
(C04/C05/C07/C09/C13) and the expansion controls (C15/X10/X11) bind multiple
existing checks. Bucket-3 MRRA checks deliberately not migrated: EXT-003/005/011/012,
MON-001.

## 7. Scriptable vs. Questionnaire

- **Scanner / Hybrid** controls run on z/OS (or externally for R02) and pre-fill results.
- **Interview / Document / Hybrid-fallback** controls are emitted as an **Excel questionnaire
  workbook + machine-readable JSON/CSV** for client workshop completion (see
  the scanner implementation).

## 8. Scope Clarification

MYTHOS does not assess IBM Z hardware, firmware, LIC, Secure Boot, or HMC. Active external
reconnaissance (MYT-R02) is **off by default** and requires recorded operator authorization
plus a documented rules-of-engagement (`docs/mythos-recon.md`).

## References

- Anthropic Claude Mythos (Apr 2026); CNBC, Bain, The Conversation, Dark Reading analyses.
- Google M-Trends 2026 (mean-time-to-exploit ≈ −7 days).
- Unit 42 Frontier AI Defense (3-phase model: discover exposure → strengthen controls →
  modernize detect/respond).
- IBM Z Cyber Vault, DS8000 Safeguarded Copy (storage-layer immutability).
