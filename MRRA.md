# Mainframe Ransomware Readiness Assessment (MRRA)

## Executive Overview

### What is MRRA?

The Mainframe Ransomware Readiness Assessment (MRRA) is a **workshop-based 3-day security assessment** designed to evaluate your IBM Z mainframe environment's resilience against ransomware attacks. Unlike traditional hands-on technical assessments, MRRA uses a **structured interview and document review approach** combined with **client-run scanner output**, making it accessible to organizations without requiring deep mainframe security expertise from the assessment team and nearly no hands on keyboard.

**Assessment Approach:**
- **Workshop-driven**: Structured interviews with mainframe sysadmins, security managers, and operations teams
- **Document review**: Policy, procedure, and configuration evidence collection
- **Client-run scanner**: Simple commands run by your sysadmin team to collect RACF/SMF data
- **No assessor console access required**: Validation through evidence review, not hands-on testing

### Why MRRA?

**The Ransomware Threat to Mainframes is Real:**
- **ICBC 2023**: World's largest bank suffered 6-day disruption, manual failover to USB drives
- **Average Breach Cost**: $432 million for mainframe-related incidents (Equifax, OPM, Anthem)
- **Dwell Time**: Attackers remain undetected for average 207 days before ransomware deployment
- **Recovery Challenge**: 88% of organizations experience mainframe backup corruption during ransomware events
- **Nordea 2012**: Demonstrated that z/OS mainframes can be compromised through credential theft

**Regulatory Pressure:**
- **NIS2 Directive**: Requires 24-hour incident notification, 72-hour full reporting
- **Executive Liability**: C-level executives personally accountable for cybersecurity failures
- **Financial Penalties**: Up to €10M or 2% of global revenue for non-compliance

**Unique Mainframe Vulnerabilities:**
- Legacy authentication (TSO passwords without MFA)
- APF library privilege escalation paths
- Audit log tampering (SMF manipulation)
- Inadequate database activity monitoring
- Insufficient SIEM integration for real-time detection
- USS (Unix System Services) exposure to network attacks
- Critical transactions run on mainframes (banking, insurance, government)

**Threat Scenarios (STRIDE/DREAD Analysis)**

| # | Scenario | STRIDE | DREAD Score | Risk Level |
|---|----------|--------|-------------|------------|
| 1 | Credential Spoofing (RACF SPECIAL account theft) | Spoofing | 8.2 | CRITICAL |
| 2 | APF Library Tampering (privilege escalation) | Tampering, Elevation | 8.2 | CRITICAL |
| 3 | SMF Audit Log Tampering (evidence destruction) | Repudiation | 7.4 | HIGH |
| 4 | DB2 Database Exfiltration (data theft) | Information Disclosure | 7.6 | HIGH |
| 5 | Ransomware via Batch Jobs (encryption attack) | Denial of Service | 7.2 | HIGH |
| 6 | Insider Threat (malicious sysadmin) and Backup & Recovery capabilities compromise | All STRIDE categories | 7.4 | HIGH |

### Service Value Proposition

**1. Ransomware-Focused Risk Assessment**
- Evaluate your defenses against 6 critical attack scenarios from real-world breaches
- Quantitative DREAD risk scoring for each vulnerability (1-10 scale)
- Prioritized remediation roadmap based on exploitability and impact

**2. NIS2 Compliance Gap Analysis**
- Direct mapping of findings to NIS2 Article 21 (Risk Management) and Article 23 (Incident Reporting)
- Identify compliance gaps before regulatory audits
- Actionable recommendations for 24/72-hour reporting capability

**3. Workshop-Based Validation**
- Structured interviews with mainframe security, operations, and storage teams
- Document and evidence review (policies, procedures, configurations)
- Client-run scanner output analysis (no assessor console access required)
- 50 controls across 10 NIST CSF functions

**4. Executive-Ready Reporting**
- Management summary with financial risk quantification
- Technical findings with remediation guidance
- 90-day remediation roadmap with effort/cost estimates
- Board-presentation materials included

**5. Knowledge Transfer**
- 4-hour workshop with your security and mainframe teams
- Detection rule templates for IBM zSecure Alert
- Incident response playbook for mainframe ransomware

**6. Path to Advanced Assessment**
- MRRA identifies gaps; **MSMA (Mainframe Security Maturity Assessment)** provides deep-dive technical validation
- Clear upsell path for organizations requiring hands-on penetration testing or advanced controls assessment

**Clarification of scope:**
MRRA does not assess IBM Z hardware, firmware, LIC, Secure Boot, or HMC configuration. These are addressed in much more granularity in a proper MSMA (Mainframe Security Maturity Assessment).

In the context of storage, MRRA only covers ransomware-relevant storage aspects (immutability, recovery) not storage architecture security as a broader element. 

AI-infused security and Quantum-Safe readinesses are excluded from MRRA and handled in MSMA.

MRRA is not a reduced quality assessment but an explicitely reduced scope one.

---

## Service Delivery Methodology

### 3-Day Engagement Overview

| Day | Focus Area | Activities | Deliverables |
|-----|------------|------------|--------------|
| **Day 1** | Discovery Workshop | Stakeholder interviews, architecture review, policy/document collection | Architecture summary, initial gaps |
| **Day 2** | Deep-Dive Interviews + Client Pre-Work | 10-function assessment interviews, client runs scanner scripts | Comprehensive gap analysis |
| **Day 3** | Validation & Findings | Scanner output review, evidence validation, findings presentation | Draft findings report |

**Post-Engagement (1-2 weeks later):**
- Final MRRA report delivery (PDF + Excel)
- Optional executive presentation (Day 4 add-on)
- Remediation roadmap with cost estimates

**Key Principle: No Assessor Console Access Required**
- All technical validation performed via interview + document review + scanner output
- Client's sysadmin team runs simple pre-built commands (Day 2 evening)
- Assessor reviews output, asks clarification questions
- Complex hands-on testing reserved for MSMA advanced engagement
- Leveraging our alliance with Ostrich and their tooling to improve assessment speed and report generation

---

### Day 1: Discovery Workshop (On-site or Remote)

**Participants Required:**
- Mainframe Security Administrator (RACF/ACF2/TopSecret)
- z/OS Systems Programmer
- Storage Administrator (Cyber Vault/GDPS)
- CISO or Security Manager

**Morning Session (4 hours): Architecture & Security Landscape**

**1. Architecture Review Workshop (90 min)**

*Interview Questions:*
- How many LPARs do you have? (Prod/Test/Dev separation?)
- What Sysplex configuration is in place?
- What storage infrastructure supports mainframe? (DS8000, TS7700, Cyber Vault?)
- How is network access segmented? (TN3270, USS, API gateways?)

*Documents to Collect:*
- [ ] LPAR topology diagram
- [ ] Network architecture diagram
- [ ] Storage configuration summary

**2. Security Controls Inventory (90 min)**

*Interview Questions:*
- Which ESM do you use? (RACF/ACF2/TopSecret) Version?
- Is MFA deployed? For which users? (Privileged only? All TSO?)
- Do you have database activity monitoring? (Guardium? Native DB2 audit?)
- Where do SMF logs go? (SIEM? Local only?)
- Any file integrity monitoring deployed?
- Is pervasive encryption enabled?

*Documents to Collect:*
- [ ] Security tools inventory list
- [ ] SIEM integration documentation (if any)
- [ ] Encryption coverage summary

**Afternoon Session (4 hours): Incident Response & Operations**

**3. Incident Response Readiness (60 min)**

*Interview Questions:*
- Do you have a mainframe-specific IR playbook?
- What's your estimated time to detect a compromise?
- Do you have break-glass emergency credentials?
- When was your last DR test? Result?
- How would you isolate an infected LPAR?

*Documents to Collect:*
- [ ] IR playbook (mainframe section)
- [ ] DR test results (last 12 months)
- [ ] Emergency procedures documentation

**4. Privileged Access Overview (60 min)**

*Interview Questions:*
- How many users have RACF SPECIAL attribute?
- How many users have OPERATIONS attribute?
- Are there any shared userids?
- How is console access (CN00) controlled?
- How do third-party vendors access the mainframe?

*Documents to Collect:*
- [ ] Privileged user list (can be provided Day 2 from scanner)
- [ ] Vendor access procedures

**5. Document Collection Wrap-up (60 min)**

*Request from Client (for Day 2 review):*
- [ ] RACF security policy document
- [ ] Backup policies and schedules
- [ ] Password policy documentation
- [ ] Recent security audit reports (if available)
- [ ] Training records for mainframe staff

**End-of-Day 1 Deliverables:**
- Architecture understanding documented
- Security controls inventory (interview-based)
- Document collection checklist with gaps identified
- Day 2 interview focus areas confirmed
- Scanner instructions provided to client for Day 2 evening

---

### Day 2: Deep-Dive Interviews + Client Pre-Work (On-site or Remote)

**Morning Session (4 hours): 10-Function Assessment Interviews**

Work through each NIST CSF function with targeted interview questions. All validation is interview-based; technical evidence collected via client-run scanner.

**Function 1: Asset Inventory (30 min)**
- Is there a complete LPAR inventory with criticality ratings?
- Are critical business services mapped to mainframe workloads?
- Is data classified (PCI, PHI, PII)?
- Are all network entry points documented?

**Function 2: Identity & Access Management (45 min)**
- Is MFA deployed for privileged users? All users?
- How many users have SPECIAL/OPERATIONS/AUDITOR?
- What's the password policy? (Length, complexity, expiration)
- Are there any shared userids?
- How are started tasks (STCs) secured?
- How is console access controlled?

**Function 3: Encryption (30 min)**
- Is pervasive encryption enabled?
- How are encryption keys managed? (ICSF? Hardware HSM?)
- Is TN3270 traffic encrypted?
- Is FTP disabled in favor of SFTP/FTPS?

**Function 4: Network Segmentation (30 min)**
- Are Prod/Test/Dev LPARs isolated?
- What firewall rules protect mainframe access?
- Is there a jump server for administrative access?

**Afternoon Session (4 hours): Operational Readiness**

**Function 5: Backup & Recovery (45 min)**
- Do you have immutable backups? (Safeguarded Copy, LWORM?)
- Are backups air-gapped from production?
- When was the last full LPAR recovery test?
- What are the defined RTO/RPO targets?
- Is the RACF database backed up offline?

**Function 6: Patch Management (30 min)**
- What's the SLA for critical PTF application?
- Are USS components (OpenSSH, Java) regularly patched?
- Do you track mainframe-specific CVEs?
- Is there a vulnerability scanning process?

**Function 7: Monitoring & Detection (45 min)**
- Are SMF logs forwarded to SIEM? In real-time?
- Is RACF audit logging enabled?
- Do you have failed logon alerting?
- Is there 24/7 SOC coverage for mainframe alerts?
- Can you detect abnormal batch job activity?

**Function 8: Incident Response (30 min)**
- Is there a mainframe-specific IR playbook?
- Do you have emergency break-glass credentials?
- Are network/LPAR isolation procedures documented?
- When was the last tabletop exercise?

**Function 9: Training (20 min)**
- Do mainframe staff receive security-specific training?
- Is there RACF admin training?
- Are operators trained to recognize suspicious activity?

**Function 10: Third-Party Access (20 min)**
- How do MSPs/vendors access the mainframe?
- Is vendor access time-limited and MFA-protected?
- Are ISV products included in patch management?

**End-of-Day 2 Interview Deliverables:**
- Completed interview notes for all 10 functions
- Preliminary gap identification
- Evidence requests list for Day 3 validation

---

### Client Pre-Work: Scanner Activities (Day 2 Evening)

**Purpose:** Client's mainframe sysadmin runs simple commands to collect evidence for Day 3 review. No assessor console access required.

**Time Required:** 30-60 minutes
**Skill Level:** Basic z/OS sysadmin (no security expertise required)
**Risk:** READ-ONLY commands only - no system modifications

#### Scanner Script Commands

**1. RACF Privileged User Report**
```
// Run from TSO or batch - outputs privileged user list
SEARCH CLASS(USER) SPECIAL
SEARCH CLASS(USER) OPERATIONS
SEARCH CLASS(USER) AUDITOR
```
*Output: Save to dataset or email to assessor*

**2. Password Policy Settings**
```
// Display current SETROPTS settings
SETROPTS LIST
```
*Output: Screenshot or copy MINLENGTH, HISTORY, INTERVAL values*

**3. APF Library List**
```
// Display APF-authorized libraries
D PROG,APF
```
*Output: Save console output or screenshot*

**4. SMF Recording Status**
```
// Display SMF configuration
D SMF,O
```
*Output: Note which record types are active (especially 80, 83, 30)*

**5. Default Account Check**
```
// Check if default accounts exist and are revoked
LISTUSER IBMUSER
LISTUSER SYS1
```
*Output: Confirm REVOKED status or note if active*

**6. ICSF/Encryption Status (Optional)**
```
// If ICSF is installed
D ICSF,LIST
```
*Output: Note COPROCESSOR status and key status*

**7. Started Task Configuration**
```
// Sample check for STC security
RLIST STARTED * ALL
```
*Output: First page showing STC userid assignments*

#### Evidence Collection Checklist

| Item | Command/Source | Status |
|------|----------------|--------|
| Privileged users (SPECIAL) | `SEARCH CLASS(USER) SPECIAL` | ☐ |
| Privileged users (OPERATIONS) | `SEARCH CLASS(USER) OPERATIONS` | ☐ |
| Password policy | `SETROPTS LIST` | ☐ |
| APF library list | `D PROG,APF` | ☐ |
| SMF recording status | `D SMF,O` | ☐ |
| Default accounts | `LISTUSER IBMUSER` | ☐ |
| Backup job schedule | JCL library listing | ☐ |
| DR test report | Document from storage team | ☐ |

**Delivery Method:**
- Email output files/screenshots to assessor before Day 3
- Or prepare for screen-share review on Day 3 morning

**Important Notes:**
- All commands are READ-ONLY
- No system modifications
- No password or credential exposure
- Output can be sanitized if needed (remove specific userids)

---

### Day 3: Validation & Findings (On-site or Remote)

**No Assessor Console Access Required** - All validation through evidence review and clarification interviews.

**Morning Session (4 hours): Scanner Output Review & Validation**

**1. Evidence Review (60 min)**

Review scanner output provided by client:
- SPECIAL/OPERATIONS/AUDITOR user lists
- SETROPTS password policy settings
- APF library inventory
- SMF recording configuration
- Default account status

**2. Threat Scenario Validation (3 hours)**

For each of the 6 DREAD threat scenarios, validate findings against evidence:

---

**Scenario 1: Credential Spoofing Assessment**

| Check | Evidence Source | Finding |
|-------|-----------------|---------|
| SPECIAL user count | Scanner output | Count: ___ (Target: <5) |
| Password policy (MINLENGTH) | SETROPTS LIST | Value: ___ (Target: 15+) |
| MFA deployed | Interview | Yes/No/Partial |
| Default accounts disabled | LISTUSER output | IBMUSER: Revoked? |

**Clarification Questions:**
- "The scanner shows 8 SPECIAL users. Can you explain why each needs this access?"
- "I see MINLENGTH=8. Is there a plan to increase to 15?"

**DREAD Score:** 8.2 / 10 (CRITICAL)
- Damage: 9 | Reproducibility: 8 | Exploitability: 7 | Affected: 9 | Discoverability: 8

---

**Scenario 2: APF Library Tampering Assessment**

| Check | Evidence Source | Finding |
|-------|-----------------|---------|
| APF library count | D PROG,APF output | Count: ___ |
| APF libraries RACF-protected | Interview | Yes/No |
| Change control process | Document review | Documented? |
| File integrity monitoring | Interview | Deployed? |

**Clarification Questions:**
- "Are all APF libraries protected with UACC(NONE)?"
- "Do you have any monitoring for APF library modifications?"

**DREAD Score:** 8.2 / 10 (CRITICAL)
- Damage: 10 | Reproducibility: 8 | Exploitability: 7 | Affected: 9 | Discoverability: 7

---

**Scenario 3: SMF Audit Log Tampering Assessment**

| Check | Evidence Source | Finding |
|-------|-----------------|---------|
| SMF recording active | D SMF,O output | Types active: ___ |
| Critical types recorded | Scanner output | 80, 83, 30 present? |
| SIEM integration | Interview | Real-time forwarding? |
| SMF dataset protected | Interview | RACF protection? |

**Clarification Questions:**
- "How quickly do SMF events reach your SIEM?"
- "Who has UPDATE access to SMF datasets?"

**DREAD Score:** 7.4 / 10 (HIGH)
- Damage: 8 | Reproducibility: 7 | Exploitability: 7 | Affected: 7 | Discoverability: 7

---

**Afternoon Session (4 hours): Remaining Scenarios & Findings**

**Scenario 4: Database Exfiltration Assessment**

| Check | Evidence Source | Finding |
|-------|-----------------|---------|
| DB2 audit logging | Interview | Enabled? |
| Database activity monitoring | Interview | Guardium/native? |
| Sensitive data encrypted | Interview | Column-level? |

**DREAD Score:** 7.6 / 10 (HIGH)

---

**Scenario 5: Ransomware via Batch Jobs Assessment**

| Check | Evidence Source | Finding |
|-------|-----------------|---------|
| JCL submission controls | Interview | Restricted? |
| Batch job monitoring | Interview | Alerting active? |
| Critical dataset protection | Interview | UACC(NONE)? |

**DREAD Score:** 7.2 / 10 (HIGH)

---

**Scenario 6: Backup & Recovery Assessment**

| Check | Evidence Source | Finding |
|-------|-----------------|---------|
| Immutable backups | Interview | Safeguarded Copy/LWORM? |
| Backup air-gap | Interview | Network isolated? |
| Last DR test | Document | Date: ___ Result: ___ |
| RACF database backup | Interview | Offline copy? |

**Risk Mitigation Note:** IBM Z Cyber Vault reduces ransomware risk by 90%

---

**3. Findings Consolidation (60 min)**

- Compile all findings by NIST function
- Calculate weighted scores per function
- Identify Top 5 critical gaps (P0 failures)
- Draft preliminary recommendations

**4. Stakeholder Findings Preview (60 min)**

Present preliminary findings to:
- Security Manager
- Mainframe Lead
- (Optional) CISO

**Agenda:**
- Overall maturity score (visual)
- DREAD risk summary (6 scenarios)
- Top 5 critical gaps
- Preview of remediation priorities
- Q&A and clarification

**End-of-Day 3 Deliverables:**
- Preliminary findings presentation
- DREAD scores for all 6 threat scenarios
- Evidence log with supporting documentation
- Gap analysis across 10 NIST functions
- Draft remediation priorities

**Post-Engagement (1-2 weeks):**
- Final MRRA Report (PDF)
- Controls Checklist (Excel)
- Remediation Roadmap
- Optional Day 4 executive presentation

---

### Day 4: Executive Presentation & Knowledge Transfer (Optional - Scheduled 1-2 weeks after Day 3)

**Why Day 4 is Optional:**
- Allows time for detailed report writing and quality assurance
- Enables custom slide deck creation tailored to your organization
- Permits coordination with executive and board calendars
- Provides buffer for clarification questions and additional analysis
- Reduces stakeholder fatigue (full day presentation vs. concurrent with testing)

**Pre-Day 4 Deliverables (Prepared Between Day 3 and Day 4):**
- Final MRRA Report (PDF + Word) - 40-45 pages
- Controls Checklist (Excel spreadsheet) - 30+ controls with status
- Remediation Roadmap (Excel) - 90-day action plan with costs
- Detection Rule Templates (text files / SIEM XML) --> NOT NOW
- Incident Response Playbook (PDF) --> must be optionally paid

**Morning Session (4 hours): Presentation Preparation & Rehearsal**

**Activities:**

**1. Executive Summary Writing (90 min)**
   - Overall risk posture assessment (Red/Yellow/Green)
   - Top 5 critical findings with business impact
   - Financial risk quantification (potential breach cost)
   - NIS2 compliance status summary
   - Recommended immediate actions (next 30 days)

**2. Technical Findings Documentation (90 min)**
   - Detailed findings for each of 6 threat scenarios
   - DREAD risk scores with justification
   - Evidence (RACF reports, SMF queries, configuration screenshots)
   - Step-by-step remediation guidance
   - Verification procedures

**3. Remediation Roadmap Development (60 min)**
   - 90-day action plan with milestones
   - Effort estimates (person-days) and cost estimates
   - Prioritization matrix (risk vs. effort)
   - Dependencies and sequencing
   - Quick wins vs. strategic initiatives

**Afternoon Session (4 hours): Presentation & Knowledge Transfer**

**1. Executive Briefing (90 min)**

**Audience:** CISO, CIO, Head of Mainframe, Risk Management, Compliance

**Presentation Structure:**
- **Risk Overview** (15 min)
  - Current security posture (visual risk dashboard)
  - Comparison to industry benchmarks
  - NIS2 compliance gaps

- **Critical Findings** (30 min)
  - Top 5 findings with business context
  - Real-world breach examples (ICBC, Equifax)
  - Potential financial impact

- **Remediation Roadmap** (30 min)
  - Phased implementation plan (30/60/90 days)
  - Resource requirements and budget
  - Risk reduction metrics

- **Q&A and Discussion** (15 min)

**2. Technical Workshop (2 hours remote with our top experts (e.g. Davide))**

**Audience:** Mainframe Security Team, Systems Programmers, Security Operations

**Workshop Content:**
- **Detection Rule Templates** (45 min)
  - IBM zSecure Alert rules for 6 threat scenarios
  - SIEM correlation rules for QRadar/Splunk
  - Threshold tuning guidance

- **Incident Response Playbook** (45 min)
  - Mainframe ransomware response procedures
  - Containment strategies (LPAR isolation, network segmentation)
  - Recovery procedures (Cyber Vault restoration)
  - Evidence collection for forensics

- **Q&A and Next Steps** (30 min)

**End-of-Day Deliverables:**
- Final MRRA Report (PDF + Word)
- Controls Checklist (Excel spreadsheet)
- Detection Rule Templates (text files)
- Incident Response Playbook (PDF)
- Presentation slides (PowerPoint)

---

## MRRA Controls Checklist

### How to Use This Checklist

**Streamlined for Workshop Assessment:** 50 controls across 10 NIST CSF functions, designed for interview-based validation with client-run scanner support.

**Format:** This checklist is provided in markdown format and can be exported to Excel/CSV. Each control includes:
- **Control ID**: Unique identifier for tracking (organized by NIST CSF function)
- **Control Name**: Descriptive name
- **Priority**: P0 (Critical), P1 (High - 60 days), P2 (Medium - 90 days)
- **Validation Method**: Interview, Document Review, or Scanner Output
- **STRIDE Mapping**: Threat type addressed
- **Status**: ☐ Not Started | ⚠️ In Progress | ✅ Complete | ❌ Failed | N/A

**Note:** Advanced controls requiring hands-on technical validation are documented in [MSMA-Advanced-Controls.md](MSMA-Advanced-Controls.md) for follow-on engagement. The real MSMA will be handled by expert team #Davide

---

### NIST CSF Function 1: Asset Inventory & Risk Assessment (IDENTIFY)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| ID-001 | LPAR Inventory with Criticality Ratings | P0 | Interview + Doc | All | ☐ |
| ID-002 | Privileged User Inventory (SPECIAL/OPERATIONS/AUDITOR) | P0 | Scanner | Spoofing, Priv Esc | ☐ |
| ID-003 | APF Library Inventory | P0 | Scanner | Priv Esc | ☐ |
| ID-004 | Network Entry Points Mapping | P1 | Interview + Doc | All | ☐ |
| ID-005 | Data Classification (PCI, PHI, PII) | P0 | Interview + Doc | Info Disclosure | ☐ |
| ID-006 | Critical Business Service Mapping | P1 | Interview | All | ☐ |

---

### NIST CSF Function 2: Privileged Access & Identity Management (PROTECT)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| IAM-001 | Multi-Factor Authentication Coverage | P0 | Interview | Spoofing | ☐ |
| IAM-002 | Strong Password Policy (SETROPTS) | P0 | Scanner | Spoofing | ☐ |
| IAM-003 | Default Account Removal (IBMUSER, SYS1) | P0 | Scanner | Spoofing | ☐ |
| IAM-004 | RACF SPECIAL Attribute Restriction (<5 users) | P0 | Scanner | Priv Esc | ☐ |
| IAM-005 | Started Task (STC) Security | P1 | Interview + Scanner | Priv Esc | ☐ |
| IAM-006 | Console Security (CN00 Restriction) | P1 | Interview | Priv Esc | ☐ |
| IAM-007 | Shared Userid Elimination | P0 | Interview | Repudiation | ☐ |
| IAM-008 | Batch Job RACF Enforcement (BATCHALLRACF) | P1 | Scanner | Priv Esc | ☐ |

Detailed EASM internals (ABAC, MLS, SERVERAUTH deep dives) are deferred to the MSMA

**Interview Questions for IAM:**
- IAM-001: "Is MFA deployed? For privileged users only, or all TSO/USS users?"
- IAM-002: Validated via scanner (SETROPTS LIST output)
- IAM-003: Validated via scanner (LISTUSER IBMUSER)
- IAM-004: Validated via scanner (SEARCH CLASS(USER) SPECIAL)
- IAM-005: "Do all started tasks run under dedicated userids?"
- IAM-006: "How many users can access the master console?"
- IAM-007: "Are there any shared TSO or batch userids?"

---

### NIST CSF Function 3: Data Protection & Encryption (PROTECT)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| ENC-001 | Pervasive Encryption Enabled | P1 | Interview | Info Disclosure | ☐ |
| ENC-002 | ICSF Key Management | P0 | Interview + Scanner | Info Disclosure | ☐ |
| ENC-003 | Critical Dataset Encryption | P1 | Interview | Info Disclosure | ☐ |
| ENC-004 | Network Encryption (TN3270E, SFTP) | P0 | Interview | Info Disclosure | ☐ |
| ENC-005 | Crypto Hardware Utilization | P1 | Scanner | Info Disclosure | ☐ |

MRRA validates the existence and governance of encryption controls. Detailed crytpographics configurations, key store inspection, algorithm in compliace and PQC readiness are assessed in MSMA and/or Quantum-safe engagements. This areas assess the surfaces concepts. Experts might expect more.

**Interview Questions for ENC:**
- ENC-001: "Is pervasive encryption enabled on your z14/z15/z16?"
- ENC-002: "How are encryption keys managed? When was the last master key rotation?"
- ENC-003: "Which datasets are encrypted? PCI/PHI data?"
- ENC-004: "Is TN3270 traffic encrypted? Is plain FTP disabled?"
- ENC-005: Validated via scanner (D ICSF,LIST)

---

### NIST CSF Function 4: Network Segmentation & Perimeter Defense (PROTECT)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| NET-001 | LPAR Isolation (Prod/Dev/Test) | P0 | Interview + Doc | All | ☐ |
| NET-002 | Network Segmentation (TCP/IP, HiperSockets) | P1 | Interview | All | ☐ |
| NET-003 | External Firewall Rules | P0 | Interview + Doc | All | ☐ |
| NET-004 | Administrative Jump Server Access | P1 | Interview | Spoofing | ☐ |

**Interview Questions for NET:**
- NET-001: "Are Prod/Dev/Test LPARs isolated? Can dev access prod data?"
- NET-002: "Is internal LPAR traffic (HiperSockets) separate from external?"
- NET-003: "What ports are open to mainframe from external networks?"
- NET-004: "Do administrators access mainframe directly or via jump server?"

---

### NIST CSF Function 5: Backup & Recovery (PROTECT & RECOVER)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| BCK-001 | Immutable Backups (Safeguarded Copy/LWORM) | P0 | Interview | DoS, Tampering | ☐ |
| BCK-002 | Backup Air-Gap (Network Isolation) | P0 | Interview | DoS | ☐ |
| BCK-003 | Critical System Backup (RACF DB, Catalogs) | P0 | Interview | DoS, Priv Esc | ☐ |
| BCK-004 | RTO/RPO Definition per Workload | P1 | Interview + Doc | DoS | ☐ |
| BCK-005 | DR Recovery Testing (Last 12 months) | P0 | Interview + Doc | DoS | ☐ |
| BCK-006 | Physical/Offline Tape Backups | P1 | Interview | DoS | ☐ |

**Interview Questions for BCK:**
- BCK-001: "Do you have Safeguarded Copy or LWORM tape? Can backups be deleted by admins?"
- BCK-002: "Are backup systems isolated from production network?"
- BCK-003: "Is the RACF database backed up offline? ICF catalogs?"
- BCK-004: "What are your RTO/RPO targets for critical workloads?"
- BCK-005: "When was your last full LPAR recovery test? Did it succeed?"
- BCK-006: "Do you have physical tape backups stored offsite?"

---

### NIST CSF Function 6: Vulnerability & Patch Management (PROTECT)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| PTH-001 | z/OS Patch Management Process (PTF/RSU) | P0 | Interview | All | ☐ |
| PTH-002 | USS & Middleware Patching | P0 | Interview | All | ☐ |
| PTH-003 | Vulnerability Scanning | P1 | Interview | All | ☐ |
| PTH-004 | CVE Tracking Process | P1 | Interview | All | ☐ |

**Interview Questions for PTH:**
- PTH-001: "What's your SLA for critical PTF application? RSU cadence?"
- PTH-002: "How are USS components (OpenSSH, Java) and middleware (CICS, DB2) patched?"
- PTH-003: "Do you have vulnerability scanning for z/OS? How often?"
- PTH-004: "How do you track mainframe-specific CVEs? IBM PSIRTs?"

---

### NIST CSF Function 7: Monitoring, Detection & Response (DETECT & RESPOND)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| MON-001 | SMF Recording (Critical Types: 80, 83, 30) | P0 | Scanner | Repudiation | ☐ |
| MON-002 | SMF Forwarding to SIEM | P0 | Interview | All | ☐ |
| MON-003 | RACF Audit Logging (SETROPTS AUDIT) | P0 | Scanner | Repudiation | ☐ |
| MON-004 | Failed Logon Alerting | P1 | Interview | Spoofing | ☐ |
| MON-005 | Privileged Account Monitoring | P1 | Interview | Priv Esc | ☐ |
| MON-006 | Console Activity Logging | P1 | Interview | Repudiation | ☐ |
| MON-007 | 24/7 SOC Coverage for Mainframe | P0 | Interview | All | ☐ |

Advanced SMF record anlaysis (e.g. RMF 70-2, crypto usage SMF 82-31) is our of scope for MRRA and covered in MSMA.

**Interview Questions for MON:**
- MON-001: Validated via scanner (D SMF,O)
- MON-002: "Are SMF logs forwarded to SIEM? Real-time or batch?"
- MON-003: Validated via scanner (SETROPTS LIST - AUDIT settings)
- MON-004: "Do you have alerting for failed logon attempts? Threshold?"
- MON-005: "Is privileged user activity (SPECIAL users) monitored differently?"
- MON-006: "Is console activity logged and reviewed?"
- MON-007: "Is your SOC aware of mainframe alerts? 24/7 coverage?"

---

### NIST CSF Function 8: Incident Response & Playbooks (RESPOND)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| IR-001 | Mainframe-Specific IR Playbook | P0 | Document | DoS | ☐ |
| IR-002 | Emergency Break-Glass Credentials | P0 | Interview | DoS | ☐ |
| IR-003 | Network/LPAR Isolation Procedures | P0 | Document | DoS | ☐ |
| IR-004 | Recovery Procedures (RACF, Datasets) | P0 | Document | DoS | ☐ |
| IR-005 | Tabletop Exercise (Last 12 months) | P1 | Interview + Doc | All | ☐ |

**Interview Questions for IR:**
- IR-001: "Do you have a mainframe-specific incident response playbook?"
- IR-002: "Are there break-glass emergency credentials? Where stored?"
- IR-003: "Are procedures documented to isolate an infected LPAR?"
- IR-004: "Are RACF database and critical dataset recovery procedures documented?"
- IR-005: "When was your last mainframe incident tabletop exercise?"

---

### NIST CSF Function 9: Security Awareness & Training (PROTECT)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| TRN-001 | Mainframe Security Training (Sysprogs/DBAs) | P1 | Interview | All | ☐ |
| TRN-002 | RACF Admin Security Training | P0 | Interview | Priv Esc | ☐ |
| TRN-003 | Security Awareness (Phishing for Admins) | P1 | Interview | Spoofing | ☐ |

**Interview Questions for TRN:**
- TRN-001: "Do mainframe staff receive security-specific training?"
- TRN-002: "Have RACF administrators received privilege escalation awareness training?"
- TRN-003: "Are mainframe admins included in phishing awareness programs?"

---

### NIST CSF Function 10: Third-Party & Supply Chain (IDENTIFY & PROTECT)

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| 3PT-001 | MSP/Vendor Access Controls (MFA + Time-Limited) | P0 | Interview | Spoofing, Priv Esc | ☐ |
| 3PT-002 | ISV Product Patching | P1 | Interview | All | ☐ |
| 3PT-003 | Remote Support Access Logging | P1 | Interview | Repudiation | ☐ |

**Interview Questions for 3PT:**
- 3PT-001: "How do MSPs/vendors access the mainframe? MFA? Time-limited?"
- 3PT-002: "Are third-party products (CA, BMC, Rocket) included in patch management?"
- 3PT-003: "Is IBM remote support access logged and reviewed?"

---

## Optional Module: System Core Integrity (F11)

**Scope:** This module is OPTIONAL and adds 4 controls to the standard 50-control assessment. Include when:
- Client has advanced security maturity
- Specific concerns about APF library tampering
- Preparing for MSMA deep-dive engagement
- Regulatory requirements for integrity monitoring

### NIST CSF Function 11: System Core Integrity (PROTECT) - OPTIONAL

*Based on Kyndryl MSMA framework - addresses "zCore system integrity not guaranteed" vulnerability*

| Control ID | Control Name | Priority | Validation | STRIDE | Status |
|------------|--------------|----------|------------|--------|--------|
| SCI-001 | APF Library Integrity Monitoring | P0 | Interview | Tampering, Priv Esc | ☐ |
| SCI-002 | System Library Change Control | P0 | Interview + Doc | Tampering | ☐ |
| SCI-003 | File Integrity Monitoring (FIM) Deployment | P1 | Interview | Tampering | ☐ |
| SCI-004 | Program Control (RACF PROGRAM Class) | P1 | Scanner | Priv Esc | ☐ |
| SCI-005 | RACF Database Protection (UACC=NONE) | P0 | Scanner | Tampering, Priv Esc | ☐ |
| SCI-006 | ICHAUTAB Authorization Bypass Table | P1 | Scanner | Priv Esc | ☐ |

**Interview Questions for SCI (Optional):**
- SCI-001: "Do you have monitoring for APF library modifications? Real-time alerting?"
- SCI-002: "Is there a change control process for system libraries (SYS1.LPALIB, etc.)?"
- SCI-003: "Is a File Integrity Monitoring tool deployed? (IBM Threat Detector, MainTegrity FIM+)"
- SCI-004: Validated via scanner (SETROPTS LIST — WHEN(PROGRAM))
- SCI-005: Validated via scanner (RLIST DATASET SYS1.RACF — UACC should be NONE)
- SCI-006: Validated via scanner (SETROPTS LIST — ICHAUTAB should not be present)

**Scanner Commands (Client Pre-Work - Optional):**
```
// APF library list
D PROG,APF

// Program Control status
SETR LIST
// Look for WHEN(PROGRAM) settings

// Check controlled programs
RLIST PROGRAM * ALL
```

**Why This Module Matters:**
APF libraries contain programs that execute with system authority. Tampering with APF libraries enables:
- Privilege escalation to SPECIAL equivalent
- Security control bypass
- Persistent backdoors surviving IPL
- Ransomware payload injection

**Note:** For deep technical validation of SCI controls (hash baselines, SVC monitoring), see MSMA Advanced Assessment.

---

## Control Assessment Guidance

**Note:** This section provides assessment guidance for key controls. For detailed implementation guidance, see the full MRRA deliverable package or the MSMA advanced assessment.

### Assessment Approach

For each control, the assessor should:
1. **Ask** the interview question(s)
2. **Review** supporting evidence (documents, scanner output)
3. **Validate** the response against best practices
4. **Score** as Pass / Partial / Fail / N/A
5. **Document** findings and gaps

---

#### IAM-001: Multi-Factor Authentication Coverage

**Rationale:**
Credential theft is the #1 attack vector in mainframe breaches (Nordea 2012, Anthem 2015, OPM 2015). MFA prevents 99.9% of account compromise attacks.

**Priority:** P0 (Critical)

**Assessment Interview Questions:**
1. "Is MFA deployed for mainframe access?"
2. "Which users are covered?" (Privileged only? All TSO? USS users?)
3. "What MFA technology is used?" (IBM MFA for z/OS, RSA SecurID, TOTP?)
4. "Is there a break-glass account without MFA? How is it secured?"

**Scoring Criteria:**
| Status | Criteria |
|--------|----------|
| ✅ Pass | MFA deployed for all privileged users (SPECIAL, OPERATIONS, AUDITOR) |
| ⚠️ Partial | MFA deployed but incomplete coverage or weak fallback |
| ❌ Fail | No MFA deployed for privileged users |

**Best Practice Targets:**
- All SPECIAL/OPERATIONS/AUDITOR users require MFA
- MFA coverage for USS UID=0 users
- Break-glass account secured in sealed envelope

**NIS2 Mapping:** Article 21.2(d) - Multi-factor authentication

**Cost Estimate (if gap identified):** €25,000-€35,000 (IBM MFA for z/OS)

---

#### IAM-002: Strong Password Policy (SETROPTS)

**Rationale:**
Weak passwords enable brute-force attacks. RACF SETROPTS controls password complexity, history, and expiration. The Nordea 2012 breach exploited weak passwords.

**Priority:** P0 (Critical)

**Assessment Method:** Scanner output review (SETROPTS LIST)

**Scanner Command (Client runs Day 2):**
```
SETROPTS LIST
```

**What to Look For:**
| Setting | Target Value | Risk if Gap |
|---------|-------------|-------------|
| MINLENGTH | 15+ | Brute-force attacks |
| HISTORY | 24+ | Password reuse |
| INTERVAL | 90-180 | Stale credentials |
| REVOKE | 3-5 | No lockout protection |
| RULES | 8 | Weak passwords |

**Scoring Criteria:**
| Status | Criteria |
|--------|----------|
| ✅ Pass | MINLENGTH ≥ 12, HISTORY ≥ 12, REVOKE enabled |
| ⚠️ Partial | Some settings meet target, others below |
| ❌ Fail | MINLENGTH < 8 or REVOKE disabled |

**NIS2 Mapping:** Article 21.2(a) - Authentication mechanisms

**Cost Estimate (if gap identified):** €0 (SETROPTS is built-in)

---

#### MON-004: Failed Logon Alerting

**Rationale:**
Brute-force attacks generate failed authentication events. Real-time alerting enables early warning (NIS2 24-hour requirement). The Nordea 2012 breach involved credential attacks that went undetected for weeks.

**Priority:** P1 (High)

**Assessment Interview Questions:**
1. "Do you have alerting for failed logon attempts?"
2. "What's the threshold before an alert is generated?"
3. "How quickly does the alert reach the SOC?"
4. "Are privileged user failures alerted at a lower threshold?"

**Scoring Criteria:**
| Status | Criteria |
|--------|----------|
| ✅ Pass | Failed logon alerting active, integrated with SIEM, <5 min detection |
| ⚠️ Partial | Alerting exists but not real-time or not integrated with SOC |
| ❌ Fail | No failed logon alerting |

**NIS2 Mapping:** Article 23.1 - Early warning (24-hour requirement)

**Cost Estimate (if gap identified):** €10,000-€20,000 (SIEM integration)

---

#### BCK-001: Immutable Backups (Safeguarded Copy/LWORM)

**Rationale:**
Ransomware typically targets backup systems before encrypting production data. Immutable backups (Safeguarded Copy, LWORM tape) cannot be deleted or modified, even by administrators with SPECIAL authority.

**Priority:** P0 (Critical)

**Assessment Interview Questions:**
1. "Do you have immutable backups? (Safeguarded Copy, LWORM tape)"
2. "Can backup copies be deleted by system administrators?"
3. "How long are immutable copies retained?"
4. "When was the last test restore from immutable backup?"

**Scoring Criteria:**
| Status | Criteria |
|--------|----------|
| ✅ Pass | Immutable backups deployed (Safeguarded Copy or LWORM), tested |
| ⚠️ Partial | Immutable backups exist but untested or limited coverage |
| ❌ Fail | No immutable backup capability |

**Best Practice:** IBM Z Cyber Vault with Safeguarded Copy reduces ransomware risk by 90%

**NIS2 Mapping:** Article 21.2(c) - Business continuity and disaster recovery

**Cost Estimate (if gap identified):** €50,000-€150,000 (depends on storage infrastructure)

---

#### MON-001: SMF Recording (Critical Types)

**Rationale:**
SMF (System Management Facility) records provide audit trail for security events. Without proper SMF recording, malicious activity goes undetected.

**Priority:** P0 (Critical)

**Assessment Method:** Scanner output review (D SMF,O)

**Scanner Command (Client runs Day 2):**
```
D SMF,O
```

**Critical SMF Record Types:**
| Type | Description | Required? |
|------|-------------|-----------|
| 30 | Job accounting | Yes |
| 80 | RACF events | Yes |
| 83 | RACF security | Yes |
| 14/15 | Dataset activity | Recommended |
| 42 | DFSMS statistics | Recommended |

**Scoring Criteria:**
| Status | Criteria |
|--------|----------|
| ✅ Pass | Types 30, 80, 83 all ACTIVE |
| ⚠️ Partial | Some critical types missing |
| ❌ Fail | SMF recording disabled or minimal |

**NIS2 Mapping:** Article 21.2(b) - Incident handling (audit capability)

---

**Note:** The 6 STRIDE threat scenarios (Credential Spoofing, APF Library Tampering, SMF Audit Log Tampering, DB2 Database Exfiltration, Ransomware via Batch Jobs, Insider Threat) are addressed through the 10 NIST CSF functions. Each control is mapped to the relevant STRIDE threats in the "STRIDE Mapping" column.

**Control Count Summary:**
- **Standard Scope**: 50 controls across 10 NIST CSF functions
- **Optional Module**: +4 controls (F11: System Core Integrity)
- **Full Scope**: 54 controls across 11 functions

**Priority Breakdown (Standard 50):**
- **P0 (Critical)**: 23 controls - must verify
- **P1 (High)**: 27 controls - verify within assessment scope

**Validation Method Summary:**
- **Interview-based**: 35 controls (70%)
- **Scanner output**: 12 controls (24%)
- **Document review**: 8 controls (16%)
- *Note: Some controls use multiple validation methods*

**Controls by Function:**
| Function | Controls | Count | Scope |
|----------|----------|-------|-------|
| ID (Asset Inventory) | ID-001 to ID-006 | 6 | Standard |
| IAM (Identity & Access) | IAM-001 to IAM-007 | 7 | Standard |
| ENC (Encryption) | ENC-001 to ENC-005 | 5 | Standard |
| NET (Network) | NET-001 to NET-004 | 4 | Standard |
| BCK (Backup & Recovery) | BCK-001 to BCK-006 | 6 | Standard |
| PTH (Patch Management) | PTH-001 to PTH-004 | 4 | Standard |
| MON (Monitoring) | MON-001 to MON-007 | 7 | Standard |
| IR (Incident Response) | IR-001 to IR-005 | 5 | Standard |
| TRN (Training) | TRN-001 to TRN-003 | 3 | Standard |
| 3PT (Third-Party) | 3PT-001 to 3PT-003 | 3 | Standard |
| **Standard Total** | | **50** | |
| SCI (System Core Integrity) | SCI-001 to SCI-004 | 4 | **Optional** |
| **Full Total** | | **54** | |

**STRIDE Coverage:**
- **Spoofing**: Covered by IAM, NET, TRN, 3PT functions
- **Tampering**: Covered by MON, BCK, SCI (optional) functions
- **Repudiation**: Covered by MON (SMF, RACF audit), IR functions
- **Information Disclosure**: Covered by ENC, ID, IAM functions
- **Denial of Service**: Covered by BCK, IR, MON functions
- **Elevation of Privilege**: Covered by IAM, ID, PTH, SCI (optional) functions

**Additional Resources:**
- **Dropped Controls**: Preserved in [dropped-checks.md](dropped-checks.md) for reference
- **Advanced Controls (MSMA)**: Hands-on technical validation in [MSMA-Advanced-Controls.md](MSMA-Advanced-Controls.md)

---

## MRRA Final Report Structure

### Report Deliverables

1. **Executive Summary Report** (10-15 pages) - For: CISO, CIO, Board
2. **Technical Findings Report** (40-60 pages) - For: Mainframe security team, sysprogs
3. **Remediation Roadmap** (Excel spreadsheet) - 90-day action plan
4. **Controls Checklist** (Excel spreadsheet) - All 30+ controls with Pass/Fail status
5. **Detection Rule Templates** (Text files / QRadar XML) - SIEM rules for 6 scenarios
6. **Incident Response Playbook** (PDF) - Step-by-step ransomware response
7. **Presentation Slides** (PowerPoint) - Executive briefing and technical workshop

---

### Executive Summary Report Structure

**Cover Page:**
- Company logo and name
- Report title: "Mainframe Ransomware Readiness Assessment (MRRA)"
- Assessment date range
- Confidentiality statement
- Prepared by: [Your Company]

**Section 1: Executive Summary** (2 pages)
- Overall security posture (Red/Yellow/Green rating)
- Top 5 critical findings
- Financial risk quantification ($X million potential breach cost)
- NIS2 compliance status (% compliant)
- Recommended immediate actions (next 30 days)

**Section 2: Assessment Scope** (1 page)
- LPARs and systems assessed
- Assessment methodology (STRIDE + DREAD)
- Stakeholders interviewed
- Duration and effort

**Section 3: Risk Assessment Summary** (3 pages)
- Risk dashboard (visual heat map of 6 threat scenarios)
- DREAD scores for each scenario
- Comparison to industry benchmarks (average mainframe security posture)
- Trend analysis (improving/degrading over time if re-assessment)

**Section 4: Key Findings** (4 pages)
- Top 5 critical findings (1 page each):
  - Finding description
  - Business impact (financial, operational, reputational)
  - Real-world example (ICBC 2023, Equifax 2017, etc.)
  - Recommended action
  - Expected risk reduction

**Section 5: NIS2 Compliance Gap Analysis** (2 pages)
- Compliance status by NIS2 article
- Critical gaps (24/72-hour reporting capability, MFA, encryption, business continuity)
- Timeline to achieve full compliance

**Section 6: Remediation Roadmap** (2 pages)
- 90-day action plan (visual timeline with milestones)
- Budget estimate (tools, resources, training)
- Expected risk reduction (before/after DREAD scores)
- Success metrics (KPIs for measuring progress)

**Section 7: Conclusion and Next Steps** (1 page)
- Summary of assessment value
- Call to action (approve budget, initiate Phase 1)
- Contact information for follow-up

**Appendices:**
- Glossary of mainframe terms (RACF, APF, SMF, USS, LPAR, etc.)
- References (IBM documentation, case studies)
- Assessment team credentials

---

### Technical Findings Report Structure

**Section 1: Introduction** (2 pages)
- Assessment objectives
- Methodology (STRIDE + DREAD)
- Scope and limitations
- Document organization

**Section 2: Architecture Review** (5 pages)
- LPAR topology diagram
- Sysplex configuration
- Storage architecture (DASD, Cyber Vault, DR replication)
- Network architecture (TN3270, USS, API gateways)
- Security controls inventory

**Section 3-8: Threat Scenario Analysis** (30 pages total, 5 pages each)

For each of 6 threat scenarios:
- STRIDE classification
- Attack path breakdown (step-by-step)
- DREAD risk score with justification
- Technical evidence (RACF reports, SMF queries, screenshots)
- Existing controls assessment (what's working, what's missing)
- Gaps identified (specific vulnerabilities)
- Detailed remediation guidance (RACF commands, configuration changes, verification)
- Detection and alerting recommendations (SIEM rules)
- Mapping to NIS2 requirements

**Section 9: NIS2 Compliance Detailed Assessment** (5 pages)
- Article-by-article analysis
- Evidence of compliance (or gaps)
- Remediation guidance for each gap

**Section 10: Industry Benchmarking** (3 pages)
- Comparison to mainframe security best practices
- Peer organization comparison (anonymized)
- Maturity model assessment (Level 1-5)

**Section 11: References** (2 pages)
- IBM documentation links
- Case study references
- NIST SP 800-53 control mapping
- Tools and vendor contacts

**Appendices:**
- RACF reports (user lists, dataset profiles, group connections)
- SMF analysis results (record type statistics, security events)
- Configuration files (SMFPRMXX, IOCP, PROGxx)
- Interview notes

---

### Incident Response Playbook Structure

**Playbook Sections:**

**1. Incident Classification**
   - Severity levels (Critical/High/Medium/Low)
   - Incident types (ransomware, data theft, insider threat, APF tampering)
   - Escalation criteria (when to involve CISO, legal, PR)

**2. Roles and Responsibilities**
   - Incident Commander (CISO or delegate)
   - Technical Lead (Mainframe security admin)
   - Communications Lead (PR/Legal)
   - Scribe (documentation)
   - Subject Matter Experts (z/OS sysprog, storage admin, network engineer)

**3. Detection and Analysis**
   - Initial alert triage (SIEM, FIM, zSecure, user report)
   - Preliminary investigation (SMF log review, RACF audit)
   - Scope determination (which LPARs, datasets, users affected)
   - NIS2 24-hour notification trigger assessment

**4. Containment Procedures**
   - Short-term containment:
     - Revoke compromised userids (ALTUSER userid REVOKE)
     - Isolate infected LPAR (disable TCP/IP stack: V TCP/IP,STOP)
     - Block malicious IP addresses (firewall ACL update)
     - Disable external access (HiperSockets only)
   - Long-term containment:
     - Rebuild compromised systems from clean images
     - Patch vulnerabilities (apply IBM PTFs)
     - Reset all credentials (force password change)

**5. Eradication Procedures**
   - Malware removal (delete malicious JCL, USS files)
   - Restore from Cyber Vault (immutable Safeguarded Copy)
   - Verify APF library integrity (hash comparison with baseline)
   - Database recovery (DB2 restore and roll-forward to point-in-time)
   - RACF database restore (from offline backup)

**6. Recovery Procedures**
   - Prioritize critical applications (payment processing, core banking, customer-facing systems)
   - Staged recovery (pilot LPAR first, validate, then production)
   - Validation testing (functional, security, performance)
   - Return to normal operations (enable external access after verification)

**7. Post-Incident Activities**
   - Forensic analysis (root cause determination, attack timeline)
   - Lessons learned meeting (within 7 days)
   - Update defenses (patch systems, tune SIEM alerts, update procedures)
   - NIS2 final report (1-month timeline per Article 23.4)

**8. Communication Plan**
   - Internal: Executive updates (every 4 hours during active incident)
   - External: Customer notification (if personal data breach per GDPR)
   - Regulatory: NIS2 notification (24 hours early warning, 72 hours full report, 1 month final)
   - Media: Public relations (if public disclosure required)

**9. Evidence Collection Checklist**
   - SMF logs (all types, 7 days before incident through resolution)
   - RACF database snapshot (IRRDBU00 backup)
   - APF library backups (before/after comparison)
   - DB2 logs (archive and active logs for roll-forward)
   - Network flow logs (firewall, TN3270 connections)
   - Operator console logs (hardcopy log for manual commands)
   - SIEM event timeline (complete attack timeline)
   - USS filesystem snapshot (for malware analysis)
   - Memory dumps (if ransomware sample needed for analysis)

**Playbook Appendices:**
- Contact lists (internal team, IBM support, vendors, regulators, law enforcement)
- RACF commands quick reference (common emergency commands)
- z/OS recovery procedures (IPL, restore RACF, activate DR)
- NIS2 notification templates (24-hour early warning, 72-hour full report formats)

---

## Next Steps After MRRA

**Immediate Actions (Post-Assessment):**
1. Review MRRA report with executive team (within 1 week)
2. Approve budget for Phase 1 remediation (P0 controls)
3. Assign owners to each control implementation
4. Schedule follow-up meeting with assessment team (knowledge transfer)

**Phase 1: Quick Wins (Month 1-2)** - €50K budget
- Deploy QRadar SIEM integration (€25K)
- Enable comprehensive SMF recording (€0, built-in)
- Implement strong password policy (€0, built-in)
- Remove default accounts (€0, configuration change)
- Document critical gaps (€5K, consultant time)

**Phase 2: Full Compliance (Month 3-6)** - €100K budget
- Deploy IBM MFA for z/OS (€30K)
- Implement File Integrity Monitoring (€30K)
- Configure real-time SMF forwarding (€15K)
- Deploy IBM Guardium for z/OS (€20K)
- DR testing and validation (€5K)

**Phase 3: Continuous Improvement (Month 7-12)** - €50K/year
- Quarterly penetration testing (€20K/yr)
- Annual MRRA re-assessment (€15K)
- Security training refresh (€10K/yr)
- Threat intelligence integration (€5K/yr)

---

## Conclusion

The Mainframe Ransomware Readiness Assessment (MRRA) provides a **workshop-based, interview-driven** evaluation of your IBM Z environment's resilience against ransomware and related cyber threats. By combining STRIDE threat modeling, DREAD risk scoring, and structured interviews with client-run scanner validation, MRRA delivers actionable findings that:

1. **Identify ransomware readiness gaps** through 50 controls across 10 NIST CSF functions
2. **Achieve NIS2 compliance awareness** with clear gap analysis and remediation roadmap
3. **Enable 24/72-hour incident reporting** capability assessment
4. **Validate backup recoverability** understanding through interviews
5. **Empower your team** with detection rule templates and incident response playbooks

**Why Choose MRRA:**
- Workshop-based assessment (no assessor console access required)
- Industry-first mainframe-specific ransomware assessment aligned with NIST CSF
- Real-world breach analysis (ICBC 2023, Equifax 2017, Nordea 2012)
- Interview + document review + scanner output validation
- Delivered in 3 days core engagement + optional executive presentation
- Streamlined coverage: 50 controls across 10 NIST CSF functions
- Clear path to advanced MSMA assessment for deeper technical validation

**Path to Advanced Assessment:**
MRRA identifies gaps → MSMA provides deep-dive technical validation with hands-on testing. See [MSMA-Advanced-Controls.md](MSMA-Advanced-Controls.md) for controls requiring advanced assessment.

**Contact Information:**
[Vito Rallo]
[Email: vito.rallo@kyndryl.com]
[Phone: +1-XXX-XXX-XXXX]

---

**Document Version:** 2.0 (Streamlined Workshop Edition)
**Last Updated:** 2025-01-27
**Classification:** CONFIDENTIAL/INTERNAL

