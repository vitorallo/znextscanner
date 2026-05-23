# Connection Method Comparison

## Side-by-Side Test Results (z/OS 3.1 Hercules Devlab)

Tested all three connection methods against the same z/OS 3.1 system on the same
day with identical credentials. All results are consistent — differences are
explained entirely by which command types each method supports.

### Summary

| Method | Passed | Partial | Failed | Skipped | Errors | Score | Duration |
|--------|--------|---------|--------|---------|--------|-------|----------|
| **Hybrid** | 11 | 8 | 8 | 0 | 0 | **40.7%** | 31s |
| z/OSMF | 8 | 8 | 7 | 4 | 0 | 29.6% | 88s |
| SSH | 7 | 6 | 8 | 6 | 0 | 25.9% | 31s |

**Hybrid is recommended** — it runs all checks with 0 skips by combining
z/OSMF Console API (for MVS display commands) with SSH tsocmd (for RACF and USS
commands).

### Per-Check Comparison

```
Check          z/OSMF      SSH   Hybrid  Name
-----------------------------------------------------------
ID-002           Pass     Pass     Pass  Privileged User Inventory
ID-003           Pass  Skipped     Pass  APF Library Inventory
IAM-002          Pass     Pass     Pass  Strong Password Policy
IAM-003          Fail     Fail     Fail  Default Account Removal
IAM-004          Pass     Pass     Pass  SPECIAL Attribute Restriction
IAM-005          Pass     Pass     Pass  Started Task Security
MON-001          Pass  Skipped     Pass  SMF Recording Status
MON-003          Fail     Fail     Fail  RACF Audit Logging
ENC-002          Pass  Skipped     Pass  ICSF Key Management
ENC-005       Partial  Skipped  Partial  Crypto Hardware Utilization
SCI-001       Partial  Skipped  Partial  APF Library Integrity
SCI-004       Partial  Partial  Partial  Program Control Status
EXT-001          Fail     Fail     Fail  FTP Status
EXT-004       Partial  Partial  Partial  Session Timeout
EXT-005       Partial  Partial  Partial  VTAM Security
EXT-006          Fail     Fail     Fail  Console Security
EXT-007          Fail     Fail     Fail  OPERAUDIT Status
EXT-008          Fail     Fail     Fail  LOGOPTIONS Status
EXT-009          Fail     Fail     Fail  PROTECTALL Status
EXT-010       Partial  Partial  Partial  ERASE Status
EXT-012       Skipped     Pass     Pass  USS Running Processes
EXT-013       Partial  Partial  Partial  Dataset Encryption
EXT-014          Pass  Skipped     Pass  TCP/IP Stack Summary
EXT-015       Partial  Partial  Partial  RACF Class Status
EXT-002       Skipped     Pass     Pass  Java Version
EXT-003       Skipped     Fail     Fail  USS Syslog Config
EXT-011       Skipped     Pass     Pass  USS Network Listeners
```

### Why the Differences

Every difference is explained by the command type each method supports:

| Command Type | z/OSMF | SSH | Hybrid | Checks Affected |
|-------------|--------|-----|--------|-----------------|
| TSO (RACF) | Yes (fresh session per command) | Yes (tsocmd) | SSH | ID-002, IAM-002-005, MON-003, SCI-004, EXT-004-010, EXT-013, EXT-015 |
| Console (MVS) | Yes (Console API) | No (skipped) | z/OSMF | ID-003, MON-001, ENC-002, ENC-005, SCI-001, EXT-014 |
| USS | No (skipped) | Yes (direct SSH) | SSH | EXT-002, EXT-003, EXT-011, EXT-012 |

- **z/OSMF skips 4 USS checks** — it has no USS command execution capability
- **SSH skips 6 Console checks** — MVS operator commands not available via SSH
- **Hybrid skips nothing** — uses z/OSMF for Console, SSH for TSO and USS

### Scoring

Skipped checks are excluded from the score denominator. This means:

- **z/OSMF**: 8 passed out of 23 evaluated = 29.6%
- **SSH**: 7 passed out of 21 evaluated = 25.9%
- **Hybrid**: 11 passed out of 27 evaluated = 40.7%

The devlab's low score is expected — it lacks AUDIT, OPERAUDIT, LOGOPTIONS,
PROTECTALL, CONSOLE profiles, syslog config, and has FTP enabled. These are all
real security findings.

### Performance

| Method | Duration | Why |
|--------|----------|-----|
| z/OSMF | 88s | Fresh TSO session per command (~5s each × 12 TSO checks) + 0.5s delays |
| SSH | 31s | Single SSH connection, tsocmd is fast (~1s per command) |
| Hybrid | 31s | SSH speed for TSO + instant z/OSMF Console responses |

Hybrid achieves full coverage at SSH speed because TSO commands (the slow part
via z/OSMF) are handled by the fast SSH path.

### Recommendation

| Scenario | Recommended Method |
|----------|-------------------|
| Full assessment (best coverage) | `--method hybrid` |
| z/OSMF available, no SSH | `--method zosmf` (default) |
| SSH only, no z/OSMF | `--method ssh` |
| z/OS V1R13 (no z/OSMF Console API) | `--method ssh` |
| Quick test / development | `--mock tests/fixtures` |

### Configuration Examples

```bash
# Hybrid (recommended for assessments)
znextscan scan -m hybrid -H zos.example.com -P 10443 -u MRRASCN

# z/OSMF only (default)
znextscan scan -H zos.example.com -P 10443 -u MRRASCN

# SSH only
znextscan scan -m ssh -H zos.example.com -u MRRASCN
```
