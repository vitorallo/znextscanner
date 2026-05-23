# z/OS Version Compatibility

## Supported Versions

MRRA Scanner supports z/OS V1R13 through z/OS 3.1. Parser logic is data-driven (reacts to what it finds) with no version-specific branching.

## Per-Check Compatibility Matrix

| Control | Name | Command Type | V1R13 | V2.3+ | V3.1 | Notes |
|---------|------|-------------|-------|-------|------|-------|
| ID-002 | Privileged Users | TSO | Yes | Yes | Yes | |
| ID-003 | APF Libraries | Console | SSH only | Yes | Yes | Console API requires z/OSMF V2.3+ |
| IAM-002 | Password Policy | TSO | Yes | Yes | Yes | MASKED algorithm on V1R13 |
| IAM-003 | Default Accounts | TSO | Yes | Yes | Yes | |
| IAM-004 | SPECIAL Count | TSO | Yes | Yes | Yes | |
| IAM-005 | Started Tasks | TSO | Yes | Yes | Yes | |
| ENC-002 | ICSF Key Mgmt | Console | SSH only* | Yes | Yes | *Also requires ICSF FMID |
| ENC-005 | Crypto Hardware | Console | SSH only* | Yes | Yes | *Also requires ICSF FMID |
| MON-001 | SMF Recording | Console | SSH only | Yes | Yes | Console API requires z/OSMF V2.3+ |
| MON-003 | RACF Audit | TSO | Yes | Yes | Yes | |
| SCI-001 | APF Integrity | Console+TSO | SSH only | Yes | Yes | Console part needs SSH on V1R13 |
| SCI-004 | Program Control | TSO | Yes | Yes | Yes | |
| EXT-021 | Backup Storage | Console | SSH only | Yes | Yes | D SMS,SG available since z/OS 1.4 |
| EXT-022 | Backup Processes | USS | Yes | Yes | Yes | ps -ef via SSH |

## Connection Requirements by Version

| z/OS Version | z/OSMF TSO API | z/OSMF Console API | SSH Fallback |
|-------------|---------------|-------------------|-------------|
| V1R13 | Limited | Not available | Required for console commands |
| V2.3+ | Full | Full | Optional fallback |
| V3.1 | Full | Full | Optional fallback |

## Known Version Differences

### Password Encryption Algorithm
- **V1R13:** `MASKED` or `DES` — finding notes upgrade to KDFAES requires z/OS 2.3+
- **V2.3+:** `KDFAES` or `PHASH` — best practice
- Parser extracts whatever algorithm is present; evaluator categorizes into tiers

### ICSF Availability
- **V1R13 base:** D ICSF console commands NOT available without ICSF FMID HCR77B1
- **V2.3+:** D ICSF, D ICSF,CARDS available when ICSF is active
- **All versions:** `D ICSF,STATUS` is NOT a valid command (never was)
- Checks return `Skipped` when ICSF is not active

### SETROPTS LIST Output
- **V1R13:** No PassPhrase section, no IDT options, no MFA fields
- **V3.1:** Adds PassPhrase intervals, Identity Token, MFA settings
- Parser uses regex `re.search` — gracefully returns `None` for missing fields

### D SMF,O Output
- **All versions:** Same `IEE967I` parameter-dump format with `-- DEFAULT/PARMLIB/SYS` suffixes
- **V1R13:** May not have `RECORDING(LOGSTREAM)` — parser handles `None`
- **All versions:** TYPE ranges use same `start:end` notation (e.g., `75:83`)

### RACF Internal Entries
- `irrcerta`, `irrmulti`, `irrsitec` — present on all versions since z/OS 1.4
- Always filtered from SEARCH output by parser

### D PROG,APF
- `CSV450I` format unchanged across all versions

## Graceful Degradation

When a command is not available (e.g., Console API on V1R13 without SSH):
- Connection raises `CommandNotSupportedError`
- Check returns `CheckStatus.SKIPPED` with descriptive finding
- Scan continues with remaining checks
- Results clearly indicate which checks were skipped and why
