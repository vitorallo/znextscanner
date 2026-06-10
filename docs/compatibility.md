# z/OS Version Compatibility

## Supported Versions

zNextScan supports any z/OS that runs z/OSMF — V1R13 through z/OS 3.1. Parser logic is
data-driven (reacts to what it finds) with no version-specific branching.

**The supercompatibility invariant:** every check either runs (Pass/Partial/Fail) or
degrades to **Skipped with a clear reason** — *never* `Error` — on any supported level over
any connection method. This is enforced by `tests/test_compat_matrix.py` (both profiles ×
9 connection variants, including V1R13-over-z/OSMF, V1R13-over-SSH, z/OSMF-only, empty and
garbage output) and `tests/test_parser_robustness.py` (every parser/check survives empty,
binary, old-RACF-error, truncated and pathological input).

> The per-check `V1R13` column below assumes the **right connection method**: on a true
> V1R13 the z/OSMF **TSO/E REST API does not exist** (it arrived in z/OSMF V2R1) and the
> **Console REST API** arrived in V2.3 — so on V1R13 *all* TSO/console commands must go over
> **SSH** (`tsocmd` / `opercmd`). The scanner detects this at runtime: a missing servlet
> returns HTTP 404 → `CommandNotSupportedError` → Skipped (with the target z/OS level
> appended to the finding when `/zosmf/info` is reachable).

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
| V1R13 | **Not available** (TSO/E REST is z/OSMF V2R1+) | **Not available** (Console REST is V2.3+) | **Required** for all TSO/console commands |
| V2R1–V2R2 | Full | Not available | Required for console commands |
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

## Mythos profile compatibility

The `mythos` profile reuses the MRRA checks above (same compatibility) plus
native checks. Their commands are valid across z/OS V1R13–3.1; availability
depends on connection method, and everything degrades to **Skipped** (never
Error) when unavailable:

| Mythos check | Command(s) | Needs | Degrades when |
|--------------|-----------|-------|---------------|
| MYT-R01 op-code surface | `LISTA STATUS` + `$D PROCLIB` | TSO (+console for PROCLIB) | console absent → SYSEXEC/SYSPROC only |
| MYT-V01 maintenance currency | `D IPLINFO` | console | z/OSMF-only V1R13 → Skipped |
| MYT-X01/X11 backup | `D SMS,SG(ALL)`, `D A,L` | console | console absent → Skipped |
| MYT-R05 API glass-box | `D A,L` + `D TCPIP,,N,CONN` | console | TCPIP enrich optional; D A,L gates |
| MYT-X08 SMF→SIEM | `D SMF,O` | console | recording method absent → Skipped |
| MYT-X10 audit logging | `SETROPTS LIST` + EXT-007/008 | TSO | always available |
| MYT-C10 MFA | `SETROPTS LIST` + `RLIST MFADEF` | TSO | MFADEF undefined → no factors |
| MYT-C12 USS hardening | `find` (perms) | SSH/hybrid (USS) | z/OSMF-only → Skipped |
| MYT-V02 JRE CVEs | java sweep of `/usr/lpp/java/*` | SSH/hybrid (USS) | no java / z/OSMF-only → Skipped |
| MYT-V07 USS/OSS currency | `ssh -V`/`openssl`/`python3`/`zoaversion` | SSH/hybrid (USS) | components absent → omitted |
| MYT-R02 source-exposure recon | external (GitHub/paste) | network + authorization | not authorized → Skipped |
| MYT-R10 dev-plane inventory | `D A,L` + `D TCPIP,,N,CONN` + `RLIST EJBROLE * ALL` | console + TSO | console absent → Skipped; EJBROLE optional |
| MYT-C16 REST API exposure | `D TCPIP,,N,CONN` (+ `D A,L`) | console | no listener → Skipped; TLS/auth → questionnaire |
| MYT-X12 dev-plane logging | `D SMF,O` (type 80/119) | console | recording undetermined → Skipped |

USS-based Mythos checks (V02, V07, C12) require SSH or **hybrid**; under a
z/OSMF-only connection they Skip. The offline CVE map (`znextscan/data/cve_map.json`)
is version-independent and shipped with the package.

## Enrichment policy

A check's **primary** command is never wrapped — if it fails the check degrades
(Skipped/Error) as documented. **Secondary, enrichment** commands (e.g. `$D PROCLIB`
augmenting MYT-R01, `RLIST MFADEF` augmenting MYT-C10) run through `BaseCheck._optional()`,
which returns `""` on any failure so an absent enrichment never changes the check's outcome.

## Production behaviours

- **Per-scan command cache** (`CachingConnection`): identical read-only commands hit z/OS
  once per scan (the dozen `SETROPTS LIST` callers, repeated `D A,L`/`D TCPIP`/`D SMF,O`).
  Failures are never cached, so degradation is unchanged.
- **Transient retry** (`connection.retries`, default 2): timeouts / transport / SSH-session
  errors are retried with backoff; `CommandNotSupportedError` and `PermissionError` are
  never retried.
- **Version annotation**: `/zosmf/info` is read once per scan (best-effort) and surfaced as
  `scan_metadata.zos_version`; it annotates Skips but never pre-filters checks.
- **`host_header`**: override the HTTP Host when connecting by IP behind a VIP/proxy (or the
  Hercules lab where httpx cannot resolve the mDNS `.local` name).

## Fixture provenance

`tests/fixtures/real_zos/` are authentic captures from live z/OS 3.1.
`tests/fixtures/v1r13/` are authored to documented V1R13 output formats (message IDs,
headers and field sets that are stable across the V1R13–3.1 range), except the
version-specific ones — ICSF `NOT ACTIVE`, `IPLINFO` release `01.13.00`, MFADEF
`IKJ56712I`, EJBROLE `ICH13003I NOTHING TO LIST` — which exercise the downlevel paths.
