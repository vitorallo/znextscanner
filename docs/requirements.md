# MRRA Scanner - System and User Requirements

This document describes everything your z/OS system administrator needs to prepare
before running the MRRA Scanner. The scanner is **strictly read-only** — it executes
only display and query commands. It never modifies users, profiles, datasets, or
system settings.

---

## 1. Supported z/OS Versions

| z/OS Version | Support Level | Notes |
|-------------|--------------|-------|
| z/OS V1R13 | Partial | TSO commands via SSH only; z/OSMF Console API not available |
| z/OS V2.3 | Full | z/OSMF Console API available from this version |
| z/OS V2.4 | Full | |
| z/OS V2.5 | Full | |
| z/OS V3.1 | Full | Tested and validated |

---

## 2. Connection Methods

### 2.1 z/OSMF REST API (Default, Recommended)

z/OSMF is the primary and recommended connection method. It provides access to
**TSO and Console checks** using two API endpoints:

- **TSO API** (`/zosmf/tsoApp/tso`) — for RACF query commands (LISTUSER, SETROPTS, RLIST)
- **Console API** (`/zosmf/restconsoles/consoles`) — for MVS display commands (D PROG, D SMF, D ICSF)

| Requirement | Details |
|------------|---------|
| z/OSMF server | Must be running and accessible |
| z/OSMF port | Typically 443 or custom (e.g., 10443) |
| Protocol | HTTPS (TLS) — self-signed certificates are accepted |
| API endpoints needed | `/zosmf/info`, `/zosmf/tsoApp/tso`, `/zosmf/restconsoles/consoles/defcn` |
| z/OSMF version | V2.3+ for full functionality (Console API) |

**Firewall:** The workstation running the scanner must be able to reach the z/OSMF
port over HTTPS. No inbound connections to the workstation are required.

### 2.2 SSH (Alternative)

SSH connects via OpenSSH and executes RACF commands using `tsocmd`. It provides
access to **TSO and USS checks** — but console-based checks (D PROG,APF,
D SMF,O, D ICSF, D SMS) are skipped because MVS operator commands are not
available via SSH. Use `--method hybrid` for full coverage.

| Requirement | Details |
|------------|---------|
| OpenSSH | IBM Ported Tools OpenSSH must be installed on z/OS |
| SSH port | Typically 22 or custom |
| Shell access | User must have a TSO/OMVS login shell |

Use SSH when:
- z/OSMF is not available or not configured
- You need faster scan times (~18s vs ~52s on z/OSMF)
- You are running on z/OS V1R13 where z/OSMF Console API doesn't exist
- You only need TSO-based checks (RACF configuration, no system displays)

### 2.3 Decision Logic

```
Is z/OSMF + SSH both available?
├── YES → Use method: hybrid (recommended — full coverage)
└── Only z/OSMF?
    ├── YES → Use method: zosmf (default — skips USS checks)
    └── Only SSH?
        ├── YES → Use method: ssh (skips console checks)
        └── NO → Scanner cannot connect
```

**Hybrid mode (future):** A planned enhancement will allow `method: zosmf` with
`tso_method: ssh` to use z/OSMF for console commands and SSH for TSO commands,
combining the best of both.

### 2.4 Password Configuration

The scanner needs credentials for the z/OS user ID. Password can be provided via:

1. **Interactive prompt** (recommended): omit `--password`, scanner asks securely
2. **Environment variable** (for automation): `export MRRA_PASSWORD='xxxxx'`
3. **Config file**: `password: xxxxx` in the YAML config (less secure — file on disk)

The password is **never** included in the JSON report, evidence bundle, or logs.

**Important:** If your password contains `!` or other shell special characters,
do NOT pass it via the `--password` CLI flag — bash may silently mangle it via
history expansion. Use the interactive prompt or set `MRRA_PASSWORD` in a script.

---

## 3. User ID Requirements

The scanner needs a z/OS user ID with **READ-ONLY** access to security configuration
data. No SPECIAL, OPERATIONS, or AUDITOR authority is required. The user ID must
**never** have write or alter access to any system resource.

### 3.1 Option A: Use an Existing User ID

Any user ID that can run TSO and has the authorities listed in Section 3.3 below
will work. A system programmer or security administrator's user ID typically has
these authorities already. However, we recommend creating a dedicated scan user
(Option B) for audit trail clarity.

### 3.2 Option B: Create a Dedicated Scan User (Recommended)

Create a minimal user ID dedicated to scanner operations. This provides a clean
audit trail and follows the principle of least privilege.

```
ADDUSER MRRASCN NAME('MRRA SCANNER SERVICE') +
  DFLTGRP(SYS1) +
  PASSWORD(xxxxxxxx) +
  TSO(ACCTNUM(IZUACCT) PROC(IZUFPROC) SIZE(4096)) +
  OMVS(HOME(/tmp) PROGRAM(/bin/sh) UID(nnnnn))
```

Replace `xxxxxxxx` with a strong password and `nnnnn` with an available UID number.
The OMVS segment is needed for SSH access; it is optional for z/OSMF-only mode.

### 3.3 Required Authorities

The scanner user needs the following READ-ONLY authorities. These are all query
commands — none of them modify anything on the system.

#### RACF Authorities

| Authority | Purpose | RACF Command to Grant |
|----------|---------|----------------------|
| LISTUSER | View user profile details (attributes, revoke status) | `PERMIT IRR.RADMIN.LISTUSER CLASS(FACILITY) ID(MRRASCN) ACCESS(READ)` |
| RLIST | View RACF profiles in classes (STARTED, DATASET, CONSOLE, APPL) | `PERMIT IRR.RADMIN.RLIST CLASS(FACILITY) ID(MRRASCN) ACCESS(READ)` |
| SETROPTS LIST | View system-wide RACF options | Granted by default to all TSO users |

**Important:** If your site uses `IRR.RADMIN.*` profiles in the FACILITY class to
control RACF command access, the PERMIT commands above are required. If these
profiles do not exist (common on many systems), the LISTUSER and RLIST commands
are available to any user with RACF READ authority by default.

To check if `IRR.RADMIN.*` profiles exist on your system:

```
RLIST FACILITY IRR.RADMIN.LISTUSER ALL
```

If the profile is not found, no additional PERMIT is needed.

#### MVS Console Command Authority (z/OSMF only)

The scanner issues these display-only MVS console commands through z/OSMF:

| Command | Purpose | What It Shows |
|---------|---------|--------------|
| `D PROG,APF` | APF library inventory | List of APF-authorized libraries |
| `D SMF,O` | SMF recording status | Active SMF recording parameters |
| `D ICSF` | ICSF cryptographic status | Whether ICSF is active, FMID level |
| `D ICSF,CARDS` | Crypto hardware status | Cryptographic card types and status |
| `D TCPIP,,N,CONN` | TCP/IP connections | Network connection baseline |
| `D SMS,SG(ALL)` | Storage groups | COPY-type groups = FlashCopy/Safeguarded Copy |
| `D A,L` | Active address spaces | Detects DFHSM, CSM, GDPS backup automation |

These commands require:

```
PERMIT MVS.MCSOPER.* CLASS(OPERCMDS) ID(MRRASCN) ACCESS(READ)
```

If the OPERCMDS class is not active or MVS.MCSOPER profiles don't exist, console
commands are available by default via z/OSMF.

#### z/OSMF Access

```
CONNECT MRRASCN GROUP(IZUUSER)
```

The IZUUSER group grants basic z/OSMF access. This is sufficient — the scanner does
not need IZUADMIN or any administrative z/OSMF roles.

### 3.4 Authorities NOT Required

| Authority | Why Not Needed |
|----------|---------------|
| SPECIAL | Scanner only reads, never modifies RACF profiles |
| OPERATIONS | Scanner does not access datasets by bypassing security |
| AUDITOR | Scanner reads SETROPTS LIST (available to all users) |
| ALTER/UPDATE to datasets | Scanner never writes to datasets |
| Admin commands (ADDUSER, ALTUSER, PERMIT, RALTER) | Scanner only uses query commands |
| Started task (STC) authority | Scanner runs as a TSO user, not a started task |

---

## 4. Commands Executed by the Scanner

Complete list of every command the scanner executes. All commands are **read-only**.

### TSO/RACF Commands (via z/OSMF TSO API or SSH tsocmd)

| Command | Check(s) | Purpose |
|---------|----------|---------|
| `LISTUSER *` | ID-002, IAM-004 | List all users and their attributes (SPECIAL, OPERATIONS, AUDITOR) |
| `LISTUSER IBMUSER` | IAM-003 | Check if default IBMUSER account is active/revoked/PROTECTED |
| `LISTUSER SYS1` | IAM-003 | Check if default SYS1 account is active/revoked/PROTECTED |
| `SETROPTS LIST` | IAM-002, MON-003, SCI-004, EXT-004, EXT-007 to EXT-010, EXT-015 | Password policy, audit, session timeout, OPERAUDIT, PROTECTALL, ERASE, LOGOPTIONS, active RACF classes |
| `RLIST STARTED * ALL` | IAM-005 | Started task profiles (assigned userids, TRUSTED flag) |
| `RLIST DATASET SYS1.* ALL` | SCI-001 | Dataset profiles for SYS1 APF libraries |
| `RLIST APPL * ALL` | EXT-005 | Application access control profiles |
| `RLIST CONSOLE * ALL` | EXT-006 | Console access control profiles |
| `NETSTAT CONN` | EXT-001 | Active TCP connections (FTP port 21 check) |
| `LISTDS 'SYS1.PARMLIB' LABEL` | EXT-013 | Dataset label with SMS DATACLAS (encryption check) |

### MVS Console Commands (via z/OSMF Console API only)

| Command | Check(s) | Purpose |
|---------|----------|---------|
| `D PROG,APF` | ID-003, SCI-001 | APF-authorized library list |
| `D SMF,O` | MON-001 | SMF recording parameters and active types |
| `D ICSF` | ENC-002 | ICSF status and FMID |
| `D ICSF,CARDS` | ENC-005 | Crypto hardware cards |
| `D TCPIP,,N,CONN` | EXT-014 | TCP/IP connection summary |
| `D SMS,SG(ALL)` | EXT-021 | Storage groups (COPY = FlashCopy/Safeguarded Copy) |
| `D A,L` | EXT-021 | Active address spaces (DFHSM, CSM, GDPS) |

### USS Commands (via SSH only)

| Command | Check(s) | Purpose |
|---------|----------|---------|
| `java -version` | EXT-002 | Java version and vendor |
| `cat /etc/syslog.conf` | EXT-003 | Syslog remote forwarding config |
| `netstat -a` | EXT-011 | Open listening ports inventory |
| `ps -ef` | EXT-012, EXT-022 | Running processes + backup automation (DFHSM, CSM, GDPS) |

### What the Scanner Does NOT Execute

- No `ADDUSER`, `ALTUSER`, `DELUSER`, `CONNECT` — never modifies users
- No `PERMIT`, `RALTER`, `RDEFINE`, `RDELETE` — never modifies profiles
- No `SETROPTS` (without LIST) — never changes system options
- No `SEARCH CLASS(USER) SPECIAL` — this is not a valid RACF command (see note below)
- No dataset writes, JCL submission, or job execution
- No system commands that modify state (`SET`, `MODIFY`, `STOP`, `START`, `CANCEL`)

**Note on SEARCH command:** The RACF `SEARCH` command does not support `SPECIAL`,
`OPERATIONS`, or `AUDITOR` as operands. These are `ADDUSER`/`ALTUSER` operands.
The scanner uses `LISTUSER *` to enumerate all users and parses the `ATTRIBUTES=`
lines to identify privileged users.

---

## 5. Pre-Scan Checklist

### System Configuration

- [ ] z/OSMF server running and accessible (or SSH if using SSH mode)
- [ ] z/OSMF port (e.g., 443 or 10443) open in firewall
- [ ] z/OSMF TSO application enabled (check z/OSMF Installed Plugins)
- [ ] z/OSMF Console task enabled (for MVS display commands)

### User ID Setup

- [ ] Scanner user ID exists (e.g., MRRASCN) or existing user ID identified
- [ ] User has a valid TSO segment (ACCTNUM, PROC, SIZE)
- [ ] User connected to IZUUSER group (z/OSMF access)
- [ ] If IRR.RADMIN.* profiles exist: READ access for LISTUSER, RLIST
- [ ] If MVS.MCSOPER.* profiles exist: READ access in OPERCMDS class
- [ ] User does NOT have SPECIAL, OPERATIONS, or AUDITOR (least privilege)

### Verification Commands

Run these commands as the scanner user to verify access:

```
SETROPTS LIST                        (should display RACF options)
LISTUSER IBMUSER                     (should display IBMUSER profile)
RLIST STARTED * ALL                  (should display started task profiles)
```

If any command returns `ICH408I` (insufficient authority), the corresponding
FACILITY class PERMIT is needed.

### Network Test

From the scanner workstation:

```bash
curl -sk https://<hostname>:<port>/zosmf/info
```

Should return JSON with `zos_version` and `zosmf_hostname`.

---

## 6. Scanner Output

| Output | Description | Contains Sensitive Data? |
|--------|-------------|------------------------|
| `mrra-scan-results.json` | JSON report with check results, findings, and scores | Yes — user IDs, library names |
| `evidence/bundle.zip` | ZIP archive with raw command outputs | Yes — full command output |
| Console log | Structured log of scan execution | No — only check IDs and status |

**Data handling:** The JSON report and evidence bundle contain z/OS security
configuration data (user IDs, APF libraries, RACF settings). Handle according to
your organization's data classification policies. The scanner supports optional
userid redaction (`redact_userids: true` in config) to anonymize user IDs in output.

---

## 7. Quick Reference: Minimal RACF Setup

For a new dedicated scan user on a system with IRR.RADMIN and OPERCMDS protections:

```
/* Create the scanner user */
ADDUSER MRRASCN NAME('MRRA SCANNER SERVICE') +
  DFLTGRP(SYS1) +
  PASSWORD(xxxxxxxx) +
  TSO(ACCTNUM(IZUACCT) PROC(IZUFPROC) SIZE(4096))

/* Grant z/OSMF access */
CONNECT MRRASCN GROUP(IZUUSER)

/* Grant RACF read-only query access (only if IRR.RADMIN profiles exist) */
PERMIT IRR.RADMIN.LISTUSER CLASS(FACILITY) ID(MRRASCN) ACCESS(READ)
PERMIT IRR.RADMIN.RLIST    CLASS(FACILITY) ID(MRRASCN) ACCESS(READ)

/* Grant console command access (only if MVS.MCSOPER profiles exist) */
PERMIT MVS.MCSOPER.* CLASS(OPERCMDS) ID(MRRASCN) ACCESS(READ)

/* Refresh in-memory profiles */
SETROPTS RACLIST(FACILITY) REFRESH
SETROPTS RACLIST(OPERCMDS) REFRESH
```

**Total authority granted:** READ-ONLY access to query RACF profiles and issue
display-only MVS commands. No write, alter, or administrative capability.
