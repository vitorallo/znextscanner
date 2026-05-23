# MRRA Scanner — Command Quick Reference

All commands executed by the scanner. Every command is **read-only** — none modify
the target system. Commands marked (TSO) run via z/OSMF TSO API or SSH tsocmd.
Commands marked (Console) run via z/OSMF Console API.

## TSO/RACF Commands

| Command | Type | Check(s) | What It Returns |
|---------|------|----------|----------------|
| `LISTUSER *` | TSO | ID-002, IAM-004 | All user profiles with attributes (SPECIAL, OPERATIONS, AUDITOR, PROTECTED, REVOKED) |
| `LISTUSER IBMUSER` | TSO | IAM-003 | IBMUSER profile details (attributes, revoke status, last access) |
| `LISTUSER SYS1` | TSO | IAM-003 | SYS1 profile details |
| `SETROPTS LIST` | TSO | IAM-002, MON-003, SCI-004, EXT-004, EXT-007 to EXT-010, EXT-015, EXT-023, EXT-025 | Password policy, audit, WHEN(PROGRAM), timeout, OPERAUDIT, PROTECTALL, ERASE, LOGOPTIONS, classes, BATCHALLRACF, ICHAUTAB |
| `RLIST STARTED * ALL` | TSO | IAM-005 | Started task profiles with assigned userids and TRUSTED/PRIVILEGED flags |
| `RLIST APPL * ALL` | TSO | EXT-005 | APPL class profiles (application access control) |
| `RLIST CONSOLE * ALL` | TSO | EXT-006 | CONSOLE class profiles (console access control) |
| `RLIST DATASET SYS1.* ALL` | TSO | SCI-001 | Dataset profiles for SYS1 APF libraries (UACC, access lists) |
| `RLIST DATASET SYS1.RACF ALL` | TSO | EXT-024 | RACF database dataset protection (UACC should be NONE) |
| `RLIST DATASET SYS1.RACFB ALL` | TSO | EXT-024 | RACF backup database protection |
| `NETSTAT CONN` | TSO | EXT-001 | Active TCP connections (checks for FTP on port 21) |
| `LISTDS 'SYS1.PARMLIB' LABEL` | TSO | EXT-013 | Dataset label info including SMS DATACLAS (encryption check) |

## MVS Console Commands

| Command | Type | Check(s) | What It Returns |
|---------|------|----------|----------------|
| `D PROG,APF` | Console | ID-003, SCI-001 | APF-authorized library list (entry number, volume, dataset name) |
| `D SMF,O` | Console | MON-001 | SMF recording parameters (active status, TYPE ranges, recording method) |
| `D ICSF` | Console | ENC-002 | ICSF cryptographic services status (active/inactive, FMID/release) |
| `D ICSF,CARDS` | Console | ENC-005 | Crypto hardware card inventory (card type, status, mode) |
| `D TCPIP,,N,CONN` | Console | EXT-014 | TCP/IP stack connection summary (listeners + established) |
| `D SMS,SG(ALL)` | Console | EXT-021 | SMS storage groups — COPY type = FlashCopy/Safeguarded Copy |
| `D A,L` | Console | EXT-021 | Active address spaces — detects DFHSM, CSM, GDPS backup STCs |

## USS Commands (via SSH or z/OSMF USS API)

| Command | Type | Check(s) | What It Returns |
|---------|------|----------|----------------|
| `java -version` | USS | EXT-002 | Java version and vendor (IBM Java detection) |
| `cat /etc/syslog.conf` | USS | EXT-003 | Syslog configuration (remote forwarding check) |
| `netstat -a` | USS | EXT-011 | USS network listeners (open ports inventory) |
| `ps -ef` | USS | EXT-012, EXT-022 | Running processes (flags FTPD, SSHD, httpd, Java, DB2, MQ, DFHSM, CSM, GDPS) |

## Command Availability by Connection Method

| Command | z/OSMF | SSH (tsocmd) | Notes |
|---------|--------|-------------|-------|
| `LISTUSER *` | Yes | Yes | Large output — SSH more reliable |
| `LISTUSER <user>` | Yes | Yes | |
| `SETROPTS LIST` | Yes | Yes | |
| `RLIST STARTED * ALL` | Yes | Yes | Large output |
| `RLIST DATASET SYS1.* ALL` | Yes | Yes | |
| `NETSTAT CONN` | Yes | Yes | |
| `LISTDS ... LABEL` | Yes | Yes | |
| `java -version` | No | Yes (USS) | Requires OMVS segment |
| `cat /etc/syslog.conf` | No | Yes (USS) | Requires OMVS segment |
| `netstat -a` (USS) | No | Yes (USS) | Requires OMVS segment |
| `ps -ef` | No | Yes (USS) | Requires OMVS segment |
| `D SMS,SG(ALL)` | Yes (Console API) | No* | *Requires opercmd or SDSF |
| `D A,L` | Yes (Console API) | No* | *Requires opercmd or SDSF |
| `D PROG,APF` | Yes (Console API) | No* | *Requires opercmd or SDSF |
| `D SMF,O` | Yes (Console API) | No* | *Requires opercmd or SDSF |
| `D ICSF` | Yes (Console API) | No* | *Requires opercmd or SDSF |
| `D ICSF,CARDS` | Yes (Console API) | No* | *Requires opercmd or SDSF |

## z/OS Version Compatibility

| Command | V1R13 | V2.3+ | V3.1 | Notes |
|---------|-------|-------|------|-------|
| `LISTUSER *` | Yes | Yes | Yes | Core RACF command, all versions |
| `LISTUSER <user>` | Yes | Yes | Yes | |
| `SETROPTS LIST` | Yes | Yes | Yes | V3.1 adds IDT/MFA fields |
| `RLIST STARTED * ALL` | Yes | Yes | Yes | |
| `D PROG,APF` | Yes | Yes | Yes | CSV450I format unchanged |
| `D SMF,O` | Yes | Yes | Yes | IEE967I parameter-dump format |
| `D ICSF` | Needs FMID | Yes | Yes | Requires ICSF HCR77B1+ on V1R13 |
| `D ICSF,CARDS` | Needs FMID | Yes | Yes | Requires ICSF HCR77B1+ on V1R13 |

## Commands NOT Used (and why)

| Command | Why Not Used |
|---------|-------------|
| `SEARCH CLASS(USER) SPECIAL` | **Invalid** — SPECIAL is not a SEARCH operand. See `docs/search-special-incident.md` |
| `SEARCH CLASS(USER) OPERATIONS` | **Invalid** — same reason as above |
| `SEARCH CLASS(USER) AUDITOR` | **Invalid** — same reason as above |
| `D ICSF,STATUS` | **Invalid** — not a valid DISPLAY ICSF keyword on any z/OS version |
| `ADDUSER`, `ALTUSER`, `DELUSER` | Scanner is read-only — never modifies users |
| `PERMIT`, `RALTER`, `RDEFINE` | Scanner is read-only — never modifies profiles |
| `SET`, `MODIFY`, `STOP`, `START` | Scanner is read-only — never modifies system state |

## Output Message IDs

| Message ID | Source Command | Meaning |
|-----------|---------------|---------|
| `CSV450I` | `D PROG,APF` | APF library display header |
| `IEE967I` | `D SMF,O` | SMF parameters display |
| `CSFM668I` | `D ICSF` | ICSF LIST response |
| `CSFM680I` | `D ICSF,CARDS` | ICSF CARDS response |
| `IKJ56712I` | Any TSO | Invalid keyword (command syntax error) |
| `IKJ56703A` | Any TSO | Reenter operand prompt |
| `ICH408I` | RACF | Insufficient authority for command |
| `ICH30012I` | LISTUSER | No users listed (empty result) |
| `EZZ2500I` | `D TCPIP` | TCP/IP NETSTAT display header |
| `EZZ2350I` | `NETSTAT CONN` | TSO NETSTAT display header |
| `EZZ2587I` | `NETSTAT CONN` | TSO NETSTAT connection line |
| `IKJ58503I` | `LISTDS` | Dataset not in catalog |

## RACF SEARCH Valid Operands (for reference)

The RACF `SEARCH` command supports only these operands:

```
SEARCH  [CLASS(class-name)]
        [FILTER(filter-string)]
        [MASK(mask)]
        [NOMASK]
        [CLIST('command-prefix')]
        [GENERIC]
        [NOLIST]
```

It does **not** support `SPECIAL`, `OPERATIONS`, `AUDITOR`, or any attribute
filter. To find users by attribute, use `LISTUSER *` and parse the output.
