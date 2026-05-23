# Parsers

## Overview

All parsers live in `znextscan/parsers/racf_parser.py`. They take raw z/OS command output text and return Python dicts/lists. Built and validated against real z/OS 3.1 output from the Hercules devlab.

## Key Design Decisions

### RACF Internal Entries
RACF SEARCH output includes internal certificate entries (`irrcerta`, `irrmulti`, `irrsitec`). These are filtered out by `parse_search_output()` since they're not real user accounts.

### SMF Parameter-Dump Format
On z/OS 3.1, `D SMF,O` returns a parameter-dump format (not a table):
```
SYS(TYPE(0,2:10,14,15,20,22:24,26,30,32:34,40,42,47:48,64,
70:73,74(3:6),75:83,...)) -- PARMLIB
ACTIVE -- PARMLIB
```
The parser handles multi-line TYPE specs, nested parentheses for subtypes like `74(3:6)`, and range notation like `75:83`.

### ICSF Command Differences
On z/OS 3.1:
- `D ICSF` works and returns basic ICSF info (CSFM668I message)
- `D ICSF,STATUS` is NOT a valid command (syntax error)
- `D ICSF,LIST` maps to the same as `D ICSF`

## Parser Functions

`racf_parser.py` provides **23** data-driven parsers (regex-based; missing
fields return `None`/empty so older z/OS degrades gracefully):

| Function | Input command | Returns |
|----------|--------------|---------|
| `parse_search_output` | `SEARCH CLASS(USER) …` | `list[str]` userids (filters irr* internals) |
| `parse_listuser` | `LISTUSER <user>` | `dict` — userid, attributes, revoke, protected |
| `parse_listuser_all` | `LISTUSER *` | `dict` — users grouped by SPECIAL/OPERATIONS/AUDITOR |
| `parse_apf_list` | `D PROG,APF` | `list[dict]` entry/volume/dsname |
| `parse_apf_profiles` | `RLIST DATASET …` | `list[dict]` name/uacc/access_list |
| `parse_setropts_password` | `SETROPTS LIST` | `dict` password policy |
| `parse_setropts_audit` | `SETROPTS LIST` | `dict` audit_active/saudit/logoptions |
| `parse_setropts_extended` | `SETROPTS LIST` | `dict` operaudit/protectall/erase |
| `parse_program_control` | `SETROPTS LIST` | `dict` when_program + PROGRAM-class membership |
| `parse_active_classes` | `SETROPTS LIST` | `list[str]` active RACF classes |
| `parse_rlist_class` | `RLIST <class> * ALL` | `list[dict]` profiles/uacc (APPL, CONSOLE, MFADEF) |
| `parse_smf_status` | `D SMF,O` | `dict` active/type-flags/recording method |
| `parse_icsf_status` | `D ICSF` | `dict` active/fmid |
| `parse_icsf_cards` | `D ICSF,CARDS` | `list[dict]` crypto cards |
| `parse_started_tasks` | `RLIST STARTED * ALL` | `list[dict]` profile/user/trusted |
| `parse_listds_label` | `LISTDS … LABEL` | `dict` DATACLAS / encryption readiness |
| `parse_ikjtso_timeout` | `SETROPTS LIST` | `dict` session timeout |
| `parse_netstat_conn` | `D TCPIP,,N,CONN` / `NETSTAT CONN` | `list[dict]` userid/socket/state/port |
| `parse_sms_storage_groups` | `D SMS,SG(ALL)` | `list[dict]` name/type (COPY = Safeguarded) |
| `parse_active_address_spaces` | `D A,L` | `list[str]` active job names |
| `parse_java_version` | `java -version` | `dict` version/IBM-Java |
| `parse_ps_output` | `ps -ef` | `list[dict]` USS processes |
| `parse_syslog_conf` | `cat /etc/syslog.conf` | `dict` syslog config |

Mythos-native checks add their own light parsing inline in
`znextscan/checks/mythos_checks.py` (JRE sweep, USS component versions, file
permissions, IPLINFO, recon findings), reusing the parsers above where one
exists (`parse_sms_storage_groups`, `parse_netstat_conn`, `parse_smf_status`,
`parse_active_classes`).

## Real z/OS 3.1 Validation

Parsers validated against outputs captured from the Hercules z/OS 3.1 devlab:
- `tests/fixtures/real_zos/console_D_PROG_APF.txt` — 71 APF libraries
- `tests/fixtures/real_zos/console_D_SMF_O.txt` — parameter-dump format
- `tests/fixtures/real_zos/console_D_ICSF.txt` — CSFM668I format
- `tests/fixtures/real_zos/tso_SEARCH_SPECIAL.txt` — 20 SPECIAL users (includes irrcerta etc.)
