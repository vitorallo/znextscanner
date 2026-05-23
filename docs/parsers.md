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

| Function | Input Command | Returns |
|----------|--------------|---------|
| `parse_search_output()` | `SEARCH CLASS(USER) xxx` | `list[str]` — userids |
| `parse_apf_list()` | `D PROG,APF` | `list[dict]` — entry/volume/dsname |
| `parse_setropts_password()` | `SETROPTS LIST` | `dict` — min_length, history, etc. |
| `parse_listuser()` | `LISTUSER xxx` | `dict` — userid, attributes, etc. |
| `parse_smf_status()` | `D SMF,O` | `dict` — active, type flags, recording method |
| `parse_setropts_audit()` | `SETROPTS LIST` | `dict` — audit_active, saudit, logoptions |
| `parse_icsf_status()` | `D ICSF` | `dict` — active, fmid, sysname |
| `parse_started_tasks()` | `RLIST STARTED * ALL` | `list[dict]` — profile/user/trusted |
| `parse_apf_profiles()` | `RLIST DATASET xxx` | `list[dict]` — name/uacc/access_list |
| `parse_program_control()` | `SETROPTS LIST` | `dict` — when_program, program_class_active |
| `parse_setropts_extended()` | `SETROPTS LIST` | `dict` — operaudit, protectall, erase, logoptions |

## Real z/OS 3.1 Validation

Parsers validated against outputs captured from the Hercules z/OS 3.1 devlab:
- `tests/fixtures/real_zos/console_D_PROG_APF.txt` — 71 APF libraries
- `tests/fixtures/real_zos/console_D_SMF_O.txt` — parameter-dump format
- `tests/fixtures/real_zos/console_D_ICSF.txt` — CSFM668I format
- `tests/fixtures/real_zos/tso_SEARCH_SPECIAL.txt` — 20 SPECIAL users (includes irrcerta etc.)
