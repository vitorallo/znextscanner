# Connections

## Overview

MRRA Scanner uses a connection abstraction layer (`BaseConnection`) to support
multiple methods of interacting with z/OS. All connections expose three command
methods:

- `execute_tso_command(command)` — RACF commands (LISTUSER, SETROPTS, RLIST)
- `execute_console_command(command)` — MVS display commands (D PROG, D SMF, D ICSF)
- `execute_uss_command(command)` — Unix System Services commands

When a command is not available for a connection method, `CommandNotSupportedError`
is raised and the check returns `Skipped`.

## Connection Method Comparison

| | z/OSMF (default) | SSH | Hybrid | Mock |
|---|---|---|---|---|
| TSO commands | Yes (fresh session per command) | Yes (tsocmd) | SSH | Yes (fixtures) |
| Console commands | Yes (Console API) | No (skipped) | z/OSMF | Yes (fixtures) |
| USS commands | No (skipped) | Yes | SSH | Yes (fixtures) |
| Coverage | TSO + Console | TSO + USS | All | All |
| Speed | ~88s | ~31s | ~31s | <1s |
| Auth | Base64 over HTTPS | Password or SSH key | Both | None |

**Hybrid is recommended** for full coverage. See `docs/connection-comparison.md` for live test results.

## Connection Factory

`znextscan/connections/factory.py` creates the appropriate connection from
config. Used by the CLI — not called directly by checks.

```python
from znextscan.connections.factory import create_connection
conn = create_connection(config.connection)
```

## BaseConnection (ABC)

Defined in `znextscan/connections/base.py`. Supports context manager protocol.
Also defines `CommandNotSupportedError` for version/method compatibility.

## ZOSMFConnection

Defined in `znextscan/connections/zosmf.py`.

**Validated against:** z/OS 3.1 on Hercules, z/OSMF V29.

### Design Decisions

**Fresh TSO session per command:** Each TSO command gets its own session
(start → consume READY → send command → collect output → delete). This avoids
prompt-cycling where the TSO API's prompt-response model splits RACF command
operands across exchanges. The overhead is ~3-5s per command on Hercules.

**Base64 auth header:** The standard HTTP Basic Auth (`-u user:pass`) breaks when
the password contains special characters like `!`. We encode manually with Base64.

**Receive polling auto-detection:** Some z/OSMF implementations (e.g., Hercules)
return 404 on the `/receive` endpoint. The connection auto-detects this and stops
polling, reading output directly from the PUT response instead.

### Console API
- `PUT /restconsoles/consoles/defcn` with `{"cmd": "..."}`
- Returns output immediately in `cmd-response` field
- Works perfectly for D PROG,APF, D SMF,O, D ICSF, D ICSF,CARDS
- Returns 404 if Console API not available (pre-V2.3) → `CommandNotSupportedError`

### TSO API
- Start session: `POST /tsoApp/tso?proc=IZUFPROC&...`
- Send command: `PUT /tsoApp/tso/{key}` with `{"TSO RESPONSE": {"VERSION":"0100","DATA":"..."}}`
- Filters TSO noise: IKJ56455I, IKJ56951I, IKJ56703A, IKJ56712I

### Live Results (z/OS 3.1)
- TSO + Console checks run, USS checks skipped
- Console API: instant response, perfect output
- TSO API: reliable with fresh-session-per-command approach

## SSHConnection

Defined in `znextscan/connections/ssh.py`. Uses Paramiko.

**Validated against:** z/OS 3.1 on Hercules with OpenSSH.

### How It Works
- **TSO commands:** Executes via `tsocmd "COMMAND"` over SSH. Output decoded as UTF-8.
- **Console commands:** Attempts `opercmd "COMMAND"`. If not available, raises
  `CommandNotSupportedError` → check is skipped.
- **USS commands:** Executed directly via SSH shell.

### Live Results (z/OS 3.1)
- TSO + USS checks run, console checks skipped (~31s)
- TSO commands: perfect output (LISTUSER *, SETROPTS LIST, RLIST all work)
- Faster than z/OSMF because no session setup overhead per command

### Known Limitation: tsocmd and SEARCH
The `tsocmd` utility rejects certain RACF SEARCH operands (e.g., `SPECIAL`) as
invalid keywords. This is not a bug — `SPECIAL` is not a valid SEARCH operand.
The scanner uses `LISTUSER *` instead. See `docs/search-special-incident.md`.

## MockConnection

Defined in `znextscan/connections/mock.py`. Maps commands to fixture files
in `tests/fixtures/`. Used for development and testing.

## Command-to-Fixture Mapping

| Command | Fixture File |
|---------|-------------|
| `LISTUSER *` | `LISTUSER-ALL.txt` |
| `LISTUSER IBMUSER` | `IAM-003-LISTUSER-IBMUSER.txt` |
| `LISTUSER SYS1` | `IAM-003-LISTUSER-IBMUSER.txt` |
| `SETROPTS LIST` | `IAM-002-SETROPTS-LIST.txt` |
| `RLIST STARTED * ALL` | `IAM-005-STARTED-TASKS.txt` |
| `RLIST DATASET SYS1` | `SCI-001-APF-PROFILES.txt` |
| `RLIST APPL * ALL` | `EXT-005-RLIST-APPL.txt` |
| `RLIST CONSOLE * ALL` | `EXT-006-RLIST-CONSOLE.txt` |
| `D PROG,APF` | `ID-003-APF-LIST.txt` |
| `D SMF,O` | `MON-001-SMF-STATUS.txt` |
| `D ICSF,CARDS` | `ENC-005-ICSF-CARDS.txt` |
| `D ICSF` | `ENC-002-ICSF-LIST.txt` |
