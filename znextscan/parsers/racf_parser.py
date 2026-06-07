"""Parsers for RACF and z/OS command outputs.

All parsers take raw command output text and return structured dictionaries.
Built against real z/OS 3.1 output formats.
"""

import re
from typing import Any

# RACF internal entries to exclude from user counts
RACF_INTERNAL_ENTRIES = {"irrcerta", "irrmulti", "irrsitec"}


def parse_search_output(output: str) -> list[str]:
    """Parse SEARCH CLASS(USER) NOMASK output into a list of userids.

    Filters out RACF internal certificate entries (irrcerta, irrmulti, irrsitec)
    and blank/header lines.

    Note: SEARCH CLASS(USER) SPECIAL is NOT a valid RACF command.
    The SPECIAL keyword is an operand of ADDUSER/ALTUSER, not SEARCH.
    Use parse_listuser_all() to find users by attribute instead.
    """
    users = []
    for line in output.strip().splitlines():
        userid = line.strip()
        if not userid:
            continue
        if userid.lower() in RACF_INTERNAL_ENTRIES:
            continue
        if userid.upper().startswith(("SEARCH ", "SR ", "LU ", "LISTUSER ")):
            continue
        users.append(userid)
    return users


def parse_listuser_all(output: str) -> dict[str, list[str]]:
    """Parse LISTUSER * output to extract users grouped by attribute.

    LISTUSER * returns all user profiles. We parse USER= lines and
    ATTRIBUTES= lines to categorize users by their system-level attributes.

    Returns dict with keys: special, operations, auditor, revoked, protected
    Each value is a list of userids with that attribute.

    Real z/OS 3.1 output format:
      USER=IBMUSER  NAME=...  OWNER=IBMUSER   CREATED=21.243
       ATTRIBUTES=SPECIAL OPERATIONS
       ATTRIBUTES=NOPASSWORD PASSPHRASE
          CONNECT ATTRIBUTES=NONE
    """
    result: dict[str, list[str]] = {
        "special": [],
        "operations": [],
        "auditor": [],
        "revoked": [],
        "protected": [],
    }

    current_user: str | None = None

    for line in output.splitlines():
        # Match USER=xxx at start of a user profile block
        m = re.match(r"^USER=(\S+)", line)
        if m:
            current_user = m.group(1)
            # Skip RACF internal entries
            if current_user.lower() in RACF_INTERNAL_ENTRIES:
                current_user = None
            continue

        if current_user is None:
            continue

        # Match system-level ATTRIBUTES= line (not CONNECT ATTRIBUTES=)
        stripped = line.strip()
        if stripped.startswith("ATTRIBUTES=") and "CONNECT" not in line:
            attrs = stripped[len("ATTRIBUTES=") :].split()
            for attr in attrs:
                attr_upper = attr.upper()
                if attr_upper == "SPECIAL" and current_user not in result["special"]:
                    result["special"].append(current_user)
                elif attr_upper == "OPERATIONS" and current_user not in result["operations"]:
                    result["operations"].append(current_user)
                elif attr_upper == "AUDITOR" and current_user not in result["auditor"]:
                    result["auditor"].append(current_user)
                elif attr_upper == "REVOKED" and current_user not in result["revoked"]:
                    result["revoked"].append(current_user)
                elif attr_upper == "PROTECTED" and current_user not in result["protected"]:
                    result["protected"].append(current_user)

    return result


def parse_apf_list(output: str) -> list[dict[str, str]]:
    """Parse D PROG,APF output into a list of APF library entries.

    Each entry has: entry_num, volume, dsname
    Real z/OS 3.1 format:
      CSV450I HH.MM.SS PROG,APF DISPLAY NNN
      FORMAT=DYNAMIC
      ENTRY VOLUME DSNAME
         1  Z31VS1 SYS1.LINKLIB
    """
    libraries = []
    for line in output.strip().splitlines():
        line = line.strip()
        # Match lines like: 1  Z31VS1 SYS1.LINKLIB  or  50  *SMS*  IRLM.SDXRRESL
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+(\S+)$", line)
        if match:
            libraries.append(
                {
                    "entry": match.group(1),
                    "volume": match.group(2),
                    "dsname": match.group(3),
                }
            )
    return libraries


def parse_setropts_password(output: str) -> dict[str, Any]:
    """Parse SETROPTS LIST output for password policy settings.

    Extracts: min_length, max_length, history, revoke_count, change_interval,
    mixed_case, encryption_algorithm, inactive_revoke_days.
    """
    config: dict[str, Any] = {}

    # Password minimum length
    m = re.search(r"PASSWORD MINIMUM LENGTH IS (\d+)", output, re.IGNORECASE)
    config["min_length"] = int(m.group(1)) if m else None

    # Password maximum length
    m = re.search(r"PASSWORD MAXIMUM LENGTH IS (\d+)", output, re.IGNORECASE)
    config["max_length"] = int(m.group(1)) if m else None

    # Password history generations
    m = re.search(r"PASSWORD HISTORY GENERATIONS IS (\d+)", output, re.IGNORECASE)
    config["history"] = int(m.group(1)) if m else None

    # Password revoke count
    m = re.search(r"PASSWORD REVOKE COUNT IS (\d+)", output, re.IGNORECASE)
    config["revoke_count"] = int(m.group(1)) if m else None

    # Password change interval
    m = re.search(r"PASSWORD CHANGE INTERVAL IS (\d+)", output, re.IGNORECASE)
    config["change_interval"] = int(m.group(1)) if m else None

    # Mixed case support
    config["mixed_case"] = bool(
        re.search(r"MIXED CASE PASSWORD SUPPORT IS IN EFFECT", output, re.IGNORECASE)
    )

    # Encryption algorithm
    m = re.search(r"ACTIVE PASSWORD ENCRYPTION ALGORITHM IS (\S+)", output, re.IGNORECASE)
    config["encryption_algorithm"] = m.group(1) if m else None

    # Inactive userid revoke
    m = re.search(
        r"INACTIVE USERIDS ARE BEING AUTOMATICALLY REVOKED AFTER (\d+) DAYS",
        output,
        re.IGNORECASE,
    )
    config["inactive_revoke_days"] = int(m.group(1)) if m else None

    return config


def parse_listuser(output: str) -> dict[str, Any]:
    """Parse LISTUSER output for a single user.

    Extracts: userid, name, owner, attributes, revoke_date, last_access,
    default_group, passdate, protected status.
    """
    user: dict[str, Any] = {}

    # USER=xxx  NAME=xxx
    m = re.search(r"USER=(\S+)\s+NAME=(.+?)\s{2,}", output)
    if m:
        user["userid"] = m.group(1)
        user["name"] = m.group(2).strip()

    # OWNER=xxx
    m = re.search(r"OWNER=(\S+)", output)
    if m:
        user["owner"] = m.group(1)

    # DEFAULT-GROUP=xxx
    m = re.search(r"DEFAULT-GROUP=(\S+)", output)
    if m:
        user["default_group"] = m.group(1)

    # ATTRIBUTES=xxx
    m = re.search(r"ATTRIBUTES=(.+?)$", output, re.MULTILINE)
    if m:
        attrs_str = m.group(1).strip()
        user["attributes"] = attrs_str.split() if attrs_str != "NONE" else []

    # REVOKE DATE=xxx
    m = re.search(r"REVOKE DATE=(\S+)", output)
    if m:
        user["revoke_date"] = m.group(1)

    # LAST-ACCESS=xxx
    m = re.search(r"LAST-ACCESS=(\S+)", output)
    if m:
        user["last_access"] = m.group(1)

    # PASSDATE=xxx
    m = re.search(r"PASSDATE=(\S+)", output)
    if m:
        user["passdate"] = m.group(1)

    # PROTECTED status (in attributes)
    user["protected"] = "PROTECTED" in (user.get("attributes") or [])

    return user


def parse_smf_status(output: str) -> dict[str, Any]:
    """Parse D SMF,O output for SMF recording status.

    Real z/OS 3.1 format is a parameter dump with keywords like:
      ACTIVE -- PARMLIB
      SYS(TYPE(0,2:10,...,75:83,...)) -- PARMLIB
      SUBSYS(STC,TYPE(...)) -- SYS
      REC(PERM) -- PARMLIB
      RECORDING(LOGSTREAM) -- PARMLIB
    """
    config: dict[str, Any] = {}

    # Check if SMF is active
    config["active"] = bool(re.search(r"^\s+ACTIVE\b", output, re.MULTILINE))

    # Extract SYS TYPE ranges to determine which SMF record types are being collected
    type_ranges = _extract_type_spec(output, "SYS(TYPE(")
    # Also merge SUBSYS types
    type_ranges.extend(_extract_type_spec(output, "SUBSYS(STC,TYPE("))

    # Expand type ranges to check for critical types
    recorded_types = _expand_smf_types(type_ranges)
    config["recorded_types"] = sorted(recorded_types)

    # Check for critical SMF types
    config["has_type_30"] = 30 in recorded_types
    config["has_type_80"] = 80 in recorded_types
    config["has_type_83"] = 83 in recorded_types

    # Recording method
    rec_match = re.search(r"RECORDING\((\w+)\)", output, re.IGNORECASE)
    config["recording_method"] = rec_match.group(1) if rec_match else None

    # SMF parmlib member
    member_match = re.search(r"MEMBER\s*=\s*(\S+)", output, re.IGNORECASE)
    config["parmlib_member"] = member_match.group(1) if member_match else None

    # Interval
    intval_match = re.search(r"INTVAL\((\d+)\)", output, re.IGNORECASE)
    config["interval_minutes"] = int(intval_match.group(1)) if intval_match else None

    return config


def _extract_type_spec(output: str, prefix: str) -> list[str]:
    """Extract a TYPE(...) specification from SMF output, handling multi-line and nested parens.

    Finds `prefix` (e.g., 'SYS(TYPE(') in the output and collects everything
    until the matching closing parentheses, across multiple lines.
    """
    upper = output.upper()
    idx = upper.find(prefix.upper())
    if idx == -1:
        return []

    # Start after the prefix
    start = idx + len(prefix)
    depth = 1  # We're inside the TYPE( paren
    pos = start
    while pos < len(output) and depth > 0:
        ch = output[pos]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        pos += 1

    type_str = output[start : pos - 1]
    # Clean up: remove source annotations (-- PARMLIB, -- SYS), whitespace
    type_str = re.sub(r"\s*--\s*\w+", "", type_str)
    type_str = re.sub(r"\s+", "", type_str)
    return [t.strip() for t in type_str.split(",") if t.strip()]


def _expand_smf_types(type_ranges: list[str]) -> set[int]:
    """Expand SMF type range notation into individual type numbers.

    Handles: single numbers (30), ranges (75:83), subtypes (74(3:6))
    """
    types: set[int] = set()
    for item in type_ranges:
        # Remove subtype specs like 74(3:6)
        base = re.sub(r"\(.*\)", "", item)
        if ":" in base:
            parts = base.split(":")
            try:
                start, end = int(parts[0]), int(parts[1])
                types.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                types.add(int(base))
            except ValueError:
                pass
    return types


def parse_setropts_audit(output: str) -> dict[str, Any]:
    """Parse SETROPTS LIST output for audit settings.

    Extracts: audit_active, saudit, logoptions, cmdviol.
    """
    config: dict[str, Any] = {}

    config["audit_active"] = bool(
        re.search(r"AUDIT PROCESSING IS IN EFFECT", output, re.IGNORECASE)
    )
    config["saudit"] = bool(re.search(r"SAUDIT IS IN EFFECT", output, re.IGNORECASE))
    config["cmdviol"] = bool(re.search(r"CMDVIOL IS BEING LOGGED", output, re.IGNORECASE))

    # LOGOPTIONS
    config["log_logon_failures"] = bool(
        re.search(r"FAILURES\(LOGON\) ARE BEING LOGGED", output, re.IGNORECASE)
    )
    config["log_logon_successes"] = bool(
        re.search(r"SUCCESSES\(LOGON\) ARE BEING LOGGED", output, re.IGNORECASE)
    )

    return config


def parse_icsf_status(output: str) -> dict[str, Any]:
    """Parse D ICSF output for ICSF availability.

    Real z/OS 3.1 format (D ICSF):
      CSFM668I HH.MM.SS ICSF LIST NNN
        Systems supporting SETICSF and DISPLAY ICSF commands:
          SYSNAME   RELEASE  DOM  CHG_DATE
          VS01      HCR77E0  N/A  01/29/24

    If ICSF is not started, the response may be:
      IEE341I ... ICSF ... NOT ACTIVE
    """
    config: dict[str, Any] = {}

    # Check if ICSF is responding (CSFM668I = ICSF LIST response)
    config["active"] = bool(re.search(r"CSFM668I", output))

    # Also check for explicit NOT ACTIVE
    if re.search(r"NOT ACTIVE|NOT FOUND|UNKNOWN", output, re.IGNORECASE):
        config["active"] = False

    # Extract release/FMID
    m = re.search(r"\b(HCR\w+)\b", output)
    config["fmid"] = m.group(1) if m else None

    # Extract system name
    lines = output.strip().splitlines()
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[1].startswith("HCR"):
            config["sysname"] = parts[0]
            break

    return config


def parse_icsf_cards(output: str) -> dict[str, Any]:
    """Parse D ICSF,CARDS output for crypto hardware information.

    Valid on all z/OS versions (2.3+). Example output:
      CSFM680I HH.MM.SS ICSF CARDS NNN
        CARD  TYPE    STATUS   SPEED  MODE     DOMAIN
        00    CEX8S   ONLINE   ...    ACCEL    00
        01    CEX8S   ONLINE   ...    CCA      01

    If ICSF is not active, returns active=False.
    If no crypto cards, returns empty cards list.
    """
    config: dict[str, Any] = {}

    # Check if ICSF responded (CSFM message prefix)
    config["active"] = bool(re.search(r"CSFM\d+I", output))

    if re.search(r"NOT ACTIVE|NOT FOUND|UNKNOWN|ASA101I", output, re.IGNORECASE):
        config["active"] = False
        config["cards"] = []
        return config

    # Extract FMID if present
    m = re.search(r"\b(HCR\w+)\b", output)
    config["fmid"] = m.group(1) if m else None

    # Parse crypto card lines
    cards: list[dict[str, str]] = []
    for line in output.splitlines():
        # Match lines like: 00    CEX8S   ONLINE   ...    ACCEL    00
        m = re.match(
            r"\s*(\d{2})\s+(CEX\w+)\s+(ONLINE|OFFLINE|DECONFIG)\s+\S*\s*(\w+)",
            line,
        )
        if m:
            cards.append(
                {
                    "id": m.group(1),
                    "type": m.group(2),
                    "status": m.group(3),
                    "mode": m.group(4),
                }
            )

    config["cards"] = cards
    return config


def parse_started_tasks(output: str) -> list[dict[str, Any]]:
    """Parse RLIST STARTED * ALL output for started task profiles.

    Format:
    STARTED    OMVS.*                  NONE               NO
      STDATA INFORMATION
      ------------------
        USER=OMVSKERN  GROUP=OMVSGRP  TRUSTED=YES  PRIVILEGED=NO  TRACE=NO
    """
    tasks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for line in output.splitlines():
        # Match started task profile line
        m = re.match(r"^STARTED\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if m:
            current = {
                "profile": m.group(1),
                "uacc": m.group(2),
                "warning": m.group(3),
            }
            tasks.append(current)
            continue

        # Match STDATA user/group/trusted line
        if current and "USER=" in line:
            for field in ["USER", "GROUP", "TRUSTED", "PRIVILEGED", "TRACE"]:
                fm = re.search(rf"{field}=(\S+)", line)
                if fm:
                    val = fm.group(1)
                    current[field.lower()] = (
                        val == "YES" if field in ("TRUSTED", "PRIVILEGED", "TRACE") else val
                    )

    return tasks


def parse_apf_profiles(output: str) -> list[dict[str, Any]]:
    """Parse RLIST DATASET output for APF library RACF profiles.

    Extracts: profile_name, uacc, access_list entries.
    """
    profiles: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_access_list = False

    for line in output.splitlines():
        # Match profile header
        m = re.match(r"^DATASET\s+(\S+)\s+(\S+)\s+(\S+)", line)
        if m:
            current = {
                "name": m.group(1),
                "uacc": m.group(2),
                "warning": m.group(3),
                "access_list": [],
            }
            profiles.append(current)
            in_access_list = False
            continue

        if current:
            if "ACCESS LIST" in line:
                in_access_list = True
                continue
            if in_access_list:
                m = re.match(r"^\s+(\S+)\s+(ALTER|CONTROL|UPDATE|READ|NONE|EXECUTE)", line)
                if m:
                    current["access_list"].append(
                        {
                            "userid": m.group(1),
                            "access": m.group(2),
                        }
                    )
                elif line.strip().startswith("---"):
                    continue
                elif line.strip() == "":
                    in_access_list = False

    return profiles


def parse_program_control(output: str) -> dict[str, Any]:
    """Parse SETROPTS LIST for WHEN(PROGRAM) and PROGRAM class status."""
    config: dict[str, Any] = {}

    config["when_program"] = bool(
        re.search(r"WHEN\(PROGRAM\)\s+IS IN EFFECT", output, re.IGNORECASE)
    )

    # PROGRAM must be a member of the ACTIVE CLASSES list — not merely present
    # somewhere in the output (e.g. the "NOWHEN(PROGRAM)" attribute).
    active = {c.upper() for c in parse_active_classes(output)}
    config["program_class_active"] = "PROGRAM" in active

    return config


def parse_setropts_extended(output: str) -> dict[str, Any]:
    """Parse extended SETROPTS settings (EXT-007 to EXT-010)."""
    config: dict[str, Any] = {}

    config["operaudit"] = bool(re.search(r"OPERAUDIT IS IN EFFECT", output, re.IGNORECASE))
    config["protectall"] = bool(re.search(r"PROTECTALL IS IN EFFECT", output, re.IGNORECASE))
    config["erase"] = bool(
        re.search(r"ERASE-ON-SCRATCH.*IS IN EFFECT", output, re.IGNORECASE)
        or re.search(r"ERASE.*BY SECURITY LEVEL.*IS IN EFFECT", output, re.IGNORECASE)
    )
    config["log_failures"] = bool(re.search(r"FAILURES\(LOGON\).*LOGGED", output, re.IGNORECASE))
    config["log_successes"] = bool(re.search(r"SUCCESSES\(LOGON\).*LOGGED", output, re.IGNORECASE))

    # BATCHALLRACF — batch jobs must go through RACF auth
    config["batchallracf"] = bool(re.search(r"BATCHALLRACF", output, re.IGNORECASE))

    return config


def parse_rlist_class(output: str, class_name: str) -> list[dict[str, Any]]:
    """Parse RLIST output for a generic RACF class (APPL, CONSOLE, etc.).

    Returns a list of profiles with name, uacc, and warning fields.

    Format:
      APPL       OMVSAPPL (G)
      LEVEL  OWNER      UNIVERSAL ACCESS  YOUR ACCESS  WARNING
      -----  --------   ----------------  -----------  -------
       00    IBMUSER    NONE              READ         NO
    """
    profiles: list[dict[str, Any]] = []

    for line in output.splitlines():
        m = re.match(rf"^{class_name}\s+(\S+)", line)
        if m:
            profiles.append(
                {
                    "name": m.group(1),
                    "generic": "(G)" in line,
                    "uacc": None,
                }
            )
            continue

        if profiles and line.strip() and re.match(r"^\s+\d{2}\s+", line):
            parts = line.split()
            if len(parts) >= 3:
                profiles[-1]["uacc"] = parts[2]

    return profiles


_ACCESS_LEVELS = ("NONE", "EXECUTE", "READ", "UPDATE", "CONTROL", "ALTER")
_ACCESS_RE = re.compile(r"^\s*(\S+)\s+(" + "|".join(_ACCESS_LEVELS) + r")\b")


def parse_general_resource_access(output: str, class_name: str) -> list[dict[str, Any]]:
    """Parse ``RLIST <class> * ALL`` output into profiles with their access lists.

    Handles RACF general-resource classes (EJBROLE, ZMFAPLA, …). Each profile
    block begins with a ``<class> <profile>`` line; the standard-access list
    follows a ``USER      ACCESS`` column header and ends at the next blank line
    or profile. Used by MYT-R10 to inventory the z/OSMF developer-plane roles
    (IZUUSER/IZUADMIN/IZUSECADMIN) and how many identities hold each.

    Returns a list of ``{"name", "generic", "access_list": [{"id", "access"}]}``.
    """
    profiles: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_access = False

    for line in output.splitlines():
        m = re.match(rf"^{re.escape(class_name)}\s+(\S+)", line)
        if m:
            current = {"name": m.group(1), "generic": "(G)" in line, "access_list": []}
            profiles.append(current)
            in_access = False
            continue
        if current is None:
            continue
        if re.match(r"^\s*USER\s+ACCESS\b", line, re.IGNORECASE):
            in_access = True
            continue
        if in_access:
            if not line.strip():
                in_access = False
                continue
            am = _ACCESS_RE.match(line)
            if am and am.group(1) != "----":
                current["access_list"].append({"id": am.group(1), "access": am.group(2)})

    return profiles


def parse_netstat_conn(output: str) -> list[dict[str, str]]:
    """Parse NETSTAT CONN or USS netstat output for TCP connections.

    z/OS netstat uses .. as port separator (e.g., 0.0.0.0..21).
    """
    connections: list[dict[str, str]] = []
    for line in output.splitlines():
        m = re.match(
            r"(?:EZZ2587I\s+)?(\S+)\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)",
            line.strip(),
        )
        if m and m.group(4).upper() in (
            "LISTEN",
            "ESTABLSH",
            "ESTBLSH",
            "CLOSWAIT",
            "TIMEWAIT",
        ):
            local = m.group(2)
            port_match = re.search(r"\.\.(\d+)$", local)
            port = int(port_match.group(1)) if port_match else 0
            connections.append(
                {
                    "userid": m.group(1),
                    "local_socket": local,
                    "foreign_socket": m.group(3),
                    "state": m.group(4),
                    "port": str(port),
                }
            )
    return connections


def parse_java_version(output: str) -> dict[str, Any]:
    """Parse java -version output."""
    result: dict[str, Any] = {"installed": False, "version": None, "ibm_java": False}
    if "not found" in output.lower() or not output.strip():
        return result
    m = re.search(r'java version "([^"]+)"', output)
    if m:
        result["installed"] = True
        result["version"] = m.group(1)
    result["ibm_java"] = "IBM" in output or "J9 VM" in output
    return result


def parse_syslog_conf(output: str) -> dict[str, Any]:
    """Parse /etc/syslog.conf for remote log forwarding."""
    result: dict[str, Any] = {"exists": True, "remote_destinations": [], "line_count": 0}
    if "No such file" in output or "not found" in output.lower() or not output.strip():
        result["exists"] = False
        return result
    lines = [l for l in output.strip().splitlines() if l.strip() and not l.startswith("#")]
    result["line_count"] = len(lines)
    for line in lines:
        m = re.search(r"@(\S+)", line)
        if m:
            result["remote_destinations"].append(m.group(1))
    return result


def parse_ikjtso_timeout(output: str) -> dict[str, Any]:
    """Parse IKJTSOxx parmlib member for session timeout (TIME/RECONLIM)."""
    result: dict[str, Any] = {"timeout_minutes": None, "configured": False}
    m = re.search(r"TIME\((\d+)\)", output, re.IGNORECASE)
    if m:
        result["timeout_minutes"] = int(m.group(1))
        result["configured"] = True
    m = re.search(r"RECONLIM\((\d+)\)", output, re.IGNORECASE)
    if m:
        result["timeout_minutes"] = int(m.group(1))
        result["configured"] = True
    return result


def parse_ps_output(output: str) -> list[dict[str, str]]:
    """Parse USS ps -ef output into process list.

    Returns list of {uid, pid, cmd} dicts.
    """
    processes: list[dict[str, str]] = []
    for line in output.splitlines():
        # Skip header
        if "UID" in line and "PID" in line and "CMD" in line:
            continue
        parts = line.split()
        if len(parts) >= 8:
            processes.append(
                {
                    "uid": parts[0],
                    "pid": parts[1],
                    "cmd": parts[7],
                }
            )
    return processes


# Known services to flag in process listing
NOTABLE_PROCESSES = {
    "FTPD": "FTP daemon",
    "httpd": "Apache HTTP server",
    "java": "Java process",
    "node": "Node.js",
    "CSQXJST": "MQ (WebSphere MQ)",
    "DB2SSU00": "DB2",
    "DFSHSM": "HSM (storage management)",
    "SSHD": "SSH daemon",
    "sshd:": "SSH session",
}


def parse_listds_label(output: str) -> dict[str, Any]:
    """Parse LISTDS output with LABEL info for encryption check.

    Looks for DATACLAS and encryption-related keywords.
    """
    result: dict[str, Any] = {
        "dsname": None,
        "dataclas": None,
        "mgmtclas": None,
        "storclas": None,
        "encrypted": False,
    }

    lines = output.strip().splitlines()
    if not lines:
        return result

    # First non-empty line is typically the dataset name
    result["dsname"] = lines[0].strip()

    for line in lines:
        # Parse DATACLAS--MGMTCLAS--STORCLAS line values
        if "DATACLAS" in line and "MGMTCLAS" in line:
            continue  # header line
        parts = line.split()
        if len(parts) == 3 and not line.startswith("--"):
            # Could be the values line under DATACLAS/MGMTCLAS/STORCLAS
            result["dataclas"] = parts[0] if parts[0] != "NONE" else None
            result["mgmtclas"] = parts[1] if parts[1] != "NONE" else None
            result["storclas"] = parts[2] if parts[2] != "NONE" else None

    # Check if dataclas suggests encryption
    dc = (result.get("dataclas") or "").upper()
    if any(kw in dc for kw in ("ENCRYPT", "CRYPT", "ENC")):
        result["encrypted"] = True

    return result


def parse_active_classes(output: str) -> list[str]:
    """Extract ACTIVE CLASSES list from SETROPTS LIST output."""
    classes: list[str] = []
    in_section = False
    for line in output.splitlines():
        upper = line.upper().strip()
        if "ACTIVE CLASSES" in upper:
            # May have classes on the same line after "="
            if "=" in upper:
                after_eq = upper.split("=", 1)[1].strip()
                classes.extend(after_eq.split())
            in_section = True
            continue
        if in_section:
            # Classes are indented continuation lines
            if line.startswith(" ") and line.strip():
                classes.extend(line.split())
            else:
                break
    return classes


def parse_sms_storage_groups(output: str) -> list[dict[str, Any]]:
    """Parse D SMS,SG(ALL) output for storage group inventory.

    Extracts storage group name, type (POOL, COPY, VIO, DUMMY), and space info.
    COPY type groups indicate FlashCopy/Safeguarded Copy infrastructure.
    """
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for line in output.splitlines():
        # Match: STORGRP  TYPE    SYSTEM= 1
        # Next line: SGBASE   POOL
        parts = line.split()
        if len(parts) >= 2 and parts[1] in ("POOL", "COPY", "VIO", "DUMMY"):
            current = {"name": parts[0], "type": parts[1]}
            groups.append(current)
        elif current and "TOTAL SPACE" in line:
            m = re.search(r"TOTAL SPACE\s*=\s*(\d+)MB", line)
            if m:
                current["total_mb"] = int(m.group(1))
            m = re.search(r"USAGE%\s*=\s*(\d+)", line)
            if m:
                current["usage_pct"] = int(m.group(1))

    return groups


def parse_active_address_spaces(output: str) -> list[str]:
    """Parse D A,L output to extract active address space names.

    Returns a flat list of address space names (STC names).
    """
    names: list[str] = []
    for line in output.splitlines():
        # Skip header lines
        if any(kw in line for kw in ("DISPLAY ACTIVITY", "JOBS", "M/S", "TS USERS")):
            continue
        # Address spaces appear as columns of name triples: NAME PROC_NAME STEP NSW S
        tokens = line.split()
        # Each entry is roughly: NAME NAME PROC STATE FLAG [NAME NAME PROC STATE FLAG ...]
        for token in tokens:
            # Valid STC names are 1-8 uppercase alphanumeric
            if (
                token.isalnum()
                and token == token.upper()
                and len(token) <= 8
                and token not in ("NSW", "OWT", "IN", "OUT", "S", "SO", "AO", "STEP1")
            ):
                if token not in names:
                    names.append(token)

    return names


# Known backup/recovery related address space names
BACKUP_ADDRESS_SPACES = {
    "DFHSM": "DFSMShsm — Hierarchical Storage Manager (automated backup/migration)",
    "HSM": "DFSMShsm (alternate name)",
    "CSM": "Copy Services Manager (FlashCopy/Safeguarded Copy orchestration)",
    "GDPS": "Geographically Dispersed Parallel Sysplex (disaster recovery)",
    "ANTMAIN": "Advanced Copy Services (FlashCopy/XRC management)",
    "ADRDSSU": "DFSMSdss (data set services — dump/restore)",
    "OAM": "Object Access Method (optical/tape archive)",
}
