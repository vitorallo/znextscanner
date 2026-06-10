"""Extended checks: EXT-001 to EXT-025."""

from typing import Any

from znextscan.checks._patterns import (
    RlistUaccCheck,
    SetroptsFlagCheck,
    join_sections,
    split_sections,
)
from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.parsers.racf_parser import (
    BACKUP_ADDRESS_SPACES,
    NOTABLE_PROCESSES,
    parse_active_address_spaces,
    parse_active_classes,
    parse_apf_profiles,
    parse_ikjtso_timeout,
    parse_java_version,
    parse_listds_label,
    parse_netstat_conn,
    parse_ps_output,
    parse_setropts_extended,
    parse_sms_storage_groups,
    parse_syslog_conf,
)


class OperauditCheck(SetroptsFlagCheck):
    """EXT-007: OPERAUDIT Status.

    OPERAUDIT tracks operator commands issued by users with OPERATIONS.
    Parsed from SETROPTS LIST output (no additional command needed).
    """

    control_id = "EXT-007"
    control_name = "OPERAUDIT Status"
    nist_function = "Detect"
    priority = "P2"
    flag_key = "operaudit"
    on_finding = "OPERAUDIT is in effect"
    off_finding = "OPERAUDIT is NOT in effect — OPERATIONS user commands not audited"


class LogoptionsCheck(BaseCheck):
    """EXT-008: LOGOPTIONS Status.

    Checks that logon failures (and ideally successes) are being logged.
    """

    control_id = "EXT-008"
    control_name = "LOGOPTIONS Status"
    nist_function = "Detect"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_setropts_extended(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        failures = data.get("log_failures", False)
        successes = data.get("log_successes", False)
        findings: list[str] = []

        if failures:
            findings.append("Logon failures are being logged")
        else:
            findings.append("Logon failures are NOT being logged")

        if successes:
            findings.append("Logon successes are being logged")

        if failures:
            status = CheckStatus.PASS
        else:
            status = CheckStatus.FAIL

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class ProtectallCheck(SetroptsFlagCheck):
    """EXT-009: PROTECTALL Status.

    PROTECTALL requires explicit RACF profiles for dataset access.
    Without it, datasets without profiles may be accessible.
    """

    control_id = "EXT-009"
    control_name = "PROTECTALL Status"
    nist_function = "Protect"
    priority = "P2"
    flag_key = "protectall"
    on_finding = "PROTECTALL is in effect"
    off_finding = "PROTECTALL is NOT in effect — datasets without profiles may be accessible"


class EraseCheck(SetroptsFlagCheck):
    """EXT-010: ERASE-ON-SCRATCH Status.

    ERASE ensures deleted dataset content is overwritten, preventing recovery.
    """

    control_id = "EXT-010"
    control_name = "ERASE Status"
    nist_function = "Protect"
    priority = "P2"
    flag_key = "erase"
    on_finding = "ERASE-ON-SCRATCH is in effect"
    off_finding = "ERASE-ON-SCRATCH is NOT in effect — deleted data may be recoverable"
    off_status = CheckStatus.PARTIAL


class VTAMSecurityCheck(RlistUaccCheck):
    """EXT-005: VTAM/Application Security.

    Checks that RACF APPL class profiles exist to control application access.
    """

    control_id = "EXT-005"
    control_name = "VTAM Security"
    nist_function = "Protect"
    priority = "P2"
    racf_class = "APPL"
    missing_finding = "No APPL class profiles defined — application access not controlled"


class ConsoleSecurityCheck(RlistUaccCheck):
    """EXT-006: Console Security.

    Checks that RACF CONSOLE class profiles exist with UACC(NONE).
    """

    control_id = "EXT-006"
    control_name = "Console Security"
    nist_function = "Protect"
    priority = "P2"
    racf_class = "CONSOLE"
    missing_finding = "No CONSOLE class profiles defined — console access not controlled"


# ---- EXT-001, EXT-002, EXT-003, EXT-004, EXT-011 ----


class FTPStatusCheck(BaseCheck):
    """EXT-001: FTP Status Check. Flags FTP listening on port 21."""

    control_id = "EXT-001"
    control_name = "FTP Status"
    nist_function = "Protect"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("NETSTAT CONN")

    def parse(self, output: str) -> dict[str, Any]:
        conns = parse_netstat_conn(output)
        return {
            "connections": conns,
            "ftp_listening": any(c["port"] == "21" for c in conns),
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        if data.get("ftp_listening"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=["FTP server listening on port 21 — should be disabled or restricted"],
                data=data,
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=["FTP server is not listening on port 21"],
            data=data,
        )


class JavaVersionCheck(BaseCheck):
    """EXT-002: Java Version. Checks if Java is installed and its version."""

    control_id = "EXT-002"
    control_name = "Java Version"
    nist_function = "Protect"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command("java -version 2>&1")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_java_version(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        if not data.get("installed"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                findings=["Java is not installed (or not in PATH)"],
                data=data,
            )
        version = data.get("version", "unknown")
        findings = [f"Java version: {version}"]
        if data.get("ibm_java"):
            findings.append("IBM Java detected")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=findings,
            data=data,
        )


class SyslogConfigCheck(BaseCheck):
    """EXT-003: USS Syslog Configuration. Checks for remote log forwarding."""

    control_id = "EXT-003"
    control_name = "USS Syslog Config"
    nist_function = "Detect"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command("cat /etc/syslog.conf 2>&1")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_syslog_conf(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        if not data.get("exists"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=["/etc/syslog.conf does not exist — USS logging not configured"],
                data=data,
            )
        remote = data.get("remote_destinations", [])
        if remote:
            findings = [f"Syslog forwarding to: {', '.join(remote)}"]
            status = CheckStatus.PASS
        else:
            findings = ["/etc/syslog.conf exists but no remote forwarding configured"]
            status = CheckStatus.PARTIAL
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class SessionTimeoutCheck(BaseCheck):
    """EXT-004: Session Timeout. Reads SESSION INTERVAL from SETROPTS LIST."""

    control_id = "EXT-004"
    control_name = "Session Timeout"
    nist_function = "Protect"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        import re

        result: dict[str, Any] = {"timeout_minutes": None, "configured": False}
        m = re.search(r"SESSION INTERVAL IS (\d+)", output, re.IGNORECASE)
        if m:
            result["timeout_minutes"] = int(m.group(1))
            result["configured"] = True
        return result

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        timeout = data.get("timeout_minutes")
        if not data.get("configured") or timeout is None:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PARTIAL,
                findings=["Session timeout not configured"],
                data=data,
            )
        findings = [f"Session timeout: {timeout} minutes"]
        if timeout <= 15:
            status = CheckStatus.PASS
        elif timeout <= 30:
            status = CheckStatus.PARTIAL
            findings.append("Recommended: <= 15 minutes")
        else:
            status = CheckStatus.FAIL
            findings.append("Excessive timeout — should be <= 15 minutes")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class USSListenersCheck(BaseCheck):
    """EXT-011: USS Network Listeners. Identifies open listening ports."""

    control_id = "EXT-011"
    control_name = "USS Network Listeners"
    nist_function = "Identify"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command("netstat -a 2>&1")

    def parse(self, output: str) -> dict[str, Any]:
        conns = parse_netstat_conn(output)
        listeners = [c for c in conns if c["state"].upper() == "LISTEN"]
        return {"listeners": listeners, "count": len(listeners)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        listeners = data.get("listeners", [])
        count = data.get("count", 0)
        findings = [f"{count} listening ports detected"]
        for listener in listeners:
            findings.append(
                f"  {listener['userid']:<10} port {listener['port']:>5}  {listener['local_socket']}"
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=findings,
            data=data,
        )


class USSProcessCheck(BaseCheck):
    """EXT-012: USS Running Processes. Identifies known services via ps -ef."""

    control_id = "EXT-012"
    control_name = "USS Running Processes"
    nist_function = "Identify"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command("ps -ef 2>&1")

    def parse(self, output: str) -> dict[str, Any]:
        processes = parse_ps_output(output)
        notable = []
        for proc in processes:
            cmd = proc["cmd"]
            for pattern, description in NOTABLE_PROCESSES.items():
                if pattern in cmd:
                    notable.append({**proc, "description": description})
                    break
        return {"total_processes": len(processes), "notable": notable}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        notable = data.get("notable", [])
        total = data.get("total_processes", 0)
        findings = [f"{total} total USS processes"]
        if notable:
            findings.append(f"{len(notable)} notable services:")
            for p in notable:
                findings.append(f"  {p['uid']:<10} {p['cmd']:<12} ({p['description']})")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=findings,
            data=data,
        )


class DatasetEncryptionCheck(BaseCheck):
    """EXT-013: Dataset Encryption. Checks SMS DATACLAS for encryption."""

    control_id = "EXT-013"
    control_name = "Dataset Encryption"
    nist_function = "Protect"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("LISTDS 'SYS1.PARMLIB' LABEL")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_listds_label(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        encrypted = data.get("encrypted", False)
        dataclas = data.get("dataclas")
        findings: list[str] = []
        if dataclas:
            findings.append(f"DATACLAS: {dataclas}")
        else:
            findings.append("No DATACLAS assigned")
        if encrypted:
            findings.append("Encryption-enabled DATACLAS detected")
        else:
            findings.append("No dataset encryption — review Pervasive Encryption readiness")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS if encrypted else CheckStatus.PARTIAL,
            findings=findings,
            data=data,
        )


class TCPIPStackCheck(BaseCheck):
    """EXT-014: TCP/IP Stack Summary. Network baseline via D TCPIP."""

    control_id = "EXT-014"
    control_name = "TCP/IP Stack Summary"
    nist_function = "Identify"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D TCPIP,,N,CONN")

    def parse(self, output: str) -> dict[str, Any]:
        conns = parse_netstat_conn(output)
        listeners = [c for c in conns if c["state"].upper() == "LISTEN"]
        established = [
            c for c in conns if c["state"].upper() in ("ESTABLSH", "ESTBLSH", "ESTABLISHED")
        ]
        return {
            "total": len(conns),
            "listeners": len(listeners),
            "established": len(established),
            "connections": conns,
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=[
                f"{data.get('total', 0)} connections: "
                f"{data.get('listeners', 0)} listening, "
                f"{data.get('established', 0)} established"
            ],
            data=data,
        )


class RACFClassStatusCheck(BaseCheck):
    """EXT-015: RACF Class Status. Lists active RACF security classes."""

    control_id = "EXT-015"
    control_name = "RACF Class Status"
    nist_function = "Identify"
    priority = "P2"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        classes = parse_active_classes(output)
        return {"active_classes": classes, "count": len(classes)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        classes = data.get("active_classes", [])
        count = data.get("count", 0)
        findings = [f"{count} RACF classes active"]
        active_upper = {c.upper() for c in classes}

        critical = {"DATASET", "USER", "GROUP", "FACILITY", "STARTED", "PROGRAM"}
        missing = critical - active_upper
        if missing:
            findings.append(f"Critical classes NOT active: {', '.join(sorted(missing))}")

        # ICSF key protection classes (from Health Checker RACF_CSFSERV/CSFKEYS_ACTIVE)
        crypto_classes = {"CSFSERV", "CSFKEYS"}
        missing_crypto = crypto_classes - active_upper
        if not missing_crypto:
            findings.append("CSFSERV and CSFKEYS active — ICSF key access controlled by RACF")
        elif missing_crypto:
            findings.append(
                f"ICSF protection classes NOT active: {', '.join(sorted(missing_crypto))} "
                "— crypto key access not controlled by RACF"
            )

        all_missing = missing | missing_crypto
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS if not all_missing else CheckStatus.PARTIAL,
            findings=findings,
            data=data,
        )


# ---- Backup Infrastructure Checks (EXT-021, EXT-022) ----


class BackupStorageCheck(BaseCheck):
    """EXT-021: Backup Storage Infrastructure.

    Checks for COPY-type SMS storage groups (FlashCopy/Safeguarded Copy)
    and backup-related address spaces (DFHSM, CSM, GDPS) via D SMS,SG(ALL)
    and D A,L console commands.
    """

    control_id = "EXT-021"
    control_name = "Backup Storage Infrastructure"
    nist_function = "Protect"
    priority = "P1"

    def execute(self, connection: BaseConnection) -> str:
        sg_output = connection.execute_console_command("D SMS,SG(ALL)")
        da_output = connection.execute_console_command("D A,L")
        return join_sections([("SMS", sg_output), ("ACTIVITY", da_output)])

    def parse(self, output: str) -> dict[str, Any]:
        sections = split_sections(output, ["SMS", "ACTIVITY"])
        storage_groups = parse_sms_storage_groups(sections["SMS"])
        address_spaces = parse_active_address_spaces(sections["ACTIVITY"])

        # Find COPY-type storage groups
        copy_groups = [g for g in storage_groups if g["type"] == "COPY"]

        # Find backup-related address spaces
        backup_stcs = []
        for name in address_spaces:
            if name in BACKUP_ADDRESS_SPACES:
                backup_stcs.append(
                    {
                        "name": name,
                        "description": BACKUP_ADDRESS_SPACES[name],
                    }
                )

        return {
            "storage_groups": storage_groups,
            "copy_groups": copy_groups,
            "backup_stcs": backup_stcs,
            "has_copy_storage": len(copy_groups) > 0,
            "has_hsm": any(s["name"] in ("DFHSM", "HSM") for s in backup_stcs),
            "has_csm": any(s["name"] == "CSM" for s in backup_stcs),
            "has_gdps": any(s["name"] == "GDPS" for s in backup_stcs),
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []
        score = 0

        # Storage groups
        total_sg = len(data.get("storage_groups", []))
        findings.append(f"{total_sg} SMS storage groups defined")

        copy_groups = data.get("copy_groups", [])
        if copy_groups:
            names = ", ".join(g["name"] for g in copy_groups)
            findings.append(f"COPY storage groups found: {names} (FlashCopy/Safeguarded Copy)")
            score += 2
        else:
            findings.append(
                "No COPY-type storage groups — no FlashCopy/Safeguarded Copy infrastructure detected"
            )

        # Backup address spaces
        backup_stcs = data.get("backup_stcs", [])
        if backup_stcs:
            for stc in backup_stcs:
                findings.append(f"Backup STC active: {stc['name']} — {stc['description']}")
                score += 1
        else:
            findings.append("No backup-related address spaces running (DFHSM, CSM, GDPS)")

        if data.get("has_hsm"):
            findings.append("DFSMShsm active — automated backup/migration in place")
        if data.get("has_csm"):
            findings.append(
                "Copy Services Manager active — FlashCopy/Safeguarded Copy orchestration"
            )
        if data.get("has_gdps"):
            findings.append("GDPS active — disaster recovery infrastructure")

        if score >= 3:
            status = CheckStatus.PASS
        elif score >= 1:
            status = CheckStatus.PARTIAL
        else:
            status = CheckStatus.FAIL

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class BackupProcessCheck(BaseCheck):
    """EXT-022: Backup Automation Processes.

    Checks USS process listing for backup-related processes (DFHSM, CSM,
    GDPS, FlashCopy agents). Complements EXT-021 with USS-level visibility.
    """

    control_id = "EXT-022"
    control_name = "Backup Automation Processes"
    nist_function = "Protect"
    priority = "P1"

    BACKUP_KEYWORDS = {
        "DFHSM": "DFSMShsm (automated backup/migration)",
        "HSM": "Hierarchical Storage Manager",
        "CSM": "Copy Services Manager",
        "GDPS": "Geographically Dispersed Parallel Sysplex",
        "ANTMAIN": "Advanced Copy Services",
        "ADRDSSU": "DFSMSdss (dump/restore)",
        "BCOPY": "Backup copy process",
        "VAULT": "Cyber Vault related",
        "FLASHC": "FlashCopy process",
    }

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command("ps -ef 2>&1")

    def parse(self, output: str) -> dict[str, Any]:
        processes = parse_ps_output(output)
        backup_procs = []
        for proc in processes:
            cmd = proc["cmd"].upper()
            for keyword, description in self.BACKUP_KEYWORDS.items():
                if keyword in cmd:
                    backup_procs.append({**proc, "description": description})
                    break
        return {
            "backup_processes": backup_procs,
            "count": len(backup_procs),
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        procs = data.get("backup_processes", [])
        count = data.get("count", 0)

        if count > 0:
            findings = [f"{count} backup-related processes detected:"]
            for p in procs:
                findings.append(f"  {p['uid']:<10} {p['cmd']:<12} ({p['description']})")
            status = CheckStatus.PASS
        else:
            findings = ["No backup-related processes detected in USS process listing"]
            status = CheckStatus.PARTIAL

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


# ---- Health Checker aligned checks (EXT-023 to EXT-025) ----


class BatchAllRACFCheck(SetroptsFlagCheck):
    """EXT-023: Batch Job RACF Enforcement (aligns with RACF_BATCHALLRACF)."""

    control_id = "EXT-023"
    control_name = "Batch Job RACF Enforcement"
    nist_function = "Protect"
    priority = "P2"
    flag_key = "batchallracf"
    on_finding = "BATCHALLRACF in effect — all batch jobs require RACF authentication"
    off_finding = "BATCHALLRACF NOT in effect — batch jobs may bypass RACF authentication"
    data_keys = ("batchallracf",)


class RACFDatabaseProtectionCheck(BaseCheck):
    """EXT-024: RACF Database Protection (aligns with RACF_SENSITIVE_RESOURCES)."""

    control_id = "EXT-024"
    control_name = "RACF Database Protection"
    nist_function = "Protect"
    priority = "P1"

    def execute(self, connection: BaseConnection) -> str:
        outputs: list[str] = []
        errors: list[Exception] = []
        for dsn in ("SYS1.RACF", "SYS1.RACFB"):
            try:
                outputs.append(connection.execute_tso_command(f"RLIST DATASET {dsn} ALL"))
            except (CommandNotSupportedError, PermissionError) as e:
                # A single dataset profile not being listable is tolerable; only a
                # total inability to query (every dsn unsupported) should Skip.
                errors.append(e)
        if not outputs and errors and all(isinstance(e, CommandNotSupportedError) for e in errors):
            raise errors[0]
        return "\n".join(outputs)

    def parse(self, output: str) -> dict[str, Any]:
        profiles = parse_apf_profiles(output)
        return {"profiles": profiles, "count": len(profiles)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        profiles = data.get("profiles", [])
        if not profiles:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PARTIAL,
                findings=["No RACF database profiles found (SYS1.RACF/SYS1.RACFB)"],
                data=data,
            )
        findings: list[str] = []
        issues = 0
        for p in profiles:
            uacc = p.get("uacc", "NONE")
            if uacc not in ("NONE", None):
                findings.append(f"{p['name']}: UACC={uacc} — should be NONE")
                issues += 1
            else:
                findings.append(f"{p['name']}: UACC=NONE (protected)")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS if issues == 0 else CheckStatus.FAIL,
            findings=findings,
            data=data,
        )


class ICHAUTABCheck(BaseCheck):
    """EXT-025: ICHAUTAB Authorization Bypass (aligns with RACF_ICHAUTAB_NONLPA)."""

    control_id = "EXT-025"
    control_name = "ICHAUTAB Authorization Bypass"
    nist_function = "Protect"
    priority = "P1"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        import re

        has_ichautab = bool(re.search(r"ICHAUTAB", output, re.IGNORECASE))
        no_exits = bool(re.search(r"NO INSTALLATION.*EXIT", output, re.IGNORECASE))
        return {"ichautab_referenced": has_ichautab, "no_exits": no_exits}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        if data.get("ichautab_referenced"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PARTIAL,
                findings=["ICHAUTAB referenced — verify no entries bypass RACF authorization"],
                data=data,
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=["No ICHAUTAB authorization bypass table detected"],
            data=data,
        )
