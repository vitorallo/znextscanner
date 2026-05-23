"""Monitoring checks: MON-001 (SMF Recording), MON-003 (RACF Audit)."""

from typing import Any

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection
from znextscan.parsers.racf_parser import parse_setropts_audit, parse_smf_status


class SMFRecordingCheck(BaseCheck):
    """MON-001: SMF Recording Status."""

    control_id = "MON-001"
    control_name = "SMF Recording Status"
    nist_function = "Detect"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D SMF,O")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_smf_status(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []

        if not data.get("active"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=["SMF recording is NOT active"],
                data=data,
            )

        findings.append("SMF recording is active")

        # Check critical SMF record types
        missing_types = []
        if not data.get("has_type_30"):
            missing_types.append("30 (job/step accounting)")
        if not data.get("has_type_80"):
            missing_types.append("80 (RACF events)")
        if not data.get("has_type_83"):
            missing_types.append("83 (RACF audit records)")

        if missing_types:
            findings.append(f"Missing critical SMF types: {', '.join(missing_types)}")
            status = CheckStatus.PARTIAL
        else:
            findings.append("All critical SMF types (30, 80, 83) are being recorded")
            status = CheckStatus.PASS

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class RACFAuditCheck(BaseCheck):
    """MON-003: RACF Audit Logging."""

    control_id = "MON-003"
    control_name = "RACF Audit Logging"
    nist_function = "Detect"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_setropts_audit(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []
        issues = 0

        if data.get("audit_active"):
            findings.append("AUDIT processing is in effect")
        else:
            findings.append("AUDIT processing is NOT in effect")
            issues += 1

        if data.get("saudit"):
            findings.append("SAUDIT is in effect (SPECIAL user auditing)")
        else:
            findings.append("SAUDIT is NOT in effect")
            issues += 1

        if data.get("log_logon_failures"):
            findings.append("Logon failures are being logged")
        else:
            findings.append("Logon failures are NOT being logged")
            issues += 1

        if issues == 0:
            status = CheckStatus.PASS
        elif issues <= 1:
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
