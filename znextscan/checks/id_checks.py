"""Identity checks: ID-002 (Privileged Users), ID-003 (APF Libraries)."""

from typing import Any

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection
from znextscan.parsers.racf_parser import parse_apf_list, parse_listuser_all


class PrivilegedUserCheck(BaseCheck):
    """ID-002: Privileged User Inventory (SPECIAL/OPERATIONS/AUDITOR).

    Uses LISTUSER * to enumerate all users and extract those with
    SPECIAL, OPERATIONS, or AUDITOR system-level attributes.

    Note: SEARCH CLASS(USER) SPECIAL is NOT a valid RACF command.
    The SPECIAL keyword is an ADDUSER/ALTUSER operand, not a SEARCH operand.
    """

    control_id = "ID-002"
    control_name = "Privileged User Inventory"
    nist_function = "Identify"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("LISTUSER *")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_listuser_all(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        special = data.get("special", [])
        operations = data.get("operations", [])
        auditor = data.get("auditor", [])
        findings: list[str] = []
        special_count = len(special)

        if special_count > 10:
            status = CheckStatus.FAIL
            findings.append(f"{special_count} users with SPECIAL (>10 is excessive)")
        elif special_count > 5:
            status = CheckStatus.PARTIAL
            findings.append(f"{special_count} users with SPECIAL (5-10 should be reviewed)")
        else:
            status = CheckStatus.PASS

        if special:
            findings.append(f"SPECIAL users: {', '.join(special)}")
        if operations:
            findings.append(f"{len(operations)} users with OPERATIONS: {', '.join(operations)}")
        if auditor:
            findings.append(f"{len(auditor)} users with AUDITOR: {', '.join(auditor)}")

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data={
                "special_users": special,
                "special_count": special_count,
                "operations_users": operations,
                "auditor_users": auditor,
            },
        )


class APFLibraryCheck(BaseCheck):
    """ID-003: APF Library Inventory."""

    control_id = "ID-003"
    control_name = "APF Library Inventory"
    nist_function = "Identify"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D PROG,APF")

    def parse(self, output: str) -> dict[str, Any]:
        libraries = parse_apf_list(output)
        return {"libraries": libraries, "count": len(libraries)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        libraries = data.get("libraries", [])
        count = data.get("count", 0)
        findings: list[str] = [f"Total APF libraries: {count}"]

        ibm_prefixes = (
            "SYS1.",
            "CEE.",
            "ISF.",
            "ISP.",
            "IOE.",
            "TCPIP.",
            "CSF.",
            "CBC.",
            "EQAW.",
            "BZU.",
            "FEK.",
            "FEL.",
            "FEU.",
            "IPV.",
        )
        non_system = [lib for lib in libraries if not lib["dsname"].startswith(ibm_prefixes)]
        if non_system:
            findings.append(
                f"{len(non_system)} non-IBM APF libraries found — review for legitimacy"
            )

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=findings,
            data=data,
        )
