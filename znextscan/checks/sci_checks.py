"""System/Configuration Integrity checks: SCI-001 (APF Integrity), SCI-004 (Program Control)."""

from typing import Any

from znextscan.checks._patterns import join_sections, split_sections
from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection
from znextscan.parsers.racf_parser import (
    parse_apf_list,
    parse_apf_profiles,
    parse_program_control,
)


class APFIntegrityCheck(BaseCheck):
    """SCI-001: APF Library Integrity."""

    control_id = "SCI-001"
    control_name = "APF Library Integrity"
    nist_function = "Protect"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        apf_output = connection.execute_console_command("D PROG,APF")
        profile_output = connection.execute_tso_command("RLIST DATASET SYS1")
        return join_sections([("APF", apf_output), ("PROFILES", profile_output)])

    def parse(self, output: str) -> dict[str, Any]:
        sections = split_sections(output, ["APF", "PROFILES"])
        libraries = parse_apf_list(sections["APF"])
        profiles = parse_apf_profiles(sections["PROFILES"])

        return {"libraries": libraries, "profiles": profiles}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        libraries = data.get("libraries", [])
        profiles = data.get("profiles", [])
        findings: list[str] = []
        issues = 0

        # Check for profiles with UACC other than NONE
        for profile in profiles:
            if profile.get("uacc") not in ("NONE", None):
                findings.append(f"{profile['name']}: UACC={profile['uacc']} (should be NONE)")
                issues += 1

        # Check how many APF libraries have RACF profiles
        protected = {p["name"] for p in profiles}
        sys_libs = [l for l in libraries if l["dsname"].startswith("SYS1.")]
        unprotected = [l for l in sys_libs if l["dsname"] not in protected]
        if unprotected:
            findings.append(f"{len(unprotected)} SYS1 APF libraries without RACF dataset profiles")

        if issues == 0 and not unprotected:
            status = CheckStatus.PASS
        elif issues == 0:
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


class ProgramControlCheck(BaseCheck):
    """SCI-004: Program Control Status."""

    control_id = "SCI-004"
    control_name = "Program Control Status"
    nist_function = "Protect"
    priority = "P1"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_program_control(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []
        issues = 0

        if data.get("when_program"):
            findings.append("WHEN(PROGRAM) is in effect")
        else:
            findings.append("WHEN(PROGRAM) is NOT in effect")
            issues += 1

        if data.get("program_class_active"):
            findings.append("PROGRAM class is active")
        else:
            findings.append("PROGRAM class is NOT active")
            issues += 1

        if issues == 0:
            status = CheckStatus.PASS
        elif issues == 1:
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
