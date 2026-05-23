"""IAM checks: IAM-002 (Password Policy), IAM-003 (Default Accounts),
IAM-004 (SPECIAL Count), IAM-005 (Started Tasks)."""

from typing import Any

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection
from znextscan.parsers.racf_parser import (
    parse_listuser,
    parse_listuser_all,
    parse_setropts_password,
    parse_started_tasks,
)


class PasswordPolicyCheck(BaseCheck):
    """IAM-002: Strong Password Policy."""

    control_id = "IAM-002"
    control_name = "Strong Password Policy"
    nist_function = "Protect"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_setropts_password(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []
        all_pass = True

        min_len = data.get("min_length")
        if min_len is not None and min_len < 8:
            findings.append(f"Password minimum length is {min_len} (should be >= 8)")
            all_pass = False
        elif min_len is not None and min_len < 12:
            findings.append(f"Password minimum length is {min_len} (recommended >= 12)")

        history = data.get("history")
        if history is not None and history < 5:
            findings.append(f"Password history is {history} (should be >= 5)")
            all_pass = False
        elif history is not None and history < 12:
            findings.append(f"Password history is {history} (recommended >= 12)")

        revoke = data.get("revoke_count")
        if revoke is not None and revoke > 5:
            findings.append(f"Password revoke count is {revoke} (should be <= 5)")
            all_pass = False

        if not data.get("mixed_case"):
            findings.append("Mixed case password support not in effect")

        algo = data.get("encryption_algorithm", "")
        if algo and algo not in ("KDFAES", "PHASH"):
            if algo == "MASKED":
                findings.append(
                    f"Password encryption is {algo} — upgrade to KDFAES (requires z/OS 2.3+)"
                )
            else:
                findings.append(
                    f"Password encryption is {algo} — KDFAES strongly recommended "
                    "(requires z/OS 2.3+)"
                )

        if all_pass and not findings:
            status = CheckStatus.PASS
        elif all_pass:
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


class DefaultAccountCheck(BaseCheck):
    """IAM-003: Default Account Removal."""

    control_id = "IAM-003"
    control_name = "Default Account Removal"
    nist_function = "Protect"
    priority = "P0"

    DEFAULT_ACCOUNTS = ["IBMUSER", "SYS1"]

    def execute(self, connection: BaseConnection) -> str:
        outputs = []
        for acct in self.DEFAULT_ACCOUNTS:
            output = connection.execute_tso_command(f"LISTUSER {acct}")
            outputs.append(output)
        return "\n---SEPARATOR---\n".join(outputs)

    def parse(self, output: str) -> dict[str, Any]:
        sections = output.split("---SEPARATOR---")
        users = []
        for section in sections:
            section = section.strip()
            if section:
                user = parse_listuser(section)
                if user:
                    users.append(user)
        return {"default_accounts": users}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []
        accounts = data.get("default_accounts", [])
        all_secure = True

        for acct in accounts:
            userid = acct.get("userid", "UNKNOWN")
            attrs = acct.get("attributes", [])
            protected = acct.get("protected", False)
            revoke_date = acct.get("revoke_date", "NONE")

            if protected:
                findings.append(f"{userid}: PROTECTED (no interactive logon)")
            elif revoke_date != "NONE":
                findings.append(f"{userid}: Revoked (date={revoke_date})")
            elif "SPECIAL" in attrs:
                findings.append(f"{userid}: ACTIVE with SPECIAL — should be revoked or PROTECTED")
                all_secure = False
            else:
                findings.append(f"{userid}: Active — review if necessary")

        status = CheckStatus.PASS if all_secure else CheckStatus.FAIL
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class SpecialCountCheck(BaseCheck):
    """IAM-004: SPECIAL Attribute Restriction.

    Uses LISTUSER * to find all users with SPECIAL attribute.
    Note: SEARCH CLASS(USER) SPECIAL is NOT a valid RACF command.
    """

    control_id = "IAM-004"
    control_name = "SPECIAL Attribute Restriction"
    nist_function = "Protect"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("LISTUSER *")

    def parse(self, output: str) -> dict[str, Any]:
        all_users = parse_listuser_all(output)
        users = all_users.get("special", [])
        return {"special_users": users, "count": len(users)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        count = data.get("count", 0)
        users = data.get("special_users", [])
        findings: list[str] = [f"SPECIAL attribute assigned to {count} users"]

        if count <= 5:
            status = CheckStatus.PASS
        elif count <= 10:
            status = CheckStatus.PARTIAL
            findings.append("Review whether all SPECIAL assignments are necessary")
        else:
            status = CheckStatus.FAIL
            findings.append("Excessive SPECIAL assignments — immediate review required")

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data={"special_users": users, "count": count},
        )


class StartedTaskCheck(BaseCheck):
    """IAM-005: Started Task Security."""

    control_id = "IAM-005"
    control_name = "Started Task Security"
    nist_function = "Protect"
    priority = "P1"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("RLIST STARTED * ALL")

    def parse(self, output: str) -> dict[str, Any]:
        tasks = parse_started_tasks(output)
        return {"started_tasks": tasks, "count": len(tasks)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        tasks = data.get("started_tasks", [])
        findings: list[str] = []
        issues = 0

        for task in tasks:
            profile = task.get("profile", "")
            user = task.get("user", "=MEMBER")
            trusted = task.get("trusted", False)

            if user == "=MEMBER":
                findings.append(f"{profile}: Uses =MEMBER (inherits STC name as userid)")
            if trusted:
                findings.append(f"{profile}: TRUSTED=YES (bypasses RACF checking)")
                issues += 1

        if issues == 0:
            status = CheckStatus.PASS
        elif issues <= 2:
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
