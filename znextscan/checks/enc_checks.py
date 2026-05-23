"""Encryption checks: ENC-002 (ICSF Key Management), ENC-005 (Crypto Hardware)."""

from typing import Any

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection
from znextscan.parsers.racf_parser import parse_icsf_cards, parse_icsf_status


class ICSFKeyManagementCheck(BaseCheck):
    """ENC-002: ICSF Key Management."""

    control_id = "ENC-002"
    control_name = "ICSF Key Management"
    nist_function = "Protect"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D ICSF")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_icsf_status(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        findings: list[str] = []

        if not data.get("active"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["ICSF is not active — encryption checks skipped"],
                data=data,
            )

        findings.append("ICSF is active")
        fmid = data.get("fmid")
        if fmid:
            findings.append(f"ICSF FMID: {fmid}")

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=findings,
            data=data,
        )


class CryptoHardwareCheck(BaseCheck):
    """ENC-005: Crypto Hardware Utilization.

    Uses D ICSF,CARDS to enumerate crypto hardware. This command is valid
    on all z/OS versions (2.3+). Note: D ICSF,STATUS is NOT a valid command
    on any z/OS version despite appearing in some documentation.
    Falls back to D ICSF (LIST) if CARDS output is unavailable.
    """

    control_id = "ENC-005"
    control_name = "Crypto Hardware Utilization"
    nist_function = "Protect"
    priority = "P1"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D ICSF,CARDS")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_icsf_cards(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        if not data.get("active"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["ICSF is not active — crypto hardware check skipped"],
                data=data,
            )

        cards = data.get("cards", [])
        findings: list[str] = []

        if cards:
            online = [c for c in cards if c.get("status") == "ONLINE"]
            findings.append(f"{len(cards)} crypto cards found, {len(online)} online")
            for card in cards:
                findings.append(
                    f"  Card {card.get('id','?')}: {card.get('type','?')} "
                    f"status={card.get('status','?')} mode={card.get('mode','?')}"
                )
        else:
            findings.append("No crypto hardware cards detected (or D ICSF,CARDS not available)")

        fmid = data.get("fmid")
        if fmid:
            findings.append(f"ICSF release: {fmid}")

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS if cards else CheckStatus.PARTIAL,
            findings=findings,
            data=data,
        )
