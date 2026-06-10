"""Reusable check patterns and multi-command section helpers.

Declarative base classes for the families of checks that share an identical
execute/parse/evaluate skeleton, plus helpers for the ``@@NAME@@`` delimiters
that pack several command outputs into one ``execute()`` return value.
"""

from __future__ import annotations

from typing import Any, Sequence

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection
from znextscan.parsers.racf_parser import parse_rlist_class, parse_setropts_extended


class SetroptsFlagCheck(BaseCheck):
    """A ``SETROPTS LIST`` check that turns on a single boolean option.

    Subclasses set ``control_id``/``control_name`` and the flag metadata.
    """

    flag_key: str  # key in parse_setropts_extended() output
    on_finding: str
    off_finding: str
    off_status: CheckStatus = CheckStatus.FAIL
    data_keys: tuple[str, ...] | None = None  # None => keep the full parsed dict

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("SETROPTS LIST")

    def parse(self, output: str) -> dict[str, Any]:
        return parse_setropts_extended(output)

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        active = bool(data.get(self.flag_key, False))
        out_data = (
            data if self.data_keys is None else {k: data.get(k, False) for k in self.data_keys}
        )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS if active else self.off_status,
            findings=[self.on_finding if active else self.off_finding],
            data=out_data,
        )


class RlistUaccCheck(BaseCheck):
    """A ``RLIST <class> * ALL`` check: profiles must exist and have UACC(NONE)."""

    racf_class: str  # e.g. "APPL", "CONSOLE"
    missing_finding: str  # FAIL message when zero profiles are defined

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command(f"RLIST {self.racf_class} * ALL")

    def parse(self, output: str) -> dict[str, Any]:
        profiles = parse_rlist_class(output, self.racf_class)
        return {"profiles": profiles, "count": len(profiles)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        profiles = data.get("profiles", [])
        count = data.get("count", 0)
        if count == 0:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=[self.missing_finding],
                data=data,
            )

        findings = [f"{count} {self.racf_class} class profiles defined"]
        open_profiles = [p for p in profiles if p.get("uacc") not in ("NONE", None)]
        if open_profiles:
            names = ", ".join(p["name"] for p in open_profiles)
            findings.append(f"Profiles with UACC != NONE: {names}")

        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS if not open_profiles else CheckStatus.PARTIAL,
            findings=findings,
            data=data,
        )


# ---- multi-command section delimiters ----


def section_delim(name: str) -> str:
    """The in-band delimiter that separates packed command outputs: ``@@NAME@@``."""
    return f"@@{name}@@"


def join_sections(sections: Sequence[tuple[str, str]]) -> str:
    """Join ``(name, output)`` pairs into one delimited string for ``execute()``."""
    parts: list[str] = []
    for name, output in sections:
        parts.append(section_delim(name))
        parts.append(output)
    return "\n".join(parts)


def split_sections(output: str, names: Sequence[str]) -> dict[str, str]:
    """Inverse of :func:`join_sections`; missing trailing sections become ``''``."""
    result = {name: "" for name in names}
    for name in names:
        delim = section_delim(name)
        idx = output.find(delim)
        if idx == -1:
            continue
        start = idx + len(delim)
        # the section runs until the next delimiter that appears after it
        end = len(output)
        for other in names:
            if other == name:
                continue
            j = output.find(section_delim(other), start)
            if j != -1:
                end = min(end, j)
        result[name] = output[start:end].strip("\n")
    return result
