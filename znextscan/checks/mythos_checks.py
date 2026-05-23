"""Mythos-native scriptable checks.

These are Mythos-native checks (control IDs ``MYT-*``); they are *not* part of
the legacy MRRA ``CHECK_REGISTRY``. Hybrid checks degrade to ``Skipped`` via
``CommandNotSupportedError`` and are then surfaced through the questionnaire.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection, CommandNotSupportedError

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_cve_map() -> dict[str, Any] | None:
    """Load the offline CVE map; return None if missing/malformed (→ Skipped)."""
    try:
        return json.loads((_DATA_DIR / "cve_map.json").read_text())
    except (OSError, ValueError):
        return None


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


_PROCLIB_DELIM = "@@PROCLIB@@"
_DISP_WORDS = {
    "KEEP",
    "DELETE",
    "CATALOG",
    "UNCATALOG",
    "KEEP,KEEP",
    "KEEP,DELETE",
    "SHR",
    "OLD",
    "MOD",
    "NEW",
    "SYSIN",
    "SYSOUT",
}


class OperationalCodeSurfaceCheck(BaseCheck):
    """MYT-R01: Readable operational-code surface inventory.

    Enumerates the AI-legible operational-code libraries — the layer frontier AI
    is strongest against — from their real sources:
      * REXX/CLIST: the SYSEXEC and SYSPROC concatenations (TSO ``LISTA STATUS``)
      * JCL procs:  the JES2 PROCLIB concatenations (``$D PROCLIB``)
    Validated live on z/OS 3.1. NOTE: SYSEXEC/SYSPROC reflect the *connected TSO
    environment* — the z/OSMF TSO servlet exposes the full ISPF concatenations,
    whereas a bare SSH ``tsocmd`` session shows only its own DDs. PROCLIB (via the
    console) is connection-independent.
    """

    control_id = "MYT-R01"
    control_name = "Readable operational-code surface inventory"
    nist_function = "Identify"
    priority = "P1"
    frameworks = ("mythos",)
    mythos_dimension = "R"
    validation_method = "Scanner"

    def execute(self, connection: BaseConnection) -> str:
        listalc = connection.execute_tso_command("LISTA STATUS")
        # PROCLIB ($D, JES2) is optional enrichment — tolerate console-unavailable
        # or auth failures without failing the whole check.
        try:
            proclib = connection.execute_console_command("$D PROCLIB")
        except Exception:
            proclib = ""
        return f"{listalc}\n{_PROCLIB_DELIM}\n{proclib}"

    def parse(self, output: str) -> dict[str, Any]:
        listalc, _, proclib_out = output.partition(_PROCLIB_DELIM)

        # LISTALC STATUS: a dataset-name line (col 0) followed by a "DDNAME DISP"
        # line (indented); a blank DDNAME continues the previous DD's concatenation.
        dd_map: dict[str, list[str]] = {}
        pending_dsn: str | None = None
        last_dd: str | None = None
        for raw in listalc.splitlines():
            if not raw.strip():
                continue
            if raw[0] != " ":  # dataset name (or USS path) line
                pending_dsn = raw.strip()
                continue
            toks = raw.split()
            if toks and toks[0] not in _DISP_WORDS:  # named DDNAME
                last_dd = toks[0]
            if pending_dsn and last_dd:
                dd_map.setdefault(last_dd, []).append(pending_dsn)
            pending_dsn = None

        sysexec = list(dict.fromkeys(dd_map.get("SYSEXEC", [])))
        sysproc = list(dict.fromkeys(dd_map.get("SYSPROC", [])))
        proclib = list(dict.fromkeys(re.findall(r"DSNAME=([A-Z0-9.@#$]+)", proclib_out)))
        rexx_clist = sorted(set(sysexec) | set(sysproc))
        all_libs = sorted(set(rexx_clist) | set(proclib))
        return {
            "sysexec": sysexec,
            "sysproc": sysproc,
            "proclib": proclib,
            "rexx_clist_libs": rexx_clist,
            "all_libraries": all_libs,
            "total": len(all_libs),
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        total = data["total"]
        findings = [
            f"AI-legible operational-code libraries: {total} distinct",
            f"REXX/CLIST (SYSEXEC/SYSPROC): {len(data['rexx_clist_libs'])} — "
            + ", ".join(data["rexx_clist_libs"][:8]),
            f"JCL PROCLIB datasets: {len(data['proclib'])} — " + ", ".join(data["proclib"][:8]),
        ]
        if total == 0:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["No SYSEXEC/SYSPROC/PROCLIB libraries enumerated"],
                data=data,
            )
        status = CheckStatus.PARTIAL if total > 15 else CheckStatus.PASS
        if status is CheckStatus.PARTIAL:
            findings.append(
                "Large AI-legible operational-code surface — prioritize source-egress "
                "controls (MYT-C11) and exposure recon (MYT-R02)"
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            findings=findings,
            data=data,
        )


class SMPECurrencyCheck(BaseCheck):
    """MYT-V01: Maintenance currency vs. the hours-scale exploitation reality.

    z/OS exposes no single REST/console command for SMP/E PTF currency (that
    needs a GIMSMP CSI query). ``D IPLINFO`` is used as the scriptable proxy —
    it yields the z/OS release and last-IPL date — and deep PTF/RSU currency is
    deferred to the questionnaire (this is a Hybrid control). Validated live on
    z/OS 3.1: command works, output parsed.
    """

    control_id = "MYT-V01"
    control_name = "Maintenance currency (release + IPL recency)"
    nist_function = "Identify"
    priority = "P0"
    frameworks = ("mythos",)
    mythos_dimension = "V"
    validation_method = "Hybrid"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D IPLINFO")

    def parse(self, output: str) -> dict[str, Any]:
        rel = re.search(r"RELEASE\s+(z/OS\s+[\d.]+)", output)
        ipl = re.search(r"IPLED AT\s+[\d.]+\s+ON\s+(\d{2})/(\d{2})/(\d{4})", output)
        ipl_date = None
        if ipl:
            mm, dd, yyyy = ipl.groups()
            ipl_date = f"{yyyy}-{mm}-{dd}"
        return {"release": rel.group(1) if rel else None, "ipl_date": ipl_date}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        from datetime import date

        rel = data.get("release")
        ipl_date = data.get("ipl_date")
        if not rel:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["IPLINFO not parseable — complete SMP/E currency via questionnaire"],
                data=data,
            )
        findings = [f"z/OS release: {rel}"]
        age_days = None
        if ipl_date:
            y, m, d = (int(x) for x in ipl_date.split("-"))
            age_days = (date.today() - date(y, m, d)).days
            findings.append(f"Last IPL: {ipl_date} ({age_days} days ago)")
        findings.append(
            "SMP/E PTF/RSU currency vs. the hours-scale exploitation reality requires a "
            "CSI review — complete via questionnaire (MYT-V01)."
        )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PARTIAL,
            findings=findings,
            data={**data, "ipl_age_days": age_days},
        )


# Enumerate one working java per /usr/lpp/java install dir (no current-symlink
# dupes), plus any java on PATH. Each block is tagged "=== JRE: <path> ===".
_JAVA_SWEEP_CMD = (
    'command -v java >/dev/null 2>&1 && { echo "=== JRE: (PATH) ==="; java -version 2>&1; }; '
    "for d in /usr/lpp/java/*/; do "
    'jb=""; for cand in "$d"bin/java "$d"*_64/bin/java "$d"J*/bin/java; do '
    '[ -x "$cand" ] && { jb="$cand"; break; }; done; '
    '[ -n "$jb" ] && { echo "=== JRE: ${jb} ==="; "$jb" -version 2>&1; }; '
    "done"
)


def _parse_java_version(block: str) -> str | None:
    """Extract a comparable 4-part version: IBM SR build (8.0.8.15) or
    Semeru/OpenJDK quad (11.0.22.0); fall back to the 'version' string."""
    build = re.search(r"build (\d+\.\d+\.\d+\.\d+)", block)
    if build:
        return build.group(1)
    quad = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", block)
    if quad:
        return quad.group(1)
    ver = re.search(r'version "?([0-9][0-9._]+)', block)
    return ver.group(1).replace("_", ".") if ver else None


class CVEExposureCheck(BaseCheck):
    """MYT-V02: Known-CVE exposure across all installed JREs (offline map).

    Sweeps every JRE under /usr/lpp/java (java8/11/17/… incl. WebSphere's
    bundled runtimes), since java is usually not on PATH. Each JRE's version is
    matched against the offline CVE map *within its own major* to avoid
    cross-version false matches. Validated live on z/OS 3.1.
    """

    control_id = "MYT-V02"
    control_name = "Known-CVE exposure for installed JREs"
    nist_function = "Identify"
    priority = "P0"
    frameworks = ("mythos",)
    mythos_dimension = "V"
    validation_method = "Hybrid"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command(_JAVA_SWEEP_CMD)

    def parse(self, output: str) -> dict[str, Any]:
        jres: list[dict[str, Any]] = []
        blocks = re.split(r"=== JRE: (.*?) ===", output)
        # re.split keeps captured paths: [pre, path1, body1, path2, body2, ...]
        if len(blocks) > 1:
            for i in range(1, len(blocks), 2):
                path = blocks[i].strip()
                ver = _parse_java_version(blocks[i + 1])
                if ver:
                    jres.append({"path": path, "version": ver})
        else:
            ver = _parse_java_version(output)
            if ver:
                jres.append({"path": "(unknown)", "version": ver})
        # de-dup identical (version) entries (PATH java often symlinks an install)
        seen: set[str] = set()
        uniq = []
        for j in jres:
            if j["version"] not in seen:
                seen.add(j["version"])
                uniq.append(j)
        return {"component": "java", "jres": uniq}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        jres = data.get("jres", [])
        if not jres:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["No JRE versions could be determined"],
                data=data,
            )
        cve_map = _load_cve_map()
        if cve_map is None:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["Offline CVE map unavailable — verify component CVEs manually"],
                data=data,
            )
        java_entries = cve_map.get("java", [])
        findings: list[str] = []
        any_vuln = False
        for jre in jres:
            ver = jre["version"]
            major = _version_tuple(ver)[0]
            hits: list[str] = []
            for entry in java_entries:
                emax = entry["max_vulnerable_version"]
                if _version_tuple(emax)[0] != major:  # same-major only
                    continue
                if _version_tuple(ver) <= _version_tuple(emax):
                    hits.extend(entry["cves"])
            jre["cves"] = sorted(set(hits))
            if hits:
                any_vuln = True
                findings.append(f"VULNERABLE  java {ver} ({jre['path']}): {', '.join(jre['cves'])}")
            else:
                findings.append(f"clean       java {ver} ({jre['path']})")
        n = len(jres)
        vuln_n = sum(1 for j in jres if j.get("cves"))
        findings.insert(0, f"{n} JRE(s) inspected, {vuln_n} with known CVEs in offline map")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.FAIL if any_vuln else CheckStatus.PASS,
            findings=findings,
            data=data,
        )


# Probe real version commands for common USS/OSS components, tolerating absence
# (java is not on PATH on z/OS; openssl/python likewise often live off PATH).
_USS_PKG_CMD = (
    "ssh -V 2>&1; "
    "openssl version 2>&1; "
    "(python3 --version 2>&1 || "
    "for p in /usr/lpp/IBM/cyp/*/*/bin/python3 /usr/lpp/IBM/python3*/*/bin/python3; do "
    '[ -x "$p" ] && { "$p" --version 2>&1; break; }; done); '
    "(zoaversion 2>&1 || "
    'for z in /usr/lpp/IBM/zoautil/bin/zoaversion; do [ -x "$z" ] && { "$z" 2>&1; break; }; done)'
)

# component -> (regex capturing version, minimum acceptable version)
_USS_COMPONENTS: list[tuple[str, str, str]] = [
    ("openssh", r"OpenSSH_(\d+\.\d+)", "9.8"),
    ("libressl", r"LibreSSL (\d+\.\d+\.\d+)", "3.8.0"),
    ("openssl", r"OpenSSL (\d+\.\d+\.\d+)", "3.0.14"),
    ("python", r"Python (\d+\.\d+\.\d+)", "3.11.0"),
    ("zoau", r"(?:zoau|ZOAU)[^\d]*(\d+\.\d+\.\d+)", "1.3.0"),
]


class USSComponentPatchCheck(BaseCheck):
    """MYT-V07: USS / open-source component patch currency.

    Probes real version commands (ssh -V, openssl version, python3, zoaversion)
    and compares each detected component against a minimum acceptable version.
    Components that aren't installed are simply omitted. Validated live on
    z/OS 3.1 (OpenSSH/LibreSSL present; others absent on a minimal system).
    """

    control_id = "MYT-V07"
    control_name = "USS / open-source component patch currency"
    nist_function = "Identify"
    priority = "P1"
    frameworks = ("mythos",)
    mythos_dimension = "V"
    validation_method = "Hybrid"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command(_USS_PKG_CMD)

    def parse(self, output: str) -> dict[str, Any]:
        components: dict[str, str] = {}
        for name, pattern, _min in _USS_COMPONENTS:
            m = re.search(pattern, output)
            if m:
                components[name] = m.group(1)
        return {"components": components}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        components = data.get("components", {})
        if not components:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["No USS/OSS component versions detected"],
                data=data,
            )
        mins = {name: minv for name, _p, minv in _USS_COMPONENTS}
        outdated: list[str] = []
        findings: list[str] = []
        for name, ver in components.items():
            minv = mins[name]
            if _version_tuple(ver) < _version_tuple(minv):
                outdated.append(name)
                findings.append(f"OUTDATED  {name} {ver} (< {minv})")
            else:
                findings.append(f"current   {name} {ver} (>= {minv})")
        findings.insert(0, f"{len(components)} component(s) inspected, {len(outdated)} outdated")
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.FAIL if outdated else CheckStatus.PASS,
            findings=findings,
            data={**data, "outdated": outdated},
        )


class ImmutableBackupCheck(BaseCheck):
    """MYT-X01: Immutable backup / Safeguarded Copy presence (first Recover check)."""

    control_id = "MYT-X01"
    control_name = "Immutable backup / Safeguarded Copy presence"
    nist_function = "Recover"
    priority = "P0"
    frameworks = ("mythos",)
    mythos_dimension = "X"
    validation_method = "Hybrid"

    def execute(self, connection: BaseConnection) -> str:
        # Safeguarded Copy is a DS8000 storage-layer feature not directly
        # displayable from z/OS; enumerate SMS storage groups and look for any
        # immutability indicator, otherwise defer to the questionnaire.
        return connection.execute_console_command("D SMS,SG(ALL)")

    def parse(self, output: str) -> dict[str, Any]:
        from znextscan.parsers.racf_parser import parse_sms_storage_groups

        groups = parse_sms_storage_groups(output)
        names = [g["name"] for g in groups]
        # COPY-type storage groups are the z/OS-observable FlashCopy/Safeguarded
        # Copy signal (same logic as EXT-021).
        copy_groups = [g["name"] for g in groups if g.get("type") == "COPY"]
        return {"storage_groups": names, "count": len(names), "copy_groups": copy_groups}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        copy_groups = data.get("copy_groups", [])
        if copy_groups:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                findings=[
                    "FlashCopy/Safeguarded Copy storage group(s) present: "
                    + ", ".join(copy_groups),
                    "Confirm immutability/retention enforcement at the storage layer "
                    "(DS8000) via questionnaire (MYT-X02/X04).",
                ],
                data=data,
            )
        n = data.get("count", 0)
        if n == 0:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["No SMS storage groups enumerated — verify backup via questionnaire"],
                data=data,
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PARTIAL,
            findings=[
                f"{n} SMS storage groups, but no COPY-type (FlashCopy/Safeguarded Copy) "
                "infrastructure detected — ransomware could encrypt backups. Confirm "
                "immutable/air-gapped backup via questionnaire (MYT-X02/X04).",
                "Storage groups: " + ", ".join(data.get("storage_groups", [])),
            ],
            data=data,
        )


class SourceExposureReconCheck(BaseCheck):
    """MYT-R02: Authorization-gated source/component exposure reconnaissance.

    Performs NO external query unless recon is enabled, authorization is recorded,
    and identifiers are supplied. When gated off it returns ``Skipped`` with the
    reason (never an error), satisfying the spec's authorization scenarios.
    """

    control_id = "MYT-R02"
    control_name = "Source/component exposure reconnaissance"
    nist_function = "Identify"
    priority = "P0"
    frameworks = ("mythos",)
    mythos_dimension = "R"
    validation_method = "Scanner"

    def execute(self, connection: BaseConnection) -> str:
        # connection is unused — this control reconnoiters external sources.
        from znextscan.recon import get_context, run_recon
        from znextscan.recon.engine import authorize

        ctx = get_context()
        ok, reason = authorize(ctx)
        if not ok:
            raise CommandNotSupportedError(reason)
        assert ctx is not None
        findings = run_recon(ctx)
        return json.dumps(
            [
                {"source": f.source, "title": f.title, "url": f.url, "detail": f.detail}
                for f in findings
            ]
        )

    def parse(self, output: str) -> dict[str, Any]:
        items = json.loads(output) if output else []
        return {"findings": items, "count": len(items)}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        items = data.get("findings", [])
        if not items:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                findings=["No external mainframe source/component exposure detected"],
                data=data,
            )
        # Redaction-safe: only source/title/url, never response bodies.
        listed = [f"[{i['source']}] {i['title']} {i['url']}".strip() for i in items[:25]]
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.FAIL,
            findings=[f"{len(items)} potential exposure(s) found:"] + listed,
            data=data,
        )


_MFADEF_DELIM = "@@MFADEF@@"


class MFACoverageCheck(BaseCheck):
    """MYT-C10: MFA framework coverage for privileged/vendor access.

    Scriptable signal: is the RACF MFADEF class active and are factor profiles
    defined? Per-user enrollment coverage is deferred to the questionnaire
    (Hybrid). Validated live on z/OS 3.1 (MFADEF not active → no MFA framework).
    """

    control_id = "MYT-C10"
    control_name = "MFA coverage for privileged & vendor access"
    nist_function = "Protect"
    priority = "P0"
    frameworks = ("mythos",)
    mythos_dimension = "C"
    validation_method = "Hybrid"

    def execute(self, connection: BaseConnection) -> str:
        setropts = connection.execute_tso_command("SETROPTS LIST")
        # RLIST MFADEF is optional enrichment — on older RACF the MFADEF class may
        # not be defined; tolerate a failure rather than erroring the whole check.
        try:
            mfadef = connection.execute_tso_command("RLIST MFADEF * ALL")
        except Exception:
            mfadef = ""
        return f"{setropts}\n{_MFADEF_DELIM}\n{mfadef}"

    def parse(self, output: str) -> dict[str, Any]:
        from znextscan.parsers.racf_parser import parse_active_classes

        setropts, _, mfadef = output.partition(_MFADEF_DELIM)
        active = {c.upper() for c in parse_active_classes(setropts)}
        has_factors = "NOTHING TO LIST" not in mfadef.upper() and bool(mfadef.strip())
        return {"mfadef_active": "MFADEF" in active, "has_factor_profiles": has_factors}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        if not data.get("mfadef_active"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=[
                    "MFADEF class is NOT active — no RACF MFA framework configured; "
                    "privileged/vendor access relies on passwords alone (high Mythos risk)."
                ],
                data=data,
            )
        if not data.get("has_factor_profiles"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PARTIAL,
                findings=[
                    "MFADEF class active but no factor profiles defined — MFA not usable yet"
                ],
                data=data,
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PARTIAL,
            findings=[
                "MFA framework present (MFADEF active, factor profiles defined). "
                "Per-user enrollment coverage for privileged/vendor IDs — confirm via "
                "questionnaire (MYT-C10)."
            ],
            data=data,
        )


_TCPIP_DELIM = "@@TCPIP@@"
# Web/API listening ports that mark an HTTP/API "glass-box" surface.
_WEB_PORTS = {"80", "443", "8080", "8443", "9080", "9443", "10443", "8180", "9043"}

# Address-space name patterns for API / modernization "glass-box" servers.
_API_SERVERS: list[tuple[str, str]] = [
    ("z/OSMF (Liberty)", r"\bIZUSVR\d*\b"),
    ("z/OSMF Angel", r"\bIZUANG\d*\b"),
    ("z/OS Connect EE", r"\bBAQ[A-Z0-9]*\b"),
    ("WAS/Liberty", r"\bBB[OG][A-Z0-9]*\b"),
    ("z/OS Connect (ZCEE)", r"\bZCEE[A-Z0-9]*\b"),
    ("LDAP (GLD)", r"\bGLD[A-Z0-9]*\b"),
    ("HTTP Server", r"\b(?:IMWEBSRV|HTTPD|DFHWS)[A-Z0-9]*\b"),
]


class APISurfaceCheck(BaseCheck):
    """MYT-R05: z/OS Connect / Liberty API glass-box inventory.

    Detects API/modernization server address spaces (z/OSMF, Liberty, z/OS
    Connect, WAS) from ``D A,L`` — the readable HTTP/API layer that is a
    frontier-AI modernization-exposure vector. Validated live on z/OS 3.1.
    """

    control_id = "MYT-R05"
    control_name = "z/OS Connect / API glass-box inventory"
    nist_function = "Identify"
    priority = "P1"
    frameworks = ("mythos",)
    mythos_dimension = "R"
    validation_method = "Scanner"

    def execute(self, connection: BaseConnection) -> str:
        dal = connection.execute_console_command("D A,L")
        # Port enrichment is optional — tolerate auth/proc-name/console failures
        # so name-based detection from D A,L still returns a result.
        try:
            tcp = connection.execute_console_command("D TCPIP,,N,CONN")
        except Exception:
            tcp = ""
        return f"{dal}\n{_TCPIP_DELIM}\n{tcp}"

    def parse(self, output: str) -> dict[str, Any]:
        dal, _, tcp = output.partition(_TCPIP_DELIM)
        # Name-based detection from D A,L
        detected: dict[str, list[str]] = {}
        for label, pattern in _API_SERVERS:
            matches = sorted(set(re.findall(pattern, dal)))
            if matches:
                detected[label] = matches
        # Behaviour-based detection: address spaces LISTENing on web/API ports
        # (catches servers whose name doesn't match, e.g. z/OS Connect ZOSCSRV).
        from znextscan.parsers.racf_parser import parse_netstat_conn

        api_listeners: dict[str, list[str]] = {}
        for c in parse_netstat_conn(tcp):
            if c["state"] == "LISTEN" and c["port"] in _WEB_PORTS:
                ports = api_listeners.setdefault(c["userid"], [])
                if c["port"] not in ports:
                    ports.append(c["port"])
        surface = set(api_listeners) | {n for names in detected.values() for n in names}
        return {
            "api_servers": detected,
            "api_listeners": api_listeners,
            "surface": sorted(surface),
            "count": len(surface),
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        surface = data.get("surface", [])
        if not surface:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                findings=["No API/modernization server address spaces or web listeners detected"],
                data=data,
            )
        findings = [f"{len(surface)} API/modernization 'glass-box' address space(s):"]
        for job, ports in data.get("api_listeners", {}).items():
            findings.append(f"  {job} LISTEN :{','.join(ports)}")
        for label, names in data.get("api_servers", {}).items():
            findings.append(f"  {label}: {', '.join(names)}")
        findings.append(
            "Readable API/HTTP surface raises Mythos exposure — review egress/DLP (MYT-C11) "
            "and source exposure (MYT-R02)."
        )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PARTIAL,
            findings=findings,
            data=data,
        )


class USSHardeningCheck(BaseCheck):
    """MYT-C12: USS file-permission hardening.

    Three signals via one USS probe:
      * world/group-writable setuid/setgid files — CRITICAL (trivial privesc)
      * world-writable files in /etc, /var — FAIL
      * setuid/setgid inventory — informational count
    Validated live on z/OS 3.1 (found /etc/ipnodes world-writable; no dangerous
    setuid). Skips gracefully when USS is unavailable (z/OSMF-only).
    """

    control_id = "MYT-C12"
    control_name = "USS hardening (file permissions)"
    nist_function = "Protect"
    priority = "P1"
    frameworks = ("mythos",)
    mythos_dimension = "C"
    validation_method = "Scanner"

    _CMD = (
        'echo "@@WW@@"; find /etc /var -xdev -type f -perm -0002 2>/dev/null; '
        'echo "@@COMBO@@"; find /bin /usr/sbin /etc /var -xdev '
        "\\( -perm -4000 -o -perm -2000 \\) \\( -perm -0002 -o -perm -0020 \\) 2>/dev/null; "
        'echo "@@SETUID@@"; find /bin /usr/sbin -xdev \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null'
    )

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_uss_command(self._CMD)

    def parse(self, output: str) -> dict[str, Any]:
        sections: dict[str, str] = {}
        parts = re.split(r"@@(WW|COMBO|SETUID)@@", output)
        for i in range(1, len(parts) - 1, 2):
            sections[parts[i]] = parts[i + 1]

        def paths(key: str) -> list[str]:
            return [
                l.strip() for l in sections.get(key, "").splitlines() if l.strip().startswith("/")
            ]

        setuid = paths("SETUID")
        return {
            "world_writable": paths("WW"),
            "dangerous_setuid": paths("COMBO"),
            "setuid_count": len(setuid),
            "probe_ran": bool(sections),  # markers echoed back ⇒ the find probe ran
        }

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        ww = data.get("world_writable", [])
        combo = data.get("dangerous_setuid", [])
        n_su = data.get("setuid_count", 0)
        if not data.get("probe_ran"):
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=["USS hardening probe produced no output — verify via questionnaire"],
                data=data,
            )
        if combo:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=[
                    f"CRITICAL: {len(combo)} world/group-writable setuid/setgid file(s) — "
                    "trivial privilege escalation:",
                    *[f"  {p}" for p in combo[:15]],
                ],
                data=data,
            )
        if ww:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=[
                    f"{len(ww)} world-writable file(s) in /etc or /var — remove o+w:",
                    *[f"  {p}" for p in ww[:15]],
                    f"({n_su} setuid/setgid binaries inventoried, none writable)",
                ],
                data=data,
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            findings=[f"No world-writable files in /etc or /var; {n_su} setuid/setgid binaries"],
            data=data,
        )


class SMFForwardingCheck(BaseCheck):
    """MYT-X08: SMF/audit forwarding to SIEM (real-time readiness).

    SMF recording via System Logger log streams (LOGSTREAM) is forwarding-capable
    for real-time SIEM ingestion; dataset recording is batch-only. The actual
    SIEM forwarding config is off-platform, so it's deferred to the questionnaire
    (Hybrid). Validated live on z/OS 3.1.
    """

    control_id = "MYT-X08"
    control_name = "SMF/audit forwarding to SIEM (real-time readiness)"
    nist_function = "Detect"
    priority = "P1"
    frameworks = ("mythos",)
    mythos_dimension = "X"
    validation_method = "Hybrid"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_console_command("D SMF,O")

    def parse(self, output: str) -> dict[str, Any]:
        from znextscan.parsers.racf_parser import parse_smf_status

        s = parse_smf_status(output)
        return {"active": s.get("active"), "recording_method": s.get("recording_method")}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        method = (data.get("recording_method") or "").upper()
        if method == "LOGSTREAM":
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.PARTIAL,
                findings=[
                    "SMF recording via System Logger log streams — real-time "
                    "forwarding-capable. Confirm SIEM ingestion of the log streams "
                    "via questionnaire (MYT-X08).",
                ],
                data=data,
            )
        if method == "DATASET":
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                findings=[
                    "SMF recording to datasets (batch) — not real-time SIEM-ready; "
                    "move to LOGSTREAM recording for machine-speed detection."
                ],
                data=data,
            )
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.SKIPPED,
            findings=["SMF recording method undetermined — verify via questionnaire"],
            data=data,
        )


MYTHOS_NATIVE_CHECKS: list[type[BaseCheck]] = [
    OperationalCodeSurfaceCheck,
    SourceExposureReconCheck,
    SMPECurrencyCheck,
    CVEExposureCheck,
    USSComponentPatchCheck,
    ImmutableBackupCheck,
    MFACoverageCheck,
    APISurfaceCheck,
    USSHardeningCheck,
    SMFForwardingCheck,
]
