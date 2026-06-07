"""Tests for Mythos-native scriptable checks."""

from pathlib import Path

import pytest

from znextscan.checks.base_check import CheckStatus
from znextscan.checks.mythos_checks import (
    _C16_DELIM,
    _MFADEF_DELIM,
    _PROCLIB_DELIM,
    _R10_ROLE_DELIM,
    _R10_TCP_DELIM,
    _TCPIP_DELIM,
    APISurfaceCheck,
    CVEExposureCheck,
    DeveloperPlaneAccessCheck,
    DeveloperPlaneLoggingCheck,
    ImmutableBackupCheck,
    MFACoverageCheck,
    OperationalCodeSurfaceCheck,
    RESTAPIExposureCheck,
    SMFForwardingCheck,
    SMPECurrencyCheck,
    USSComponentPatchCheck,
    USSHardeningCheck,
)
from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.connections.mock import MockConnection

FIXTURES = str(Path(__file__).parent / "fixtures")
REAL_DIR = Path(__file__).parent / "fixtures" / "real_zos"


@pytest.fixture
def conn() -> MockConnection:
    return MockConnection(FIXTURES)


class _UnsupportedConnection(BaseConnection):
    def execute_tso_command(self, command: str) -> str:
        raise CommandNotSupportedError(f"unsupported: {command}")

    def execute_console_command(self, command: str) -> str:
        raise CommandNotSupportedError(f"unsupported: {command}")

    def execute_uss_command(self, command: str) -> str:
        raise CommandNotSupportedError(f"unsupported: {command}")

    def close(self) -> None:
        pass


def test_r01_operational_code_surface(conn: MockConnection) -> None:
    r = OperationalCodeSurfaceCheck().run(conn)
    assert r.control_id == "MYT-R01"
    assert r.status in (CheckStatus.PASS, CheckStatus.PARTIAL)
    # SYSEXEC/SYSPROC concatenations parsed from LISTALC
    assert "ISP.SISPEXEC" in r.data["rexx_clist_libs"]
    assert "ISP.SISPCLIB" in r.data["rexx_clist_libs"]
    # PROCLIB datasets parsed from $D PROCLIB
    assert "SYS1.PROCLIB" in r.data["proclib"]
    assert "K2.PROCLIB" in r.data["proclib"]
    assert r.data["total"] >= 5


def test_v01_currency_proxy_from_iplinfo(conn: MockConnection) -> None:
    r = SMPECurrencyCheck().run(conn)
    assert r.control_id == "MYT-V01"
    # Hybrid: D IPLINFO yields release + IPL date; PTF currency deferred to questionnaire.
    assert r.status == CheckStatus.PARTIAL
    assert r.data["release"] == "z/OS 03.01.00"
    assert any("questionnaire" in f.lower() for f in r.findings)


def test_v02_cve_sweep_across_jres(conn: MockConnection) -> None:
    r = CVEExposureCheck().run(conn)
    assert r.control_id == "MYT-V02"
    versions = {j["version"] for j in r.data["jres"]}
    # Three JREs swept (java8/11/17), parsed to comparable quads.
    assert {"8.0.8.15", "11.0.22.0", "17.0.9.0"}.issubset(versions)
    # java8 8.0.8.15 is newer than the map's 8.0.8.10 -> clean (no cross-major match).
    j8 = next(j for j in r.data["jres"] if j["version"] == "8.0.8.15")
    assert j8["cves"] == []
    # java11 / java17 are flagged -> overall FAIL.
    j11 = next(j for j in r.data["jres"] if j["version"] == "11.0.22.0")
    assert "CVE-2024-20952" in j11["cves"]
    assert r.status == CheckStatus.FAIL


def test_v07_uss_components_current(conn: MockConnection) -> None:
    r = USSComponentPatchCheck().run(conn)
    assert r.control_id == "MYT-V07"
    assert r.status == CheckStatus.PASS
    comps = r.data["components"]
    assert comps.get("openssh") == "9.9"
    assert comps.get("python") == "3.11.4"
    assert r.data["outdated"] == []


def test_x01_copy_storage_group_pass(conn: MockConnection) -> None:
    r = ImmutableBackupCheck().run(conn)
    assert r.control_id == "MYT-X01"
    # Mock fixture has a COPY-type storage group (SGCOPY) = FlashCopy/Safeguarded infra.
    assert r.status == CheckStatus.PASS
    assert "SGCOPY" in r.data["copy_groups"]


def test_x01_no_copy_defers_to_questionnaire() -> None:
    chk = ImmutableBackupCheck()
    out = "STORGRP  TYPE\nSGBASE   POOL            +\nSGAPPL   POOL            +\n"
    r = chk.evaluate(chk.parse(out))
    # No COPY-type SG → can't confirm immutable backup from z/OS → PARTIAL + questionnaire.
    assert r.status == CheckStatus.PARTIAL
    assert r.data["copy_groups"] == []
    assert any("questionnaire" in f.lower() for f in r.findings)


def test_c10_mfa_not_active(conn: MockConnection) -> None:
    r = MFACoverageCheck().run(conn)
    assert r.control_id == "MYT-C10"
    # Mock SETROPTS has no MFADEF in active classes -> FAIL (no MFA framework).
    assert r.status == CheckStatus.FAIL
    assert r.data["mfadef_active"] is False


def test_c10_mfa_partial_when_framework_present() -> None:
    chk = MFACoverageCheck()
    out = (
        "ACTIVE CLASSES = DATASET USER MFADEF FACILITY\n"
        f"{_MFADEF_DELIM}\n"
        "CLASS      NAME\n-----      ----\nMFADEF     AZFSIDP1\n"
    )
    r = chk.evaluate(chk.parse(out))
    assert r.status == CheckStatus.PARTIAL
    assert r.data["mfadef_active"] is True
    assert r.data["has_factor_profiles"] is True


def test_r05_api_surface(conn: MockConnection) -> None:
    r = APISurfaceCheck().run(conn)
    assert r.control_id == "MYT-R05"
    # Mock D A,L fixture contains IZUANG1 (z/OSMF angel); D TCPIP shows IZUSVR1:10443.
    assert r.status == CheckStatus.PARTIAL
    assert "z/OSMF Angel" in r.data["api_servers"]
    assert "IZUSVR1" in r.data["api_listeners"]
    assert "10443" in r.data["api_listeners"]["IZUSVR1"]


def test_c12_dangerous_setuid_critical(conn: MockConnection) -> None:
    r = USSHardeningCheck().run(conn)
    assert r.control_id == "MYT-C12"
    # Mock fixture has a world-writable setuid file -> CRITICAL FAIL (takes precedence).
    assert r.status == CheckStatus.FAIL
    assert r.data["dangerous_setuid"] == ["/var/tmp/rogue_suid"]
    assert "/etc/ipnodes" in r.data["world_writable"]
    assert "CRITICAL" in r.findings[0]


def test_c12_world_writable_only() -> None:
    chk = USSHardeningCheck()
    out = "@@WW@@\n/etc/ipnodes\n@@COMBO@@\n@@SETUID@@\n/bin/at\n/bin/su\n"
    r = chk.evaluate(chk.parse(out))
    assert r.status == CheckStatus.FAIL
    assert r.data["dangerous_setuid"] == []
    assert "/etc/ipnodes" in r.data["world_writable"]
    assert r.data["setuid_count"] == 2


def test_x08_smf_logstream_partial(conn: MockConnection) -> None:
    r = SMFForwardingCheck().run(conn)
    assert r.control_id == "MYT-X08"
    # Mock SMF fixture records via LOGSTREAM -> forwarding-capable (PARTIAL).
    assert r.status == CheckStatus.PARTIAL
    assert r.data["recording_method"] == "LOGSTREAM"


# --- §6.1 expansion checks (M9–M12) ---


def test_r10_developer_plane_inventory(conn: MockConnection) -> None:
    r = DeveloperPlaneAccessCheck().run(conn)
    assert r.control_id == "MYT-R10"
    # Mock D A,L has IZUANG1 (z/OSMF angel); D TCPIP shows IZUSVR1:10443 + SSHD:22.
    assert r.status == CheckStatus.PARTIAL
    assert "z/OSMF Angel" in r.data["servers"]
    assert "IZUSVR1" in r.data["listeners"]
    assert "10443" in r.data["listeners"]["IZUSVR1"]["ports"]
    assert r.data["listeners"]["IZUSVR1"]["exposed"] is True
    # EJBROLE roles enumerated with privileged-role counts (no userids in findings).
    assert r.data["role_count"] == 3
    assert r.data["privileged_role_count"] == 2
    assert r.data["total_permitted_ids"] == 5
    assert not any("IBMUSER" in f for f in r.findings)


def test_r10_passes_when_no_dev_plane() -> None:
    chk = DeveloperPlaneAccessCheck()
    out = f"  SOMEJOB  SOMEJOB  STEP1  NSW S\n{_R10_TCP_DELIM}\n\n{_R10_ROLE_DELIM}\n"
    r = chk.evaluate(chk.parse(out))
    assert r.status == CheckStatus.PASS
    assert r.data["surface_count"] == 0


def test_c16_exposed_listener_fails(conn: MockConnection) -> None:
    r = RESTAPIExposureCheck().run(conn)
    assert r.control_id == "MYT-C16"
    # Mock D TCPIP: IZUSVR1 listens 0.0.0.0..10443 -> reachable on all interfaces -> FAIL.
    assert r.status == CheckStatus.FAIL
    assert any(l["port"] == "10443" for l in r.data["exposed"])
    assert any("questionnaire" in f.lower() for f in r.findings)


def test_c16_bound_listener_partial() -> None:
    chk = RESTAPIExposureCheck()
    tcp = (
        " USER ID  CONN     LOCAL SOCKET           FOREIGN SOCKET         STATE\n"
        " IZUSVR1  00000082 192.168.10.5..10443    0.0.0.0..0             LISTEN\n"
    )
    r = chk.evaluate(chk.parse(f"{tcp}\n{_C16_DELIM}\n"))
    assert r.status == CheckStatus.PARTIAL
    assert r.data["exposed"] == []


def test_c16_no_listener_skips() -> None:
    chk = RESTAPIExposureCheck()
    r = chk.evaluate(chk.parse(f"no listeners here\n{_C16_DELIM}\n"))
    assert r.status == CheckStatus.SKIPPED


def test_x12_missing_type_119_fails(conn: MockConnection) -> None:
    r = DeveloperPlaneLoggingCheck().run(conn)
    assert r.control_id == "MYT-X12"
    # Mock D SMF,O records type 80 (75:83) via LOGSTREAM but NOT type 119.
    assert r.status == CheckStatus.FAIL
    assert r.data["has_type_80"] is True
    assert r.data["has_type_119"] is False
    assert any("119" in f for f in r.findings)


def test_x12_full_coverage_logstream_partial() -> None:
    chk = DeveloperPlaneLoggingCheck()
    out = (
        "        SYS(TYPE(0,30,80,119,120)) -- PARMLIB\n"
        "        RECORDING(LOGSTREAM) -- PARMLIB\n"
        "        ACTIVE -- PARMLIB\n"
    )
    r = chk.evaluate(chk.parse(out))
    assert r.status == CheckStatus.PARTIAL
    assert r.data["has_type_119"] is True


def test_x12_dataset_recording_fails() -> None:
    chk = DeveloperPlaneLoggingCheck()
    out = (
        "        SYS(TYPE(0,30,80,119)) -- PARMLIB\n"
        "        RECORDING(DATASET) -- PARMLIB\n"
        "        ACTIVE -- PARMLIB\n"
    )
    r = chk.evaluate(chk.parse(out))
    assert r.status == CheckStatus.FAIL
    assert any("batch" in f.lower() for f in r.findings)


@pytest.mark.parametrize(
    "check_cls",
    [
        SMPECurrencyCheck,
        CVEExposureCheck,
        USSComponentPatchCheck,
        ImmutableBackupCheck,
        MFACoverageCheck,
        USSHardeningCheck,
        SMFForwardingCheck,
        DeveloperPlaneAccessCheck,
        RESTAPIExposureCheck,
        DeveloperPlaneLoggingCheck,
    ],
)
def test_hybrid_checks_skip_when_unsupported(check_cls: type) -> None:
    r = check_cls().run(_UnsupportedConnection())
    assert r.status == CheckStatus.SKIPPED


def _real(name: str) -> str:
    p = REAL_DIR / name
    if not p.exists():
        pytest.skip(f"No real z/OS capture: {name}")
    return p.read_text()


class TestRealZosCaptures:
    """Validate parsers against authentic z/OS 3.1 output (captured 2026-05-22)."""

    def test_r01_real(self) -> None:
        combined = (
            f"{_real('tso_LISTA_STATUS.txt')}\n{_PROCLIB_DELIM}\n{_real('console_D_PROCLIB.txt')}"
        )
        data = OperationalCodeSurfaceCheck().parse(combined)
        assert "ISP.SISPEXEC" in data["rexx_clist_libs"]
        assert "SYS1.PROCLIB" in data["proclib"]
        assert data["total"] >= 5

    def test_v01_real(self) -> None:
        data = SMPECurrencyCheck().parse(_real("console_D_IPLINFO.txt"))
        assert data["release"] and data["release"].startswith("z/OS")
        assert data["ipl_date"]

    def test_v02_real(self) -> None:
        data = CVEExposureCheck().parse(_real("uss_java_sweep.txt"))
        versions = {j["version"] for j in data["jres"]}
        assert "11.0.22.0" in versions  # Semeru quad parsed
        assert len(data["jres"]) >= 3

    def test_v07_real(self) -> None:
        data = USSComponentPatchCheck().parse(_real("uss_pkg_versions.txt"))
        assert "openssh" in data["components"]

    def test_x01_real(self) -> None:
        data = ImmutableBackupCheck().parse(_real("console_D_SMS_SG.txt"))
        assert data["count"] >= 1

    def test_c10_real(self) -> None:
        combined = (
            f"{_real('tso_SETROPTS_LIST.txt')}\n{_MFADEF_DELIM}\n{_real('tso_RLIST_MFADEF.txt')}"
        )
        data = MFACoverageCheck().parse(combined)
        # Ground truth: MFADEF not active on this lab.
        assert data["mfadef_active"] is False

    def test_r05_real(self) -> None:
        combined = (
            f"{_real('console_D_A_L.txt')}\n{_TCPIP_DELIM}\n{_real('console_D_TCPIP_CONN.txt')}"
        )
        data = APISurfaceCheck().parse(combined)
        assert data["count"] >= 1
        # z/OSMF Liberty listens on 10443; ZOSCSRV (z/OS Connect) caught by port 9443.
        listeners = data["api_listeners"]
        assert any("10443" in ports for ports in listeners.values())

    def test_c12_real(self) -> None:
        data = USSHardeningCheck().parse(_real("uss_perms.txt"))
        assert "/etc/ipnodes" in data["world_writable"]
        assert data["dangerous_setuid"] == []
        assert data["setuid_count"] >= 10

    def test_x08_real(self) -> None:
        data = SMFForwardingCheck().parse(_real("console_D_SMF_O.txt"))
        assert data["recording_method"] == "LOGSTREAM"

    def test_r10_real(self) -> None:
        # Authentic z/OS 3.1 captures (D A,L, D TCPIP,,N,CONN, RLIST EJBROLE * ALL),
        # captured live 2026-06-07.
        combined = (
            f"{_real('console_D_A_L.txt')}\n{_R10_TCP_DELIM}\n"
            f"{_real('console_D_TCPIP_CONN.txt')}\n{_R10_ROLE_DELIM}\n"
            f"{_real('tso_RLIST_EJBROLE.txt')}"
        )
        data = DeveloperPlaneAccessCheck().parse(combined)
        # Real lab: IZUSVR1 (z/OSMF), ZOSCSRV (z/OS Connect), SSHD daemons present.
        assert "z/OSMF (Liberty)" in data["servers"]
        assert "z/OS Connect" in data["servers"]
        assert "IZUSVR1" in data["listeners"]
        assert "10443" in data["listeners"]["IZUSVR1"]["ports"]
        # EJBROLE access list parsed from the real (generic-profile) RLIST format.
        assert data["role_count"] == 1
        assert data["roles"][0]["role"] == "IZUDFLT.*.izuUsers"
        assert data["total_permitted_ids"] == 3

    def test_c16_real(self) -> None:
        data = RESTAPIExposureCheck().parse(
            f"{_real('console_D_TCPIP_CONN.txt')}\n{_C16_DELIM}\n{_real('console_D_A_L.txt')}"
        )
        # Real lab: z/OSMF 10443 and z/OS Connect 9443 listen on 0.0.0.0 -> exposed.
        exposed_ports = {l["port"] for l in data["exposed"]}
        assert "10443" in exposed_ports
        assert "9443" in exposed_ports
        assert data["zosmf_active"] is True

    def test_x12_real(self) -> None:
        data = DeveloperPlaneLoggingCheck().parse(_real("console_D_SMF_O.txt"))
        # Real lab ground truth: type 80 recorded, type 119 NOT recorded, LOGSTREAM.
        assert data["has_type_80"] is True
        assert data["has_type_119"] is False
        assert data["recording_method"] == "LOGSTREAM"
