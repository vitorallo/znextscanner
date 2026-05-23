"""Tests for Mythos-native scriptable checks."""

from pathlib import Path

import pytest

from znextscan.checks.base_check import CheckStatus
from znextscan.checks.mythos_checks import (
    APISurfaceCheck,
    CVEExposureCheck,
    ImmutableBackupCheck,
    MFACoverageCheck,
    OperationalCodeSurfaceCheck,
    SMFForwardingCheck,
    SMPECurrencyCheck,
    USSComponentPatchCheck,
    USSHardeningCheck,
    _MFADEF_DELIM,
    _PROCLIB_DELIM,
    _TCPIP_DELIM,
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
