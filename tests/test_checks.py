"""Tests for concrete check implementations."""

from pathlib import Path

from znextscan.checks.base_check import CheckStatus
from znextscan.checks.enc_checks import CryptoHardwareCheck, ICSFKeyManagementCheck
from znextscan.checks.ext_checks import (
    BackupProcessCheck,
    BackupStorageCheck,
    BatchAllRACFCheck,
    ConsoleSecurityCheck,
    DatasetEncryptionCheck,
    EraseCheck,
    FTPStatusCheck,
    ICHAUTABCheck,
    JavaVersionCheck,
    LogoptionsCheck,
    OperauditCheck,
    ProtectallCheck,
    RACFClassStatusCheck,
    RACFDatabaseProtectionCheck,
    SessionTimeoutCheck,
    SyslogConfigCheck,
    TCPIPStackCheck,
    USSListenersCheck,
    USSProcessCheck,
    VTAMSecurityCheck,
)
from znextscan.checks.iam_checks import (
    DefaultAccountCheck,
    PasswordPolicyCheck,
    SpecialCountCheck,
    StartedTaskCheck,
)
from znextscan.checks.id_checks import APFLibraryCheck, PrivilegedUserCheck
from znextscan.checks.mon_checks import RACFAuditCheck, SMFRecordingCheck
from znextscan.checks.sci_checks import APFIntegrityCheck, ProgramControlCheck
from znextscan.connections.mock import MockConnection

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def make_conn() -> MockConnection:
    return MockConnection(FIXTURE_DIR)


class TestPrivilegedUserCheck:
    def test_run(self) -> None:
        check = PrivilegedUserCheck()
        result = check.run(make_conn())
        assert result.control_id == "ID-002"
        assert result.status in (CheckStatus.PASS, CheckStatus.PARTIAL, CheckStatus.FAIL)
        assert result.data["special_count"] > 0
        assert "IBMUSER" in result.data["special_users"]


class TestAPFLibraryCheck:
    def test_run(self) -> None:
        check = APFLibraryCheck()
        result = check.run(make_conn())
        assert result.control_id == "ID-003"
        assert result.status == CheckStatus.PASS
        assert result.data["count"] == 13


class TestPasswordPolicyCheck:
    def test_run(self) -> None:
        check = PasswordPolicyCheck()
        result = check.run(make_conn())
        assert result.control_id == "IAM-002"
        assert result.data["min_length"] == 8
        assert result.data["history"] == 10
        assert result.data["revoke_count"] == 3

    def test_weak_policy(self) -> None:
        check = PasswordPolicyCheck()
        weak_data = {
            "min_length": 4,
            "history": 2,
            "revoke_count": 10,
            "mixed_case": False,
            "encryption_algorithm": "DES",
        }
        result = check.evaluate(weak_data)
        assert result.status == CheckStatus.FAIL
        assert any("minimum length" in f for f in result.findings)

    def test_v1r13_masked_algorithm(self) -> None:
        """V1R13 uses MASKED encryption — finding should note z/OS 2.3+ requirement."""
        check = PasswordPolicyCheck()
        # V1R13 with weak settings -> FAIL (correct — min_length 6 < 8)
        v1r13_data = {
            "min_length": 6,
            "max_length": 8,
            "history": 5,
            "revoke_count": 5,
            "change_interval": 60,
            "mixed_case": False,
            "encryption_algorithm": "MASKED",
            "inactive_revoke_days": 60,
        }
        result = check.evaluate(v1r13_data)
        assert result.status == CheckStatus.FAIL
        assert any("MASKED" in f and "z/OS 2.3+" in f for f in result.findings)

    def test_v1r13_decent_policy_with_masked(self) -> None:
        """V1R13 with good settings except MASKED encryption -> PARTIAL."""
        check = PasswordPolicyCheck()
        v1r13_decent = {
            "min_length": 8,
            "max_length": 8,
            "history": 8,
            "revoke_count": 3,
            "change_interval": 60,
            "mixed_case": False,
            "encryption_algorithm": "MASKED",
            "inactive_revoke_days": 60,
        }
        result = check.evaluate(v1r13_decent)
        assert result.status == CheckStatus.PARTIAL
        assert any("MASKED" in f for f in result.findings)


class TestDefaultAccountCheck:
    def test_run(self) -> None:
        check = DefaultAccountCheck()
        result = check.run(make_conn())
        assert result.control_id == "IAM-003"
        # IBMUSER has SPECIAL and is not revoked/PROTECTED -> FAIL
        assert result.status == CheckStatus.FAIL
        assert any("IBMUSER" in f for f in result.findings)


class TestSpecialCountCheck:
    def test_run(self) -> None:
        check = SpecialCountCheck()
        result = check.run(make_conn())
        assert result.control_id == "IAM-004"
        assert result.data["count"] == 5
        assert result.status == CheckStatus.PASS

    def test_excessive_special(self) -> None:
        check = SpecialCountCheck()
        result = check.evaluate({"count": 15, "special_users": [f"USER{i}" for i in range(15)]})
        assert result.status == CheckStatus.FAIL


class TestStartedTaskCheck:
    def test_run(self) -> None:
        check = StartedTaskCheck()
        result = check.run(make_conn())
        assert result.control_id == "IAM-005"
        assert result.data["count"] >= 4
        # OMVS and JES2 have TRUSTED=YES
        assert any("TRUSTED" in f for f in result.findings)


class TestSMFRecordingCheck:
    def test_run(self) -> None:
        check = SMFRecordingCheck()
        result = check.run(make_conn())
        assert result.control_id == "MON-001"
        assert result.status == CheckStatus.PASS
        assert result.data["active"] is True
        assert result.data["has_type_80"] is True


class TestRACFAuditCheck:
    def test_run(self) -> None:
        check = RACFAuditCheck()
        result = check.run(make_conn())
        assert result.control_id == "MON-003"
        assert result.status == CheckStatus.PASS
        assert result.data["audit_active"] is True
        assert result.data["saudit"] is True


class TestICSFKeyManagementCheck:
    def test_run(self) -> None:
        check = ICSFKeyManagementCheck()
        result = check.run(make_conn())
        assert result.control_id == "ENC-002"
        assert result.status == CheckStatus.PASS
        assert result.data["active"] is True

    def test_icsf_not_active(self) -> None:
        check = ICSFKeyManagementCheck()
        result = check.evaluate({"active": False})
        assert result.status == CheckStatus.SKIPPED


class TestCryptoHardwareCheck:
    def test_run(self) -> None:
        check = CryptoHardwareCheck()
        result = check.run(make_conn())
        assert result.control_id == "ENC-005"
        assert result.status == CheckStatus.PASS
        assert len(result.data["cards"]) == 2
        assert result.data["cards"][0]["type"] == "CEX8S"

    def test_no_cards(self) -> None:
        check = CryptoHardwareCheck()
        result = check.evaluate({"active": True, "cards": [], "fmid": "HCR77E0"})
        assert result.status == CheckStatus.PARTIAL

    def test_icsf_not_active(self) -> None:
        check = CryptoHardwareCheck()
        result = check.evaluate({"active": False, "cards": []})
        assert result.status == CheckStatus.SKIPPED


class TestAPFIntegrityCheck:
    def test_run(self) -> None:
        check = APFIntegrityCheck()
        result = check.run(make_conn())
        assert result.control_id == "SCI-001"
        assert result.status in (CheckStatus.PASS, CheckStatus.PARTIAL, CheckStatus.FAIL)


class TestProgramControlCheck:
    def test_run(self) -> None:
        check = ProgramControlCheck()
        result = check.run(make_conn())
        assert result.control_id == "SCI-004"
        assert result.status == CheckStatus.PASS
        assert result.data["when_program"] is True

    def test_no_program_control(self) -> None:
        check = ProgramControlCheck()
        result = check.evaluate({"when_program": False, "program_class_active": False})
        assert result.status == CheckStatus.FAIL


# ---- Extended SETROPTS checks (EXT-007 to EXT-010) ----


class TestOperauditCheck:
    def test_run(self) -> None:
        check = OperauditCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-007"
        assert result.status == CheckStatus.PASS

    def test_not_active(self) -> None:
        check = OperauditCheck()
        result = check.evaluate({"operaudit": False})
        assert result.status == CheckStatus.FAIL


class TestLogoptionsCheck:
    def test_run(self) -> None:
        check = LogoptionsCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-008"
        assert result.status == CheckStatus.PASS

    def test_no_failure_logging(self) -> None:
        check = LogoptionsCheck()
        result = check.evaluate({"log_failures": False, "log_successes": False})
        assert result.status == CheckStatus.FAIL


class TestProtectallCheck:
    def test_run(self) -> None:
        check = ProtectallCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-009"
        assert result.status == CheckStatus.PASS

    def test_not_active(self) -> None:
        check = ProtectallCheck()
        result = check.evaluate({"protectall": False})
        assert result.status == CheckStatus.FAIL


class TestEraseCheck:
    def test_run(self) -> None:
        check = EraseCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-010"
        assert result.status == CheckStatus.PASS

    def test_not_active(self) -> None:
        check = EraseCheck()
        result = check.evaluate({"erase": False})
        assert result.status == CheckStatus.PARTIAL


# ---- Extended RLIST checks (EXT-005, EXT-006) ----


class TestVTAMSecurityCheck:
    def test_run(self) -> None:
        check = VTAMSecurityCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-005"
        assert result.data["count"] == 3

    def test_no_profiles(self) -> None:
        check = VTAMSecurityCheck()
        result = check.evaluate({"profiles": [], "count": 0})
        assert result.status == CheckStatus.FAIL

    def test_open_uacc(self) -> None:
        check = VTAMSecurityCheck()
        result = check.evaluate(
            {
                "profiles": [{"name": "TSO", "uacc": "READ"}],
                "count": 1,
            }
        )
        assert result.status == CheckStatus.PARTIAL


class TestConsoleSecurityCheck:
    def test_run(self) -> None:
        check = ConsoleSecurityCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-006"
        assert result.data["count"] == 2
        assert result.status == CheckStatus.PASS

    def test_no_profiles(self) -> None:
        check = ConsoleSecurityCheck()
        result = check.evaluate({"profiles": [], "count": 0})
        assert result.status == CheckStatus.FAIL


# ---- EXT-001, EXT-002, EXT-003, EXT-004, EXT-011 ----


class TestFTPStatusCheck:
    def test_run_ftp_listening(self) -> None:
        check = FTPStatusCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-001"
        # Our fixture has FTP on port 21
        assert result.status == CheckStatus.FAIL
        assert result.data["ftp_listening"] is True

    def test_no_ftp(self) -> None:
        check = FTPStatusCheck()
        result = check.evaluate({"ftp_listening": False, "connections": []})
        assert result.status == CheckStatus.PASS


class TestJavaVersionCheck:
    def test_run(self) -> None:
        check = JavaVersionCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-002"
        assert result.data["installed"] is True
        assert "1.8.0" in result.data["version"]

    def test_not_installed(self) -> None:
        check = JavaVersionCheck()
        result = check.evaluate({"installed": False, "version": None})
        assert result.status == CheckStatus.PASS


class TestSyslogConfigCheck:
    def test_run(self) -> None:
        check = SyslogConfigCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-003"
        assert result.status == CheckStatus.PASS
        assert "siem.example.com" in result.data["remote_destinations"]

    def test_no_file(self) -> None:
        check = SyslogConfigCheck()
        result = check.evaluate({"exists": False})
        assert result.status == CheckStatus.FAIL

    def test_no_remote(self) -> None:
        check = SyslogConfigCheck()
        result = check.evaluate({"exists": True, "remote_destinations": [], "line_count": 3})
        assert result.status == CheckStatus.PARTIAL


class TestSessionTimeoutCheck:
    def test_run(self) -> None:
        check = SessionTimeoutCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-004"
        # Our SETROPTS fixture has SESSION INTERVAL IS 30
        assert result.data["timeout_minutes"] == 30
        assert result.status == CheckStatus.PARTIAL

    def test_good_timeout(self) -> None:
        check = SessionTimeoutCheck()
        result = check.evaluate({"timeout_minutes": 10, "configured": True})
        assert result.status == CheckStatus.PASS

    def test_excessive(self) -> None:
        check = SessionTimeoutCheck()
        result = check.evaluate({"timeout_minutes": 60, "configured": True})
        assert result.status == CheckStatus.FAIL


class TestUSSListenersCheck:
    def test_run(self) -> None:
        check = USSListenersCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-011"
        assert result.data["count"] >= 5
        assert result.status == CheckStatus.PASS


# ---- Tier 2 checks (EXT-012 to EXT-015) ----


class TestUSSProcessCheck:
    def test_run(self) -> None:
        check = USSProcessCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-012"
        assert result.data["total_processes"] >= 10
        notable = result.data["notable"]
        assert any(p["cmd"] == "FTPD" for p in notable)
        assert any(p["cmd"] == "SSHD" for p in notable)
        assert any(p["cmd"] == "httpd" for p in notable)


class TestDatasetEncryptionCheck:
    def test_run(self) -> None:
        check = DatasetEncryptionCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-013"
        # Our fixture has DATACLAS=STANDARD, no encryption
        assert result.status == CheckStatus.PARTIAL

    def test_encrypted(self) -> None:
        check = DatasetEncryptionCheck()
        result = check.evaluate({"dataclas": "ENCRYPT01", "encrypted": True})
        assert result.status == CheckStatus.PASS


class TestTCPIPStackCheck:
    def test_run(self) -> None:
        check = TCPIPStackCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-014"
        assert result.data["listeners"] >= 5
        assert result.data["established"] >= 1
        assert result.status == CheckStatus.PASS


class TestRACFClassStatusCheck:
    def test_run(self) -> None:
        check = RACFClassStatusCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-015"
        assert result.data["count"] >= 5
        classes = result.data["active_classes"]
        assert "USER" in classes or "user" in [c.lower() for c in classes]

    def test_missing_critical(self) -> None:
        check = RACFClassStatusCheck()
        result = check.evaluate({"active_classes": ["DATASET", "USER"], "count": 2})
        assert result.status == CheckStatus.PARTIAL
        assert any("NOT active" in f for f in result.findings)


# ---- Backup Infrastructure Checks (EXT-021, EXT-022) ----


class TestBackupStorageCheck:
    def test_run(self) -> None:
        check = BackupStorageCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-021"
        # Mock has COPY storage group + DFHSM + CSM
        assert result.data["has_copy_storage"] is True
        assert result.data["has_hsm"] is True
        assert result.data["has_csm"] is True
        assert result.status == CheckStatus.PASS

    def test_no_backup_infra(self) -> None:
        check = BackupStorageCheck()
        result = check.evaluate(
            {
                "storage_groups": [{"name": "SGBASE", "type": "POOL"}],
                "copy_groups": [],
                "backup_stcs": [],
                "has_copy_storage": False,
                "has_hsm": False,
                "has_csm": False,
                "has_gdps": False,
            }
        )
        assert result.status == CheckStatus.FAIL


class TestBackupProcessCheck:
    def test_run(self) -> None:
        check = BackupProcessCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-022"

    def test_no_backup_procs(self) -> None:
        check = BackupProcessCheck()
        result = check.evaluate({"backup_processes": [], "count": 0})
        assert result.status == CheckStatus.PARTIAL


# ---- Health Checker aligned checks (EXT-023 to EXT-025) ----


class TestBatchAllRACFCheck:
    def test_run(self) -> None:
        check = BatchAllRACFCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-023"

    def test_not_active(self) -> None:
        check = BatchAllRACFCheck()
        result = check.evaluate({"batchallracf": False})
        assert result.status == CheckStatus.FAIL

    def test_active(self) -> None:
        check = BatchAllRACFCheck()
        result = check.evaluate({"batchallracf": True})
        assert result.status == CheckStatus.PASS


class TestRACFDatabaseProtectionCheck:
    def test_run(self) -> None:
        check = RACFDatabaseProtectionCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-024"

    def test_open_uacc(self) -> None:
        check = RACFDatabaseProtectionCheck()
        result = check.evaluate(
            {
                "profiles": [{"name": "SYS1.RACF", "uacc": "READ"}],
                "count": 1,
            }
        )
        assert result.status == CheckStatus.FAIL

    def test_protected(self) -> None:
        check = RACFDatabaseProtectionCheck()
        result = check.evaluate(
            {
                "profiles": [{"name": "SYS1.RACF", "uacc": "NONE"}],
                "count": 1,
            }
        )
        assert result.status == CheckStatus.PASS


class TestICHAUTABCheck:
    def test_run(self) -> None:
        check = ICHAUTABCheck()
        result = check.run(make_conn())
        assert result.control_id == "EXT-025"

    def test_ichautab_present(self) -> None:
        check = ICHAUTABCheck()
        result = check.evaluate({"ichautab_referenced": True, "no_exits": False})
        assert result.status == CheckStatus.PARTIAL

    def test_no_ichautab(self) -> None:
        check = ICHAUTABCheck()
        result = check.evaluate({"ichautab_referenced": False, "no_exits": True})
        assert result.status == CheckStatus.PASS
