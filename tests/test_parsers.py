"""Tests for RACF output parsers."""

from pathlib import Path

import pytest

from znextscan.parsers.racf_parser import (
    parse_apf_list,
    parse_apf_profiles,
    parse_icsf_status,
    parse_listuser,
    parse_program_control,
    parse_search_output,
    parse_setropts_audit,
    parse_setropts_extended,
    parse_setropts_password,
    parse_smf_status,
    parse_started_tasks,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"
REAL_DIR = FIXTURE_DIR / "real_zos"
V1R13_DIR = FIXTURE_DIR / "v1r13"


class TestParseSearchOutput:
    def test_mock_special_users(self) -> None:
        output = (FIXTURE_DIR / "ID-002-SEARCH-SPECIAL.txt").read_text()
        users = parse_search_output(output)
        assert "IBMUSER" in users
        assert "SYS1" in users
        assert "ADMIN01" in users
        # irrcerta/irrmulti/irrsitec should be filtered
        assert "irrcerta" not in users
        assert "irrmulti" not in users

    def test_real_special_users(self) -> None:
        if not REAL_DIR.exists():
            pytest.skip("No real z/OS fixtures")
        output = (REAL_DIR / "tso_SEARCH_SPECIAL.txt").read_text()
        users = parse_search_output(output)
        assert "IBMUSER" in users
        assert "irrcerta" not in users
        assert "irrmulti" not in users
        assert "irrsitec" not in users
        assert len(users) > 0

    def test_operations_users(self) -> None:
        output = (FIXTURE_DIR / "ID-002-SEARCH-OPERATIONS.txt").read_text()
        users = parse_search_output(output)
        assert "IBMUSER" in users
        assert "OPER01" in users

    def test_auditor_users(self) -> None:
        output = (FIXTURE_DIR / "ID-002-SEARCH-AUDITOR.txt").read_text()
        users = parse_search_output(output)
        assert "IBMUSER" in users
        assert "AUDITOR1" in users

    def test_empty_output(self) -> None:
        assert parse_search_output("") == []

    def test_only_internal_entries(self) -> None:
        output = "irrcerta\nirrmulti\nirrsitec\n"
        assert parse_search_output(output) == []


class TestParseApfList:
    def test_mock_apf(self) -> None:
        output = (FIXTURE_DIR / "ID-003-APF-LIST.txt").read_text()
        libs = parse_apf_list(output)
        assert len(libs) == 13
        assert libs[0]["dsname"] == "SYS1.LINKLIB"
        assert libs[0]["volume"] == "Z31VS1"

    def test_real_apf(self) -> None:
        if not REAL_DIR.exists():
            pytest.skip("No real z/OS fixtures")
        output = (REAL_DIR / "console_D_PROG_APF.txt").read_text()
        libs = parse_apf_list(output)
        assert len(libs) > 50  # Real system has 71 entries
        assert libs[0]["dsname"] == "SYS1.LINKLIB"
        # Check for *SMS* volumes
        sms_libs = [l for l in libs if l["volume"] == "*SMS*"]
        assert len(sms_libs) > 0

    def test_empty_output(self) -> None:
        assert parse_apf_list("") == []


class TestParseSetroptsPassword:
    def test_mock_password_policy(self) -> None:
        output = (FIXTURE_DIR / "IAM-002-SETROPTS-LIST.txt").read_text()
        config = parse_setropts_password(output)
        assert config["min_length"] == 8
        assert config["max_length"] == 100
        assert config["history"] == 10
        assert config["revoke_count"] == 3
        assert config["change_interval"] == 90
        assert config["mixed_case"] is True
        assert config["encryption_algorithm"] == "KDFAES"
        assert config["inactive_revoke_days"] == 90


class TestParseListuser:
    def test_ibmuser(self) -> None:
        output = (FIXTURE_DIR / "IAM-003-LISTUSER-IBMUSER.txt").read_text()
        # Parse first user block
        user = parse_listuser(output)
        assert user["userid"] == "IBMUSER"
        assert "SPECIAL" in user["attributes"]
        assert "OPERATIONS" in user["attributes"]
        assert user["owner"] == "IBMUSER"
        assert user["default_group"] == "SYS1"
        assert user["revoke_date"] == "NONE"
        assert user["protected"] is False


class TestParseSmfStatus:
    def test_mock_smf(self) -> None:
        output = (FIXTURE_DIR / "MON-001-SMF-STATUS.txt").read_text()
        config = parse_smf_status(output)
        assert config["active"] is True
        assert config["has_type_30"] is True
        assert config["has_type_80"] is True
        assert config["has_type_83"] is True
        assert config["parmlib_member"] == "SMFPRM00"
        assert config["recording_method"] == "LOGSTREAM"

    def test_real_smf(self) -> None:
        if not REAL_DIR.exists():
            pytest.skip("No real z/OS fixtures")
        output = (REAL_DIR / "console_D_SMF_O.txt").read_text()
        config = parse_smf_status(output)
        assert config["active"] is True
        assert config["parmlib_member"] == "SMFPRM00"
        assert config["recording_method"] == "LOGSTREAM"
        # Real system has types 30, 80, 83 in the range 75:83
        assert config["has_type_30"] is True
        assert config["has_type_80"] is True
        assert config["has_type_83"] is True

    def test_empty_output(self) -> None:
        config = parse_smf_status("")
        assert config["active"] is False


class TestParseSetroptsAudit:
    def test_mock_audit(self) -> None:
        output = (FIXTURE_DIR / "MON-003-SETROPTS-AUDIT.txt").read_text()
        config = parse_setropts_audit(output)
        assert config["audit_active"] is True
        assert config["saudit"] is True
        assert config["log_logon_failures"] is True
        assert config["log_logon_successes"] is True
        assert config["cmdviol"] is True

    def test_full_setropts(self) -> None:
        output = (FIXTURE_DIR / "IAM-002-SETROPTS-LIST.txt").read_text()
        config = parse_setropts_audit(output)
        assert config["audit_active"] is True
        assert config["saudit"] is True


class TestParseIcsfStatus:
    def test_mock_icsf(self) -> None:
        output = (FIXTURE_DIR / "ENC-002-ICSF-LIST.txt").read_text()
        config = parse_icsf_status(output)
        assert config["active"] is True
        assert config["fmid"] == "HCR77E0"

    def test_real_icsf(self) -> None:
        if not REAL_DIR.exists():
            pytest.skip("No real z/OS fixtures")
        output = (REAL_DIR / "console_D_ICSF.txt").read_text()
        config = parse_icsf_status(output)
        assert config["active"] is True
        assert config["fmid"] == "HCR77E0"

    def test_icsf_not_active(self) -> None:
        config = parse_icsf_status("IEE341I ICSF NOT ACTIVE")
        assert config["active"] is False


class TestParseStartedTasks:
    def test_mock_started_tasks(self) -> None:
        output = (FIXTURE_DIR / "IAM-005-STARTED-TASKS.txt").read_text()
        tasks = parse_started_tasks(output)
        assert len(tasks) >= 4
        omvs = next(t for t in tasks if t["profile"] == "OMVS.*")
        assert omvs["user"] == "OMVSKERN"
        assert omvs["trusted"] is True
        assert omvs["uacc"] == "NONE"

    def test_empty_output(self) -> None:
        assert parse_started_tasks("") == []


class TestParseApfProfiles:
    def test_mock_profiles(self) -> None:
        output = (FIXTURE_DIR / "SCI-001-APF-PROFILES.txt").read_text()
        profiles = parse_apf_profiles(output)
        assert len(profiles) >= 2
        linklib = next(p for p in profiles if p["name"] == "SYS1.LINKLIB")
        assert linklib["uacc"] == "NONE"
        assert any(
            a["userid"] == "IBMUSER" and a["access"] == "ALTER" for a in linklib["access_list"]
        )


class TestParseProgramControl:
    def test_mock_program_control(self) -> None:
        output = (FIXTURE_DIR / "SCI-004-PROGRAM-CONTROL.txt").read_text()
        config = parse_program_control(output)
        assert config["when_program"] is True
        assert config["program_class_active"] is True

    def test_nowhen_program_not_active(self) -> None:
        # Regression (live z/OS 3.1): NOWHEN(PROGRAM) is present and "ACTIVE
        # CLASSES" exists, but PROGRAM is NOT a member — must report inactive.
        output = (
            "ATTRIBUTES = INITSTATS NOWHEN(PROGRAM)\n"
            "ACTIVE CLASSES = DATASET USER GROUP FACILITY STARTED APPL\n"
            "                 OPERCMDS SURROGAT TSOAUTH\n"
        )
        config = parse_program_control(output)
        assert config["when_program"] is False
        assert config["program_class_active"] is False

    def test_real_program_control(self) -> None:
        if not REAL_DIR.exists():
            pytest.skip("No real z/OS fixtures")
        output = (REAL_DIR / "tso_SETROPTS_LIST.txt").read_text()
        config = parse_program_control(output)
        # Ground truth: this lab runs NOWHEN(PROGRAM) and PROGRAM is not active.
        assert config["when_program"] is False
        assert config["program_class_active"] is False


class TestParseSetroptsExtended:
    def test_full_setropts_extended(self) -> None:
        output = (FIXTURE_DIR / "IAM-002-SETROPTS-LIST.txt").read_text()
        config = parse_setropts_extended(output)
        assert config["operaudit"] is True
        assert config["protectall"] is True
        assert config["erase"] is True
        assert config["log_failures"] is True
        assert config["log_successes"] is True


# ---- z/OS V1R13 compatibility tests ----


class TestV1R13Parsers:
    """Validate parsers against simulated z/OS V1R13 output."""

    def test_search_special(self) -> None:
        output = (V1R13_DIR / "SEARCH-SPECIAL.txt").read_text()
        users = parse_search_output(output)
        assert "IBMUSER" in users
        assert "irrcerta" not in users
        assert len(users) == 3

    def test_setropts_password_masked(self) -> None:
        output = (V1R13_DIR / "SETROPTS-LIST.txt").read_text()
        config = parse_setropts_password(output)
        assert config["encryption_algorithm"] == "MASKED"
        assert config["min_length"] == 6
        assert config["max_length"] == 8
        assert config["history"] == 5
        assert config["revoke_count"] == 5
        assert config["change_interval"] == 60
        assert config["mixed_case"] is False
        assert config["inactive_revoke_days"] == 60

    def test_setropts_audit(self) -> None:
        output = (V1R13_DIR / "SETROPTS-LIST.txt").read_text()
        config = parse_setropts_audit(output)
        assert config["audit_active"] is True
        assert config["saudit"] is True
        assert config["log_logon_failures"] is True

    def test_setropts_extended(self) -> None:
        output = (V1R13_DIR / "SETROPTS-LIST.txt").read_text()
        config = parse_setropts_extended(output)
        assert config["operaudit"] is True
        assert config["protectall"] is True
        assert config["erase"] is True

    def test_program_control(self) -> None:
        output = (V1R13_DIR / "SETROPTS-LIST.txt").read_text()
        config = parse_program_control(output)
        assert config["when_program"] is True
        assert config["program_class_active"] is True

    def test_apf_list(self) -> None:
        output = (V1R13_DIR / "APF-LIST.txt").read_text()
        libs = parse_apf_list(output)
        assert len(libs) == 8
        assert libs[0]["dsname"] == "SYS1.LINKLIB"
        assert libs[0]["volume"] == "SYSRES"

    def test_listuser(self) -> None:
        output = (V1R13_DIR / "LISTUSER-IBMUSER.txt").read_text()
        user = parse_listuser(output)
        assert user["userid"] == "IBMUSER"
        assert "SPECIAL" in user["attributes"]
        assert user["default_group"] == "SYS1"

    def test_smf_status(self) -> None:
        output = (V1R13_DIR / "SMF-STATUS.txt").read_text()
        config = parse_smf_status(output)
        assert config["active"] is True
        assert config["has_type_30"] is True
        assert config["has_type_80"] is True
        assert config["has_type_83"] is True
        assert config["parmlib_member"] == "SMFPRM00"
        # V1R13 may not have RECORDING(LOGSTREAM)
        assert config["recording_method"] is None
