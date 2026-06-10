"""Tests for base check classes and result models."""

from typing import Any

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection


class StubConnection(BaseConnection):
    """Minimal connection for testing."""

    def __init__(self, response: str = "") -> None:
        self.response = response

    def execute_tso_command(self, command: str) -> str:
        return self.response

    def execute_console_command(self, command: str) -> str:
        return self.response

    def execute_uss_command(self, command: str) -> str:
        return self.response

    def close(self) -> None:
        pass


class DummyCheck(BaseCheck):
    """Concrete check for testing the base class."""

    control_id = "TEST-001"
    control_name = "Test Check"
    nist_function = "Identify"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("TEST")

    def parse(self, output: str) -> dict[str, Any]:
        return {"value": output.strip()}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        status = CheckStatus.PASS if data["value"] == "OK" else CheckStatus.FAIL
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=status,
            data=data,
        )


class TestCheckStatus:
    def test_enum_values(self) -> None:
        assert CheckStatus.PASS.value == "Pass"
        assert CheckStatus.PARTIAL.value == "Partial"
        assert CheckStatus.FAIL.value == "Fail"
        assert CheckStatus.ERROR.value == "Error"
        assert CheckStatus.SKIPPED.value == "Skipped"


class TestCheckResult:
    def test_to_dict(self) -> None:
        result = CheckResult(
            control_id="ID-002",
            control_name="Privileged Users",
            status=CheckStatus.PASS,
            findings=["Found 3 SPECIAL users"],
            data={"special_users": ["IBMUSER", "SYS1", "ADMIN01"]},
        )
        d = result.to_dict()
        assert d["control_id"] == "ID-002"
        assert d["status"] == "Pass"
        assert len(d["findings"]) == 1
        assert "error" not in d

    def test_to_dict_with_error(self) -> None:
        result = CheckResult(
            control_id="ID-002",
            control_name="Privileged Users",
            status=CheckStatus.ERROR,
            error="Connection timeout",
        )
        d = result.to_dict()
        assert d["status"] == "Error"
        assert d["error"] == "Connection timeout"


class TestBaseCheck:
    def test_run_pass(self) -> None:
        conn = StubConnection("OK")
        check = DummyCheck()
        result = check.run(conn)
        assert result.status == CheckStatus.PASS
        assert result.raw_output == "OK"

    def test_run_fail(self) -> None:
        conn = StubConnection("NOT OK")
        check = DummyCheck()
        result = check.run(conn)
        assert result.status == CheckStatus.FAIL

    def test_run_error_on_exception(self) -> None:
        class BrokenConnection(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise RuntimeError("Connection lost")

        conn = BrokenConnection()
        check = DummyCheck()
        result = check.run(conn)
        assert result.status == CheckStatus.ERROR
        assert "Connection lost" in (result.error or "")

    def test_run_skipped_on_command_not_supported(self) -> None:
        from znextscan.connections.base import CommandNotSupportedError

        class V1R13Connection(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise CommandNotSupportedError("Console API not available on z/OS V1R13")

        conn = V1R13Connection()
        check = DummyCheck()
        result = check.run(conn)
        assert result.status == CheckStatus.SKIPPED
        assert "V1R13" in result.findings[0]
        assert result.error is None

    def test_plain_permission_error_skips(self) -> None:
        # z/OSMF console HTTP 403 raises a plain PermissionError (not RACFPermissionError)
        # — it must degrade to Skipped, never Error.
        class ForbiddenConnection(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise PermissionError("Not authorized for console command — needs OPERCMDS")

        result = DummyCheck().run(ForbiddenConnection())
        assert result.status == CheckStatus.SKIPPED
        assert "OPERCMDS" in result.findings[0]
