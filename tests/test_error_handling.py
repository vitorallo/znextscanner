"""Tests for error handling: retry, permission denied, timeouts."""

import time
from typing import Any
from unittest.mock import MagicMock

import pytest

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.utils.errors import RACFPermissionError, check_racf_errors
from znextscan.utils.retry import retry_on_transient

# ---- Retry logic ----


class TestRetryOnTransient:
    def test_succeeds_first_try(self) -> None:
        call_count = 0

        @retry_on_transient(max_retries=3)
        def succeed() -> str:
            nonlocal call_count
            call_count += 1
            return "ok"

        assert succeed() == "ok"
        assert call_count == 1

    def test_retries_on_transient(self) -> None:
        call_count = 0

        @retry_on_transient(max_retries=3, base_delay=0.01)
        def fail_twice() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionResetError("reset")
            return "ok"

        assert fail_twice() == "ok"
        assert call_count == 3

    def test_exhausts_retries(self) -> None:
        @retry_on_transient(max_retries=2, base_delay=0.01)
        def always_fail() -> str:
            raise TimeoutError("timed out")

        with pytest.raises(TimeoutError, match="timed out"):
            always_fail()

    def test_no_retry_on_non_transient(self) -> None:
        call_count = 0

        @retry_on_transient(max_retries=3, base_delay=0.01)
        def perm_error() -> str:
            nonlocal call_count
            call_count += 1
            raise ValueError("bad value")

        with pytest.raises(ValueError):
            perm_error()
        assert call_count == 1  # No retries


# ---- RACF error detection ----


class TestCheckRacfErrors:
    def test_ich408i_raises_permission_error(self) -> None:
        output = "ICH408I MRRASCN NOT AUTHORIZED TO LISTUSER"
        with pytest.raises(RACFPermissionError, match="IRR.RADMIN"):
            check_racf_errors(output, command="LISTUSER IBMUSER")

    def test_ich409i_not_found_is_ignored(self) -> None:
        output = "ICH409I SYS1.NONEXIST NOT FOUND"
        check_racf_errors(output, command="RLIST DATASET SYS1.NONEXIST")
        # Should not raise

    def test_clean_output_no_error(self) -> None:
        output = "USER=IBMUSER  NAME=IBM DEFAULT\n ATTRIBUTES=SPECIAL"
        check_racf_errors(output, command="LISTUSER IBMUSER")
        # Should not raise

    def test_permission_error_includes_guidance(self) -> None:
        output = "ICH408I MRRASCN NOT AUTHORIZED TO RLIST"
        try:
            check_racf_errors(output, command="RLIST STARTED * ALL")
            pytest.fail("Should have raised")
        except RACFPermissionError as e:
            assert "IRR.RADMIN.RLIST" in str(e)
            assert "FACILITY" in str(e)
            assert e.command == "RLIST STARTED * ALL"


# ---- BaseCheck error handling ----


class StubConnection(BaseConnection):
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
    control_id = "TEST-001"
    control_name = "Test Check"
    nist_function = "Identify"
    priority = "P0"

    def execute(self, connection: BaseConnection) -> str:
        return connection.execute_tso_command("TEST")

    def parse(self, output: str) -> dict[str, Any]:
        return {"value": output.strip()}

    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        return CheckResult(
            control_id=self.control_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            data=data,
        )


class TestBaseCheckErrorHandling:
    def test_permission_denied_returns_skipped(self) -> None:
        class PermConn(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise RACFPermissionError(
                    "RACF access denied for 'LISTUSER *'",
                    command="LISTUSER *",
                )

        result = DummyCheck().run(PermConn())
        assert result.status == CheckStatus.SKIPPED
        assert "Permission denied" in (result.error or "")
        assert "RACF access denied" in result.findings[0]

    def test_timeout_returns_error(self) -> None:
        class TimeoutConn(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise TimeoutError("Command timed out after 60s")

        result = DummyCheck().run(TimeoutConn())
        assert result.status == CheckStatus.ERROR
        assert "Timeout" in (result.error or "")

    def test_command_not_supported_returns_skipped(self) -> None:
        class NoConsoleConn(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise CommandNotSupportedError("Console API not available")

        result = DummyCheck().run(NoConsoleConn())
        assert result.status == CheckStatus.SKIPPED

    def test_generic_error_returns_error(self) -> None:
        class BrokenConn(StubConnection):
            def execute_tso_command(self, command: str) -> str:
                raise RuntimeError("Connection lost")

        result = DummyCheck().run(BrokenConn())
        assert result.status == CheckStatus.ERROR
        assert "Connection lost" in (result.error or "")
