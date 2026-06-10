"""Tests for connection abstractions."""

from pathlib import Path

import pytest

from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.connections.mock import MockConnection

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestMockConnection:
    def test_is_base_connection(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        assert isinstance(conn, BaseConnection)

    def test_execute_tso_listuser_all(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_tso_command("LISTUSER *")
        assert "USER=IBMUSER" in output
        assert "SPECIAL" in output

    def test_execute_tso_setropts(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_tso_command("SETROPTS LIST")
        assert "PASSWORD MINIMUM LENGTH" in output

    def test_execute_tso_listuser(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_tso_command("LISTUSER IBMUSER")
        assert "USER=IBMUSER" in output

    def test_execute_console_apf(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_console_command("D PROG,APF")
        assert "SYS1.LINKLIB" in output

    def test_execute_console_smf(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_console_command("D SMF,O")
        assert "ACTIVE" in output
        assert "SMFPRM00" in output

    def test_execute_console_icsf(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_console_command("D ICSF")
        assert "CSFM668I" in output
        assert "HCR77E0" in output

    def test_unknown_command_raises(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        # Unmapped commands degrade like an absent facility (→ Skipped in a scan).
        with pytest.raises(CommandNotSupportedError, match="No fixture mapping"):
            conn.execute_tso_command("UNKNOWN COMMAND")

    def test_uss_unknown_command(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        with pytest.raises(CommandNotSupportedError, match="No fixture mapping"):
            conn.execute_uss_command("ls /nonexistent")

    def test_uss_java_version(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_uss_command("java -version 2>&1")
        assert "java version" in output

    def test_invalid_fixture_dir(self) -> None:
        with pytest.raises(FileNotFoundError):
            MockConnection("/nonexistent/path")

    def test_context_manager(self) -> None:
        with MockConnection(FIXTURE_DIR) as conn:
            output = conn.execute_tso_command("SETROPTS LIST")
            assert "SETROPTS" in output

    def test_started_tasks(self) -> None:
        conn = MockConnection(FIXTURE_DIR)
        output = conn.execute_tso_command("RLIST STARTED * ALL")
        assert "OMVS.*" in output
        assert "JES2.*" in output


class TestConnectionFactory:
    def test_create_mock(self) -> None:
        from znextscan.config import ConnectionConfig, ConnectionMethod
        from znextscan.connections.factory import create_connection

        cfg = ConnectionConfig(method=ConnectionMethod.MOCK, fixture_dir=str(FIXTURE_DIR))
        conn = create_connection(cfg)
        assert isinstance(conn, MockConnection)
        output = conn.execute_tso_command("SETROPTS LIST")
        assert "PASSWORD" in output
        conn.close()

    def test_create_zosmf_no_password_raises(self) -> None:
        from znextscan.config import ConnectionConfig, ConnectionMethod
        from znextscan.connections.factory import create_connection

        cfg = ConnectionConfig(method=ConnectionMethod.ZOSMF, password=None)
        with pytest.raises(ConnectionError, match="password required"):
            create_connection(cfg)

    def test_create_ssh_requires_credentials(self) -> None:
        from znextscan.config import ConnectionConfig, ConnectionMethod
        from znextscan.connections.factory import create_connection

        cfg = ConnectionConfig(method=ConnectionMethod.SSH, host="nonexistent")
        with pytest.raises(ConnectionError, match="password or key_filename"):
            create_connection(cfg)


class TestCachingConnection:
    class _Counter(BaseConnection):
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def execute_tso_command(self, command: str) -> str:
            self.calls.append(("tso", command))
            return f"tso:{command}"

        def execute_console_command(self, command: str) -> str:
            self.calls.append(("console", command))
            return f"con:{command}"

        def execute_uss_command(self, command: str) -> str:
            self.calls.append(("uss", command))
            return f"uss:{command}"

        def close(self) -> None:
            pass

    def test_identical_command_hits_inner_once(self) -> None:
        from znextscan.connections.caching import CachingConnection

        inner = self._Counter()
        conn = CachingConnection(inner)
        assert conn.execute_tso_command("SETROPTS LIST") == "tso:SETROPTS LIST"
        assert conn.execute_tso_command("SETROPTS LIST") == "tso:SETROPTS LIST"
        assert inner.calls.count(("tso", "SETROPTS LIST")) == 1

    def test_channels_keyed_separately(self) -> None:
        from znextscan.connections.caching import CachingConnection

        inner = self._Counter()
        conn = CachingConnection(inner)
        conn.execute_tso_command("D A,L")
        conn.execute_console_command("D A,L")
        assert ("tso", "D A,L") in inner.calls
        assert ("console", "D A,L") in inner.calls

    def test_exceptions_not_cached(self) -> None:
        from znextscan.connections.caching import CachingConnection

        class Flaky(BaseConnection):
            def __init__(self) -> None:
                self.n = 0

            def execute_tso_command(self, command: str) -> str:
                self.n += 1
                if self.n == 1:
                    raise CommandNotSupportedError("transient-once")
                return "ok"

            def execute_console_command(self, command: str) -> str:
                return ""

            def execute_uss_command(self, command: str) -> str:
                return ""

            def close(self) -> None:
                pass

        conn = CachingConnection(Flaky())
        with pytest.raises(CommandNotSupportedError):
            conn.execute_tso_command("CMD")
        assert conn.execute_tso_command("CMD") == "ok"  # re-attempted, not cached
