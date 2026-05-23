"""Tests for z/OSMF connection.

Unit tests use mocked httpx responses. Integration tests (marked with
pytest.mark.live) require a running z/OS system.
"""

from unittest.mock import MagicMock, patch

import pytest

from znextscan.connections.base import CommandNotSupportedError
from znextscan.connections.zosmf import ZOSMFConnection


class TestZOSMFConnectionInit:
    def test_base_url(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", port=10443, password="test")
        assert conn.base_url == "https://zos.example.com:10443/zosmf"
        conn.close()

    def test_auth_header(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", username="USER1", password="pass!")
        # Verify Base64 encoding handles special chars
        assert "Authorization" in conn.headers
        assert conn.headers["Authorization"].startswith("Basic ")
        conn.close()

    def test_csrf_header(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", password="test")
        assert conn.headers["X-CSRF-ZOSMF-HEADER"] == "*"
        conn.close()


class TestTSOHelpers:
    def test_extract_lines(self) -> None:
        data = {
            "tsoData": [
                {"TSO MESSAGE": {"VERSION": "0100", "DATA": "IBMUSER"}},
                {"TSO MESSAGE": {"VERSION": "0100", "DATA": "SYS1"}},
                {"TSO PROMPT": {"VERSION": "0100", "HIDDEN": "FALSE"}},
            ]
        }
        lines = ZOSMFConnection._extract_lines(data)
        assert lines == ["IBMUSER", "SYS1"]

    def test_extract_lines_empty(self) -> None:
        assert ZOSMFConnection._extract_lines({}) == []

    def test_has_prompt_true(self) -> None:
        data = {
            "tsoData": [
                {"TSO MESSAGE": {"VERSION": "0100", "DATA": "READY "}},
                {"TSO PROMPT": {"VERSION": "0100", "HIDDEN": "FALSE"}},
            ]
        }
        assert ZOSMFConnection._has_prompt(data) is True

    def test_has_prompt_false(self) -> None:
        data = {
            "tsoData": [
                {"TSO MESSAGE": {"VERSION": "0100", "DATA": "OUTPUT"}},
            ]
        }
        assert ZOSMFConnection._has_prompt(data) is False


class TestConsoleCommand:
    def test_console_404_raises_not_supported(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", password="test")
        mock_response = MagicMock()
        mock_response.status_code = 404
        conn.client = MagicMock()
        conn.client.put.return_value = mock_response

        with pytest.raises(CommandNotSupportedError, match="Console API not available"):
            conn.execute_console_command("D PROG,APF")
        conn.close()

    def test_console_403_raises_permission(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", password="test")
        mock_response = MagicMock()
        mock_response.status_code = 403
        conn.client = MagicMock()
        conn.client.put.return_value = mock_response

        with pytest.raises(PermissionError, match="Not authorized"):
            conn.execute_console_command("D PROG,APF")
        conn.close()

    def test_console_success_parses_response(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", password="test")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "cmd-response": " CSV450I 10.00.00 PROG,APF DISPLAY 100\r"
            "FORMAT=DYNAMIC\r"
            "ENTRY VOLUME DSNAME\r"
            "   1  SYSRES SYS1.LINKLIB"
        }
        mock_response.raise_for_status = MagicMock()
        conn.client = MagicMock()
        conn.client.put.return_value = mock_response

        output = conn.execute_console_command("D PROG,APF")
        assert "SYS1.LINKLIB" in output
        assert "CSV450I" in output
        conn.close()


class TestUSSCommand:
    def test_uss_raises_not_supported(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", password="test")
        with pytest.raises(CommandNotSupportedError, match="not yet implemented"):
            conn.execute_uss_command("ls")
        conn.close()


class TestConnectionLifecycle:
    def test_close_without_session(self) -> None:
        conn = ZOSMFConnection(host="zos.example.com", password="test")
        conn.close()  # Should not raise

    def test_context_manager(self) -> None:
        with ZOSMFConnection(host="zos.example.com", password="test") as conn:
            assert conn.base_url == "https://zos.example.com:443/zosmf"
