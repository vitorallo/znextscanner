"""SSH connection for z/OS systems via Paramiko.

Executes TSO commands via tsocmd, USS commands directly.
Console commands are not natively supported over SSH — use z/OSMF Console API
or raise CommandNotSupportedError.

Tested against z/OS 3.1 on Hercules with OpenSSH.
"""

import shlex
import socket

import paramiko
import structlog

from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.utils.errors import check_racf_errors

log = structlog.get_logger()


class SSHConnection(BaseConnection):
    """SSH connection to z/OS."""

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "IBMUSER",
        password: str | None = None,
        key_filename: str | None = None,
        timeout: int = 60,
    ) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": float(timeout),
        }
        if key_filename:
            connect_kwargs["key_filename"] = key_filename
        elif password:
            connect_kwargs["password"] = password
        else:
            raise ConnectionError("SSH requires either password or key_filename")

        log.info("ssh_connecting", host=host, port=port, username=username)
        self.client.connect(**connect_kwargs)
        log.info("ssh_connected", host=host)

    def execute_tso_command(self, command: str) -> str:
        """Execute a TSO/RACF command via tsocmd."""
        ssh_cmd = f'tsocmd "{command}"'
        log.debug("ssh_tso_command", command=command)

        try:
            stdin, stdout, stderr = self.client.exec_command(ssh_cmd, timeout=self.timeout)
            output = stdout.read().decode("utf-8", errors="replace")
        except socket.timeout as e:
            raise TimeoutError(f"TSO command '{command}' timed out after {self.timeout}s") from e

        log.debug("ssh_tso_output", command=command, output_length=len(output))

        # Check for RACF permission errors
        check_racf_errors(output, command=command)

        return output

    def execute_console_command(self, command: str) -> str:
        """Console commands are not available via SSH.

        Use z/OSMF Console API instead, or use opercmd if available.
        """
        # Try opercmd first (available on some z/OS installations)
        ssh_cmd = f'opercmd "{command}"'
        log.debug("ssh_console_command", command=command)

        try:
            stdin, stdout, stderr = self.client.exec_command(ssh_cmd, timeout=self.timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            errors = stderr.read().decode("utf-8", errors="replace")
        except socket.timeout as e:
            raise TimeoutError(
                f"Console command '{command}' timed out after {self.timeout}s"
            ) from e

        if "not found" in errors.lower() or "not found" in output.lower():
            raise CommandNotSupportedError(
                f"Console commands not available via SSH (opercmd not found). "
                f"Use z/OSMF Console API for '{command}'"
            )

        return output

    def execute_uss_command(self, command: str) -> str:
        """Execute a USS command via /bin/sh (portable across login shells)."""
        log.debug("ssh_uss_command", command=command)

        # Force /bin/sh so multi-statement scriptlets (for/[ ]&&{}) don't depend
        # on the user's login shell (which may be tcsh/restricted on z/OS).
        ssh_cmd = f"/bin/sh -c {shlex.quote(command)}"
        try:
            stdin, stdout, stderr = self.client.exec_command(ssh_cmd, timeout=self.timeout)
            output = stdout.read().decode("utf-8", errors="replace")
        except socket.timeout as e:
            raise TimeoutError(f"USS command timed out after {self.timeout}s") from e
        return output

    def close(self) -> None:
        """Close SSH connection."""
        log.info("ssh_closing", host=self.host)
        self.client.close()
