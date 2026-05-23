"""Hybrid connection — z/OSMF Console API + SSH for TSO commands.

Combines the best of both: z/OSMF for console commands (D PROG,APF, D SMF,O,
D ICSF) and SSH for TSO commands (LISTUSER, SETROPTS, RLIST) which are more
reliable via tsocmd than the z/OSMF TSO API.
"""

import structlog

from znextscan.connections.base import BaseConnection
from znextscan.connections.ssh import SSHConnection
from znextscan.connections.zosmf import ZOSMFConnection

log = structlog.get_logger()


class HybridConnection(BaseConnection):
    """z/OSMF Console + SSH TSO hybrid connection."""

    def __init__(self, zosmf: ZOSMFConnection, ssh: SSHConnection) -> None:
        self.zosmf = zosmf
        self.ssh = ssh

    def execute_tso_command(self, command: str) -> str:
        """TSO commands via SSH (more reliable for RACF)."""
        return self.ssh.execute_tso_command(command)

    def execute_console_command(self, command: str) -> str:
        """Console commands via z/OSMF (only method that supports them)."""
        return self.zosmf.execute_console_command(command)

    def execute_uss_command(self, command: str) -> str:
        """USS commands via SSH."""
        return self.ssh.execute_uss_command(command)

    def close(self) -> None:
        self.ssh.close()
        self.zosmf.close()

    def test_connection(self) -> dict:
        """Test both connections."""
        return self.zosmf.test_connection()
