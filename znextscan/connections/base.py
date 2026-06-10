"""Abstract base connection class for z/OS systems."""

from abc import ABC, abstractmethod
from typing import Any


class CommandNotSupportedError(Exception):
    """Raised when a command is not available on the target z/OS version.

    For example, z/OSMF Console API is not available before z/OS V2.3,
    so console commands (D PROG,APF, D SMF,O, D ICSF) cannot be executed
    via z/OSMF on z/OS V1R13.
    """


class BaseConnection(ABC):
    """Abstract connection to a z/OS system."""

    # True for live connections that talk to a real (slow) z/OS, so the scanner
    # paces itself between checks. False for in-memory connections (Mock).
    is_throttled: bool = False

    @abstractmethod
    def execute_tso_command(self, command: str) -> str:
        """Execute a TSO command and return the output text."""
        ...

    @abstractmethod
    def execute_console_command(self, command: str) -> str:
        """Execute an MVS console command and return the output text."""
        ...

    @abstractmethod
    def execute_uss_command(self, command: str) -> str:
        """Execute a USS (Unix) command and return the output text."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Close the connection and clean up resources."""
        ...

    def system_info(self) -> dict[str, Any]:
        """Best-effort target metadata (e.g. ``zos_version``); ``{}`` if unavailable."""
        return {}

    def __enter__(self) -> "BaseConnection":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
