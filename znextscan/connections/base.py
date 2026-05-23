"""Abstract base connection class for z/OS systems."""

from abc import ABC, abstractmethod


class CommandNotSupportedError(Exception):
    """Raised when a command is not available on the target z/OS version.

    For example, z/OSMF Console API is not available before z/OS V2.3,
    so console commands (D PROG,APF, D SMF,O, D ICSF) cannot be executed
    via z/OSMF on z/OS V1R13.
    """


class BaseConnection(ABC):
    """Abstract connection to a z/OS system."""

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

    def __enter__(self) -> "BaseConnection":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
