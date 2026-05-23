"""Base check class and result models for MRRA Scanner."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.utils.errors import RACFPermissionError


class CheckStatus(str, Enum):
    """Possible outcomes of a security check."""

    PASS = "Pass"
    PARTIAL = "Partial"
    FAIL = "Fail"
    ERROR = "Error"
    SKIPPED = "Skipped"


@dataclass
class CheckResult:
    """Result of executing a security check."""

    control_id: str
    control_name: str
    status: CheckStatus
    findings: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    raw_output: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON output."""
        result: dict[str, Any] = {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "status": self.status.value,
            "findings": self.findings,
            "data": self.data,
        }
        if self.error:
            result["error"] = self.error
        return result


class BaseCheck(ABC):
    """Abstract base class for all security checks."""

    control_id: str
    control_name: str
    nist_function: str
    priority: str

    # Framework/profile metadata. Defaulted so existing checks need no edits:
    # every check is an MRRA check unless a framework descriptor annotates it.
    frameworks: tuple[str, ...] = ("mrra",)
    mythos_dimension: Optional[str] = None
    validation_method: str = "Scanner"

    @abstractmethod
    def execute(self, connection: BaseConnection) -> str:
        """Execute the check command(s) and return raw output."""
        ...

    @abstractmethod
    def parse(self, output: str) -> dict[str, Any]:
        """Parse raw command output into structured data."""
        ...

    @abstractmethod
    def evaluate(self, data: dict[str, Any]) -> CheckResult:
        """Evaluate parsed data against security criteria."""
        ...

    def run(self, connection: BaseConnection) -> CheckResult:
        """Execute the full check lifecycle: execute -> parse -> evaluate."""
        try:
            raw_output = self.execute(connection)
            data = self.parse(raw_output)
            result = self.evaluate(data)
            result.raw_output = raw_output
            return result
        except CommandNotSupportedError as e:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=[str(e)],
            )
        except RACFPermissionError as e:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.SKIPPED,
                findings=[str(e)],
                error=f"Permission denied: {e.command}",
            )
        except TimeoutError as e:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                error=f"Timeout: {e}",
            )
        except Exception as e:
            return CheckResult(
                control_id=self.control_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                error=str(e),
            )
