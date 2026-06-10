"""Connection wrappers used by the supercompatibility matrix.

NOT a ``test_*`` module — pytest does not collect it. These wrappers simulate
the ways a real z/OS can be limited (a channel unavailable on a downlevel
release, empty output, garbled output) so the matrix can assert that no check
ever returns ``status=Error``.
"""

from __future__ import annotations

# Re-exported so the matrix and the parser suite share one definition.
from tests.test_parser_robustness import GARBAGE_BINARY, MESSAGE_SOUP  # noqa: F401
from znextscan.connections.base import BaseConnection, CommandNotSupportedError
from znextscan.utils.errors import check_racf_errors


class DegradedConnection(BaseConnection):
    """Delegate to a base connection; disabled channels raise CommandNotSupportedError.

    Models a z/OS level where a whole channel is missing — e.g. V1R13 z/OSMF has
    no Console REST API (``console=False``), or a z/OSMF-only deployment has no
    USS shell (``uss=False``).
    """

    def __init__(
        self, base: BaseConnection, *, tso: bool = True, console: bool = True, uss: bool = True
    ) -> None:
        self.base = base
        self._tso = tso
        self._console = console
        self._uss = uss

    def execute_tso_command(self, command: str) -> str:
        if not self._tso:
            raise CommandNotSupportedError("simulated: TSO unavailable on this z/OS level")
        return self.base.execute_tso_command(command)

    def execute_console_command(self, command: str) -> str:
        if not self._console:
            raise CommandNotSupportedError("simulated: Console API unavailable on this z/OS level")
        return self.base.execute_console_command(command)

    def execute_uss_command(self, command: str) -> str:
        if not self._uss:
            raise CommandNotSupportedError("simulated: USS unavailable on this z/OS level")
        return self.base.execute_uss_command(command)

    def close(self) -> None:
        self.base.close()


class CannedConnection(BaseConnection):
    """Every channel returns the same fixed payload.

    With ``apply_racf_filter`` the TSO channel runs ``check_racf_errors`` first,
    mirroring the real zosmf/ssh post-processing so old-RACF error texts are
    exercised through the production code path.
    """

    def __init__(self, payload: str, apply_racf_filter: bool = False) -> None:
        self.payload = payload
        self.apply_racf_filter = apply_racf_filter

    def execute_tso_command(self, command: str) -> str:
        if self.apply_racf_filter:
            check_racf_errors(self.payload, command=command)
        return self.payload

    def execute_console_command(self, command: str) -> str:
        return self.payload

    def execute_uss_command(self, command: str) -> str:
        return self.payload

    def close(self) -> None:
        pass


class UnsupportedConnection(BaseConnection):
    """Every channel raises CommandNotSupportedError — nothing runs at all."""

    def execute_tso_command(self, command: str) -> str:
        raise CommandNotSupportedError(f"unsupported: {command}")

    def execute_console_command(self, command: str) -> str:
        raise CommandNotSupportedError(f"unsupported: {command}")

    def execute_uss_command(self, command: str) -> str:
        raise CommandNotSupportedError(f"unsupported: {command}")

    def close(self) -> None:
        pass
