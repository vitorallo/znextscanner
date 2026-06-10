"""Per-scan command cache.

Many checks issue the same read-only command (``SETROPTS LIST`` alone is run by
a dozen checks). On a live z/OS each fresh TSO session costs seconds, so wrapping
the connection in a memo for one scan removes the repeated round-trips. Only
*successful* outputs are cached — exceptions propagate uncached, so a command
that was unavailable or unauthorized is re-attempted by the next check exactly as
before, preserving the Skipped/Error degradation behaviour.
"""

from __future__ import annotations

from typing import Callable

from znextscan.connections.base import BaseConnection


class CachingConnection(BaseConnection):
    """Memoize successful command outputs per ``(channel, command)`` for one scan."""

    def __init__(self, inner: BaseConnection) -> None:
        self.inner = inner
        self._cache: dict[tuple[str, str], str] = {}

    @property
    def is_throttled(self) -> bool:  # type: ignore[override]
        return getattr(self.inner, "is_throttled", False)

    def _cached(self, channel: str, command: str, fn: Callable[[str], str]) -> str:
        key = (channel, command)
        if key not in self._cache:
            self._cache[key] = fn(command)  # exceptions propagate, nothing stored
        return self._cache[key]

    def execute_tso_command(self, command: str) -> str:
        return self._cached("tso", command, self.inner.execute_tso_command)

    def execute_console_command(self, command: str) -> str:
        return self._cached("console", command, self.inner.execute_console_command)

    def execute_uss_command(self, command: str) -> str:
        return self._cached("uss", command, self.inner.execute_uss_command)

    def close(self) -> None:
        self.inner.close()
