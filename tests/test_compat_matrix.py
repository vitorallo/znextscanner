"""Supercompatibility invariant — no check ever returns Error.

Runs both profiles through connection variants that simulate the ways a real
z/OS can be limited (downlevel release with channels missing, empty output,
garbled output, old-RACF error texts). Every check must end Pass/Partial/Fail/
Skipped — never Error — and every Skip must explain itself.
"""

from pathlib import Path

import pytest

from tests.connection_variants import (
    GARBAGE_BINARY,
    MESSAGE_SOUP,
    CannedConnection,
    DegradedConnection,
    UnsupportedConnection,
)
from znextscan.checks.base_check import CheckStatus
from znextscan.config import ScannerConfig
from znextscan.connections.mock import MockConnection
from znextscan.scanner import run_scan

FIXTURES = str(Path(__file__).parent / "fixtures")
V1R13 = str(Path(__file__).parent / "fixtures" / "v1r13")


def _mock(fixture_dir: str = FIXTURES) -> MockConnection:
    return MockConnection(fixture_dir)


# variant id -> factory producing a fresh connection
VARIANTS = {
    "full-mock": lambda: _mock(),  # z/OS 3.1 hybrid
    "no-console": lambda: DegradedConnection(_mock(), console=False),  # V1R13-era z/OSMF
    "no-uss": lambda: DegradedConnection(_mock(), uss=False),  # z/OSMF-only mode
    "all-down": lambda: UnsupportedConnection(),  # nothing supported
    "empty-output": lambda: CannedConnection(""),  # commands run, return nothing
    "garbage-output": lambda: CannedConnection(GARBAGE_BINARY),  # EBCDIC mis-decode / noise
    "racf-soup": lambda: CannedConnection(MESSAGE_SOUP, apply_racf_filter=True),  # old-RACF texts
    # True V1R13: over z/OSMF (no Console/USS REST) and over SSH (console via opercmd).
    "v1r13-zosmf": lambda: DegradedConnection(_mock(V1R13), console=False, uss=False),
    "v1r13-ssh": lambda: _mock(V1R13),
}


def _scan(profile: str, conn):
    return run_scan(conn, ScannerConfig(scan={"profile": profile}))


@pytest.mark.parametrize("profile", ["mrra", "mythos"])
@pytest.mark.parametrize("variant", list(VARIANTS), ids=list(VARIANTS))
def test_no_check_ever_errors(profile: str, variant: str) -> None:
    scan = _scan(profile, VARIANTS[variant]())
    errors = [r for r in scan.results if r.status is CheckStatus.ERROR]
    assert not errors, "checks returned Error:\n" + "\n".join(
        f"  {r.control_id}: {r.error}" for r in errors
    )


@pytest.mark.parametrize("profile", ["mrra", "mythos"])
@pytest.mark.parametrize("variant", list(VARIANTS), ids=list(VARIANTS))
def test_skipped_results_carry_reason(profile: str, variant: str) -> None:
    scan = _scan(profile, VARIANTS[variant]())
    for r in scan.results:
        if r.status is CheckStatus.SKIPPED:
            assert r.findings and r.findings[0].strip(), f"{r.control_id} skipped without a reason"


# TSO checks that MUST actually run (not skip) on a real V1R13 — the anti-trivialization
# tripwire (the "never Error" invariant is otherwise satisfiable by skipping everything).
_V1R13_TSO_CORE = {
    "IAM-002",
    "ID-002",
    "IAM-004",
    "MON-003",
    "SCI-004",
    "EXT-007",
    "EXT-008",
    "EXT-009",
    "EXT-010",
    "EXT-015",
    "EXT-023",
    "EXT-025",
}
_V1R13_SSH_CONSOLE = {"ID-003", "MON-001"}  # additionally reachable via SSH opercmd
_RAN = {CheckStatus.PASS, CheckStatus.PARTIAL, CheckStatus.FAIL}


def test_v1r13_minimum_viable_coverage() -> None:
    zosmf = {r.control_id: r.status for r in _scan("mrra", VARIANTS["v1r13-zosmf"]()).results}
    for cid in _V1R13_TSO_CORE:
        assert zosmf.get(cid) in _RAN, f"{cid} should run on V1R13 z/OSMF, got {zosmf.get(cid)}"

    ssh = {r.control_id: r.status for r in _scan("mrra", VARIANTS["v1r13-ssh"]()).results}
    for cid in _V1R13_TSO_CORE | _V1R13_SSH_CONSOLE:
        assert ssh.get(cid) in _RAN, f"{cid} should run on V1R13 SSH, got {ssh.get(cid)}"
