"""Live validation against a real z/OS via z/OSMF (opt-in).

Set ``MRRA_LIVE_HOST`` (and optionally ``MRRA_LIVE_PORT`` / ``MRRA_LIVE_USER`` /
``MRRA_LIVE_PASSWORD`` / ``MRRA_LIVE_HOST_HEADER``) to run. Skipped entirely in
CI and normal test runs.

    MRRA_LIVE_HOST=127.0.0.1 MRRA_LIVE_HOST_HEADER=MACHINE.local \\
    MRRA_LIVE_USER=IBMUSER MRRA_LIVE_PASSWORD=... \\
    pytest tests/test_live_zos.py -v
"""

import os

import pytest

from tests.connection_variants import DegradedConnection
from znextscan.checks.base_check import CheckStatus
from znextscan.config import ScannerConfig
from znextscan.connections.zosmf import ZOSMFConnection
from znextscan.scanner import run_scan

LIVE = os.environ.get("MRRA_LIVE_HOST")
pytestmark = pytest.mark.skipif(
    not LIVE, reason="set MRRA_LIVE_HOST[/PORT/USER/PASSWORD/HOST_HEADER] to run live"
)


@pytest.fixture(scope="session")
def live_conn() -> ZOSMFConnection:
    conn = ZOSMFConnection(
        host=os.environ["MRRA_LIVE_HOST"],
        port=int(os.environ.get("MRRA_LIVE_PORT", "10443")),
        username=os.environ.get("MRRA_LIVE_USER", "IBMUSER"),
        password=os.environ.get("MRRA_LIVE_PASSWORD", ""),
        verify_ssl=False,
        timeout=120,
        host_header=os.environ.get("MRRA_LIVE_HOST_HEADER"),
    )
    yield conn
    conn.close()


def _errors(scan) -> list[str]:
    return [f"{r.control_id}: {r.error}" for r in scan.results if r.status is CheckStatus.ERROR]


@pytest.mark.parametrize("profile", ["mrra", "mythos"])
def test_live_full_scan_no_errors(live_conn: ZOSMFConnection, profile: str) -> None:
    scan = run_scan(live_conn, ScannerConfig(scan={"profile": profile}))
    assert scan.summary["errors"] == 0, "checks errored:\n" + "\n".join(_errors(scan))
    assert scan.zos_version, "/zosmf/info did not return zos_version"


def test_live_degraded_console_no_errors(live_conn: ZOSMFConnection) -> None:
    # Proves the V1R13 console-less path against real TSO output.
    conn = DegradedConnection(live_conn, console=False)
    scan = run_scan(conn, ScannerConfig(scan={"profile": "mythos"}))
    assert scan.summary["errors"] == 0, "checks errored:\n" + "\n".join(_errors(scan))


def test_live_degraded_uss_no_errors(live_conn: ZOSMFConnection) -> None:
    conn = DegradedConnection(live_conn, uss=False)
    scan = run_scan(conn, ScannerConfig(scan={"profile": "mythos"}))
    assert scan.summary["errors"] == 0, "checks errored:\n" + "\n".join(_errors(scan))
