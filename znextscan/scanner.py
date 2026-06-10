"""Scanner orchestrator — runs all checks and collects results."""

import functools
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import structlog

from znextscan.checks.base_check import BaseCheck, CheckResult, CheckStatus
from znextscan.checks.enc_checks import CryptoHardwareCheck, ICSFKeyManagementCheck
from znextscan.checks.ext_checks import (
    BackupProcessCheck,
    BackupStorageCheck,
    BatchAllRACFCheck,
    ConsoleSecurityCheck,
    DatasetEncryptionCheck,
    EraseCheck,
    FTPStatusCheck,
    ICHAUTABCheck,
    JavaVersionCheck,
    LogoptionsCheck,
    OperauditCheck,
    ProtectallCheck,
    RACFClassStatusCheck,
    RACFDatabaseProtectionCheck,
    SessionTimeoutCheck,
    SyslogConfigCheck,
    TCPIPStackCheck,
    USSListenersCheck,
    USSProcessCheck,
    VTAMSecurityCheck,
)
from znextscan.checks.iam_checks import (
    DefaultAccountCheck,
    PasswordPolicyCheck,
    SpecialCountCheck,
    StartedTaskCheck,
)
from znextscan.checks.id_checks import APFLibraryCheck, PrivilegedUserCheck
from znextscan.checks.mon_checks import RACFAuditCheck, SMFRecordingCheck
from znextscan.checks.sci_checks import APFIntegrityCheck, ProgramControlCheck
from znextscan.config import ScannerConfig
from znextscan.connections.base import BaseConnection

log = structlog.get_logger()

# All available checks in execution order
CHECK_REGISTRY: list[type[BaseCheck]] = [
    PrivilegedUserCheck,
    APFLibraryCheck,
    PasswordPolicyCheck,
    DefaultAccountCheck,
    SpecialCountCheck,
    StartedTaskCheck,
    SMFRecordingCheck,
    RACFAuditCheck,
    ICSFKeyManagementCheck,
    CryptoHardwareCheck,
    APFIntegrityCheck,
    ProgramControlCheck,
    # Extended checks
    FTPStatusCheck,
    SessionTimeoutCheck,
    VTAMSecurityCheck,
    ConsoleSecurityCheck,
    OperauditCheck,
    LogoptionsCheck,
    ProtectallCheck,
    EraseCheck,
    # Tier 2 checks
    USSProcessCheck,
    DatasetEncryptionCheck,
    TCPIPStackCheck,
    RACFClassStatusCheck,
    # Backup checks
    BackupStorageCheck,
    BackupProcessCheck,
    # Health Checker aligned checks
    BatchAllRACFCheck,
    RACFDatabaseProtectionCheck,
    ICHAUTABCheck,
    # USS checks
    JavaVersionCheck,
    SyslogConfigCheck,
    USSListenersCheck,
]


def get_check_by_id(control_id: str) -> type[BaseCheck] | None:
    """Look up a check class by its control ID (legacy or Mythos-native)."""
    from znextscan.checks.mythos_checks import MYTHOS_NATIVE_CHECKS

    for check_cls in (*CHECK_REGISTRY, *MYTHOS_NATIVE_CHECKS):
        if check_cls.control_id == control_id:
            return check_cls
    return None


@functools.cache
def _build_mythos_registry() -> list[type[BaseCheck]]:
    """Mythos profile registry: existing checks bound by the Mythos catalog.

    Annotates each bound check class so it advertises the ``mythos`` framework and
    its Mythos dimension while remaining a valid ``mrra`` check. The class-level
    annotation is intentional and one-way (a class is either Mythos-bound or not),
    so this is memoized — it runs exactly once per process. Callers receive a
    defensive copy via ``PROFILES`` so the cached list is never mutated.
    """
    from znextscan.frameworks.mythos import MYTHOS_CONTROLS, mythos_scanner_check_ids

    dim_by_check: dict[str, str] = {}
    for spec in MYTHOS_CONTROLS:
        for cid in spec.bound_check_ids:
            dim_by_check.setdefault(cid, spec.dimension)

    registry: list[type[BaseCheck]] = []
    for cid in mythos_scanner_check_ids():
        cls = get_check_by_id(cid)
        if cls is None:
            continue
        if "mythos" not in cls.frameworks:
            cls.frameworks = tuple(cls.frameworks) + ("mythos",)
        cls.mythos_dimension = dim_by_check.get(cid)
        registry.append(cls)
    return registry


# Profile -> ordered check registry. Default profile is ``mrra`` (unchanged behavior).
PROFILES: dict[str, Callable[[], list[type[BaseCheck]]]] = {
    "mrra": lambda: list(CHECK_REGISTRY),
    "mythos": lambda: list(_build_mythos_registry()),
}


def get_registry(profile: str) -> list[type[BaseCheck]]:
    """Return the ordered check registry for a profile."""
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile '{profile}'. Available: {', '.join(sorted(PROFILES))}")
    return PROFILES[profile]()


class ScanResult:
    """Container for a complete scan's results."""

    def __init__(self, config: ScannerConfig) -> None:
        self.scan_id = str(uuid.uuid4())
        self.start_time = datetime.now(timezone.utc)
        self.end_time: datetime | None = None
        self.config = config
        self.results: list[CheckResult] = []
        self.zos_version: str | None = None

    def add_result(self, result: CheckResult) -> None:
        self.results.append(result)

    def finalize(self) -> None:
        self.end_time = datetime.now(timezone.utc)

    @property
    def summary(self) -> dict[str, Any]:
        counts = {s.value: 0 for s in CheckStatus}
        for r in self.results:
            counts[r.status.value] += 1
        total = len(self.results)
        passed = counts["Pass"]
        return {
            "total_checks": total,
            "passed": passed,
            "partial": counts["Partial"],
            "failed": counts["Fail"],
            "errors": counts["Error"],
            "skipped": counts["Skipped"],
            "score_pct": round(passed / total * 100, 1) if total > 0 else 0.0,
        }

    def to_dict(self) -> dict[str, Any]:
        duration = None
        if self.end_time and self.start_time:
            duration = (self.end_time - self.start_time).total_seconds()
        return {
            "scan_metadata": {
                "scan_id": self.scan_id,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": duration,
                "connection_method": self.config.connection.method.value,
                "scanner_version": "0.1.0",
                "zos_version": self.zos_version,
            },
            "controls": [r.to_dict() for r in self.results],
            "summary": self.summary,
        }


ProgressCallback = Callable[[int, int, str, str, str], None]


def run_scan(
    connection: BaseConnection,
    config: ScannerConfig,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Execute all configured checks and return aggregated results.

    Args:
        progress: Optional callback(current, total, control_id, control_name, status)
                  called after each check completes. Use for CLI progress display.
    """
    scan = ScanResult(config)

    # Best-effort target version (annotation only — never used to pre-filter checks).
    try:
        scan.zos_version = (connection.system_info() or {}).get("zos_version")
    except Exception:
        scan.zos_version = None

    # Memoize identical read-only commands for the duration of this scan (e.g. the
    # dozen checks that each issue SETROPTS LIST hit z/OS once).
    from znextscan.connections.caching import CachingConnection

    connection = CachingConnection(connection)

    # Install the recon context so MYT-R02 can consult the authorization gate.
    from znextscan.recon import ReconContext, set_context

    set_context(
        ReconContext(
            enabled=config.recon.enabled,
            authorized=config.recon.authorized,
            identifiers=list(config.recon.identifiers),
            github_token=config.recon.github_token,
            max_results=config.recon.max_results,
        )
    )

    checks_to_run = _resolve_checks(config)
    total = len(checks_to_run)

    log.info("scan_started", total_checks=total, scan_id=scan.scan_id)

    for i, check_cls in enumerate(checks_to_run, 1):
        check = check_cls()
        log.debug("check_started", control_id=check.control_id)

        if progress:
            progress(i, total, check.control_id, check.control_name, "running")

        result = check.run(connection)
        # Annotate skips with the target level so "requires z/OSMF V2.3+" reads in
        # context (e.g. "... target is z/OS 01.13.00").
        if result.status is CheckStatus.SKIPPED and scan.zos_version:
            result.findings.append(f"Target z/OS: {scan.zos_version}")
        scan.add_result(result)

        # Brief pause between checks on live connections to avoid overwhelming
        # slow z/OS systems (prevents EZZ9674E TCPIP SYSPLEX timeouts on Hercules).
        # In-memory connections (Mock, and wrappers over it) are not throttled.
        if i < total and getattr(connection, "is_throttled", False):
            time.sleep(0.5)

        log.debug(
            "check_completed",
            control_id=check.control_id,
            status=result.status.value,
        )

        if progress:
            progress(i, total, check.control_id, check.control_name, result.status.value)

    scan.finalize()
    log.info("scan_completed", scan_id=scan.scan_id, **scan.summary)
    return scan


def _resolve_checks(config: ScannerConfig) -> list[type[BaseCheck]]:
    """Determine which checks to run based on profile and include/exclude lists."""
    include = set(config.scan.checks) if config.scan.checks else None
    exclude = set(config.scan.skip_checks)
    registry = get_registry(config.scan.profile)

    checks = []
    for check_cls in registry:
        if include and check_cls.control_id not in include:
            continue
        if check_cls.control_id in exclude:
            continue
        checks.append(check_cls)
    return checks
