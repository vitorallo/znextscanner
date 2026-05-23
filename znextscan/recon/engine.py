"""Recon engine: authorization gate, context, and backend orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

log = structlog.get_logger()


@dataclass
class ReconContext:
    """Runtime recon settings. All gates must pass before any external query."""

    enabled: bool = False
    authorized: bool = False
    identifiers: list[str] = field(default_factory=list)
    github_token: str | None = None
    max_results: int = 20


@dataclass
class ReconFinding:
    """One redaction-safe exposure finding."""

    source: str  # e.g. "github-code-search"
    title: str
    url: str
    detail: str = ""


_CONTEXT: ReconContext | None = None


def set_context(context: ReconContext | None) -> None:
    """Install the recon context (called by the scanner before a Mythos scan)."""
    global _CONTEXT
    _CONTEXT = context


def get_context() -> ReconContext | None:
    return _CONTEXT


def authorize(context: ReconContext | None) -> tuple[bool, str]:
    """Hard authorization gate. Returns (ok, reason-when-not-ok)."""
    if context is None or not context.enabled:
        return False, "recon not enabled (pass --recon)"
    if not context.authorized:
        return False, "recon not authorized (pass --authorized-recon to affirm authorization)"
    if not context.identifiers:
        return False, "no recon identifiers supplied (pass --recon-id)"
    return True, ""


def run_recon(context: ReconContext) -> list[ReconFinding]:
    """Run all backends. Caller MUST have passed ``authorize`` first."""
    from znextscan.recon.backends import default_backends

    findings: list[ReconFinding] = []
    for backend in default_backends(context):
        try:
            findings.extend(backend.search(context))
        except Exception as e:  # one backend failing must not abort the rest
            log.warning("recon_backend_error", backend=backend.name, error=str(e))
    return findings
