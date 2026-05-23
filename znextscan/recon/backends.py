"""Pluggable recon backends. Only invoked after the authorization gate passes."""

from __future__ import annotations

import time
from typing import Protocol

import httpx
import structlog

from znextscan.recon.engine import ReconContext, ReconFinding

log = structlog.get_logger()

# Signatures that strongly indicate leaked mainframe source/components.
MAINFRAME_SIGNATURES = [
    "IDENTIFICATION DIVISION",  # COBOL
    "EXEC PGM=",  # JCL
    "//SYSIN DD",  # JCL
    "ADDRESS TSO",  # REXX
    "EXEC CICS",  # CICS
]


class Backend(Protocol):
    name: str

    def search(self, context: ReconContext) -> list[ReconFinding]: ...


class GitHubCodeSearchBackend:
    """Active GitHub code-search backend.

    Queries the public GitHub code-search API for mainframe source signatures
    scoped to caller-supplied identifiers. Rate-limit aware. No query is issued
    unless identifiers are present (the engine enforces the authorization gate).
    """

    name = "github-code-search"
    API = "https://api.github.com/search/code"

    def _client(self, context: ReconContext) -> httpx.Client:
        headers = {"Accept": "application/vnd.github.text-match+json"}
        if context.github_token:
            headers["Authorization"] = f"Bearer {context.github_token}"
        return httpx.Client(timeout=20, headers=headers)

    def search(self, context: ReconContext) -> list[ReconFinding]:
        findings: list[ReconFinding] = []
        with self._client(context) as client:
            for ident in context.identifiers:
                for sig in MAINFRAME_SIGNATURES:
                    q = f'"{sig}" {ident}'
                    resp = client.get(self.API, params={"q": q, "per_page": 5})
                    if resp.status_code == 403:  # rate limited / abuse detection
                        reset = resp.headers.get("x-ratelimit-reset")
                        log.warning("github_rate_limited", reset=reset)
                        time.sleep(2)
                        continue
                    if resp.status_code != 200:
                        continue
                    for item in resp.json().get("items", [])[: context.max_results]:
                        repo = item.get("repository", {}).get("full_name", "?")
                        findings.append(
                            ReconFinding(
                                source=self.name,
                                title=f"{ident}: '{sig}' in {repo}",
                                url=item.get("html_url", ""),
                                detail=f"path={item.get('path', '?')}",
                            )
                        )
                    if len(findings) >= context.max_results:
                        return findings[: context.max_results]
        return findings


def default_backends(context: ReconContext) -> list[Backend]:
    """Backends to run. Extend here as new sources are added."""
    return [GitHubCodeSearchBackend()]
