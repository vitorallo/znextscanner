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


# Code search is rate-limited to ~10 req/min even when authenticated, so keep the
# request budget small and honour the reset header rather than hammering.
_MAX_REQUESTS = 20
_MAX_RESET_WAIT = 30  # seconds we're willing to sleep on a rate-limit reset


class GitHubCodeSearchBackend:
    """Active GitHub code-search backend.

    For each identifier, searches the GitHub code-search API for mainframe source
    signatures **scoped to that account** via the ``user:`` qualifier (precise —
    not a global text match). Domain-style identifiers fall back to a free-text
    search. Rate-limit aware (honours ``x-ratelimit-reset``, bounded request
    budget). No query is issued unless identifiers are present (the engine
    enforces the authorization gate).
    """

    name = "github-code-search"
    API = "https://api.github.com/search/code"

    def _client(self, context: ReconContext) -> httpx.Client:
        headers = {"Accept": "application/vnd.github.text-match+json"}
        if context.github_token:
            headers["Authorization"] = f"Bearer {context.github_token}"
        return httpx.Client(timeout=20, headers=headers)

    @staticmethod
    def _query(ident: str, sig: str) -> str:
        # A bare handle (no dot) is a GitHub user/org account -> scope precisely.
        # A domain (has a dot) isn't a GitHub account -> best-effort free text.
        scope = f'"{ident}"' if "." in ident else f"user:{ident}"
        return f'{scope} "{sig}"'

    def search(self, context: ReconContext) -> list[ReconFinding]:
        findings: list[ReconFinding] = []
        requests_made = 0
        with self._client(context) as client:
            for ident in context.identifiers:
                for sig in MAINFRAME_SIGNATURES:
                    if requests_made >= _MAX_REQUESTS:
                        log.warning("github_request_budget_exhausted", made=requests_made)
                        return findings[: context.max_results]
                    resp = client.get(
                        self.API, params={"q": self._query(ident, sig), "per_page": 5}
                    )
                    requests_made += 1

                    # Rate limit: honour the reset window once, then give up.
                    remaining = resp.headers.get("x-ratelimit-remaining")
                    if resp.status_code in (403, 429) or remaining == "0":
                        reset = resp.headers.get("x-ratelimit-reset")
                        wait = self._reset_wait(reset)
                        log.warning("github_rate_limited", reset=reset, wait=wait)
                        if wait <= 0:
                            continue
                        if wait > _MAX_RESET_WAIT:
                            return findings[: context.max_results]  # don't stall the scan
                        time.sleep(wait)
                        if resp.status_code != 200:
                            continue
                    if resp.status_code != 200:
                        continue

                    for item in resp.json().get("items", []):
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

    @staticmethod
    def _reset_wait(reset_header: str | None) -> int:
        try:
            return int(float(reset_header)) - int(time.time()) + 1 if reset_header else 2
        except (TypeError, ValueError):
            return 2


def default_backends(context: ReconContext) -> list[Backend]:
    """Backends to run. Extend here as new sources are added."""
    return [GitHubCodeSearchBackend()]
