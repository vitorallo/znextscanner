"""Authorization-gated external source/component exposure reconnaissance.

Powers MYT-R02. **Off by default.** No external query is performed unless the
operator both enables recon and records explicit authorization, AND identifiers
are supplied. See ``docs/mythos-recon.md`` for the rules of engagement.
"""

from znextscan.recon.engine import (
    ReconContext,
    ReconFinding,
    get_context,
    run_recon,
    set_context,
)

__all__ = [
    "ReconContext",
    "ReconFinding",
    "get_context",
    "set_context",
    "run_recon",
]
