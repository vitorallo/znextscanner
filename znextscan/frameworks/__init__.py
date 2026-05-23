"""Assessment frameworks (profiles) for zNextScan.

A *profile* selects which checks run and which control catalog drives reporting.
The default profile is ``mrra`` (the legacy 32-check Mainframe Ransomware Readiness
Assessment); ``mythos`` is the frontier-AI catalog defined in ``MYTHOS.md``.
"""

from znextscan.frameworks.mythos import (
    MYTHOS_CONTROLS,
    ControlSpec,
    mythos_scanner_check_ids,
    questionnaire_controls,
)

__all__ = [
    "ControlSpec",
    "MYTHOS_CONTROLS",
    "mythos_scanner_check_ids",
    "questionnaire_controls",
]
