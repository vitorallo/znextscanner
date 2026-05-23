"""Questionnaire builder + JSON/CSV export for non-scriptable Mythos controls."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from znextscan.frameworks import questionnaire_controls
from znextscan.frameworks.mythos import ControlSpec

_DIMENSIONS = ["R", "C", "V", "X"]

_RESPONSE_TYPE = {
    "Document": "evidence_upload",
    "Interview": "yes_no",
    "Hybrid": "yes_no",
    "Scanner": "free_text",
}


def _response_type(spec: ControlSpec) -> str:
    return _RESPONSE_TYPE.get(spec.validation_method, "free_text")


def build_questionnaire(scan: Optional[Any] = None) -> dict[str, Any]:
    """Build the questionnaire dict for the Mythos non-scriptable controls.

    If ``scan`` (a ScanResult) is provided, Hybrid/Scanner controls that also
    produced an automated result are pre-filled with that status.
    """
    prefill: dict[str, str] = {}
    if scan is not None:
        for r in scan.results:
            prefill[r.control_id] = r.status.value

    sections: list[dict[str, Any]] = []
    controls = questionnaire_controls()
    for dim in _DIMENSIONS:
        dim_controls = [c for c in controls if c.dimension == dim]
        if not dim_controls:
            continue
        entries = []
        for c in dim_controls:
            prefilled = prefill.get(c.scanner_check_id) if c.scanner_check_id else None
            entries.append(
                {
                    "control_id": c.control_id,
                    "name": c.name,
                    "priority": c.priority,
                    "nist_function": c.nist_function,
                    "validation_method": c.validation_method,
                    "question": c.question_text or c.name,
                    "evidence_prompt": c.evidence_prompt,
                    "response_type": _response_type(c),
                    "prefilled_status": prefilled,
                    "answer": None,
                    "notes": "",
                }
            )
        sections.append({"dimension": dim, "controls": entries})

    return {
        "assessment": "mythos",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": getattr(scan, "scan_id", None),
        "sections": sections,
    }


def write_questionnaire_json(questionnaire: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.write_text(json.dumps(questionnaire, indent=2))
    return p


def write_questionnaire_csv(questionnaire: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    with p.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(
            [
                "Dimension",
                "Control ID",
                "Name",
                "Priority",
                "NIST",
                "Validation",
                "Question",
                "Evidence Prompt",
                "Response Type",
                "Prefilled Status",
                "Answer",
                "Notes",
            ]
        )
        for section in questionnaire["sections"]:
            for c in section["controls"]:
                w.writerow(
                    [
                        section["dimension"],
                        c["control_id"],
                        c["name"],
                        c["priority"],
                        c["nist_function"],
                        c["validation_method"],
                        c["question"],
                        c["evidence_prompt"],
                        c["response_type"],
                        c["prefilled_status"] or "",
                        "",
                        "",
                    ]
                )
    return p
