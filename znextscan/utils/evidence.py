"""Evidence bundle creation — saves raw outputs and creates ZIP archive."""

import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from znextscan.scanner import ScanResult


def save_evidence(
    scan: ScanResult,
    evidence_dir: str | Path,
    redact_userids: bool = False,
    questionnaire: dict | None = None,
) -> Path:
    """Save raw command outputs and create a ZIP evidence bundle.

    Creates:
      evidence_dir/
        raw/           — one .txt file per check with raw output
        report.json    — the JSON scan report
        bundle.zip     — ZIP of everything above

    Returns the path to bundle.zip.
    """
    evidence_dir = Path(evidence_dir)
    raw_dir = evidence_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # Save raw outputs
    for result in scan.results:
        if result.raw_output:
            content = result.raw_output
            if redact_userids:
                content = _redact_userids(content)
            filename = f"{result.control_id}.txt"
            (raw_dir / filename).write_text(content)

    # Save JSON report
    from znextscan.reporters.json_reporter import generate_json_report

    report_content = generate_json_report(scan)
    if redact_userids:
        report_content = _redact_userids(report_content)
    (evidence_dir / "report.json").write_text(report_content)

    # Save questionnaire (Mythos non-scriptable controls) into the bundle
    if questionnaire is not None:
        import json as _json

        (evidence_dir / "questionnaire.json").write_text(_json.dumps(questionnaire, indent=2))

    # Save manifest
    timestamp = datetime.now(timezone.utc).isoformat()
    manifest = f"MRRA Scanner Evidence Bundle\nScan ID: {scan.scan_id}\nTimestamp: {timestamp}\n"
    manifest += f"Checks: {len(scan.results)}\n"
    (evidence_dir / "manifest.txt").write_text(manifest)

    # Create ZIP bundle
    zip_path = evidence_dir / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in evidence_dir.rglob("*"):
            if file.is_file() and file != zip_path:
                arcname = file.relative_to(evidence_dir)
                zf.write(file, arcname)

    return zip_path


def _redact_userids(text: str) -> str:
    """Replace common z/OS userid patterns with REDACTED.

    Redacts uppercase 1-8 char tokens that appear after USER=, OWNER=,
    or in access lists. Conservative to avoid false positives.
    """
    # Redact USER=xxx, OWNER=xxx, CONNECT-OWNER=xxx patterns
    text = re.sub(
        r"(USER=|OWNER=|CONNECT-OWNER=)([A-Z][A-Z0-9]{0,7})\b",
        r"\1REDACTED",
        text,
    )
    return text
