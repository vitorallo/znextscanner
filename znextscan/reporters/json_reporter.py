"""JSON report generation and schema validation for scan results."""

import json
from pathlib import Path
from typing import Any

import jsonschema

from znextscan.scanner import ScanResult

SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "output-schema.json"


def generate_json_report(scan: ScanResult, pretty: bool = True) -> str:
    """Generate a JSON report string from scan results."""
    report = scan.to_dict()
    indent = 2 if pretty else None
    return json.dumps(report, indent=indent, default=str)


def write_json_report(scan: ScanResult, output_path: str | Path) -> Path:
    """Write JSON report to a file. Returns the path written."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_json_report(scan)
    path.write_text(content)
    return path


def load_json_report(path: str | Path) -> dict[str, Any]:
    """Load and parse a JSON report file."""
    data: dict[str, Any] = json.loads(Path(path).read_text())
    return data


def validate_report(report: dict[str, Any]) -> list[str]:
    """Validate a report dict against the JSON schema.

    Returns a list of validation error messages (empty if valid).
    """
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = jsonschema.Draft202012Validator(schema)
    return [f"{e.json_path}: {e.message}" for e in validator.iter_errors(report)]
