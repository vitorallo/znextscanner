"""Tests for the Mythos questionnaire generator."""

import json
from pathlib import Path

import jsonschema
import pytest
from click.testing import CliRunner

from znextscan.cli import cli
from znextscan.reporters.questionnaire_excel import write_questionnaire_excel
from znextscan.reporters.questionnaire_json import (
    build_questionnaire,
    write_questionnaire_csv,
    write_questionnaire_json,
)

SCHEMA = json.loads(Path("schemas/questionnaire.schema.json").read_text())


def test_build_structure() -> None:
    q = build_questionnaire(None)
    assert q["assessment"] == "mythos"
    dims = {s["dimension"] for s in q["sections"]}
    assert dims == {"R", "C", "V", "X"}
    total = sum(len(s["controls"]) for s in q["sections"])
    assert total >= 13  # non-scriptable + hybrid controls


def test_schema_valid() -> None:
    q = build_questionnaire(None)
    jsonschema.validate(q, SCHEMA)


def test_only_non_scriptable_or_hybrid() -> None:
    q = build_questionnaire(None)
    for s in q["sections"]:
        for c in s["controls"]:
            assert c["validation_method"] in ("Interview", "Document", "Hybrid", "Scanner")
            assert c["answer"] is None


def test_json_and_csv_written(tmp_path: Path) -> None:
    q = build_questionnaire(None)
    j = write_questionnaire_json(q, tmp_path / "q.json")
    c = write_questionnaire_csv(q, tmp_path / "q.csv")
    assert j.exists() and c.exists()
    jsonschema.validate(json.loads(j.read_text()), SCHEMA)
    assert "Control ID" in c.read_text().splitlines()[0]


def test_excel_written(tmp_path: Path) -> None:
    q = build_questionnaire(None)
    x = write_questionnaire_excel(q, tmp_path / "q.xlsx")
    assert x.exists() and x.stat().st_size > 0


def test_cli_generate_questionnaire(tmp_path: Path) -> None:
    runner = CliRunner()
    jp = tmp_path / "out.json"
    xp = tmp_path / "out.xlsx"
    r = runner.invoke(
        cli,
        ["generate-questionnaire", "--json", str(jp), "--excel", str(xp)],
    )
    assert r.exit_code == 0, r.output
    assert jp.exists() and xp.exists()
    assert (tmp_path / "out.csv").exists()


def test_scan_mythos_auto_emits_questionnaire(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "scan.json"
    r = runner.invoke(
        cli,
        [
            "scan",
            "--profile",
            "mythos",
            "--mock",
            "tests/fixtures",
            "--no-evidence",
            "-o",
            str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    assert (tmp_path / "scan-questionnaire.json").exists()
    assert (tmp_path / "scan-questionnaire.xlsx").exists()
    q = json.loads((tmp_path / "scan-questionnaire.json").read_text())
    jsonschema.validate(q, SCHEMA)
    # A Hybrid control with an automated result should be pre-filled.
    prefilled = [c for s in q["sections"] for c in s["controls"] if c["prefilled_status"]]
    assert prefilled
