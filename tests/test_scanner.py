"""Tests for scanner orchestrator, JSON reporter, and evidence bundle."""

import json
import zipfile
from pathlib import Path

from znextscan.checks.base_check import CheckStatus
from znextscan.config import ScannerConfig
from znextscan.connections.mock import MockConnection
from znextscan.reporters.json_reporter import (
    generate_json_report,
    load_json_report,
    validate_report,
    write_json_report,
)
from znextscan.scanner import CHECK_REGISTRY, ScanResult, _resolve_checks, get_check_by_id, run_scan
from znextscan.utils.evidence import save_evidence

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def make_conn() -> MockConnection:
    return MockConnection(FIXTURE_DIR)


class TestRunScan:
    def test_full_scan(self) -> None:
        config = ScannerConfig()
        result = run_scan(make_conn(), config)
        assert len(result.results) == len(CHECK_REGISTRY)
        assert result.end_time is not None
        assert result.scan_id

    def test_scan_with_include(self) -> None:
        config = ScannerConfig(scan={"checks": ["ID-002", "IAM-002"]})
        result = run_scan(make_conn(), config)
        assert len(result.results) == 2
        ids = [r.control_id for r in result.results]
        assert "ID-002" in ids
        assert "IAM-002" in ids

    def test_scan_with_skip(self) -> None:
        config = ScannerConfig(scan={"skip_checks": ["ENC-002", "ENC-005"]})
        result = run_scan(make_conn(), config)
        assert len(result.results) == len(CHECK_REGISTRY) - 2
        ids = [r.control_id for r in result.results]
        assert "ENC-002" not in ids
        assert "ENC-005" not in ids


class TestScanResult:
    def test_summary(self) -> None:
        config = ScannerConfig()
        result = run_scan(make_conn(), config)
        summary = result.summary
        assert summary["total_checks"] == len(CHECK_REGISTRY)
        assert summary["passed"] + summary["partial"] + summary["failed"] == len(CHECK_REGISTRY)
        assert 0 <= summary["score_pct"] <= 100

    def test_to_dict(self) -> None:
        config = ScannerConfig()
        result = run_scan(make_conn(), config)
        d = result.to_dict()
        assert "scan_metadata" in d
        assert "controls" in d
        assert "summary" in d
        assert d["scan_metadata"]["scanner_version"] == "0.1.0"
        assert len(d["controls"]) == len(CHECK_REGISTRY)


class TestGetCheckById:
    def test_found(self) -> None:
        cls = get_check_by_id("ID-002")
        assert cls is not None
        assert cls.control_id == "ID-002"

    def test_not_found(self) -> None:
        assert get_check_by_id("NONEXISTENT") is None


class TestResolveChecks:
    def test_all_checks(self) -> None:
        config = ScannerConfig()
        checks = _resolve_checks(config)
        assert len(checks) == len(CHECK_REGISTRY)

    def test_include_filter(self) -> None:
        config = ScannerConfig(scan={"checks": ["MON-001"]})
        checks = _resolve_checks(config)
        assert len(checks) == 1
        assert checks[0].control_id == "MON-001"

    def test_exclude_filter(self) -> None:
        config = ScannerConfig(scan={"skip_checks": ["ID-002", "ID-003"]})
        checks = _resolve_checks(config)
        assert len(checks) == len(CHECK_REGISTRY) - 2


class TestJSONReporter:
    def test_generate_report(self) -> None:
        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        report = generate_json_report(scan)
        parsed = json.loads(report)
        assert "scan_metadata" in parsed
        assert len(parsed["controls"]) == len(CHECK_REGISTRY)

    def test_write_and_load(self, tmp_path: Path) -> None:
        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        out = tmp_path / "report.json"
        write_json_report(scan, out)
        assert out.exists()
        loaded = load_json_report(out)
        assert loaded["summary"]["total_checks"] == len(CHECK_REGISTRY)

    def test_report_validates_against_schema(self) -> None:
        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        report = json.loads(generate_json_report(scan))
        errors = validate_report(report)
        assert errors == [], f"Schema validation errors: {errors}"

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        out = tmp_path / "subdir" / "nested" / "report.json"
        write_json_report(scan, out)
        assert out.exists()


class TestEvidence:
    def test_save_evidence(self, tmp_path: Path) -> None:
        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        zip_path = save_evidence(scan, tmp_path / "evidence")
        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

        # Check ZIP contents
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "report.json" in names
            assert "manifest.txt" in names
            # Should have raw output files
            raw_files = [n for n in names if n.startswith("raw/")]
            assert len(raw_files) == len(CHECK_REGISTRY)

    def test_redact_userids(self, tmp_path: Path) -> None:
        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        save_evidence(scan, tmp_path / "evidence", redact_userids=True)

        # Check that userids are redacted in raw output
        iam003_path = tmp_path / "evidence" / "raw" / "IAM-003.txt"
        if iam003_path.exists():
            content = iam003_path.read_text()
            assert "USER=REDACTED" in content


class TestCLIScan:
    def test_mock_scan(self) -> None:
        from click.testing import CliRunner
        from znextscan.cli import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli, ["scan", "--mock", str(FIXTURE_DIR), "--no-evidence", "-o", "test.json"]
            )
            assert result.exit_code == 0
            assert "passed" in result.output
            assert Path("test.json").exists()

    def test_mock_scan_with_evidence(self) -> None:
        from click.testing import CliRunner
        from znextscan.cli import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["scan", "--mock", str(FIXTURE_DIR), "-o", "test.json"])
            assert result.exit_code == 0
            assert "Evidence" in result.output
            assert Path("evidence/bundle.zip").exists()

    def test_mock_scan_with_html(self) -> None:
        from click.testing import CliRunner
        from znextscan.cli import cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                [
                    "scan",
                    "--mock",
                    str(FIXTURE_DIR),
                    "--no-evidence",
                    "-o",
                    "test.json",
                    "--html",
                    "report.html",
                ],
            )
            assert result.exit_code == 0
            assert "HTML" in result.output
            html = Path("report.html").read_text()
            assert "zNextScan" in html
            assert "%" in html  # score percentage present
            assert "ID-002" in html
            assert "Pass" in html


class TestHTMLReporter:
    def test_generate_html(self) -> None:
        from znextscan.reporters.html_reporter import generate_html_report

        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        html = generate_html_report(scan)
        assert "<!DOCTYPE html>" in html
        assert "zNextScan" in html
        assert "ID-002" in html
        assert "IAM-002" in html
        assert len(html) > 5000

    def test_write_html(self, tmp_path: Path) -> None:
        from znextscan.reporters.html_reporter import write_html_report

        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        path = write_html_report(scan, tmp_path / "report.html")
        assert path.exists()
        assert path.stat().st_size > 5000

    def test_html_has_ransomware_context(self) -> None:
        from znextscan.reporters.html_reporter import generate_html_report

        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        html = generate_html_report(scan)
        assert "Ransomware Readiness" in html
        assert "NIST" in html
        assert "STRIDE" in html or "threat scenario" in html.lower()
        assert "IDENTIFY" in html or "PROTECT" in html or "DETECT" in html

    def test_html_grouped_by_function(self) -> None:
        from znextscan.reporters.html_reporter import generate_html_report

        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        html = generate_html_report(scan)
        assert "Asset Inventory" in html
        assert "Identity &" in html
        assert "Monitoring" in html


class TestPDFReporter:
    def test_write_pdf(self, tmp_path: Path) -> None:
        from znextscan.reporters.pdf_reporter import write_pdf_report

        config = ScannerConfig()
        scan = run_scan(make_conn(), config)
        path = write_pdf_report(scan, tmp_path / "report.pdf")
        assert path.exists()
        assert path.stat().st_size > 10000
        # PDF magic bytes
        assert path.read_bytes()[:4] == b"%PDF"
