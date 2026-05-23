"""Mythos reporters render correctly (HTML dimension grouping, Excel)."""

from pathlib import Path

from znextscan.config import ScannerConfig
from znextscan.connections.mock import MockConnection
from znextscan.reporters.excel_reporter import write_excel_report
from znextscan.reporters.html_reporter import (
    _get_function_for_check,
    generate_html_report,
)
from znextscan.scanner import run_scan


def _mythos_scan():
    cfg = ScannerConfig()
    cfg.scan.profile = "mythos"
    with MockConnection("tests/fixtures") as c:
        return run_scan(c, cfg)


def test_mythos_native_check_groups_by_dimension() -> None:
    assert _get_function_for_check("MYT-R01")[1] == "Preparedness & Readiness"
    assert _get_function_for_check("MYT-X01")[2] == "RESPOND/RECOVER"
    assert _get_function_for_check("MYT-V02")[1] == "Vulnerability Patching"


def test_legacy_check_grouping_unaffected() -> None:
    assert _get_function_for_check("IAM-002")[0] == "F2"
    assert _get_function_for_check("EXT-024")[0] == "EXT"


def test_html_renders_for_mythos_profile() -> None:
    scan = _mythos_scan()
    html = generate_html_report(scan)
    assert "zNextScan" in html
    assert "Response & Recovery" in html  # MYT-X01 dimension group


def test_excel_renders_for_mythos_profile(tmp_path: Path) -> None:
    scan = _mythos_scan()
    out = write_excel_report(scan, tmp_path / "m.xlsx")
    assert out.exists() and out.stat().st_size > 0
