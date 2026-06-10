"""PDF report generation — renders the HTML report to PDF via WeasyPrint."""

from pathlib import Path

from znextscan.reporters.html_reporter import generate_html_report
from znextscan.scanner import ScanResult


def write_pdf_report(scan: ScanResult, output_path: str | Path) -> Path:
    """Generate PDF report from scan results. Returns the path written."""
    try:
        import weasyprint
    except ImportError as e:
        raise RuntimeError(
            "PDF generation requires WeasyPrint — install it with: pip install 'znextscan[pdf]'"
        ) from e

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    html_content = generate_html_report(scan)
    weasyprint.HTML(string=html_content).write_pdf(str(path))
    return path
