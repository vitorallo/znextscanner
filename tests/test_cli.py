"""Tests for CLI commands."""

from pathlib import Path

from click.testing import CliRunner

from znextscan.cli import cli

FIXTURE_DIR = Path(__file__).parent / "fixtures"


class TestCLI:
    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_version(self) -> None:
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_help(self) -> None:
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "zNextScan" in result.output
        assert "scan" in result.output
        assert "list-controls" in result.output

    def test_scan_help(self) -> None:
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--user" in result.output
        assert "--method" in result.output
        assert "--html" in result.output
        assert "--pdf" in result.output

    def test_list_controls(self) -> None:
        result = self.runner.invoke(cli, ["list-controls"])
        assert result.exit_code == 0
        assert "ID-002" in result.output
        assert "IAM-002" in result.output
        assert "32 checks" in result.output

    def test_generate_config(self, tmp_path: Path) -> None:
        output_file = tmp_path / "test-config.yaml"
        result = self.runner.invoke(cli, ["generate-config", "-o", str(output_file)])
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "zosmf" in content

    def test_scan_requires_host(self) -> None:
        result = self.runner.invoke(cli, ["scan"])
        assert result.exit_code == 1
        assert "--host" in result.output or "MRRA_HOST" in result.output

    def test_scan_requires_user(self) -> None:
        result = self.runner.invoke(cli, ["scan", "--host", "zos.example.com"])
        assert result.exit_code == 1
        assert "--user" in result.output or "MRRA_USER" in result.output

    def test_scan_mock_shortcut(self) -> None:
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
                cli, ["scan", "--mock", str(FIXTURE_DIR), "--no-evidence", "-o", "test.json"]
            )
            assert result.exit_code == 0
            assert "passed" in result.output
            assert Path("test.json").exists()

    def test_scan_mock_with_html(self) -> None:
        with self.runner.isolated_filesystem():
            result = self.runner.invoke(
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
            assert Path("report.html").exists()

    def test_test_connection_requires_host(self) -> None:
        result = self.runner.invoke(cli, ["test-connection"])
        assert result.exit_code == 1
        assert "--host" in result.output or "MRRA_HOST" in result.output
