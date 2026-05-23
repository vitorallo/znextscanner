"""Tests for configuration loading and validation."""

from pathlib import Path

import pytest
import yaml

from znextscan.config import (
    ConnectionConfig,
    ConnectionMethod,
    ScannerConfig,
    generate_sample_config,
    load_config,
)


class TestConnectionConfig:
    def test_defaults(self) -> None:
        cfg = ConnectionConfig()
        assert cfg.method == ConnectionMethod.ZOSMF
        assert cfg.host is None  # must be provided
        assert cfg.username is None  # must be provided
        assert cfg.timeout == 60
        assert cfg.verify_ssl is False

    def test_effective_port(self) -> None:
        assert ConnectionConfig(method="zosmf").effective_port == 443
        assert ConnectionConfig(method="ssh").effective_port == 22
        assert ConnectionConfig(port=10443).effective_port == 10443

    def test_mock_method(self) -> None:
        cfg = ConnectionConfig(method="mock", fixture_dir="/tmp/fixtures")
        assert cfg.method == ConnectionMethod.MOCK
        assert cfg.fixture_dir == "/tmp/fixtures"


class TestScannerConfig:
    def test_defaults(self) -> None:
        cfg = ScannerConfig()
        assert cfg.connection.method == ConnectionMethod.ZOSMF
        assert cfg.scan.max_retries == 3
        assert cfg.output.output_file == "mrra-scan-results.json"

    def test_from_dict(self) -> None:
        cfg = ScannerConfig(connection={"method": "ssh", "host": "zos.example.com", "port": 22})
        assert cfg.connection.method == ConnectionMethod.SSH
        assert cfg.connection.host == "zos.example.com"
        assert cfg.connection.port == 22


class TestLoadConfig:
    def test_load_yaml(self, tmp_path: Path) -> None:
        config_data = {
            "connection": {
                "method": "mock",
                "host": "testhost",
                "port": 10443,
                "fixture_dir": "/tmp/fixtures",
            },
            "scan": {"checks": ["ID-002", "IAM-002"]},
        }
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(config_data))

        cfg = load_config(config_file)
        assert cfg.connection.method == ConnectionMethod.MOCK
        assert cfg.connection.host == "testhost"
        assert cfg.connection.port == 10443
        assert cfg.scan.checks == ["ID-002", "IAM-002"]

    def test_load_empty_yaml(self, tmp_path: Path) -> None:
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        cfg = load_config(config_file)
        assert cfg.connection.method == ConnectionMethod.ZOSMF

    def test_load_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_config(Path("/nonexistent/config.yaml"))


class TestEnvVars:
    def test_password_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MRRA_PASSWORD", "secret123")
        cfg = ConnectionConfig()
        assert cfg.password == "secret123"

    def test_host_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MRRA_HOST", "zos.prod.com")
        cfg = ConnectionConfig()
        assert cfg.host == "zos.prod.com"

    def test_user_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MRRA_USER", "SCANNER")
        cfg = ConnectionConfig()
        assert cfg.username == "SCANNER"

    def test_explicit_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MRRA_PASSWORD", "from_env")
        cfg = ConnectionConfig(password="explicit")
        assert cfg.password == "explicit"

    def test_no_env_no_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var in ("MRRA_PASSWORD", "MRRA_HOST", "MRRA_USER", "MRRA_PORT"):
            monkeypatch.delenv(var, raising=False)
        cfg = ConnectionConfig()
        assert cfg.password is None
        assert cfg.host is None
        assert cfg.username is None


class TestGenerateConfig:
    def test_generates_valid_yaml(self) -> None:
        output = generate_sample_config()
        parsed = yaml.safe_load(output)
        assert "connection" in parsed
        assert "scan" in parsed
        assert "output" in parsed
        assert parsed["connection"]["method"] == "zosmf"
