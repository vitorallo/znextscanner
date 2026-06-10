"""Pydantic configuration models for MRRA Scanner."""

import os
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, model_validator


class ConnectionMethod(str, Enum):
    """Supported connection methods."""

    ZOSMF = "zosmf"
    SSH = "ssh"
    HYBRID = "hybrid"
    MOCK = "mock"


class ConnectionConfig(BaseModel):
    """Connection settings for the target z/OS system."""

    method: ConnectionMethod = ConnectionMethod.ZOSMF
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = False
    timeout: int = 60
    retries: int = 2  # transient-failure retries per command (0 disables)
    # z/OSMF specific
    zosmf_base_path: str = "/zosmf"
    host_header: Optional[str] = None  # override Host header (IP+VIP/proxy, mDNS .local)
    # SSH specific
    ssh_key_file: Optional[str] = None
    # Mock specific
    fixture_dir: Optional[str] = None

    @model_validator(mode="after")
    def resolve_from_env(self) -> "ConnectionConfig":
        """Fill missing values from MRRA_* environment variables."""
        if self.host is None:
            self.host = os.environ.get("MRRA_HOST")
        if self.username is None:
            self.username = os.environ.get("MRRA_USER")
        if self.password is None:
            self.password = os.environ.get("MRRA_PASSWORD")
        if self.port is None:
            env_port = os.environ.get("MRRA_PORT")
            if env_port:
                self.port = int(env_port)
        return self

    @property
    def effective_port(self) -> int:
        """Return port, defaulting based on method."""
        if self.port is not None:
            return self.port
        if self.method == ConnectionMethod.SSH:
            return 22
        return 443


class ScanConfig(BaseModel):
    """Scan execution settings."""

    profile: str = "mrra"
    checks: list[str] = Field(default_factory=list)
    skip_checks: list[str] = Field(default_factory=list)
    max_retries: int = 3
    continue_on_error: bool = True


class ReconConfig(BaseModel):
    """MYT-R02 external reconnaissance settings. Off by default; gated."""

    enabled: bool = False
    authorized: bool = False
    identifiers: list[str] = Field(default_factory=list)
    github_token: Optional[str] = None
    max_results: int = 20

    @model_validator(mode="after")
    def token_from_env(self) -> "ReconConfig":
        if self.github_token is None:
            self.github_token = os.environ.get("GITHUB_TOKEN")
        return self


class OutputConfig(BaseModel):
    """Output and evidence settings."""

    output_file: str = "mrra-scan-results.json"
    evidence_dir: str = "evidence"
    redact_userids: bool = False


class ScannerConfig(BaseModel):
    """Top-level scanner configuration."""

    connection: ConnectionConfig = Field(default_factory=ConnectionConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)


def load_config(config_path: Path) -> ScannerConfig:
    """Load and validate configuration from a YAML file."""
    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}
    return ScannerConfig(**raw)


def generate_sample_config() -> str:
    """Generate a sample YAML configuration string."""
    sample = {
        "connection": {
            "method": "zosmf",
            "host": "zos.example.com",
            "port": 443,
            "username": "IBMUSER",
            "verify_ssl": False,
            "timeout": 60,
        },
        "scan": {
            "checks": [],
            "skip_checks": [],
            "max_retries": 3,
            "continue_on_error": True,
        },
        "output": {
            "output_file": "mrra-scan-results.json",
            "evidence_dir": "evidence",
            "redact_userids": False,
        },
    }
    header = (
        "# MRRA Scanner Configuration\n"
        "# Password can be set here, via MRRA_PASSWORD env var, or prompted interactively.\n"
        "# password: changeme\n\n"
    )
    return header + yaml.dump(sample, default_flow_style=False, sort_keys=False)
