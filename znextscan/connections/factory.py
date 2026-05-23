"""Connection factory — creates the right connection from config."""

import structlog

from znextscan.config import ConnectionConfig, ConnectionMethod
from znextscan.connections.base import BaseConnection

log = structlog.get_logger()


def create_connection(config: ConnectionConfig) -> BaseConnection:
    """Create a connection based on the configured method.

    Raises ConnectionError if the connection cannot be established.
    For z/OSMF and SSH, validates connectivity before returning.
    """
    if config.method == ConnectionMethod.MOCK:
        from znextscan.connections.mock import MockConnection

        fixture_dir = config.fixture_dir or "tests/fixtures"
        log.info("connection_created", method="mock", fixture_dir=fixture_dir)
        return MockConnection(fixture_dir)

    if config.method == ConnectionMethod.ZOSMF:
        from znextscan.connections.zosmf import ZOSMFConnection

        if not config.password:
            raise ConnectionError(
                "z/OSMF password required — set in config, MRRA_PASSWORD env var, "
                "or use interactive mode"
            )
        conn = ZOSMFConnection(
            host=config.host or "localhost",
            port=config.effective_port,
            username=config.username or "IBMUSER",
            password=config.password,
            verify_ssl=config.verify_ssl,
            timeout=config.timeout,
            base_path=config.zosmf_base_path,
        )
        log.info("connection_created", method="zosmf", host=config.host, port=config.port)
        return conn

    if config.method == ConnectionMethod.SSH:
        from znextscan.connections.ssh import SSHConnection

        conn = SSHConnection(
            host=config.host or "localhost",
            port=config.effective_port,
            username=config.username or "IBMUSER",
            password=config.password,
            key_filename=config.ssh_key_file,
            timeout=config.timeout,
        )
        log.info("connection_created", method="ssh", host=config.host, port=config.port)
        return conn

    if config.method == ConnectionMethod.HYBRID:
        from znextscan.connections.hybrid import HybridConnection
        from znextscan.connections.ssh import SSHConnection
        from znextscan.connections.zosmf import ZOSMFConnection

        if not config.password:
            raise ConnectionError("Password required for hybrid mode")
        host = config.host or "localhost"
        username = config.username or "IBMUSER"
        # Create SSH first (it connects eagerly), then z/OSMF (lazy client)
        try:
            ssh = SSHConnection(
                host=host,
                port=22,
                username=username,
                password=config.password,
                key_filename=config.ssh_key_file,
                timeout=config.timeout,
            )
        except Exception as e:
            raise ConnectionError(
                f"Hybrid mode: SSH connection failed ({e}). "
                f"Ensure SSH is available on {host}:22 and credentials are valid. "
                f"Use --method zosmf for z/OSMF-only mode."
            ) from e
        zosmf = ZOSMFConnection(
            host=host,
            port=config.effective_port,
            username=username,
            password=config.password,
            verify_ssl=config.verify_ssl,
            timeout=config.timeout,
            base_path=config.zosmf_base_path,
        )
        log.info("connection_created", method="hybrid", host=host)
        return HybridConnection(zosmf, ssh)

    raise ConnectionError(f"Unknown connection method: {config.method}")
