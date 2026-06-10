"""zNextScan CLI entrypoint."""

from pathlib import Path
from typing import Optional

import click

from znextscan import __version__
from znextscan.config import (
    ConnectionMethod,
    ScannerConfig,
    generate_sample_config,
    load_config,
)
from znextscan.logging import setup_logging
from znextscan.scanner import CHECK_REGISTRY

CONTROL_REGISTRY: dict[str, str] = {cls.control_id: cls.control_name for cls in CHECK_REGISTRY}


@click.group()
@click.version_option(version=__version__, prog_name="znextscan")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.option(
    "-c",
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="YAML config file (CLI flags override config values).",
)
@click.pass_context
def cli(ctx: click.Context, verbose: bool, config_path: Optional[str]) -> None:
    """zNextScan - Mainframe Ransomware Readiness Assessment Scanner."""
    setup_logging(verbose=verbose)
    ctx.ensure_object(dict)
    if config_path:
        ctx.obj["config"] = load_config(Path(config_path))
    else:
        ctx.obj["config"] = ScannerConfig()


# ---- scan command ----


@cli.command()
@click.option("--host", "-H", default=None, help="z/OS hostname or IP.")
@click.option("--port", "-P", default=None, type=int, help="Port (default: 443 zosmf, 22 ssh).")
@click.option("--user", "-u", default=None, help="z/OS username.")
@click.option("--password", default=None, help="Password (or use MRRA_PASSWORD env var).")
@click.option(
    "--method",
    "-m",
    default=None,
    type=click.Choice(["zosmf", "ssh", "hybrid", "mock"], case_sensitive=False),
    help="Connection method (default: zosmf). Hybrid uses z/OSMF Console + SSH TSO.",
)
@click.option(
    "--mock",
    "mock_dir",
    type=click.Path(exists=True),
    help="Shortcut for --method mock --fixture-dir <path>.",
)
@click.option(
    "-o",
    "--output",
    "output_file",
    default=None,
    help="JSON output path (default: mrra-scan-results.json).",
)
@click.option("--html", "html_file", default=None, help="Generate HTML report.")
@click.option("--pdf", "pdf_file", default=None, help="Generate PDF report.")
@click.option("--evidence/--no-evidence", default=True, help="Create evidence bundle.")
@click.option("--timeout", "timeout_val", default=None, type=int, help="Command timeout (seconds).")
@click.option("--excel", "excel_file", default=None, help="Generate Excel report.")
@click.option(
    "--profile",
    "profile",
    default=None,
    type=click.Choice(["mrra", "mythos"], case_sensitive=False),
    help="Assessment profile (default: mrra). 'mythos' = frontier-AI catalog.",
)
@click.option(
    "--recon",
    "recon_enabled",
    is_flag=True,
    help="Enable MYT-R02 external exposure recon (still requires authorization).",
)
@click.option(
    "--authorized-recon",
    "recon_authorized",
    is_flag=True,
    help="Affirm you are authorized to perform external recon on the identifiers.",
)
@click.option(
    "--recon-id", "recon_ids", multiple=True, help="Identifier (org/domain) for recon. Repeatable."
)
@click.option("--no-verify-ssl", is_flag=True, help="Skip SSL verification (default).")
@click.pass_context
def scan(
    ctx: click.Context,
    host: Optional[str],
    port: Optional[int],
    user: Optional[str],
    password: Optional[str],
    method: Optional[str],
    mock_dir: Optional[str],
    output_file: Optional[str],
    html_file: Optional[str],
    pdf_file: Optional[str],
    excel_file: Optional[str],
    profile: Optional[str],
    recon_enabled: bool,
    recon_authorized: bool,
    recon_ids: tuple[str, ...],
    evidence: bool,
    timeout_val: Optional[int],
    no_verify_ssl: bool,
) -> None:
    """Run ransomware readiness assessment scan.

    \b
    Examples:
      znextscan scan --host zos.example.com --user MRRASCN
      znextscan scan --method ssh --host zos.example.com --user MRRASCN
      znextscan scan --mock tests/fixtures --html report.html
      znextscan -c config.yaml scan --html report.html --pdf report.pdf
    """
    from znextscan.connections.factory import create_connection
    from znextscan.reporters.json_reporter import write_json_report
    from znextscan.scanner import run_scan
    from znextscan.utils.evidence import save_evidence

    config: ScannerConfig = ctx.obj["config"]

    # CLI flags override config
    if profile:
        config.scan.profile = profile.lower()
    if recon_enabled:
        config.recon.enabled = True
    if recon_authorized:
        config.recon.authorized = True
    if recon_ids:
        config.recon.identifiers = list(recon_ids)
    if mock_dir:
        config.connection.method = ConnectionMethod.MOCK
        config.connection.fixture_dir = mock_dir
    if method:
        config.connection.method = ConnectionMethod(method.lower())
    if host:
        config.connection.host = host
    if port:
        config.connection.port = port
    if user:
        config.connection.username = user
    if password:
        config.connection.password = password
    if timeout_val:
        config.connection.timeout = timeout_val

    # Resolve effective port
    if config.connection.port is None:
        config.connection.port = config.connection.effective_port

    # Validate required fields for live connections
    if config.connection.method in (
        ConnectionMethod.ZOSMF,
        ConnectionMethod.SSH,
        ConnectionMethod.HYBRID,
    ):
        if not config.connection.host:
            click.echo("Error: --host is required (or set MRRA_HOST env var)")
            ctx.exit(1)
            return
        if not config.connection.username:
            click.echo("Error: --user is required (or set MRRA_USER env var)")
            ctx.exit(1)
            return
        if not config.connection.password:
            config.connection.password = click.prompt("Password", hide_input=True)

        click.echo(
            f"Connecting to {config.connection.host}:{config.connection.port} "
            f"as {config.connection.username} ({config.connection.method.value})"
        )

    out_path = output_file or config.output.output_file

    try:
        connection = create_connection(config.connection)
        # Pre-flight auth check for z/OSMF to fail fast on bad credentials
        if hasattr(connection, "test_connection"):
            try:
                connection.test_connection()
            except Exception as e:
                connection.close()
                click.echo(f"Authentication failed: {e}")
                click.echo(
                    "Hint: passwords with ! may be mangled by bash. Use interactive prompt or MRRA_PASSWORD env var."
                )
                ctx.exit(1)
                return
    except ConnectionError as e:
        click.echo(f"Connection failed: {e}")
        ctx.exit(1)
        return

    # Progress display with ANSI colors
    STATUS_STYLE: dict[str, tuple[str, str]] = {
        # status -> (symbol, ansi_color)
        "running": ("\u2026", "\033[33m"),  # ellipsis, yellow
        "Pass": ("\u2713", "\033[32m"),  # checkmark, green
        "Partial": ("\u25cb", "\033[33m"),  # circle, yellow
        "Fail": ("\u2717", "\033[31m"),  # cross, red
        "Error": ("\u26a0", "\033[35m"),  # warning, magenta
        "Skipped": ("\u2014", "\033[90m"),  # dash, gray
    }
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    ORANGE = "\033[38;5;208m"
    BAR_FILL = "\033[42m"  # green background
    BAR_EMPTY = "\033[100m"  # dark gray background
    is_tty = click.get_text_stream("stderr").isatty()

    def show_progress(current: int, total: int, control_id: str, name: str, status: str) -> None:
        sym, color = STATUS_STYLE.get(status, ("?", ""))

        if is_tty:
            if status == "running":
                # Live progress bar while check is running
                pct = current / total
                filled = int(pct * 24)
                bar = f"{BAR_FILL}{' ' * filled}{RESET}{BAR_EMPTY}{' ' * (24 - filled)}{RESET}"
                line = (
                    f"  {bar} {DIM}{current}/{total}{RESET}  "
                    f"{ORANGE}{control_id}{RESET} {DIM}{name}{RESET}"
                )
                click.echo(f"\r{line}\033[K", nl=False, err=True)
            else:
                # Final result line for completed check
                line = f"  {color}{sym}{RESET}  " f"{ORANGE}{control_id:<10}{RESET} " f"{name}"
                click.echo(f"\r{line}\033[K", err=True)
        elif status != "running":
            click.echo(f"  {sym}  {control_id:<10} {name}", err=True)

    with connection:
        result = run_scan(connection, config, progress=show_progress)

    if is_tty:
        click.echo("", err=True)

    # Reports
    report_path = write_json_report(result, out_path)
    click.echo(f"Report: {report_path}")

    if html_file:
        from znextscan.reporters.html_reporter import write_html_report

        click.echo(f"HTML:   {write_html_report(result, html_file)}")

    if pdf_file:
        from znextscan.reporters.pdf_reporter import write_pdf_report

        click.echo(f"PDF:    {write_pdf_report(result, pdf_file)}")

    if excel_file:
        from znextscan.reporters.excel_reporter import write_excel_report

        click.echo(f"Excel:  {write_excel_report(result, excel_file)}")

    # Mythos profile auto-emits the questionnaire for non-scriptable controls.
    questionnaire = None
    if config.scan.profile == "mythos":
        from znextscan.reporters.questionnaire_excel import write_questionnaire_excel
        from znextscan.reporters.questionnaire_json import (
            build_questionnaire,
            write_questionnaire_csv,
            write_questionnaire_json,
        )

        questionnaire = build_questionnaire(result)
        stem = str(Path(out_path).with_suffix(""))
        qj = write_questionnaire_json(questionnaire, f"{stem}-questionnaire.json")
        write_questionnaire_csv(questionnaire, f"{stem}-questionnaire.csv")
        qx = write_questionnaire_excel(questionnaire, f"{stem}-questionnaire.xlsx")
        click.echo(f"Questionnaire: {qj} | {qx}")

    if evidence:
        zip_path = save_evidence(
            result,
            config.output.evidence_dir,
            redact_userids=config.output.redact_userids,
            questionnaire=questionnaire,
        )
        click.echo(f"Evidence: {zip_path}")

    summary = result.summary
    click.echo(
        f"\n{summary['passed']} passed, {summary['partial']} partial, "
        f"{summary['failed']} failed, {summary['skipped']} skipped, "
        f"{summary['errors']} errors ({summary['score_pct']}%)"
    )


# ---- test-connection command ----


@cli.command("test-connection")
@click.option("--host", "-H", default=None, help="z/OS hostname.")
@click.option("--port", "-P", default=None, type=int, help="Port.")
@click.option("--user", "-u", default=None, help="Username.")
@click.option("--password", default=None, help="Password.")
@click.pass_context
def test_connection(
    ctx: click.Context,
    host: Optional[str],
    port: Optional[int],
    user: Optional[str],
    password: Optional[str],
) -> None:
    """Test z/OSMF connectivity."""
    config: ScannerConfig = ctx.obj["config"]
    conn = config.connection

    if host:
        conn.host = host
    if port:
        conn.port = port
    if user:
        conn.username = user
    if password:
        conn.password = password
    if conn.port is None:
        conn.port = conn.effective_port

    if not conn.host:
        click.echo("Error: --host is required (or set MRRA_HOST)")
        ctx.exit(1)
        return

    click.echo(f"Method: {conn.method.value}")
    click.echo(f"Host:   {conn.host}:{conn.port}")
    click.echo(f"User:   {conn.username or '(not set)'}")

    if conn.method == ConnectionMethod.ZOSMF:
        if not conn.password:
            conn.password = click.prompt("Password", hide_input=True)
        try:
            from znextscan.connections.factory import create_connection
            from znextscan.connections.zosmf import ZOSMFConnection

            c = create_connection(conn)
            assert isinstance(c, ZOSMFConnection)  # zosmf branch returns ZOSMFConnection
            info = c.test_connection()
            click.echo(f"z/OS:   {info.get('zos_version', '?')}")
            click.echo(f"z/OSMF: {info.get('zosmf_full_version', '?')}")
            click.echo(f"Host:   {info.get('zosmf_hostname', '?')}")
            plugins = [p for p in info.get("plugins", []) if p.get("pluginStatus") == "ACTIVE"]
            click.echo(f"Plugins: {len(plugins)} active")
            click.echo("OK")
            c.close()
        except Exception as e:
            click.echo(f"FAILED: {e}")
            ctx.exit(1)
    else:
        click.echo("test-connection only available for zosmf method.")


# ---- list-controls ----


@cli.command("list-controls")
@click.option(
    "--profile",
    "profile",
    default="mrra",
    type=click.Choice(["mrra", "mythos"], case_sensitive=False),
    help="Profile whose controls to list (default: mrra).",
)
def list_controls(profile: str) -> None:
    """List the controls for an assessment profile."""
    profile = profile.lower()
    if profile == "mrra":
        click.echo(f"{'ID':<10} {'Name'}")
        click.echo("-" * 55)
        for cid, name in CONTROL_REGISTRY.items():
            click.echo(f"{cid:<10} {name}")
        click.echo(f"\n{len(CONTROL_REGISTRY)} checks available (mrra)")
        return

    from znextscan.frameworks import MYTHOS_CONTROLS

    click.echo(f"{'ID':<9} {'Dim':<3} {'Pri':<3} {'Validation':<10} {'Name'}")
    click.echo("-" * 72)
    scriptable = 0
    for c in MYTHOS_CONTROLS:
        flag = "*" if c.is_scriptable else " "
        if c.is_scriptable:
            scriptable += 1
        click.echo(
            f"{c.control_id:<9} {c.dimension:<3} {c.priority:<3} "
            f"{c.validation_method:<10} {flag}{c.name}"
        )
    click.echo(
        f"\n{len(MYTHOS_CONTROLS)} Mythos controls "
        f"({scriptable} scriptable now, {len(MYTHOS_CONTROLS) - scriptable} "
        f"questionnaire/pending). * = automated check available."
    )


# ---- generate-questionnaire ----


@cli.command("generate-questionnaire")
@click.option(
    "--profile",
    default="mythos",
    type=click.Choice(["mythos"], case_sensitive=False),
    help="Assessment profile (only 'mythos' has a questionnaire).",
)
@click.option(
    "--excel", "excel_path", default="mythos-questionnaire.xlsx", help="Excel workbook output path."
)
@click.option(
    "--json",
    "json_path",
    default="mythos-questionnaire.json",
    help="JSON output path (a sibling .csv is also written).",
)
def generate_questionnaire(profile: str, excel_path: str, json_path: str) -> None:
    """Generate the Mythos questionnaire (non-scriptable controls) for the workshop."""
    from znextscan.reporters.questionnaire_excel import write_questionnaire_excel
    from znextscan.reporters.questionnaire_json import (
        build_questionnaire,
        write_questionnaire_csv,
        write_questionnaire_json,
    )

    q = build_questionnaire(None)
    j = write_questionnaire_json(q, json_path)
    csv_path = str(Path(json_path).with_suffix(".csv"))
    write_questionnaire_csv(q, csv_path)
    x = write_questionnaire_excel(q, excel_path)
    n = sum(len(s["controls"]) for s in q["sections"])
    click.echo(f"Questionnaire: {n} controls\n  JSON:  {j}\n  CSV:   {csv_path}\n  Excel: {x}")


# ---- generate-config ----


@cli.command("generate-config")
@click.option("-o", "--output", "output_path", default="mrra-config.yaml", help="Output file path.")
def generate_config(output_path: str) -> None:
    """Generate a sample YAML configuration file."""
    Path(output_path).write_text(generate_sample_config())
    click.echo(f"Config written to {output_path}")
