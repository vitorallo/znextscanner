"""Structured logging setup for MRRA Scanner."""

import logging
import sys

import structlog


def setup_logging(verbose: bool = False) -> None:
    """Configure structlog with JSON output.

    In normal mode: only scanner INFO messages (check started/completed, scan summary).
    In verbose mode: everything including httpx HTTP requests and debug output.
    """
    log_level = logging.DEBUG if verbose else logging.INFO

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            (
                structlog.dev.ConsoleRenderer()
                if sys.stderr.isatty()
                else structlog.processors.JSONRenderer()
            ),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
    )

    if not verbose:
        # In normal mode, progress display replaces structlog output.
        # Only show warnings/errors from all loggers.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("weasyprint").setLevel(logging.ERROR)
        logging.getLogger("fontTools").setLevel(logging.ERROR)
        logging.getLogger("PIL").setLevel(logging.ERROR)
        logging.getLogger("znextscan").setLevel(logging.WARNING)
