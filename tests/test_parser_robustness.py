"""Property tests: parsers and check parse()/evaluate() never crash.

The supercompatibility invariant requires that *no* command output — empty,
garbage (EBCDIC mis-decode / line noise), old-RACF error soup, truncated, or
pathologically long — can make a parser raise or a check return status=Error.
These tests bypass ``BaseCheck.run()``'s catch-all on purpose, asserting the
parse/evaluate layer is robust on its own.
"""

import inspect

import pytest

from znextscan.checks.base_check import CheckStatus
from znextscan.checks.mythos_checks import MYTHOS_NATIVE_CHECKS
from znextscan.parsers import racf_parser
from znextscan.scanner import CHECK_REGISTRY

# --- payloads (shared with the compat matrix) ---
GARBAGE_BINARY = "\x00\xff\xfe\x01" + "".join(chr(i) for i in range(128, 256)) + "\n\x0c\t" * 50
MESSAGE_SOUP = (
    "ICH13003I NOTHING TO LIST\n"
    "ICH13004I NOTHING TO LIST\n"
    "IKJ56712I INVALID KEYWORD, MFADEF\n"
    "IEE305I D       COMMAND INVALID\n"
    "IKJ56500I COMMAND XYZ NOT FOUND\n"
    "CSV200I ...truncat"
)
PAYLOADS = {
    "empty": "",
    "garbage": GARBAGE_BINARY,
    "soup": MESSAGE_SOUP,
    "truncated": "TRUNCATED LINE WITH NO NEWLI",
    "crlf": "a\r\nb\r\n",
    "long": "x" * 100_000,
}

PARSERS = [
    fn
    for name, fn in inspect.getmembers(racf_parser, inspect.isfunction)
    if name.startswith("parse_")
]
ALL_CHECKS = sorted({*CHECK_REGISTRY, *MYTHOS_NATIVE_CHECKS}, key=lambda c: c.control_id)


def _call_parser(parser, payload: str):
    """Call a parser, supplying a dummy class name for the 2-arg general-resource parsers."""
    required = [
        p
        for p in inspect.signature(parser).parameters.values()
        if p.default is inspect.Parameter.empty
    ]
    if len(required) >= 2:
        return parser(payload, "APPL")
    return parser(payload)


@pytest.mark.parametrize("parser", PARSERS, ids=lambda f: f.__name__)
@pytest.mark.parametrize("payload", PAYLOADS.values(), ids=list(PAYLOADS))
def test_parser_never_raises(parser, payload: str) -> None:
    result = _call_parser(parser, payload)
    assert result is not None  # parsers always return their documented (possibly empty) shape


@pytest.mark.parametrize("check_cls", ALL_CHECKS, ids=lambda c: c.control_id)
@pytest.mark.parametrize("payload", PAYLOADS.values(), ids=list(PAYLOADS))
def test_check_parse_evaluate_never_errors(check_cls, payload: str) -> None:
    chk = check_cls()
    result = chk.evaluate(chk.parse(payload))  # bypasses run()'s catch-all on purpose
    assert result.status is not CheckStatus.ERROR
