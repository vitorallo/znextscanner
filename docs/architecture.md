# Architecture

## Overview

MRRA Scanner follows a layered architecture with clear separation between connection handling, command execution, output parsing, and security evaluation.

```
┌──────────────────────────────────────────────────┐
│                     CLI Layer                     │
│              (Click commands + config)            │
├──────────────────────────────────────────────────┤
│                  Scanner Orchestrator             │
│       (runs checks, collects ScanResult)          │
├──────────────────────────────────────────────────┤
│              Reporter + Evidence                  │
│      JSON report + raw output ZIP bundle          │
├──────────────────────────────────────────────────┤
│                   Check Layer                     │
│         BaseCheck → execute → parse → evaluate    │
│         Returns CheckResult (Pass/Fail/etc.)      │
├──────────────────────────────────────────────────┤
│                  Parser Layer                     │
│        RACF output → structured dicts/lists       │
├──────────────────────────────────────────────────┤
│                 Connection Layer                  │
│     BaseConnection (ABC)                          │
│     ├── MockConnection   (fixture files)          │
│     ├── ZOSMFConnection  (REST API) [planned]     │
│     └── SSHConnection    (Paramiko)  [planned]    │
└──────────────────────────────────────────────────┘
```

## Data Flow

```
CLI (--mock dir) → MockConnection
                      ↓
              Scanner.run_scan()
                      ↓
              for each Check:
                execute(conn) → raw text
                parse(text)   → dict
                evaluate(dict) → CheckResult
                      ↓
              ScanResult (all CheckResults)
                      ↓
              ├── JSON Reporter → report.json
              └── Evidence Bundle → bundle.zip
                      ↓
              CLI output (summary)
```

## Key Design Decisions

### Mock-First Development
All checks are built and tested against fixture files (`tests/fixtures/`) before validation on real z/OS. The `MockConnection` reads command outputs from text files, enabling development without mainframe access.

### Check Lifecycle
Every check follows a three-phase pattern:

1. **execute()** — runs one or more commands via a connection
2. **parse()** — extracts structured data from raw text output
3. **evaluate()** — compares data against security criteria, returns CheckResult

The `BaseCheck.run()` method orchestrates this and handles exceptions:
- `CommandNotSupportedError` → `CheckStatus.SKIPPED` (version compatibility)
- Other exceptions → `CheckStatus.ERROR`

### Version Compatibility
Parsers are data-driven (regex-based, return `None` for missing fields). No version branching. Works on z/OS V1R13 through 3.1. See `docs/compatibility.md`.

### Configuration
Pydantic models validate all configuration. See `znextscan/config.py`.

### Logging
structlog provides structured JSON logging for production and console output for development.

## Directory Structure

```
znextscan/
├── __init__.py           # Package version
├── cli.py                # Click CLI (scan, list-controls, test-connection, generate-config)
├── config.py             # Pydantic config models + YAML loading
├── logging.py            # structlog setup
├── scanner.py            # Orchestrator (run_scan, ScanResult, CHECK_REGISTRY)
├── connections/
│   ├── base.py           # BaseConnection ABC + CommandNotSupportedError
│   └── mock.py           # MockConnection (reads fixture files)
├── checks/
│   ├── base_check.py     # BaseCheck ABC + CheckResult + CheckStatus
│   ├── id_checks.py      # ID-002 (Privileged Users), ID-003 (APF Libraries)
│   ├── iam_checks.py     # IAM-002 (Password), IAM-003 (Defaults), IAM-004 (SPECIAL), IAM-005 (STC)
│   ├── mon_checks.py     # MON-001 (SMF), MON-003 (RACF Audit)
│   ├── enc_checks.py     # ENC-002 (ICSF Keys), ENC-005 (Crypto Hardware)
│   └── sci_checks.py     # SCI-001 (APF Integrity), SCI-004 (Program Control)
├── parsers/
│   └── racf_parser.py    # 12 parsers for RACF/z/OS command output
├── reporters/
│   └── json_reporter.py  # JSON report generation
└── utils/
    └── evidence.py       # Evidence bundle (ZIP) creation + userid redaction

tests/
├── fixtures/             # Mock z/OS command output files (z/OS 3.1 format)
│   ├── real_zos/         # Captured from live z/OS 3.1 Hercules devlab
│   └── v1r13/            # Simulated z/OS V1R13 output
├── test_checks.py        # Check class tests (all 12 checks)
├── test_checks_base.py   # BaseCheck, CheckResult, CommandNotSupportedError tests
├── test_cli.py           # CLI command tests
├── test_config.py        # Config loading/validation tests
├── test_connections.py   # MockConnection tests
├── test_parsers.py       # Parser tests (mock + real z/OS + V1R13)
└── test_scanner.py       # Scanner, reporter, evidence, end-to-end tests

docs/
├── architecture.md       # This file
├── checks.md             # Per-check documentation
├── compatibility.md      # z/OS version compatibility matrix
├── config.md             # Configuration reference
├── connections.md        # Connection layer documentation
└── parsers.md            # Parser documentation
```
