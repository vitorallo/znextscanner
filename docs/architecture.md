# Architecture

zNextScan is a layered, read-only scanner: a CLI drives a profile-aware
orchestrator that runs checks over a pluggable connection, parses raw z/OS
output into structured data, evaluates it against security criteria, and emits
reports + evidence.

```
┌────────────────────────────────────────────────────────────┐
│  CLI (Click)  scan · list-controls · test-connection ·       │
│               generate-questionnaire · generate-config       │
├────────────────────────────────────────────────────────────┤
│  Scanner orchestrator — profile-aware registry, run_scan(),  │
│  ScanResult                                                  │
├────────────────────────────────────────────────────────────┤
│  Reporters + evidence: JSON · HTML · PDF · Excel ·           │
│  questionnaire (Excel/JSON/CSV) · ZIP bundle (redaction)     │
├────────────────────────────────────────────────────────────┤
│  Check layer: BaseCheck → execute → parse → evaluate →       │
│  CheckResult (Pass/Partial/Fail/Skipped/Error)               │
├────────────────────────────────────────────────────────────┤
│  Parser layer: RACF / z/OS command output → structured data  │
├────────────────────────────────────────────────────────────┤
│  Connection layer: BaseConnection (ABC)                      │
│  ├── ZOSMFConnection  (REST: console + TSO)                  │
│  ├── SSHConnection    (Paramiko: tsocmd + USS)               │
│  ├── HybridConnection (z/OSMF console + SSH TSO/USS)         │
│  └── MockConnection   (fixture files)                        │
├────────────────────────────────────────────────────────────┤
│  recon/ — authorization-gated external exposure recon (R02)  │
└────────────────────────────────────────────────────────────┘
```

## Profiles

A **profile** selects which checks run and which catalog drives reporting
(`--profile`). `mrra` (default) = the legacy 32-check ransomware-readiness set;
`mythos` = the frontier-AI catalog (`znextscan/frameworks/mythos.py`), which
re-binds existing checks (some controls bind several) plus Mythos-native checks,
and routes non-scriptable controls to the questionnaire. `scanner.get_registry()`
resolves the registry per profile; `mrra` behavior is unchanged by Mythos.

## Check lifecycle

1. **execute(connection)** — run one or more commands, return raw text
2. **parse(text)** — extract structured data (data-driven, regex-based)
3. **evaluate(data)** — apply criteria, return a `CheckResult`

`BaseCheck.run()` orchestrates and maps failures:
`CommandNotSupportedError`/`RACFPermissionError` → **Skipped**,
`TimeoutError` → **Error**, anything else → **Error**. Checks are written so
absent features/fields degrade to Skipped/Partial, not Error.

## Key design decisions

- **Read-only** — only display/list commands; never modifies the target.
- **Mock-first** — built/tested against `tests/fixtures/`, then validated on
  real z/OS (`tests/fixtures/real_zos/`).
- **Data-driven parsers, no version branching** — works z/OS V1R13–3.1 over
  z/OSMF or SSH (see [`compatibility.md`](compatibility.md)).
- **Graceful degradation** — unavailable commands/connection methods/features
  Skip rather than error.
- **Pydantic** config; **structlog** logging.

## Directory structure

```
znextscan/
├── cli.py                # Click CLI
├── config.py             # Pydantic config (connection, scan profile, recon, output)
├── scanner.py            # Orchestrator: PROFILES, get_registry, run_scan, ScanResult
├── logging.py
├── connections/          # base, zosmf, ssh, hybrid, mock, factory
├── checks/               # base_check + id/iam/mon/enc/sci/ext + mythos_checks
├── frameworks/           # mythos.py — 42-control catalog (ControlSpec)
├── parsers/              # racf_parser.py — 23 parsers
├── recon/                # engine + backends (authorization-gated MYT-R02)
├── reporters/            # json, html, pdf, excel, questionnaire_{json,excel}
├── data/                 # cve_map.json (offline CVE map for MYT-V02)
└── utils/                # evidence (ZIP + redaction), errors, retry

tests/                    # 15 modules; fixtures/ + fixtures/real_zos + fixtures/v1r13
docs/                     # these guides
```
