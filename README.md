# zNextScan

**Mainframe security & readiness scanner for IBM Z** — automated, read-only security configuration assessment with two selectable profiles:

- **`mrra`** (default) — Mainframe Ransomware Readiness Assessment: 32 automated checks across NIST CSF dimensions.
- **`mythos`** — frontier-AI ("Claude Mythos"-class) readiness: a 42-control catalog (~37 checks run; the rest a workshop questionnaire) covering the readable operational-code surface, source/component exposure, hours-scale patch currency, and Respond/Recover — the gaps a frontier-AI adversary exploits. See [`MYTHOS.md`](MYTHOS.md).

Produces JSON, HTML, PDF, and Excel reports plus a Mythos questionnaire (Excel + JSON/CSV) and ZIP evidence bundles. All scriptable checks are live-validated against z/OS 3.1.

> **Safe for production.** zNextScan is **read-only** (display/query commands only), installs **nothing** on z/OS, can be limited to the **z/OSMF REST API**, and runs as a **least-privilege, read-only user**. See [**docs/safe-use.md**](docs/safe-use.md).

## Quick Start

```bash
# Clone and set up
git clone <repo-url> && cd znextscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[pdf]"     # include [pdf] for PDF reports, or just -e "." without

# Mock scan (no z/OS needed)
znextscan scan --mock tests/fixtures --html report.html

# Scan via z/OSMF
export MRRA_PASSWORD='your-password'
znextscan scan --host zos.example.com --user MRRASCN --html report.html --pdf report.pdf

# Scan via SSH (22 TSO checks, faster)
znextscan scan --method ssh --host zos.example.com --user MRRASCN --html report.html

# With config file
znextscan -c mrra-config.sample.yaml scan --html report.html
```

### Credentials

Password can be provided three ways (in priority order):
1. **Interactive prompt** (recommended): omit `--password`, scanner asks securely at runtime
2. **Environment variable:** `export MRRA_PASSWORD='yourpass'`
3. **CLI flag:** `--password yourpass`

Host and user can also come from env vars: `MRRA_HOST`, `MRRA_USER`, `MRRA_PORT`.

> **Warning:** If your password contains `!`, do NOT use `--password` on the command
> line — bash expands `!` via history substitution even inside single quotes in some
> contexts, causing silent authentication failures. Use the interactive prompt or
> set `MRRA_PASSWORD` in a script with `set +H` to disable history expansion.

## Assessment profiles (`--profile`)

| Profile | Catalog | Coverage |
|---------|---------|----------|
| `mrra` (default) | Ransomware readiness | 32 automated checks |
| `mythos` | Frontier-AI readiness | 42 controls — ~37 checks + questionnaire for the rest |

The Mythos profile reuses ~20 MRRA checks and adds frontier-AI-specific native checks: readable operational-code surface (REXX/CLIST/JCL), **authorization-gated** source-exposure recon, multi-JRE CVE sweep, USS/OSS patch currency, immutable-backup presence, MFA framework, z/OS Connect/API glass-box, USS file-permission hardening, and SMF→SIEM readiness. Non-scriptable controls become an Excel + JSON/CSV questionnaire. Guide: [`docs/mythos-checks.md`](docs/mythos-checks.md).

```bash
znextscan scan --profile mythos --method hybrid -H host -u user   # full Mythos scan + questionnaire
znextscan list-controls --profile mythos                          # the 42-control catalog
znextscan generate-questionnaire --profile mythos                 # standalone workshop questionnaire
```

## Features

- **Two profiles** — `mrra` (32 checks) and `mythos` (42-control frontier-AI catalog)
- **z/OSMF + SSH + Hybrid connections** — hybrid recommended for full coverage (console + TSO + USS)
- **Mythos questionnaire** — Excel workbook + JSON/CSV for the non-scriptable controls, scriptable findings pre-filled
- **Authorization-gated external recon** (MYT-R02) — off by default; requires `--recon --authorized-recon --recon-id`
- **Aligned with IBM Health Checker** — validates same settings as RACF_BATCHALLRACF, RACF_SENSITIVE_RESOURCES, RACF_ICHAUTAB_NONLPA, RACF_CSFSERV/CSFKEYS_ACTIVE
- **z/OS V1R13 through V3.1** compatibility
- **JSON + HTML + PDF** reports with Peach Studio styling
- **Evidence bundles** — ZIP archive with raw command outputs
- **Read-only** — never modifies the target system
- **Error handling** — retry on transient failures, clear guidance on permission denied
- **Live progress** — colored progress bar with per-check status (✓ ✗ ○ — ⚠)

## Commands

```bash
znextscan scan                    # Run scan (--profile mrra|mythos)
znextscan list-controls           # List checks (--profile mrra|mythos)
znextscan test-connection -H host # Test z/OSMF connectivity
znextscan generate-questionnaire  # Mythos workshop questionnaire (Excel + JSON/CSV)
znextscan generate-config         # Generate sample YAML config
```

### Scan Options

```
znextscan scan [OPTIONS]
  -H, --host TEXT           z/OS hostname or IP
  -P, --port INT            Port (default: 443 zosmf, 22 ssh)
  -u, --user TEXT           z/OS username
  --password TEXT           Password (or MRRA_PASSWORD env var)
  -m, --method [zosmf|ssh|hybrid|mock]  Connection method (default: zosmf)
  --profile [mrra|mythos]   Assessment profile (default: mrra)
  --mock <dir>              Shortcut for mock mode with fixtures
  -o, --output <file>       JSON output (default: mrra-scan-results.json)
  --html <file>             Generate HTML report
  --pdf <file>              Generate PDF report
  --excel <file>            Generate Excel report
  --evidence/--no-evidence  Evidence bundle (default: yes)
  --recon                   Enable MYT-R02 external exposure recon (mythos)
  --authorized-recon        Affirm authorization for external recon
  --recon-id TEXT           Identifier (org/domain) for recon — repeatable
  --timeout INT             Command timeout in seconds
  -v, --verbose             Debug logging
```

> **Mythos scans auto-emit the questionnaire** beside the JSON report
> (`*-questionnaire.{json,csv,xlsx}`), with scriptable findings pre-filled.

## Output

Normal mode shows a colored progress bar during scan, then per-check results:

```
  ✓  ID-002     Privileged User Inventory
  ✓  ID-003     APF Library Inventory
  ○  IAM-002    Strong Password Policy
  ✗  IAM-003    Default Account Removal
  —  ENC-005    Crypto Hardware Utilization (skipped)

19 passed, 6 partial, 2 failed, 0 skipped, 0 errors (70.4%)
```

Use `-v` / `--verbose` for full debug logging including HTTP requests and structlog output.

## Configuration

```yaml
connection:
  method: zosmf          # zosmf (default), ssh, or mock
  host: zos.example.com
  port: 10443
  username: MRRASCN
  # password via MRRA_PASSWORD env var or prompted interactively
  verify_ssl: false
  timeout: 60

scan:
  checks: []             # empty = all checks, or list specific IDs
  skip_checks: []        # controls to skip
  continue_on_error: true

output:
  output_file: mrra-scan-results.json
  evidence_dir: evidence
  redact_userids: false
```

## z/OS Requirements

See [docs/requirements.md](docs/requirements.md) for full details. Minimal setup:

```
ADDUSER MRRASCN NAME('MRRA SCANNER') DFLTGRP(SYS1) +
  TSO(ACCTNUM(IZUACCT) PROC(IZUFPROC) SIZE(4096))
CONNECT MRRASCN GROUP(IZUUSER)
PERMIT IRR.RADMIN.LISTUSER CLASS(FACILITY) ID(MRRASCN) ACCESS(READ)
PERMIT IRR.RADMIN.RLIST    CLASS(FACILITY) ID(MRRASCN) ACCESS(READ)
PERMIT MVS.MCSOPER.* CLASS(OPERCMDS) ID(MRRASCN) ACCESS(READ)
SETROPTS RACLIST(FACILITY) REFRESH
SETROPTS RACLIST(OPERCMDS) REFRESH
```

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,pdf]"
pytest                        # 255 tests
pytest --cov=znextscan        # coverage
```

## Documentation

- [docs/safe-use.md](docs/safe-use.md) — **read-only / least-privilege / production safety** + how to create the scan user
- [MYTHOS.md](MYTHOS.md) — frontier-AI threat model + 42-control catalog
- [docs/mythos-framework.md](docs/mythos-framework.md) — Mythos framework structure & 4 dimensions
- [docs/mythos-checks.md](docs/mythos-checks.md) — Mythos-native checks + how to interpret
- [docs/mythos-recon.md](docs/mythos-recon.md) — MYT-R02 external recon rules of engagement
- [docs/mythos-questionnaire.md](docs/mythos-questionnaire.md) — questionnaire generator
- [docs/assessment-profiles.md](docs/assessment-profiles.md) — profile/framework abstraction
- [docs/checks.md](docs/checks.md) — per-check reference & **interpretation guide**
- [docs/compatibility.md](docs/compatibility.md) — z/OS version compatibility (V1R13–3.1)
- [docs/requirements.md](docs/requirements.md) — z/OS system and user requirements
- [docs/config.md](docs/config.md) — configuration reference
- [docs/architecture.md](docs/architecture.md) — system architecture
- [docs/connections.md](docs/connections.md) — connection methods (z/OSMF, SSH, hybrid, mock)
- [docs/parsers.md](docs/parsers.md) — parser documentation
