# Configuration

## Overview

MRRA Scanner uses YAML configuration files validated by Pydantic models. Generate a sample config with:

```bash
znextscan generate-config -o mrra-config.yaml
```

## Connection Method Selection

| Method | Coverage | Speed | When to Use |
|--------|----------|-------|-------------|
| `hybrid` | All checks | ~31s | Full coverage — recommended for assessments |
| `zosmf` (default) | TSO + Console checks | ~88s | Standard — z/OSMF V2.3+ available |
| `ssh` | TSO + USS checks | ~18s | No z/OSMF, or z/OS V1R13, or speed priority |
| `mock` | All checks | <1s | Development/testing with fixture files |

**Default is `zosmf`** — use `--method hybrid` for full coverage including USS
checks. SSH skips console checks, z/OSMF skips USS checks. See
`docs/connection-comparison.md` for detailed comparison.

## Config Structure

### connection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `method` | string | `zosmf` | Connection method: `zosmf`, `ssh`, or `mock` |
| `host` | string | `localhost` | Target z/OS hostname |
| `port` | int | `443` | Connection port (443 for z/OSMF, 22 for SSH) |
| `username` | string | `IBMUSER` | z/OS userid |
| `password` | string | — | Set here, via `MRRA_PASSWORD` env var, or prompted interactively |
| `verify_ssl` | bool | `false` | Verify TLS certificate (z/OSMF only) |
| `timeout` | int | `60` | Command timeout in seconds |
| `zosmf_base_path` | string | `/zosmf` | z/OSMF URL base path |
| `ssh_key_file` | string | — | SSH private key path (alternative to password) |
| `fixture_dir` | string | — | Path to fixture files (mock mode only) |

### scan

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `checks` | list | `[]` | Specific controls to run (empty = all) |
| `skip_checks` | list | `[]` | Controls to skip |
| `max_retries` | int | `3` | Retry count for failed commands |
| `continue_on_error` | bool | `true` | Continue scan if a check fails |

### output

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `output_file` | string | `mrra-scan-results.json` | Results file path |
| `evidence_dir` | string | `evidence` | Raw evidence output directory |
| `redact_userids` | bool | `false` | Anonymize userids in output |

## Password Handling

The scanner needs a password to authenticate. Three options, in priority order:

1. **Interactive prompt** (recommended): omit `--password`, scanner asks securely
2. **Environment variable**: `export MRRA_PASSWORD='xxxxx'` (recommended for CI/automation)
3. **Config file**: `password: xxxxx` in the YAML (convenient but stored on disk)

The password is **never** included in JSON reports, evidence bundles, or log output.

### Known Issue: Passwords with Special Characters

If your z/OS password contains `!` (or other bash special characters), **do not
use the `--password` CLI flag**. Bash performs history expansion on `!` even inside
single quotes in some shell contexts, silently changing the password before the
scanner receives it. This causes `401 Unauthorized` errors.

**Workarounds:**
- Use the interactive prompt (omit `--password` — scanner will ask)
- Set the env var in a script: `MRRA_PASSWORD='Pass!' znextscan scan ...`
- Disable history expansion: `set +H` before running the command
- Use a config file: `password: IloveIbm1!` in YAML (no shell expansion)

## Example Configs

### z/OSMF (default, recommended)

```yaml
connection:
  method: zosmf
  host: zos.example.com
  port: 10443
  username: MRRASCN
  # password via MRRA_PASSWORD env var or interactive prompt
  verify_ssl: false
  timeout: 60

scan:
  checks: []        # empty = all checks
  skip_checks: []
  continue_on_error: true

output:
  output_file: mrra-scan-results.json
  evidence_dir: evidence
  redact_userids: false
```

### SSH

```yaml
connection:
  method: ssh
  host: zos.example.com
  port: 22
  username: MRRASCN
  ssh_key_file: ~/.ssh/id_rsa    # or use password
  timeout: 60
```

Note: SSH mode skips 5 console-based checks (ID-003, MON-001, ENC-002, ENC-005, SCI-001).

### Mock Mode (development/testing)

```yaml
connection:
  method: mock
  fixture_dir: tests/fixtures
```

Or from the command line:

```bash
znextscan scan --mock tests/fixtures
```

### Run Specific Checks Only

```yaml
scan:
  checks:
    - ID-002
    - IAM-002
    - MON-001
```

### Skip Certain Checks

```yaml
scan:
  skip_checks:
    - ENC-002     # skip if ICSF not installed
    - ENC-005
```
