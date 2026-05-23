# Assessment Profiles

zNextScan supports selectable **assessment profiles**. A profile decides which
checks run and which catalog drives reporting.

| Profile | Source | Checks | Default |
|---------|--------|--------|---------|
| `mrra` | legacy `CHECK_REGISTRY` | 32 (unchanged) | ✅ yes |
| `mythos` | `znextscan/frameworks/mythos.py` | catalog-bound subset (21: 16 reused + 5 native) | no |

## How it works

- `BaseCheck` gained defaulted attrs `frameworks`, `mythos_dimension`,
  `validation_method` — existing checks need no edits (default to `("mrra",)`).
- `znextscan/frameworks/mythos.py` holds `MYTHOS_CONTROLS` — 39 `ControlSpec`
  entries (the implementation source of truth, mirrors `MYTHOS.md`). Scanner/Hybrid controls bind to a
  check via `scanner_check_id`.
- `scanner.PROFILES` + `get_registry(profile)` resolve the registry.
  `_resolve_checks` is profile-aware via `config.scan.profile`.
- CLI: `--profile {mrra,mythos}` on `scan`; `list-controls --profile mythos`
  shows the full catalog.

**Invariant:** default profile is `mrra` and produces byte-for-byte the legacy
behavior. Mythos is purely additive.

## Usage

```bash
znextscan scan --mock tests/fixtures                  # mrra (default)
znextscan scan --profile mythos --mock tests/fixtures # mythos
znextscan list-controls --profile mythos
```
