# Mythos Questionnaire

Non-scriptable Mythos controls (Interview / Document / Hybrid) become a
client-facing questionnaire deliverable.

## Generation

- `reporters/questionnaire_json.py` → `build_questionnaire(scan=None)` builds a
  dict from `frameworks.questionnaire_controls()`, grouped by the four
  dimensions. If a `ScanResult` is passed, Hybrid/Scanner controls with an
  automated result are pre-filled (`prefilled_status`).
- Outputs: JSON (`write_questionnaire_json`), CSV (`write_questionnaire_csv`),
  Excel (`reporters/questionnaire_excel.py`, reuses `excel_reporter` styling).
- Schema: `schemas/questionnaire.schema.json` (draft-07); response types
  `yes_no | scale_1_5 | free_text | evidence_upload`.

## CLI

```bash
# Standalone blank questionnaire
znextscan generate-questionnaire --json q.json --excel q.xlsx

# Auto-emitted by every Mythos scan, beside the report:
znextscan scan --profile mythos --mock tests/fixtures -o scan.json
#   → scan-questionnaire.{json,csv,xlsx}
```

When evidence bundling is enabled, `questionnaire.json` is included in
`bundle.zip` via `utils/evidence.py`.
