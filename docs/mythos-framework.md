# Mythos Framework

Component doc for the **Mythos** frontier-AI mainframe readiness assessment framework. The
authoritative narrative and full control catalog live in [`MYTHOS.md`](../MYTHOS.md); this doc
explains the framework's structure and how it relates to the scanner.

## Relationship to MRRA

| | MRRA | Mythos |
|---|---|---|
| Adversary | Human ransomware operator, access-gated, ~207-day dwell | Frontier-AI ("Claude Mythos"-class), autonomous zero-day + exploit, hours-scale |
| Primary surface | Static RACF/SMF/ICSF config | Readable operational/procedural code (REXX/CLIST/JCL/PROC/USS) + accessible app source |
| Central amplifier | — | Source/component exposure (AI-modernization pipelines, SCM leaks, ISV breaches) |
| Respond/Recover | None | First-class (dimension X) |
| Spec source | `MRRA.md` | `MYTHOS.md` |

MRRA is retained as a selectable legacy profile; Mythos is additive.

## Four Dimensions

Every Mythos control belongs to exactly one dimension, mapped to NIST CSF:

| Code | Dimension | NIST CSF | Focus |
|------|-----------|----------|-------|
| `R` | Preparedness / Readiness | Identify | Exposure recon, attack-surface legibility, inventory, classification |
| `C` | Controls to Add | Protect | Procedural-layer hardening, reused RACF/ENC/SCI controls, source-egress/MFA/segmentation |
| `V` | Vulnerability Patching | Identify / Protect | Currency vs. the hours-SLA reality (M-Trends ≈ −7-day mean-time-to-exploit), CVE exposure |
| `X` | Response & Recovery | Respond / Recover | Immutable/air-gapped backup, Cyber Vault, recovery drills, AI-intrusion IR, SIEM forwarding |

## Control Identifier Scheme

`MYT-<D><nn>` — `<D>` is the dimension code, `<nn>` a zero-padded sequence (e.g. `MYT-R02`,
`MYT-X01`). IDs are **stable once published**; expansion is additive-only and governed by the
an additive catalog-expansion process. The catalog is 53 controls (42 core + the 11 §6.1
modern dev/runtime-surface controls): most reuse/extend existing MRRA/EXT check classes, 13
are new native scriptable checks (`znextscan/checks/mythos_checks.py`), and the rest are
non-scriptable (questionnaire). Four expansion controls (R11/R12/V08/V09) are Deferred —
registered as questionnaire items pending Linux-on-Z and zCX backends.

## Validation Methods

Each control is classified by how it is assessed:

- **Scanner** — fully scriptable on z/OS, or externally observable (e.g. exposure recon).
- **Hybrid** — scriptable where reachable; degrades to a questionnaire item via
  `CommandNotSupportedError → Skipped`.
- **Interview** — workshop question.
- **Document** — evidence/policy review.

Scanner/Hybrid controls bind to a scanner check ID for automated result pre-fill.
Interview/Document/Hybrid controls are emitted into the questionnaire deliverable (Excel
workbook + machine-readable JSON/CSV) — implemented by the scanner.

## Source/Component Exposure (Authorization-Gated)

Exposure reconnaissance (MYT-R02) is the central readiness control. Because it performs
**active external reconnaissance against client identifiers**, it is off by default and
requires recorded operator authorization plus a documented rules-of-engagement
(`docs/mythos-recon.md`, authored under the implementation change).

## Implementation Status

This framework is **defined** in `MYTHOS.md`. Scanner code,
the profile abstraction, new checks, the recon module, and the questionnaire generator are
delivered by the scanner implementation. See `MYTHOS.md` for the full
catalog and STRIDE/DREAD threat scenarios.
