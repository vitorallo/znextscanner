"""Mythos control catalog (39 controls) — the implementation source of truth.

Mirrors the catalog published in ``MYTHOS.md`` and
``MYTHOS.md``. Each control is a declarative
``ControlSpec``. Scanner/Hybrid controls bind to an existing check via
``scanner_check_id`` (a real ``control_id`` from ``CHECK_REGISTRY``); non-scriptable
controls carry ``question_text``/``evidence_prompt`` for the questionnaire deliverable.

Note: where the published catalog's "Reuse" hint was imprecise about an existing
``EXT-*`` number, the binding here uses the *correct* existing control_id. New
scriptable controls (R01, R02, V01, V02, V07-extension, X01) have no binding yet —
they are delivered as native checks and behave
as questionnaire items until their check classes exist.
"""

from __future__ import annotations

from dataclasses import dataclass

# Dimension codes
DIM_READINESS = "R"  # Preparedness / Readiness  (NIST Identify)
DIM_CONTROLS = "C"  # Controls to Add           (NIST Protect)
DIM_VULN = "V"  # Vulnerability Patching    (NIST Identify/Protect)
DIM_RESPONSE = "X"  # Response & Recovery       (NIST Respond/Recover)

VALIDATION_METHODS = {"Scanner", "Interview", "Document", "Hybrid"}


@dataclass(frozen=True)
class ControlSpec:
    """One Mythos catalog control."""

    control_id: str
    name: str
    dimension: str
    priority: str  # P0 | P1 | P2
    nist_function: str
    validation_method: str  # Scanner | Interview | Document | Hybrid
    scanner_check_id: str | None = None  # primary existing CHECK_REGISTRY control_id
    question_text: str = ""
    evidence_prompt: str = ""
    extra_check_ids: tuple[str, ...] = ()  # additional checks this control runs

    @property
    def bound_check_ids(self) -> tuple[str, ...]:
        """All scanner checks this control runs (primary + extras)."""
        ids = [self.scanner_check_id, *self.extra_check_ids]
        return tuple(i for i in ids if i)

    @property
    def is_scriptable(self) -> bool:
        """True if this control currently runs an automated check."""
        return bool(self.bound_check_ids)

    @property
    def needs_questionnaire(self) -> bool:
        """True if this control must appear in the questionnaire deliverable."""
        return self.validation_method in ("Interview", "Document", "Hybrid") or (
            self.validation_method == "Scanner" and not self.bound_check_ids
        )


def _q(text: str, evidence: str = "") -> dict[str, str]:
    return {"question_text": text, "evidence_prompt": evidence}


MYTHOS_CONTROLS: list[ControlSpec] = [
    # --- Dimension R: Preparedness / Readiness ---
    ControlSpec(
        "MYT-R01",
        "Readable operational-code surface inventory",
        DIM_READINESS,
        "P1",
        "Identify",
        "Scanner",
        "MYT-R01",
        "What is the volume/location of REXX, CLIST, JCL, PROCs and USS scripts?",
        "Library/dataset listing of operational code",
    ),
    ControlSpec(
        "MYT-R02",
        "Source/component exposure recon (SCM + paste leak)",
        DIM_READINESS,
        "P0",
        "Identify",
        "Scanner",
        "MYT-R02",
        "Authorized external recon for leaked mainframe code/components",
        "Recon scope authorization + identifiers",
    ),
    ControlSpec(
        "MYT-R03",
        "AI-modernization pipeline data governance",
        DIM_READINESS,
        "P0",
        "Identify",
        "Interview",
        None,
        "Which COBOL/PL-I/source is uploaded to AI modernization tooling, under what "
        "contract and retention?",
        "Vendor contracts, data-handling policy",
    ),
    ControlSpec(
        "MYT-R04",
        "ISV/vendor source-breach exposure mapping",
        DIM_READINESS,
        "P1",
        "Identify",
        "Document",
        None,
        "Which installed ISV products have had source/code breaches?",
        "ISV inventory + breach notifications",
    ),
    ControlSpec(
        "MYT-R05",
        "z/OS Connect / USS API glass-box inventory",
        DIM_READINESS,
        "P1",
        "Identify",
        "Scanner",
        "MYT-R05",
        "",
        "",
    ),
    ControlSpec(
        "MYT-R06",
        "Privileged-user inventory (amplification context)",
        DIM_READINESS,
        "P0",
        "Identify",
        "Scanner",
        "ID-002",
        "",
        "",
    ),
    ControlSpec(
        "MYT-R07",
        "APF library inventory (exploit-target enumeration)",
        DIM_READINESS,
        "P0",
        "Identify",
        "Scanner",
        "ID-003",
        "",
        "",
    ),
    ControlSpec(
        "MYT-R08",
        "Crown-jewel data classification & LPAR criticality",
        DIM_READINESS,
        "P0",
        "Identify",
        "Interview",
        None,
        "How are crown-jewel datasets classified and LPARs rated for criticality?",
        "Data classification + LPAR criticality register",
    ),
    ControlSpec(
        "MYT-R09",
        "Mainframe component & version inventory (SBOM)",
        DIM_READINESS,
        "P1",
        "Identify",
        "Hybrid",
        "EXT-002",
        "Is there a complete component/version inventory (SBOM) for the estate?",
        "SBOM / component inventory",
    ),
    # --- Dimension C: Controls to Add ---
    ControlSpec(
        "MYT-C01",
        "Strong password/passphrase policy",
        DIM_CONTROLS,
        "P0",
        "Protect",
        "Scanner",
        "IAM-002",
        "",
        "",
    ),
    ControlSpec(
        "MYT-C02",
        "Default/dormant account elimination",
        DIM_CONTROLS,
        "P0",
        "Protect",
        "Scanner",
        "IAM-003",
        "",
        "",
    ),
    ControlSpec(
        "MYT-C03",
        "SPECIAL attribute restriction",
        DIM_CONTROLS,
        "P0",
        "Protect",
        "Scanner",
        "IAM-004",
        "",
        "",
    ),
    ControlSpec(
        "MYT-C04",
        "Started-task / batch RACF enforcement",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "IAM-005",
        "",
        "",
        extra_check_ids=("EXT-023",),
    ),
    ControlSpec(
        "MYT-C05",
        "Program control / APF / ICHAUTAB integrity",
        DIM_CONTROLS,
        "P0",
        "Protect",
        "Scanner",
        "SCI-001",
        "",
        "",
        extra_check_ids=("SCI-004", "EXT-025", "EXT-015"),
    ),
    ControlSpec(
        "MYT-C06",
        "RACF database & catalog protection",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "EXT-024",
        "",
        "",
    ),
    ControlSpec(
        "MYT-C07",
        "ICSF key management & crypto-hardware use",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "ENC-002",
        "",
        "",
        extra_check_ids=("ENC-005",),
    ),
    ControlSpec(
        "MYT-C08",
        "Dataset / pervasive encryption coverage",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "EXT-013",
        "",
        "",
    ),
    ControlSpec(
        "MYT-C09",
        "Network exposure reduction (FTP/Telnet/TCPIP)",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "EXT-001",
        "",
        "",
        extra_check_ids=("EXT-014",),
    ),
    ControlSpec(
        "MYT-C10",
        "MFA coverage for privileged & vendor access",
        DIM_CONTROLS,
        "P0",
        "Protect",
        "Hybrid",
        "MYT-C10",
        "Is MFA enforced for all privileged and vendor access paths?",
        "MFA policy + RACF MFA configuration",
    ),
    ControlSpec(
        "MYT-C11",
        "Source-egress / DLP for mainframe code",
        DIM_CONTROLS,
        "P0",
        "Protect",
        "Interview",
        None,
        "What controls prevent mainframe source leaving for AI tools / SCM?",
        "DLP/egress policy",
    ),
    ControlSpec(
        "MYT-C12",
        "USS hardening (file permissions)",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "MYT-C12",
        "",
        "",
    ),
    ControlSpec(
        "MYT-C13",
        "Session timeout / console security",
        DIM_CONTROLS,
        "P2",
        "Protect",
        "Scanner",
        "EXT-004",
        "",
        "",
        extra_check_ids=("EXT-006",),
    ),
    ControlSpec(
        "MYT-C14",
        "AI-attack network containment / segmentation",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Interview",
        None,
        "How are LPARs/networks segmented to contain an AI-accelerated intrusion?",
        "Network segmentation diagram",
    ),
    # --- Dimension V: Vulnerability Patching ---
    ControlSpec(
        "MYT-V01",
        "SMP/E maintenance currency vs. hours-SLA",
        DIM_VULN,
        "P0",
        "Identify",
        "Hybrid",
        "MYT-V01",
        "What is SMP/E maintenance age vs. the hours-scale exploitation reality?",
        "SMP/E LIST SYSMODS / RECEIVE history",
    ),
    ControlSpec(
        "MYT-V02",
        "Known-CVE exposure for installed middleware",
        DIM_VULN,
        "P0",
        "Identify",
        "Hybrid",
        "MYT-V02",
        "Which installed middleware versions map to known CVEs?",
        "Component versions + CVE mapping",
    ),
    ControlSpec(
        "MYT-V03",
        "Vulnerability scanning coverage of estate",
        DIM_VULN,
        "P1",
        "Identify",
        "Interview",
        None,
        "Is the mainframe estate covered by vulnerability scanning?",
        "Scan coverage report",
    ),
    ControlSpec(
        "MYT-V04",
        "Patch-SLA shift to hours (process maturity)",
        DIM_VULN,
        "P0",
        "Protect",
        "Interview",
        None,
        "Can patch SLAs operate in hours, not days/weeks?",
        "Patch SLA policy + recent metrics",
    ),
    ControlSpec(
        "MYT-V05",
        "Virtual / compensating-control patching",
        DIM_VULN,
        "P1",
        "Protect",
        "Interview",
        None,
        "Is there a virtual-patching / compensating-control capability?",
        "Compensating-control runbook",
    ),
    ControlSpec(
        "MYT-V06",
        "ISV product patch currency",
        DIM_VULN,
        "P1",
        "Identify",
        "Document",
        None,
        "Are ISV products at supported, current maintenance levels?",
        "ISV maintenance evidence",
    ),
    ControlSpec(
        "MYT-V07",
        "USS / open-source component patch currency",
        DIM_VULN,
        "P1",
        "Identify",
        "Hybrid",
        "MYT-V07",
        "Are USS/open-source components (Python-for-z/OS, OpenSSH) current?",
        "USS package/version listing",
    ),
    # --- Dimension X: Response & Recovery ---
    ControlSpec(
        "MYT-X01",
        "Immutable backup / Safeguarded Copy presence",
        DIM_RESPONSE,
        "P0",
        "Recover",
        "Hybrid",
        "MYT-X01",
        "Is storage-layer immutable backup (Safeguarded Copy) in place?",
        "Safeguarded Copy / immutable-backup config",
    ),
    ControlSpec(
        "MYT-X02",
        "Air-gapped / isolated backup copy",
        DIM_RESPONSE,
        "P0",
        "Recover",
        "Interview",
        None,
        "Is there an air-gapped or network-isolated backup copy?",
        "Backup architecture diagram",
    ),
    ControlSpec(
        "MYT-X03",
        "RACF coverage of backup datasets & catalogs",
        DIM_RESPONSE,
        "P0",
        "Protect",
        "Scanner",
        "EXT-024",
        "",
        "",
    ),
    ControlSpec(
        "MYT-X04",
        "IBM Z Cyber Vault presence & validation cadence",
        DIM_RESPONSE,
        "P1",
        "Recover",
        "Interview",
        None,
        "Is IBM Z Cyber Vault deployed and how often is data validated?",
        "Cyber Vault configuration + validation logs",
    ),
    ControlSpec(
        "MYT-X05",
        "Recovery drill recency & RTO/RPO per workload",
        DIM_RESPONSE,
        "P0",
        "Recover",
        "Interview",
        None,
        "When was the last recovery drill; what are RTO/RPO per workload?",
        "Recovery drill report",
    ),
    ControlSpec(
        "MYT-X06",
        "AI-intrusion mainframe IR playbook",
        DIM_RESPONSE,
        "P1",
        "Respond",
        "Document",
        None,
        "Is there an IR playbook for an AI-accelerated mainframe intrusion?",
        "IR playbook document",
    ),
    ControlSpec(
        "MYT-X07",
        "Break-glass credentials & LPAR isolation procedures",
        DIM_RESPONSE,
        "P1",
        "Respond",
        "Interview",
        None,
        "Are break-glass credentials and LPAR-isolation procedures defined?",
        "Break-glass + isolation procedures",
    ),
    ControlSpec(
        "MYT-X08",
        "SMF/audit forwarding to SIEM (real-time)",
        DIM_RESPONSE,
        "P1",
        "Detect",
        "Hybrid",
        "MYT-X08",
        "Is SMF/audit data forwarded to a SIEM in real time?",
        "SIEM ingestion evidence",
    ),
    ControlSpec(
        "MYT-X09",
        "24/7 SOC coverage & mainframe detection content",
        DIM_RESPONSE,
        "P1",
        "Respond",
        "Interview",
        None,
        "Is there 24/7 SOC coverage with mainframe-specific detection content?",
        "SOC runbook + detection rules",
    ),
    # --- Catalog expansion: orphan MRRA checks
    #     grouped into Mythos controls ---
    ControlSpec(
        "MYT-X10",
        "RACF audit logging coverage",
        DIM_RESPONSE,
        "P0",
        "Detect",
        "Scanner",
        "MON-003",
        "",
        "",
        extra_check_ids=("EXT-007", "EXT-008"),
    ),
    ControlSpec(
        "MYT-C15",
        "RACF dataset-protection hardening (PROTECTALL/ERASE)",
        DIM_CONTROLS,
        "P1",
        "Protect",
        "Scanner",
        "EXT-009",
        "",
        "",
        extra_check_ids=("EXT-010",),
    ),
    ControlSpec(
        "MYT-X11",
        "Backup infrastructure & automation",
        DIM_RESPONSE,
        "P1",
        "Recover",
        "Hybrid",
        "EXT-021",
        "Is automated/immutable backup infrastructure (DFHSM/FlashCopy/CSM) in place?",
        "Backup architecture + automation evidence",
        extra_check_ids=("EXT-022",),
    ),
]

assert len(MYTHOS_CONTROLS) == 42, f"expected 42 controls, got {len(MYTHOS_CONTROLS)}"


def mythos_scanner_check_ids() -> list[str]:
    """All existing control_ids bound by Mythos controls (primary + extras, deduped, ordered)."""
    seen: dict[str, None] = {}
    for spec in MYTHOS_CONTROLS:
        for cid in spec.bound_check_ids:
            if cid not in seen:
                seen[cid] = None
    return list(seen)


def questionnaire_controls() -> list[ControlSpec]:
    """Controls that must appear in the questionnaire deliverable."""
    return [c for c in MYTHOS_CONTROLS if c.needs_questionnaire]
