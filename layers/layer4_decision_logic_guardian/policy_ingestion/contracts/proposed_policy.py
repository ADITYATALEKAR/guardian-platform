"""
Purpose

Produced by PolicyAgent

Derived from PDFs, web pages, scraped content

Never used directly by PolicyEngine

Always requires human review

"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, List, Dict
from datetime import datetime
import uuid


ProposedPolicySource = Literal[
    "PDF_UPLOAD",
    "WEB_SCRAPE",
    "MANUAL_ENTRY",
    "INTERNAL_DOC",
    "UNKNOWN",
]

ProposedPolicyStatus = Literal[
    "SUBMITTED",
    "UNDER_REVIEW",
    "APPROVED",
    "REJECTED",
]


@dataclass(frozen=True)
class ProposedPolicy:
    """
    A policy proposal extracted from an untrusted/probabilistic source.
    This is NOT legally safe until approved.

    Key principle:
    - ProposedPolicy may be incomplete or ambiguous.
    - Must be reviewed by human.
    """

    proposed_policy_id: str = field(default_factory=lambda: f"prop_{uuid.uuid4().hex}")
    tenant_id: Optional[str] = None  # None allowed for global regulatory proposals
    source: ProposedPolicySource = "UNKNOWN"

    # Provenance
    source_url: Optional[str] = None
    source_file_name: Optional[str] = None
    extracted_text_excerpt: Optional[str] = None

    # Suggested metadata (probabilistic)
    jurisdiction: Optional[str] = None  # "EU", "US", "IN", etc.
    framework: Optional[str] = None     # "GDPR", "RBI", "PCI-DSS", "INTERNAL", etc.
    policy_name: Optional[str] = None

    requirement_text: str = ""
    violation_risk: Optional[str] = None
    remediation_deadline_days: Optional[int] = None
    enforcement_authority: Optional[str] = None

    # Mapping proposals (NOT trusted until approved)
    proposed_pattern_labels: List[str] = field(default_factory=list)

    # Extraction confidence (NLP/agent output)
    extraction_confidence: Optional[float] = None  # 0.0–1.0
    extraction_notes: List[str] = field(default_factory=list)

    status: ProposedPolicyStatus = "SUBMITTED"

    submitted_at_utc: datetime = field(default_factory=datetime.utcnow)
    submitted_by: Optional[str] = None  # user/email/service

    def __post_init__(self):
        if self.extraction_confidence is not None:
            if not (0.0 <= self.extraction_confidence <= 1.0):
                raise ValueError("extraction_confidence must be between 0.0 and 1.0")
