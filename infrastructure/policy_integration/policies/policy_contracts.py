from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ProposedPolicyDraft:
    title: str
    jurisdiction: str
    source: str
    filename: str = ""
    extracted_text: str = ""
    summary: str = ""
    tags: List[str] = field(default_factory=list)
    effective_from: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
