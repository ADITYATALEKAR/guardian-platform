from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import hashlib


def _safe_str(x: Any, default: str = "") -> str:
    try:
        s = str(x) if x is not None else ""
    except Exception:
        s = ""
    s = s.strip()
    return s if s else default


def _bound_str(value: str, max_len: int) -> str:
    s = _safe_str(value, "")
    if max_len <= 0:
        return ""
    return s if len(s) <= max_len else s[:max_len]


def _stable_id(prefix: str, text: str) -> str:
    payload = _safe_str(text, "")
    digest = hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()
    return f"{prefix}_{digest[:12]}"


@dataclass(frozen=True, kw_only=True)
class ComplianceSource:
    label: str
    url: str
    source_type: str
    refresh_days: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "url": self.url,
            "source_type": self.source_type,
            "refresh_days": int(self.refresh_days),
        }


@dataclass(frozen=True, kw_only=True)
class ComplianceJurisdiction:
    jurisdiction_id: str
    label: str
    country_code: str
    sources: List[ComplianceSource] = field(default_factory=list)

    def __post_init__(self) -> None:
        label = _bound_str(self.label, 80)
        country_code = _bound_str(self.country_code, 8).upper()
        jurisdiction_id = _safe_str(self.jurisdiction_id, "")
        if not jurisdiction_id:
            jurisdiction_id = _stable_id("jur", f"{country_code}|{label}")

        normalized_sources = [s for s in self.sources if isinstance(s, ComplianceSource)]
        normalized_sources.sort(key=lambda s: (s.source_type, s.label, s.url))

        object.__setattr__(self, "jurisdiction_id", jurisdiction_id)
        object.__setattr__(self, "label", label)
        object.__setattr__(self, "country_code", country_code)
        object.__setattr__(self, "sources", normalized_sources[:16])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "jurisdiction_id": self.jurisdiction_id,
            "label": self.label,
            "country_code": self.country_code,
            "sources": [s.to_dict() for s in self.sources],
        }


class ComplianceCatalog:
    def __init__(self) -> None:
        self._jurisdictions: Dict[str, ComplianceJurisdiction] = {}
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        defaults = [
            ComplianceJurisdiction(
                jurisdiction_id="",
                label="European Union (EU)",
                country_code="EU",
                sources=[
                    ComplianceSource(
                        label="EUR-Lex",
                        url="https://eur-lex.europa.eu",
                        source_type="official_site",
                        refresh_days=14,
                    )
                ],
            ),
            ComplianceJurisdiction(
                jurisdiction_id="",
                label="United Kingdom (UK)",
                country_code="GB",
                sources=[
                    ComplianceSource(
                        label="FCA Handbook",
                        url="https://www.handbook.fca.org.uk",
                        source_type="official_site",
                        refresh_days=14,
                    )
                ],
            ),
            ComplianceJurisdiction(
                jurisdiction_id="",
                label="United States (US)",
                country_code="US",
                sources=[
                    ComplianceSource(
                        label="NIST Publications",
                        url="https://csrc.nist.gov/publications",
                        source_type="standards_body",
                        refresh_days=30,
                    )
                ],
            ),
            ComplianceJurisdiction(
                jurisdiction_id="",
                label="India (IN)",
                country_code="IN",
                sources=[
                    ComplianceSource(
                        label="RBI Notifications",
                        url="https://www.rbi.org.in",
                        source_type="official_site",
                        refresh_days=14,
                    )
                ],
            ),
        ]
        for jurisdiction in defaults:
            self._jurisdictions[jurisdiction.jurisdiction_id] = jurisdiction

    def list_jurisdictions(self) -> List[Dict[str, Any]]:
        jurisdictions = sorted(self._jurisdictions.values(), key=lambda x: (x.country_code, x.label))
        return [j.to_dict() for j in jurisdictions]

    def get(self, jurisdiction_id: str) -> Optional[ComplianceJurisdiction]:
        return self._jurisdictions.get(_safe_str(jurisdiction_id, ""))

    def add_custom(self, jurisdiction: ComplianceJurisdiction) -> None:
        self._jurisdictions[jurisdiction.jurisdiction_id] = jurisdiction
