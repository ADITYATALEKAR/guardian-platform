from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass(frozen=True)
class Jurisdiction:
    code: str
    display_name: str


class JurisdictionCatalog:
    _DISPLAY: List[Jurisdiction] = [
        Jurisdiction(code="NONE", display_name="None (Disable Policy)"),
        Jurisdiction(code="EUROPE", display_name="Europe"),
        Jurisdiction(code="UNITED STATES", display_name="United States"),
        Jurisdiction(code="CHINA", display_name="China"),
        Jurisdiction(code="GERMANY", display_name="Germany"),
        Jurisdiction(code="JAPAN", display_name="Japan"),
        Jurisdiction(code="INDIA", display_name="India"),
        Jurisdiction(code="UNITED KINGDOM", display_name="United Kingdom"),
        Jurisdiction(code="FRANCE", display_name="France"),
        Jurisdiction(code="ITALY", display_name="Italy"),
        Jurisdiction(code="CANADA", display_name="Canada"),
        Jurisdiction(code="BRAZIL", display_name="Brazil"),
        Jurisdiction(code="RUSSIA", display_name="Russia"),
        Jurisdiction(code="SOUTH KOREA", display_name="South Korea"),
        Jurisdiction(code="AUSTRALIA", display_name="Australia"),
        Jurisdiction(code="SPAIN", display_name="Spain"),
        Jurisdiction(code="MEXICO", display_name="Mexico"),
        Jurisdiction(code="INDONESIA", display_name="Indonesia"),
        Jurisdiction(code="NETHERLANDS", display_name="Netherlands"),
        Jurisdiction(code="SAUDI ARABIA", display_name="Saudi Arabia"),
        Jurisdiction(code="TURKEY", display_name="Turkey"),
        Jurisdiction(code="SWITZERLAND", display_name="Switzerland"),
        Jurisdiction(code="POLAND", display_name="Poland"),
        Jurisdiction(code="SWEDEN", display_name="Sweden"),
        Jurisdiction(code="BELGIUM", display_name="Belgium"),
        Jurisdiction(code="ARGENTINA", display_name="Argentina"),
        Jurisdiction(code="SINGAPORE", display_name="Singapore"),
        Jurisdiction(code="UNITED ARAB EMIRATES", display_name="United Arab Emirates"),
        Jurisdiction(code="SOUTH AFRICA", display_name="South Africa"),
    ]

    @classmethod
    def list_display(cls) -> List[Jurisdiction]:
        return list(cls._DISPLAY)

    @staticmethod
    def _alias(code: str) -> str:
        aliases = {
            "EU": "EUROPE",
            "IN": "INDIA",
            "US": "UNITED STATES",
            "USA": "UNITED STATES",
            "UK": "UNITED KINGDOM",
            "DE": "GERMANY",
            "JP": "JAPAN",
            "CN": "CHINA",
            "BR": "BRAZIL",
            "ZA": "SOUTH AFRICA",
            "AE": "UNITED ARAB EMIRATES",
            "SG": "SINGAPORE",
            "DISABLED": "NONE",
            "NO": "NONE",
        }
        return aliases.get(code, code)

    @staticmethod
    def normalize_selection(jurisdictions: Iterable[str]) -> List[str]:
        out: List[str] = []
        seen: set[str] = set()
        for j in jurisdictions or []:
            code = (j or "").strip().upper()
            if not code:
                continue
            code = JurisdictionCatalog._alias(code)
            if code in seen:
                continue
            seen.add(code)
            out.append(code)
        out.sort()
        return out

    @staticmethod
    def expand_with_supersets(jurisdictions: List[str]) -> List[str]:
        expanded = list(jurisdictions or [])
        current = set(expanded)
        if "GERMANY" in current and "EUROPE" not in current:
            expanded.append("EUROPE")
        return sorted(set(expanded))
