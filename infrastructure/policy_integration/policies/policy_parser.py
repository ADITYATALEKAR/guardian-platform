from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .policy_contracts import ProposedPolicyDraft
from .policy_utils import bound_str, safe_str


@dataclass(frozen=True)
class PolicyParserConfig:
    max_title_len: int = 256
    max_summary_len: int = 512


class PolicyParser:
    def __init__(self, *, config: Optional[PolicyParserConfig] = None) -> None:
        self._config = config or PolicyParserConfig()

    def parse_policy_payload(
        self,
        *,
        filename: str,
        extracted_text: str,
        jurisdiction: str,
        source: str,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        fname = bound_str(filename, max_len=256)
        juris = bound_str(jurisdiction, max_len=64)
        src = bound_str(source, max_len=64)
        text = safe_str(extracted_text)
        text_preview = text[:2048]

        tag_values = [t.strip() for t in (tags or []) if safe_str(t)]
        tag_values = sorted(set(tag_values))[:32]

        title_base = fname or f"{juris} Policy ({src})"
        title = bound_str(title_base, max_len=self._config.max_title_len)
        summary = ""
        if text:
            summary = bound_str(text.replace("\n", " "), max_len=self._config.max_summary_len)

        policy_id = self._stable_policy_id(
            title=title,
            jurisdiction=juris,
            source=src,
            tags=tag_values,
            text_preview=text_preview,
        )

        draft = ProposedPolicyDraft(
            title=title,
            jurisdiction=juris,
            source=src,
            filename=fname,
            extracted_text=text,
            summary=summary,
            tags=tag_values,
            effective_from=None,
            evidence={
                "filename": fname,
                "jurisdiction": juris,
                "source": src,
                "text_preview": text_preview,
            },
        )

        return {
            "policy_id": policy_id,
            "title": draft.title,
            "jurisdiction": draft.jurisdiction,
            "source": draft.source,
            "filename": draft.filename,
            "summary": draft.summary,
            "tags": draft.tags,
            "effective_from": draft.effective_from,
            "evidence": draft.evidence,
        }

    def _stable_policy_id(
        self,
        *,
        title: str,
        jurisdiction: str,
        source: str,
        tags: List[str],
        text_preview: str,
    ) -> str:
        payload = {
            "title": title,
            "jurisdiction": jurisdiction,
            "source": source,
            "tags": tags,
            "text_preview": text_preview,
        }
        raw = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:24]
