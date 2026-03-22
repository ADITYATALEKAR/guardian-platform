from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set


class CTLongitudinalAnalyzer:
    """
    Optional/offline CT longitudinal summarizer.

    Notes:
    - Disabled by default to keep synchronous discovery bounded.
    - Designed for phase-5 enrichment consumers.
    """

    CRTSH_JSON_URL = "https://crt.sh/json"

    def __init__(
        self,
        *,
        enabled: bool = False,
        timeout_seconds: int = 8,
        max_records: int = 500,
    ) -> None:
        self.enabled = bool(enabled)
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.max_records = max(10, int(max_records))

    def summarize_domain(self, domain: str) -> Dict[str, Any]:
        host = self._normalize_domain(domain)
        if not host:
            return {
                "status": "invalid_domain",
                "domain": str(domain or "").strip().lower(),
                "issuance_count": 0,
                "shadow_subdomains": [],
                "algorithm_timeline": [],
            }

        if not self.enabled:
            return {
                "status": "disabled",
                "domain": host,
                "issuance_count": 0,
                "shadow_subdomains": [],
                "algorithm_timeline": [],
            }

        try:
            rows = self._fetch_ct_rows(host)
            return self._build_summary(host, rows)
        except Exception as exc:
            return {
                "status": "error",
                "domain": host,
                "error": str(exc),
                "issuance_count": 0,
                "shadow_subdomains": [],
                "algorithm_timeline": [],
            }

    def _fetch_ct_rows(self, domain: str) -> List[Dict[str, Any]]:
        query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
        url = f"{self.CRTSH_JSON_URL}?{query}"
        request = urllib.request.Request(
            url=url,
            headers={"User-Agent": "Guardian-Posture/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            payload = response.read()
        decoded = payload.decode("utf-8", errors="replace")
        data = json.loads(decoded)
        if not isinstance(data, list):
            raise RuntimeError("invalid ct response")

        out: List[Dict[str, Any]] = []
        for row in data[: self.max_records]:
            if isinstance(row, dict):
                out.append(row)
        return out

    def _build_summary(self, domain: str, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        names: Set[str] = set()
        timestamps: List[str] = []
        recent_count = 0
        now = time.time()
        thirty_days_seconds = 30 * 24 * 60 * 60

        for row in rows:
            name_value = str(row.get("name_value", "") or "")
            for token in name_value.splitlines():
                normalized = self._normalize_domain(token)
                if normalized and normalized.endswith(domain):
                    names.add(normalized)

            ts = str(row.get("entry_timestamp", "") or "").strip()
            if ts:
                timestamps.append(ts)
                try:
                    epoch = self._entry_timestamp_to_epoch(ts)
                    if now - epoch <= thirty_days_seconds:
                        recent_count += 1
                except Exception:
                    pass

        shadow_subdomains = sorted(
            n for n in names if n != domain and not n.startswith("www.")
        )

        algorithm_timeline = [
            {
                "algorithm": "UNKNOWN",
                "note": "crt.sh JSON feed does not expose certificate public key algorithm",
            }
        ]

        issuance_anomaly = recent_count >= 20
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        return {
            "status": "ok",
            "domain": domain,
            "issuance_count": len(rows),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "shadow_subdomains": shadow_subdomains,
            "issuance_anomaly": issuance_anomaly,
            "algorithm_timeline": algorithm_timeline,
        }

    @staticmethod
    def _normalize_domain(value: Any) -> Optional[str]:
        token = str(value or "").strip().lower()
        if not token:
            return None
        if token.startswith("*."):
            token = token[2:]
        if ":" in token:
            token = token.split(":", 1)[0]
        token = token.strip(".")
        if "." not in token:
            return None
        return token

    @staticmethod
    def _entry_timestamp_to_epoch(value: str) -> float:
        from datetime import datetime, timezone

        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()

