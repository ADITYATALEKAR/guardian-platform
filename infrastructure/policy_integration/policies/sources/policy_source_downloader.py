from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import hashlib
import os
import time
import urllib.request

from infrastructure.storage_manager.storage_manager import StorageManager

from ...compliance.compliance_catalog import ComplianceCatalog, ComplianceSource
from ...io import policy_root
from ..policy_utils import bound_str, safe_str


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class PolicySourceDownloaderConfig:
    max_bytes_per_fetch: int = 2_000_000
    timeout_seconds: int = 10
    user_agent: str = "AvyaktaPolicyIntegration/1.0"


class PolicySourceDownloader:
    def __init__(
        self,
        *,
        storage_manager: StorageManager,
        catalog: Optional[ComplianceCatalog] = None,
        config: Optional[PolicySourceDownloaderConfig] = None,
    ) -> None:
        self._storage_manager = storage_manager
        self._catalog = catalog or ComplianceCatalog()
        self._config = config or PolicySourceDownloaderConfig()

    def _target_dir(self, tenant_id: str, jurisdiction_id: str) -> Path:
        root = policy_root(self._storage_manager, tenant_id)
        target = root / "source_artifacts" / bound_str(jurisdiction_id, max_len=64)
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _fetch_url(self, url: str) -> Tuple[bytes, Dict[str, str]]:
        request = urllib.request.Request(
            safe_str(url),
            headers={"User-Agent": self._config.user_agent},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._config.timeout_seconds) as response:
                raw = response.read(self._config.max_bytes_per_fetch)
                headers = {
                    bound_str(str(k), max_len=80): bound_str(str(v), max_len=240)
                    for k, v in response.headers.items()
                }
                return bytes(raw or b""), headers
        except Exception:
            return b"", {}

    def fetch_jurisdiction_sources(self, *, tenant_id: str, jurisdiction_id: str) -> List[Dict[str, Any]]:
        jurisdiction = self._catalog.get(jurisdiction_id)
        if jurisdiction is None:
            return []

        output: List[Dict[str, Any]] = []
        target_dir = self._target_dir(tenant_id, jurisdiction_id)
        for source in jurisdiction.sources:
            if not isinstance(source, ComplianceSource):
                continue
            content, headers = self._fetch_url(source.url)
            digest = _sha256_bytes(content) if content else ""

            filename = f"source_{_now_ms()}_{digest[:12] or 'empty'}.bin"
            artifact_path = target_dir / filename
            try:
                with open(artifact_path, "wb") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                persisted_path = str(artifact_path)
            except Exception:
                persisted_path = ""

            output.append(
                {
                    "tenant_id": safe_str(tenant_id),
                    "jurisdiction_id": bound_str(jurisdiction_id, max_len=64),
                    "source_label": bound_str(source.label, max_len=120),
                    "source_url": bound_str(source.url, max_len=400),
                    "content_sha256": bound_str(digest, max_len=64),
                    "content_bytes_len": len(content),
                    "storage_path": persisted_path,
                    "headers": headers,
                }
            )

        output.sort(key=lambda item: (item["source_label"], item["storage_path"]))
        return output
