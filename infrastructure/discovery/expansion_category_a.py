"""
Category A compatibility facade.

Primary implementation moved to:
  infrastructure.discovery.expansion_a.impl
"""

from infrastructure.discovery.expansion_a.impl import *  # noqa: F401,F403
from infrastructure.discovery.expansion_a import impl as _impl
from infrastructure.discovery.expansion_a.impl import safe_http_get  # backward-compatible monkeypatch target


class CertificateTransparencyModule(_impl.CertificateTransparencyModule):
    """
    Compatibility subclass so monkeypatching
    `infrastructure.discovery.expansion_category_a.safe_http_get`
    affects CT fetch behavior as before the facade split.
    """

    def _fetch_all_entries(self, root: str, *, context=None):
        all_entries = []
        seen_entry_keys = set()
        base = self._registrable_base_domain(root)

        query_patterns = [f"%.{root}", root]
        if base and base != root:
            query_patterns.extend([f"%.{base}", base])

        for query in query_patterns:
            offset = 0
            while True:
                if context is not None and getattr(context, "should_stop", lambda: False)():
                    return all_entries
                data = safe_http_get(
                    self.CT_URL,
                    params={"q": query, "output": "json", "offset": offset},
                    timeout=15,
                    context=context,
                )
                if not data:
                    break
                if isinstance(data, dict):
                    data = [data]
                if not data:
                    break

                for entry in data:
                    if not isinstance(entry, dict):
                        continue
                    key = self._entry_key(entry)
                    if key in seen_entry_keys:
                        continue
                    seen_entry_keys.add(key)
                    all_entries.append(entry)

                if len(data) < self.PAGE_SIZE:
                    break
                offset += self.PAGE_SIZE

        return all_entries
