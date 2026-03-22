from __future__ import annotations

from typing import Dict, List, Optional

from infrastructure.operator_plane.storage.pg_operator_storage import (
    read_operator_links,
    write_operator_links,
)


def list_tenants(root: str, operator_id: str) -> List[str]:
    links = read_operator_links(root)
    tenant_ids = links.get(operator_id, [])
    if not isinstance(tenant_ids, list):
        raise RuntimeError("Corrupt operator storage: operator_tenant_links.json")
    return sorted(set(tenant_ids))


def get_tenant(root: str, operator_id: str) -> Optional[str]:
    tenant_ids = list_tenants(root, operator_id)
    if not tenant_ids:
        return None
    return tenant_ids[0]


def list_operators_for_tenant(root: str, tenant_id: str) -> List[str]:
    links = read_operator_links(root)
    operator_ids: List[str] = []
    for operator_id, tenant_ids in links.items():
        if not isinstance(tenant_ids, list):
            raise RuntimeError("Corrupt operator storage: operator_tenant_links.json")
        if tenant_id in set(str(tid) for tid in tenant_ids):
            operator_ids.append(operator_id)
    return sorted(set(operator_ids))


def add_link(root: str, operator_id: str, tenant_id: str) -> Dict[str, List[str]]:
    if not operator_id or not tenant_id:
        raise ValueError("operator_id")
    links = read_operator_links(root)
    tenant_ids = list(links.get(operator_id, []))
    deduped = sorted(set(tenant_ids))
    if deduped and tenant_id not in deduped:
        raise RuntimeError("operator already linked to a different tenant")
    deduped = [tenant_id]
    links[operator_id] = deduped
    write_operator_links(root, links)
    return links


def remove_operator(root: str, operator_id: str) -> None:
    links = read_operator_links(root)
    if operator_id in links:
        del links[operator_id]
        write_operator_links(root, links)
