from __future__ import annotations

import ipaddress
from typing import Optional

# Common second-level labels used beneath ccTLD public suffixes.
# This is intentionally conservative: if we are unsure, we avoid
# collapsing to a junk scope such as "or.jp" or "org.mx".
_COMMON_CCTLD_SECOND_LEVELS = {
    "ac",
    "co",
    "com",
    "edu",
    "go",
    "gob",
    "gov",
    "gr",
    "mil",
    "ne",
    "net",
    "or",
    "org",
}


def extract_registrable_base(host: str) -> Optional[str]:
    hostname = str(host or "").strip().strip(".").lower()
    if not hostname or "." not in hostname:
        return None

    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    labels = [label for label in hostname.split(".") if label]
    if len(labels) < 2:
        return None

    # Reject public-suffix-like pairs such as "co.jp", "or.jp", "org.mx".
    if len(labels) == 2:
        if len(labels[-1]) == 2 and labels[-2] in _COMMON_CCTLD_SECOND_LEVELS:
            return None
        return hostname

    if len(labels[-1]) == 2 and labels[-2] in _COMMON_CCTLD_SECOND_LEVELS:
        return ".".join(labels[-3:])

    return ".".join(labels[-2:])


__all__ = ["extract_registrable_base"]
