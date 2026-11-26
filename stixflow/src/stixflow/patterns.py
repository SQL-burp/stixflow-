"""Extract hunt-able observables from STIX 2.1 indicator patterns.

A STIX pattern looks like:

    [ipv4-addr:value = '198.51.100.23' OR domain-name:value = 'evil.example']
    [file:hashes.'SHA-256' = 'aec0...']

This module does NOT implement the full STIX patterning grammar (temporal
qualifiers, FOLLOWEDBY, etc.). It pulls out the equality comparisons that map
to concrete IOCs - which is what a SOC actually loads into a blocklist or
matches against logs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# object-type : property-path  operator  'value'
_COMPARISON = re.compile(
    r"(?P<obj>[a-z0-9-]+):(?P<path>[^\s=!<>]+?)\s*(?P<op>=|!=|LIKE|MATCHES|IN)\s*"
    r"'(?P<val>(?:[^'\\]|\\.)*)'",
    re.IGNORECASE,
)

# (stix object type, property path prefix) -> normalized IOC type
_TYPE_MAP = {
    ("ipv4-addr", "value"): "ipv4",
    ("ipv6-addr", "value"): "ipv6",
    ("domain-name", "value"): "domain",
    ("url", "value"): "url",
    ("email-addr", "value"): "email",
    ("mac-addr", "value"): "mac",
    ("process", "name"): "process",
    ("windows-registry-key", "key"): "registry",
}


@dataclass(frozen=True)
class Observable:
    ioc_type: str  # ipv4 | ipv6 | domain | url | email | hash | ...
    value: str
    detail: str = ""  # e.g. hash algorithm


def _normalize(ioc_type: str, value: str) -> str:
    value = value.replace("\\'", "'").strip()
    if ioc_type in {"domain", "email", "hash", "mac"}:
        return value.lower()
    if ioc_type in {"ipv4", "ipv6"}:
        try:
            if "/" in value:
                return str(ipaddress.ip_network(value, strict=False))
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    return value


def extract_observables(pattern: str) -> list[Observable]:
    """Return de-duplicated equality observables found in a STIX pattern."""
    found: list[Observable] = []
    seen: set[tuple[str, str]] = set()
    for m in _COMPARISON.finditer(pattern or ""):
        if m.group("op") != "=":
            continue  # only exact matches become IOCs
        obj, path, val = m.group("obj").lower(), m.group("path"), m.group("val")

        if obj in {"file", "artifact", "x509-certificate"} and path.startswith("hashes."):
            algo = path.split(".", 1)[1].strip("'\"").upper()
            obs = Observable("hash", _normalize("hash", val), algo)
        elif obj == "file" and path == "name":
            obs = Observable("filename", val)
        else:
            ioc_type = _TYPE_MAP.get((obj, path.split(".")[0]))
            if not ioc_type:
                continue
            obs = Observable(ioc_type, _normalize(ioc_type, val))

        key = (obs.ioc_type, obs.value)
        if key not in seen:
            seen.add(key)
            found.append(obs)
    return found
