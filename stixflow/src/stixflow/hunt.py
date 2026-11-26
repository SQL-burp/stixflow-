"""Match stored STIX indicators against arbitrary log files.

Works on any text log (firewall, proxy, DNS, Zeek, Windows event exports): it
pulls candidate IPs, domains, URLs, hashes and emails out of each line, refangs
defanged values (hxxp, [.]), then checks them against the indicator store,
including CIDR containment for range indicators.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .store import StixStore

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_URL = re.compile(r"\bhttps?://[^\s\"'<>,]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.IGNORECASE)

# object types worth surfacing as "why should I care" context for a hit
CONTEXT_TYPES = {"malware", "tool", "intrusion-set", "threat-actor", "campaign"}
ACTOR_CONTEXT = {"intrusion-set", "threat-actor", "campaign"}


def refang(text: str) -> str:
    return (
        text.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
        .replace("hxxp", "http")
        .replace("hXXp", "http")
        .replace("[@]", "@")
    )


@dataclass
class Hit:
    line_no: int
    observed: str
    ioc_type: str
    matched: str
    indicator_id: str
    indicator_name: str
    context: list[str] = field(default_factory=list)
    line: str = ""


def extract_candidates(line: str) -> set[str]:
    line = refang(line)
    cands: set[str] = set()
    for url in _URL.findall(line):
        cands.add(url.rstrip(".);]"))
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0]
        cands.add(host.lower())
    cands.update(e.lower() for e in _EMAIL.findall(line))
    cands.update(_IPV4.findall(line))
    cands.update(h.lower() for h in _HASH.findall(line))
    for d in _DOMAIN.findall(line):
        if not _IPV4.fullmatch(d):
            cands.add(d.lower())
    return cands


class Hunter:
    def __init__(self, store: StixStore):
        self.store = store
        self._nets = []
        for row in store.network_observables():
            try:
                self._nets.append((ipaddress.ip_network(row["value"], strict=False), row))
            except ValueError:
                pass
        self._ctx_cache: dict[str, list[str]] = {}
        self._name_cache: dict[str, str] = {}

    def context_for(self, indicator_id: str) -> list[str]:
        if indicator_id not in self._ctx_cache:
            names = []
            for depth, _rel, _dir, obj, _parent in self.store.related(indicator_id, max_depth=3):
                # direct links (what the indicator indicates) + any adversary further up the chain;
                # skips sibling malware/tools that would only add noise
                relevant = depth == 1 or obj["type"] in ACTOR_CONTEXT
                if relevant and obj["type"] in CONTEXT_TYPES and obj.get("name"):
                    names.append(f"{obj['type']}: {obj['name']}")
            self._ctx_cache[indicator_id] = names
        return self._ctx_cache[indicator_id]

    def _indicator_name(self, indicator_id: str) -> str | None:
        """Name of a live indicator, or None if it is revoked/missing."""
        if indicator_id not in self._name_cache:
            obj = self.store.get(indicator_id)
            self._name_cache[indicator_id] = "" if not obj or obj.get("revoked") else obj.get("name", indicator_id)
        return self._name_cache[indicator_id] or None

    def match_value(self, value: str) -> list[tuple[str, str, str]]:
        """Return (ioc_type, matched_value, indicator_id) for a single observed value."""
        out = [(r["ioc_type"], r["value"], r["indicator_id"]) for r in self.store.find_by_value(value)]
        if self._nets and _IPV4.fullmatch(value):
            ip = ipaddress.ip_address(value)
            out += [(r["ioc_type"], r["value"], r["indicator_id"]) for net, r in self._nets if ip in net]
        return out

    def hunt_lines(self, lines: Iterable[str]) -> list[Hit]:
        hits: list[Hit] = []
        for n, line in enumerate(lines, 1):
            seen: set[tuple[str, str]] = set()
            for cand in extract_candidates(line):
                for ioc_type, matched, ind_id in self.match_value(cand):
                    name = self._indicator_name(ind_id)
                    if name is None or (cand, ind_id) in seen:
                        continue
                    seen.add((cand, ind_id))
                    hits.append(Hit(n, cand, ioc_type, matched, ind_id, name, self.context_for(ind_id),
                                    line.rstrip("\n")))
        return hits

    def hunt_file(self, path: str | Path) -> list[Hit]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return self.hunt_lines(fh)
