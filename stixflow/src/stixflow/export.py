"""Export stored intel in formats downstream tools actually consume."""

from __future__ import annotations

import csv
import io
import json
import uuid

from .store import StixStore


def to_csv(store: StixStore) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ioc_type", "value", "detail", "indicator_name", "indicator_id"])
    for r in store.observables():
        w.writerow([r["ioc_type"], r["value"], r["detail"] or "", r["indicator_name"] or "", r["indicator_id"]])
    return buf.getvalue()


def to_json(store: StixStore) -> str:
    rows = [dict(r) for r in store.observables()]
    return json.dumps(rows, indent=2)


def to_blocklist(store: StixStore, ioc_types: tuple[str, ...] = ("ipv4", "ipv6", "domain")) -> str:
    """One value per line - drop-in for firewall EDLs / DNS sinkholes."""
    values = sorted({r["value"] for r in store.observables() if r["ioc_type"] in ioc_types})
    return "\n".join(values) + ("\n" if values else "")


def to_stix_bundle(store: StixStore, types: list[str] | None = None) -> str:
    objs = list(store.iter_objects(types))
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}, indent=2)


FORMATS = {"csv": to_csv, "json": to_json, "txt": to_blocklist, "stix": to_stix_bundle}
