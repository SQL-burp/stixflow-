"""SQLite-backed STIX 2.1 object store.

Design notes
------------
* One row per STIX ID. A newer ``modified`` timestamp replaces the stored
  version (STIX versioning rule); older or equal versions are ignored, so
  re-pulling a feed is idempotent.
* Relationship SROs are mirrored into an edge table for fast graph pivots.
* Indicator patterns are parsed into an ``observables`` table so hunting is a
  simple indexed lookup instead of re-parsing patterns every time.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from .patterns import extract_observables

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    name        TEXT,
    created     TEXT,
    modified    TEXT,
    revoked     INTEGER DEFAULT 0,
    source      TEXT,
    raw         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_objects_type ON objects(type);

CREATE TABLE IF NOT EXISTS relationships (
    id                TEXT PRIMARY KEY,
    source_ref        TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_ref        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source_ref);
CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target_ref);

CREATE TABLE IF NOT EXISTS observables (
    indicator_id TEXT NOT NULL,
    ioc_type     TEXT NOT NULL,
    value        TEXT NOT NULL,
    detail       TEXT,
    PRIMARY KEY (indicator_id, ioc_type, value)
);
CREATE INDEX IF NOT EXISTS idx_obs_value ON observables(value);

CREATE TABLE IF NOT EXISTS sync_state (
    feed            TEXT PRIMARY KEY,   -- "<api_root_url>|<collection_id>"
    last_date_added TEXT
);
"""


@dataclass
class IngestResult:
    added: int = 0
    updated: int = 0
    skipped: int = 0

    def __iadd__(self, other: IngestResult) -> IngestResult:
        self.added += other.added
        self.updated += other.updated
        self.skipped += other.skipped
        return self


class StixStore:
    def __init__(self, path: str | Path = "stixflow.db"):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    # ------------------------------------------------------------------ ingest
    def ingest(self, objects: Iterable[dict], source: str = "") -> IngestResult:
        result = IngestResult()
        with self.conn:
            for obj in objects:
                result += self._upsert(obj, source)
        return result

    def ingest_bundle(self, bundle: dict, source: str = "") -> IngestResult:
        if bundle.get("type") != "bundle":
            raise ValueError("Not a STIX bundle (missing type: bundle)")
        return self.ingest(bundle.get("objects", []), source)

    def _upsert(self, obj: dict, source: str) -> IngestResult:
        obj_id, obj_type = obj.get("id"), obj.get("type")
        if not obj_id or not obj_type:
            return IngestResult(skipped=1)

        # marking-definitions etc. may have no `modified`; fall back to created
        modified = obj.get("modified") or obj.get("created") or ""
        row = self.conn.execute("SELECT modified FROM objects WHERE id = ?", (obj_id,)).fetchone()
        if row is not None and (row["modified"] or "") >= modified:
            return IngestResult(skipped=1)

        self.conn.execute(
            "INSERT OR REPLACE INTO objects (id, type, name, created, modified, revoked, source, raw) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                obj_id,
                obj_type,
                obj.get("name"),
                obj.get("created"),
                modified,
                int(bool(obj.get("revoked"))),
                source,
                json.dumps(obj, separators=(",", ":")),
            ),
        )

        if obj_type == "relationship":
            self.conn.execute(
                "INSERT OR REPLACE INTO relationships VALUES (?, ?, ?, ?)",
                (obj_id, obj["source_ref"], obj["relationship_type"], obj["target_ref"]),
            )
        elif obj_type == "indicator" and obj.get("pattern_type", "stix") == "stix":
            self.conn.execute("DELETE FROM observables WHERE indicator_id = ?", (obj_id,))
            for o in extract_observables(obj.get("pattern", "")):
                self.conn.execute(
                    "INSERT OR IGNORE INTO observables VALUES (?, ?, ?, ?)",
                    (obj_id, o.ioc_type, o.value, o.detail),
                )

        return IngestResult(added=1) if row is None else IngestResult(updated=1)

    # ------------------------------------------------------------------ query
    def get(self, obj_id: str) -> dict | None:
        row = self.conn.execute("SELECT raw FROM objects WHERE id = ?", (obj_id,)).fetchone()
        return json.loads(row["raw"]) if row else None

    def iter_objects(self, types: list[str] | None = None, include_revoked: bool = False) -> Iterator[dict]:
        sql, params = "SELECT raw FROM objects WHERE 1=1", []
        if types:
            sql += f" AND type IN ({','.join('?' * len(types))})"
            params += types
        if not include_revoked:
            sql += " AND revoked = 0"
        for row in self.conn.execute(sql + " ORDER BY type, name", params):
            yield json.loads(row["raw"])

    def counts_by_type(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT type, COUNT(*) AS n FROM objects WHERE revoked = 0 GROUP BY type ORDER BY n DESC"
        )
        return {r["type"]: r["n"] for r in rows}

    def neighbors(self, obj_id: str) -> list[tuple[str, str, str]]:
        """Return (direction, relationship_type, other_id) for every edge touching obj_id."""
        out = [
            ("out", r["relationship_type"], r["target_ref"])
            for r in self.conn.execute(
                "SELECT relationship_type, target_ref FROM relationships WHERE source_ref = ?", (obj_id,)
            )
        ]
        out += [
            ("in", r["relationship_type"], r["source_ref"])
            for r in self.conn.execute(
                "SELECT relationship_type, source_ref FROM relationships WHERE target_ref = ?", (obj_id,)
            )
        ]
        return out

    def related(self, obj_id: str, max_depth: int = 2) -> list[tuple[int, str, str, dict, str]]:
        """Breadth-first walk of the relationship graph.

        Returns (depth, via_relationship, direction, object, parent_id) tuples. This is how an
        analyst goes from "this IP showed up in my logs" to "it's tied to malware X,
        used by intrusion set Y, which targets my sector".
        """
        seen, frontier, results = {obj_id}, [obj_id], []
        for depth in range(1, max_depth + 1):
            nxt = []
            for current in frontier:
                for direction, rel, other in self.neighbors(current):
                    if other in seen:
                        continue
                    seen.add(other)
                    obj = self.get(other)
                    if obj and not obj.get("revoked"):
                        results.append((depth, rel, direction, obj, current))
                        nxt.append(other)
            frontier = nxt
        return results

    def observables(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT o.indicator_id, o.ioc_type, o.value, o.detail, obj.name AS indicator_name "
            "FROM observables o JOIN objects obj ON obj.id = o.indicator_id "
            "WHERE obj.revoked = 0 ORDER BY o.ioc_type, o.value"
        ).fetchall()

    def find_by_value(self, value: str) -> list[sqlite3.Row]:
        """Exact observable lookup (case-insensitive for domains/hashes)."""
        v = value.strip()
        return self.conn.execute(
            "SELECT indicator_id, ioc_type, value, detail FROM observables WHERE value IN (?, ?)",
            (v, v.lower()),
        ).fetchall()

    def network_observables(self) -> list[sqlite3.Row]:
        """IPv4/IPv6 observables that are CIDR ranges (need containment checks, not equality)."""
        return self.conn.execute(
            "SELECT indicator_id, ioc_type, value, detail FROM observables "
            "WHERE ioc_type IN ('ipv4', 'ipv6') AND value LIKE '%/%'"
        ).fetchall()

    def search(self, text: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT raw FROM objects WHERE revoked = 0 AND (name LIKE ? OR id = ?) ORDER BY type",
            (f"%{text}%", text),
        )
        return [json.loads(r["raw"]) for r in rows]

    # ------------------------------------------------------------------ sync
    def get_sync(self, feed: str) -> str | None:
        row = self.conn.execute("SELECT last_date_added FROM sync_state WHERE feed = ?", (feed,)).fetchone()
        return row["last_date_added"] if row else None

    def set_sync(self, feed: str, last_date_added: str) -> None:
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO sync_state VALUES (?, ?)", (feed, last_date_added))

    def close(self) -> None:
        self.conn.close()
