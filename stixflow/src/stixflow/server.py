"""A small but spec-shaped TAXII 2.1 server for local development and demos.

Every ``*.json`` STIX bundle in the data directory becomes a read/write
collection. It implements the parts of TAXII 2.1 a real feed consumer exercises:

* discovery, API root, collections, collection info
* GET objects with ``limit`` / ``next`` pagination, ``added_after``,
  ``match[type]`` and ``match[id]`` filters
* ``X-TAXII-Date-Added-First`` / ``-Last`` headers
* manifest, get-object-by-id, POST objects + status resource
* optional HTTP Basic auth and TAXII-style error bodies

It is intentionally in-memory: restart = reset. Do not expose it to a network
you don't control.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, Response, request

from . import TAXII_MEDIA_TYPE

API_ROOT = "api1"
NAMESPACE = uuid.UUID("6f0e8f9e-2f9a-4c55-9b0e-5e3f3c1d7a10")
DEFAULT_DATA_DIR = Path(__file__).parent / "data"
MAX_LIMIT = 1000


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Collection:
    def __init__(self, cid: str, title: str, description: str = "", can_write: bool = True):
        self.id, self.title, self.description, self.can_write = cid, title, description, can_write
        self.entries: list[tuple[str, dict]] = []  # (date_added, object), sorted by date_added

    def info(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "can_read": True,
            "can_write": self.can_write,
            "media_types": ["application/stix+json;version=2.1"],
        }

    def add(self, obj: dict, date_added: str) -> None:
        self.entries.append((date_added, obj))
        self.entries.sort(key=lambda e: e[0])


def load_collections(data_dir: Path) -> dict[str, Collection]:
    collections: dict[str, Collection] = {}
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for path in sorted(Path(data_dir).glob("*.json")):
        bundle = json.loads(path.read_text())
        if bundle.get("type") != "bundle":
            continue
        cid = str(uuid.uuid5(NAMESPACE, path.stem))
        coll = Collection(cid, bundle.get("x_stixflow_title", path.stem), bundle.get("x_stixflow_description", ""))
        for i, obj in enumerate(bundle.get("objects", [])):
            coll.add(obj, _ts(base + timedelta(milliseconds=i)))
        collections[cid] = coll
    return collections


def create_app(data_dir: str | Path | None = None, username: str | None = None, password: str | None = None) -> Flask:
    app = Flask(__name__)
    data_dir = Path(data_dir or os.environ.get("STIXFLOW_DATA_DIR") or DEFAULT_DATA_DIR)
    collections = load_collections(data_dir)
    statuses: dict[str, dict] = {}
    username = username or os.environ.get("STIXFLOW_USER")
    password = password or os.environ.get("STIXFLOW_PASSWORD")

    # ------------------------------------------------------------------ helpers
    def taxii(body: dict, status: int = 200, headers: dict | None = None) -> Response:
        return Response(json.dumps(body), status=status, mimetype=TAXII_MEDIA_TYPE, headers=headers or {})

    def error(status: int, title: str, description: str = "") -> Response:
        return taxii({"title": title, "description": description, "http_status": str(status)}, status)

    @app.before_request
    def checks():
        if username:
            auth = request.authorization
            if not auth or auth.username != username or auth.password != password:
                resp = error(401, "Unauthorized", "Valid HTTP Basic credentials required")
                resp.headers["WWW-Authenticate"] = 'Basic realm="stixflow"'
                return resp
        accept = request.headers.get("Accept", "*/*")
        if not any(t in accept for t in ("application/taxii+json", "*/*", "application/json")):
            return error(406, "Not Acceptable", f"Use Accept: {TAXII_MEDIA_TYPE}")
        return None

    def get_collection(cid: str) -> Collection | Response:
        coll = collections.get(cid)
        return coll if coll else error(404, "Collection not found", cid)

    def filtered(coll: Collection) -> list[tuple[str, dict]]:
        entries = coll.entries
        if added_after := request.args.get("added_after"):
            entries = [e for e in entries if e[0] > added_after]
        if types := request.args.get("match[type]"):
            wanted = set(types.split(","))
            entries = [e for e in entries if e[1].get("type") in wanted]
        if ids := request.args.get("match[id]"):
            wanted = set(ids.split(","))
            entries = [e for e in entries if e[1].get("id") in wanted]
        return entries

    def paginate(entries: list) -> tuple[list, bool, str | None, dict]:
        try:
            limit = min(int(request.args.get("limit", MAX_LIMIT)), MAX_LIMIT)
            offset = int(request.args.get("next", 0))
        except ValueError:
            return [], False, None, {}
        page = entries[offset : offset + limit]
        more = offset + limit < len(entries)
        headers = {}
        if page:
            headers = {"X-TAXII-Date-Added-First": page[0][0], "X-TAXII-Date-Added-Last": page[-1][0]}
        return page, more, (str(offset + limit) if more else None), headers

    # ------------------------------------------------------------------ routes
    @app.get("/taxii2/")
    def discovery():
        return taxii(
            {
                "title": "stixflow demo TAXII 2.1 server",
                "description": "Local mock server with sample ICS/OT threat intel",
                "default": f"{request.host_url}{API_ROOT}/",
                "api_roots": [f"{request.host_url}{API_ROOT}/"],
            }
        )

    @app.get(f"/{API_ROOT}/")
    def api_root():
        return taxii(
            {
                "title": "stixflow API root",
                "versions": [TAXII_MEDIA_TYPE],
                "max_content_length": 10 * 1024 * 1024,
            }
        )

    @app.get(f"/{API_ROOT}/collections/")
    def list_collections():
        return taxii({"collections": [c.info() for c in collections.values()]})

    @app.get(f"/{API_ROOT}/collections/<cid>/")
    def collection_info(cid):
        coll = get_collection(cid)
        return coll if isinstance(coll, Response) else taxii(coll.info())

    @app.get(f"/{API_ROOT}/collections/<cid>/objects/")
    def get_objects(cid):
        coll = get_collection(cid)
        if isinstance(coll, Response):
            return coll
        page, more, nxt, headers = paginate(filtered(coll))
        body = {"more": more, "objects": [o for _, o in page]}
        if nxt:
            body["next"] = nxt
        return taxii(body, headers=headers)

    @app.get(f"/{API_ROOT}/collections/<cid>/objects/<oid>/")
    def get_object(cid, oid):
        coll = get_collection(cid)
        if isinstance(coll, Response):
            return coll
        matches = [o for _, o in coll.entries if o.get("id") == oid]
        return taxii({"objects": matches}) if matches else error(404, "Object not found", oid)

    @app.get(f"/{API_ROOT}/collections/<cid>/manifest/")
    def manifest(cid):
        coll = get_collection(cid)
        if isinstance(coll, Response):
            return coll
        page, more, nxt, headers = paginate(filtered(coll))
        body = {
            "more": more,
            "objects": [
                {
                    "id": o["id"],
                    "date_added": added,
                    "version": o.get("modified", o.get("created")),
                    "media_type": "application/stix+json;version=2.1",
                }
                for added, o in page
            ],
        }
        if nxt:
            body["next"] = nxt
        return taxii(body, headers=headers)

    @app.post(f"/{API_ROOT}/collections/<cid>/objects/")
    def add_objects(cid):
        coll = get_collection(cid)
        if isinstance(coll, Response):
            return coll
        if not coll.can_write:
            return error(403, "Forbidden", "Collection is read-only")
        envelope = request.get_json(force=True, silent=True) or {}
        objs = envelope.get("objects", [])
        successes, failures = [], []
        for obj in objs:
            if not isinstance(obj, dict) or not obj.get("id") or not obj.get("type"):
                failures.append({"id": str(obj.get("id", "unknown")) if isinstance(obj, dict) else "unknown",
                                 "message": "Missing id or type"})
                continue
            coll.add(obj, _ts(datetime.now(timezone.utc)))
            successes.append({"id": obj["id"], "version": obj.get("modified", obj.get("created"))})
        status_id = str(uuid.uuid4())
        statuses[status_id] = {
            "id": status_id,
            "status": "complete",
            "request_timestamp": _ts(datetime.now(timezone.utc)),
            "total_count": len(objs),
            "success_count": len(successes),
            "failure_count": len(failures),
            "pending_count": 0,
            "successes": successes,
            "failures": failures,
        }
        return taxii(statuses[status_id], 202)

    @app.get(f"/{API_ROOT}/status/<sid>/")
    def status(sid):
        return taxii(statuses[sid]) if sid in statuses else error(404, "Status not found", sid)

    return app
