"""Round-trip tests: real HTTP between TaxiiClient and the demo TAXII 2.1 server."""

import json

import pytest
import requests

from conftest import ICS_BUNDLE
from stixflow import TAXII_MEDIA_TYPE
from stixflow.taxii_client import TaxiiClient, TaxiiError


def _ics_collection(client, root):
    return next(c for c in client.collections(root) if c["title"].startswith("ICS"))


def test_discovery_and_collections(taxii_server):
    client = TaxiiClient(taxii_server)
    disc = client.discover()
    root = disc["default"]
    assert TAXII_MEDIA_TYPE in client.api_root(root)["versions"]
    titles = {c["title"] for c in client.collections(root)}
    assert titles == {"ICS Threats - Manufacturing", "IT Commodity Threats"}


def test_pagination_returns_everything(taxii_server):
    client = TaxiiClient(taxii_server)
    root = client.discover()["default"]
    coll = _ics_collection(client, root)
    pages = list(client.iter_objects(root, coll["id"], page_size=7))
    objects = [o for p in pages for o in p.objects]
    assert len(pages) > 1
    assert len(objects) == len(json.loads(ICS_BUNDLE.read_text())["objects"])
    assert len({o["id"] for o in objects}) == len(objects)


def test_added_after_is_incremental(taxii_server):
    client = TaxiiClient(taxii_server)
    root = client.discover()["default"]
    coll = _ics_collection(client, root)
    last = list(client.iter_objects(root, coll["id"]))[-1].date_added_last
    assert last
    assert list(client.iter_objects(root, coll["id"], added_after=last))[0].objects == []


def test_match_type_filter(taxii_server):
    client = TaxiiClient(taxii_server)
    root = client.discover()["default"]
    coll = _ics_collection(client, root)
    page = client.get_objects_page(root, coll["id"], match_type=["indicator"])
    assert page.objects and {o["type"] for o in page.objects} == {"indicator"}


def test_push_then_pull(taxii_server):
    client = TaxiiClient(taxii_server)
    root = client.discover()["default"]
    coll = _ics_collection(client, root)
    cursor = list(client.iter_objects(root, coll["id"]))[-1].date_added_last
    new = {
        "type": "indicator", "spec_version": "2.1",
        "id": "indicator--33333333-3333-4333-8333-333333333333",
        "created": "2026-11-01T00:00:00.000Z", "modified": "2026-11-01T00:00:00.000Z",
        "pattern": "[ipv4-addr:value = '192.0.2.123']", "pattern_type": "stix",
        "valid_from": "2026-11-01T00:00:00Z",
    }
    status = client.add_objects(root, coll["id"], [new])
    assert status["status"] == "complete" and status["success_count"] == 1
    pulled = list(client.iter_objects(root, coll["id"], added_after=cursor))[0].objects
    assert [o["id"] for o in pulled] == [new["id"]]


def test_basic_auth(taxii_server_auth):
    with pytest.raises(TaxiiError, match="401"):
        TaxiiClient(taxii_server_auth).discover()
    assert TaxiiClient(taxii_server_auth, username="analyst", password="s3cret").discover()["api_roots"]


def test_wrong_accept_header_rejected(taxii_server):
    r = requests.get(f"{taxii_server}/taxii2/", headers={"Accept": "text/html"}, timeout=5)
    assert r.status_code == 406
    assert r.headers["Content-Type"].startswith("application/taxii+json")


def test_unknown_collection_404(taxii_server):
    client = TaxiiClient(taxii_server)
    with pytest.raises(TaxiiError, match="404"):
        client.get_objects_page(client.discover()["default"], "does-not-exist")
