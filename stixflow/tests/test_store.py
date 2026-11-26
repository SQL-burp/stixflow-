import copy
import json

import pytest

from conftest import ICS_BUNDLE


def _indicator(**overrides):
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--11111111-1111-4111-8111-111111111111",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "test",
        "pattern": "[ipv4-addr:value = '192.0.2.10']",
        "pattern_type": "stix",
        "valid_from": "2026-01-01T00:00:00Z",
    }
    obj.update(overrides)
    return obj


def test_ingest_bundle_counts(store):
    bundle = json.loads(ICS_BUNDLE.read_text())
    res = store.ingest_bundle(bundle)
    assert res.added == len(bundle["objects"])
    assert store.counts_by_type()["intrusion-set"] == 1


def test_reingest_is_idempotent(loaded_store):
    res = loaded_store.ingest_bundle(json.loads(ICS_BUNDLE.read_text()))
    assert res.added == 0 and res.updated == 0


def test_newer_version_replaces_older(store):
    store.ingest([_indicator()])
    newer = _indicator(modified="2026-02-01T00:00:00.000Z", pattern="[ipv4-addr:value = '192.0.2.99']")
    assert store.ingest([newer]).updated == 1
    assert [r["value"] for r in store.find_by_value("192.0.2.99")]
    assert not store.find_by_value("192.0.2.10")  # observables re-derived from the new pattern


def test_older_version_is_ignored(store):
    store.ingest([_indicator(modified="2026-03-01T00:00:00.000Z")])
    assert store.ingest([_indicator(modified="2026-01-01T00:00:00.000Z")]).skipped == 1


def test_revoked_objects_hidden(store):
    store.ingest([_indicator(), _indicator(id="indicator--22222222-2222-4222-8222-222222222222",
                                           pattern="[ipv4-addr:value = '192.0.2.11']", revoked=True)])
    values = [r["value"] for r in store.observables()]
    assert values == ["192.0.2.10"]


def test_relationship_walk(loaded_store):
    c2 = loaded_store.find_by_value("203.0.113.45")[0]["indicator_id"]
    names = {o.get("name") for _d, _r, _dir, o, _p in loaded_store.related(c2, max_depth=2)}
    assert {"PRESSBREAK", "COPPER LATHE"} <= names


def test_rejects_non_bundle(store):
    with pytest.raises(ValueError):
        store.ingest_bundle({"type": "indicator"})


def test_skips_objects_without_id(store):
    bad = copy.deepcopy(_indicator())
    del bad["id"]
    assert store.ingest([bad]).skipped == 1
