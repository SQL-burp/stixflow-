import json
import threading

import pytest
from werkzeug.serving import make_server

from stixflow.server import DEFAULT_DATA_DIR, create_app
from stixflow.store import StixStore

ICS_BUNDLE = DEFAULT_DATA_DIR / "ics_threats.json"
IT_BUNDLE = DEFAULT_DATA_DIR / "it_commodity.json"


@pytest.fixture
def store(tmp_path):
    s = StixStore(tmp_path / "test.db")
    yield s
    s.close()


@pytest.fixture
def loaded_store(store):
    for path in (ICS_BUNDLE, IT_BUNDLE):
        store.ingest_bundle(json.loads(path.read_text()))
    return store


def _serve(app):
    srv = make_server("127.0.0.1", 0, app)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


@pytest.fixture
def taxii_server():
    srv = _serve(create_app())
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def taxii_server_auth():
    srv = _serve(create_app(username="analyst", password="s3cret"))
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
