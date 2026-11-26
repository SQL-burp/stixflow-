"""Minimal, dependency-light TAXII 2.1 client.

Written against the OASIS TAXII 2.1 spec directly (rather than wrapping a
library) to show the protocol mechanics:

    GET  /taxii2/                                   -> discovery
    GET  /{api-root}/                               -> api root info
    GET  /{api-root}/collections/                   -> list collections
    GET  /{api-root}/collections/{id}/objects/      -> envelope {more, next, objects}
    POST /{api-root}/collections/{id}/objects/      -> status resource

Pagination uses the ``more`` / ``next`` fields of the envelope. Incremental
sync uses ``added_after`` plus the ``X-TAXII-Date-Added-Last`` response header.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

import requests

from . import TAXII_MEDIA_TYPE


class TaxiiError(RuntimeError):
    pass


@dataclass
class ObjectPage:
    objects: list[dict]
    more: bool
    next: str | None
    date_added_last: str | None


@dataclass
class TaxiiClient:
    """Client bound to a TAXII server base URL (e.g. https://host or https://host/taxii2/)."""

    base_url: str
    username: str | None = None
    password: str | None = None
    timeout: float = 30.0
    verify_tls: bool = True
    session: requests.Session = field(default_factory=requests.Session)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/") + "/"
        self.session.headers.update({"Accept": TAXII_MEDIA_TYPE, "User-Agent": "stixflow/0.1"})
        if self.username:
            self.session.auth = (self.username, self.password or "")

    # ------------------------------------------------------------------ http
    def _get(self, url: str, params: dict | None = None) -> requests.Response:
        resp = self.session.get(url, params=params, timeout=self.timeout, verify=self.verify_tls)
        self._raise_for_status(resp)
        return resp

    @staticmethod
    def _raise_for_status(resp: requests.Response) -> None:
        if resp.status_code >= 400:
            try:
                err = resp.json()
                msg = f"{err.get('title', 'error')}: {err.get('description', '')}"
            except ValueError:
                msg = resp.text[:200]
            raise TaxiiError(f"HTTP {resp.status_code} from {resp.url} - {msg}")

    @staticmethod
    def _join(root: str, *parts: str) -> str:
        return root.rstrip("/") + "/" + "/".join(p.strip("/") for p in parts) + "/"

    def _resolve_root(self, api_root: str) -> str:
        if api_root.startswith("http"):
            return api_root.rstrip("/") + "/"
        # relative api root path, resolved against the server origin
        from urllib.parse import urljoin

        return urljoin(self.base_url, api_root).rstrip("/") + "/"

    # ------------------------------------------------------------------ endpoints
    def discover(self) -> dict:
        url = self.base_url if self.base_url.endswith("taxii2/") else self._join(self.base_url, "taxii2")
        return self._get(url).json()

    def api_root(self, api_root: str) -> dict:
        return self._get(self._resolve_root(api_root)).json()

    def collections(self, api_root: str) -> list[dict]:
        url = self._join(self._resolve_root(api_root), "collections")
        return self._get(url).json().get("collections", [])

    def get_objects_page(
        self,
        api_root: str,
        collection_id: str,
        *,
        added_after: str | None = None,
        next_token: str | None = None,
        limit: int | None = None,
        match_type: list[str] | None = None,
    ) -> ObjectPage:
        url = self._join(self._resolve_root(api_root), "collections", collection_id, "objects")
        params: dict[str, str] = {}
        if added_after:
            params["added_after"] = added_after
        if next_token:
            params["next"] = next_token
        if limit:
            params["limit"] = str(limit)
        if match_type:
            params["match[type]"] = ",".join(match_type)
        resp = self._get(url, params=params)
        body = resp.json() if resp.content else {}
        return ObjectPage(
            objects=body.get("objects", []),
            more=bool(body.get("more", False)),
            next=body.get("next"),
            date_added_last=resp.headers.get("X-TAXII-Date-Added-Last"),
        )

    def iter_objects(
        self,
        api_root: str,
        collection_id: str,
        *,
        added_after: str | None = None,
        page_size: int | None = 100,
        match_type: list[str] | None = None,
    ) -> Iterator[ObjectPage]:
        """Yield pages until the server says there is no more data."""
        next_token = None
        while True:
            page = self.get_objects_page(
                api_root,
                collection_id,
                added_after=added_after,
                next_token=next_token,
                limit=page_size,
                match_type=match_type,
            )
            yield page
            if not page.more:
                break
            if page.next:
                next_token = page.next
            elif page.date_added_last:
                # spec-compliant fallback when a server paginates by date only
                added_after = page.date_added_last
            else:
                raise TaxiiError("Server reported more=true but gave no way to fetch the next page")

    def add_objects(self, api_root: str, collection_id: str, objects: list[dict]) -> dict:
        url = self._join(self._resolve_root(api_root), "collections", collection_id, "objects")
        resp = self.session.post(
            url,
            json={"objects": objects},
            headers={"Content-Type": TAXII_MEDIA_TYPE},
            timeout=self.timeout,
            verify=self.verify_tls,
        )
        self._raise_for_status(resp)
        return resp.json()
