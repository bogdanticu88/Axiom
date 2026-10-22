"""Local fake of a Jira-style tracker for fixture tests (httpx MockTransport). Not a model of Jira's internals.

Behaviour switches let tests reproduce the failure modes that matter for duplicate prevention:

* ``search_lag``: created issues become visible to search only after this many seconds (Jira's search is
  documented as not read-after-write consistent; the lag value itself is arbitrary);
* ``lose_ack``: number of upcoming creates that are stored but whose response is lost (ReadTimeout);
* ``fail_unprocessed``: number of upcoming creates refused with 503 without storing anything;
* ``connect_error``: number of upcoming creates that fail before a connection exists;
* ``hold``: an Event; when set to "armed", the next create blocks *inside the provider before storing* until
  released, which places a worker exactly at the effect boundary;
* ``idempotency`` / ``unique_label`` / ``fencing``: hypothetical provider capabilities (NOT Jira behaviour) used to
  show which provider features make repeated creates safe.
"""
from __future__ import annotations

import json
import threading
import time

import httpx


class JiraStyleFake:
    def __init__(self, *, search_lag: float = 0.0, idempotency: bool = False, unique_label: bool = False,
                 fencing: bool = False):
        self.search_lag = search_lag
        self.idempotency, self.unique_label, self.fencing = idempotency, unique_label, fencing
        self.lose_ack = 0
        self.fail_unprocessed = 0
        self.connect_error = 0
        self.issues: list[dict] = []
        self.idem: dict[str, str] = {}
        self.max_token: dict[str, int] = {}
        self.create_requests = 0
        self.lock = threading.Lock()
        self.hold_armed = False
        self.at_boundary = threading.Event()
        self.release = threading.Event()
        self.auth_seen: set[str] = set()

    # ---------------------------------------------------------------------- inspection
    def keys(self) -> list[str]:
        return [i["key"] for i in self.issues]

    def set_status(self, key: str, name: str, category: str) -> None:
        with self.lock:
            next(i for i in self.issues if i["key"] == key)["status"] = (name, category)

    def delete(self, key: str) -> None:
        with self.lock:
            self.issues = [i for i in self.issues if i["key"] != key]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    # ------------------------------------------------------------------------- handler
    def handle(self, request: httpx.Request) -> httpx.Response:
        self.auth_seen.add(request.headers.get("Authorization", ""))
        path = request.url.path
        if request.method == "POST" and path == "/rest/api/3/issue":
            return self._create(request)
        if request.method == "POST" and path == "/rest/api/3/search/jql":
            return self._search(json.loads(request.content))
        if request.method == "GET" and path.startswith("/rest/api/3/issue/"):
            key = path.rsplit("/", 1)[-1]
            with self.lock:
                for i in self.issues:
                    if i["key"] == key:
                        return httpx.Response(200, json={"id": i["id"], "key": key, "fields": {
                            "labels": i["labels"],
                            "status": {"name": i["status"][0], "statusCategory": {"key": i["status"][1]}}}})
            return httpx.Response(404, json={"errorMessages": ["Issue does not exist"]})
        return httpx.Response(404)

    def _create(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        fields = body["fields"]
        labels = fields.get("labels", [])
        op = next((label for label in labels if label.startswith("axiom-op-")), None)
        with self.lock:
            self.create_requests += 1
            if self.connect_error:
                self.connect_error -= 1
                raise httpx.ConnectError("connection refused", request=request)
            if self.fail_unprocessed:
                self.fail_unprocessed -= 1
                return httpx.Response(503, json={"errorMessages": ["try later"]})
            hold = self.hold_armed
            self.hold_armed = False
        if hold:   # the request has reached the provider; the worker that sent it is now "in flight"
            self.at_boundary.set()
            self.release.wait(30)
        with self.lock:
            if self.fencing and op:
                token = int(request.headers.get("X-Fencing-Token", "0"))
                if token < self.max_token.get(op, 0):
                    return httpx.Response(409, json={"errorMessages": ["stale fencing token"]})
                self.max_token[op] = token
            idem_key = request.headers.get("Idempotency-Key") if self.idempotency else None
            if idem_key and idem_key in self.idem:
                key = self.idem[idem_key]
                issue = next(i for i in self.issues if i["key"] == key)
                return httpx.Response(201, json={"id": issue["id"], "key": key, "self": f"https://fake/{key}"})
            if self.unique_label and op:
                existing = next((i for i in self.issues if op in i["labels"]), None)
                if existing:
                    return httpx.Response(409, json={"errorMessages": ["duplicate"], "existing_key": existing["key"]})
            n = len(self.issues) + 1
            key = f"{fields['project']['key']}-{n}"
            self.issues.append({"id": str(10000 + n), "key": key, "labels": labels, "summary": fields["summary"],
                                "created": time.monotonic(), "status": ("To Do", "new")})
            if idem_key:
                self.idem[idem_key] = key
            lose = self.lose_ack > 0
            if lose:
                self.lose_ack -= 1
        if lose:
            raise httpx.ReadTimeout("response lost", request=request)
        return httpx.Response(201, json={"id": str(10000 + n), "key": key, "self": f"https://fake/{key}"})

    def _search(self, body: dict) -> httpx.Response:
        jql = body["jql"]
        label = jql.split('"')[1] if '"' in jql else None
        now = time.monotonic()
        with self.lock:
            hits = [i for i in self.issues if label in i["labels"] and now - i["created"] >= self.search_lag]
        return httpx.Response(200, json={"issues": [{"id": i["id"], "key": i["key"],
                                                     "fields": {"labels": i["labels"]}} for i in hits]})
