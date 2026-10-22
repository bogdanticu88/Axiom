"""Local fakes of a ServiceNow-style Table API and the GitHub Issues API, for fixture tests only.

They reproduce documented request/response shapes and the failure modes relevant to duplicate prevention
(lost acknowledgement, a lookup that has not caught up, a request held at the provider). They model nothing about
either vendor's internals and prove nothing about compatibility with the live services.
"""
from __future__ import annotations

import json
import threading
import time

import httpx


class _Base:
    def __init__(self, lookup_lag: float = 0.0):
        self.lookup_lag = lookup_lag
        self.lose_ack = 0
        self.create_requests = 0
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.hold_armed = False
        self.at_boundary = threading.Event()
        self.release = threading.Event()

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _visible(self):
        now = time.monotonic()
        return [r for r in self.records if now - r["created"] >= self.lookup_lag]

    def _hold(self):
        with self.lock:
            hold, self.hold_armed = self.hold_armed, False
        if hold:
            self.at_boundary.set()
            self.release.wait(30)

    def _finish_create(self, request, status, body):
        with self.lock:
            lose = self.lose_ack > 0
            if lose:
                self.lose_ack -= 1
        if lose:
            raise httpx.ReadTimeout("response lost", request=request)
        return httpx.Response(status, json=body)


class ServiceNowFake(_Base):
    TABLE = "/api/now/table/incident"

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method == "POST" and path == self.TABLE:
            with self.lock:
                self.create_requests += 1
            self._hold()
            body = json.loads(request.content)
            with self.lock:
                n = len(self.records) + 1
                rec = {"sys_id": f"{n:032x}", "number": f"INC{n:07d}", "state": "1", "created": time.monotonic(),
                       **body}
                self.records.append(rec)
            return self._finish_create(request, 201, {"result": {k: v for k, v in rec.items() if k != "created"}})
        if request.method == "GET" and path == self.TABLE:
            field, _, value = request.url.params["sysparm_query"].partition("=")
            hits = [r for r in self._visible() if r.get(field) == value]
            return httpx.Response(200, json={"result": [{"sys_id": r["sys_id"], "number": r["number"],
                                                         field: r[field]} for r in hits]})
        if request.method == "GET" and path.startswith(self.TABLE + "/"):
            sys_id = path.rsplit("/", 1)[-1]
            rec = next((r for r in self.records if r["sys_id"] == sys_id), None)
            if rec is None:
                return httpx.Response(404, json={"error": {"message": "No Record found"}})
            return httpx.Response(200, json={"result": {k: v for k, v in rec.items() if k != "created"}})
        return httpx.Response(404)

    def set_state(self, sys_id: str, state: str) -> None:
        with self.lock:
            next(r for r in self.records if r["sys_id"] == sys_id)["state"] = state

    def refs(self):
        return [r["sys_id"] for r in self.records]


class GitHubFake(_Base):
    REPO = "/repos/acme/payments/issues"

    def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers["X-GitHub-Api-Version"] == "2022-11-28"
        path = request.url.path
        if request.method == "POST" and path == self.REPO:
            with self.lock:
                self.create_requests += 1
            self._hold()
            body = json.loads(request.content)
            with self.lock:
                n = len(self.records) + 1
                rec = {"number": n, "title": body["title"], "body": body["body"], "state": "open",
                       "state_reason": None, "labels": body.get("labels", []), "created": time.monotonic()}
                self.records.append(rec)
            return self._finish_create(request, 201, {k: v for k, v in rec.items() if k != "created"})
        if request.method == "GET" and path == self.REPO:
            page, per = int(request.url.params.get("page", "1")), int(request.url.params.get("per_page", "30"))
            items = sorted(self._visible(), key=lambda r: -r["number"])[(page - 1) * per: page * per]
            return httpx.Response(200, json=[{k: v for k, v in r.items() if k != "created"} for r in items])
        if request.method == "GET" and path.startswith(self.REPO + "/"):
            n = int(path.rsplit("/", 1)[-1])
            rec = next((r for r in self.records if r["number"] == n), None)
            if rec is None:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json={k: v for k, v in rec.items() if k != "created"})
        return httpx.Response(404)

    def close(self, n: int, reason: str = "completed") -> None:
        with self.lock:
            rec = next(r for r in self.records if r["number"] == n)
            rec["state"], rec["state_reason"] = "closed", reason

    def refs(self):
        return [f"acme/payments#{r['number']}" for r in self.records]
