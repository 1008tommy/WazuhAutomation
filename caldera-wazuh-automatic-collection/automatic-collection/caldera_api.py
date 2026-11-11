"""Minimal Caldera 5.3.0 v2 REST client. Python 3.11+; no third-party packages.

Same safety posture as the collector: no system proxy, no redirects, explicit timeouts,
and the KEY header on every call. Never calls /api/v2/operations/summary (HTTP 500 on 5.3.0).
"""
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected Caldera API redirect; check the configured CALDERA URL")


class Caldera:
    def __init__(self, base, key, timeout=30):
        self.base = base.rstrip("/")
        self.key = key
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def _request(self, method, path, body=None, extra_headers=None, raw=None):
        headers = {"KEY": self.key, "Accept": "application/json"}
        data = raw
        if raw is None and body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        request = Request(f"{self.base}/api/v2/{path}", data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as reply:
                payload = reply.read()
                return json.loads(payload) if payload else None
        except HTTPError as error:
            detail = error.read()[:300].decode(errors="replace")
            raise ValueError(f"Caldera API HTTP {error.code} on {method} {path}: {detail}") from None
        except URLError as error:
            raise ValueError(f"Cannot reach Caldera at {self.base}: {error.reason}") from None

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, body):
        return self._request("POST", path, body=body)

    def put(self, path, body):
        return self._request("PUT", path, body=body)

    def patch(self, path, body):
        return self._request("PATCH", path, body=body)

    def delete(self, path):
        return self._request("DELETE", path)

    def health(self):
        return self.get("health")

    def agents(self):
        return self.get("agents")

    def planner_id(self, name):
        """Resolve a planner by name (never hardcode the stock id)."""
        for planner in self.get("planners") or []:
            if isinstance(planner, dict) and planner.get("name") == name:
                return planner.get("id") or planner.get("planner_id")
        raise ValueError(f"Planner named {name!r} not found on Caldera")

    def adversary(self, adversary_id):
        return self.get(f"adversaries/{adversary_id}")

    def create_operation(self, fields):
        return self.post("operations", fields)

    def operation(self, operation_id):
        return self.get(f"operations/{operation_id}")

    def operation_links(self, operation_id):
        return self.get(f"operations/{operation_id}/links")

    def operation_report(self, operation_id):
        return self.post(f"operations/{operation_id}/report", {"enable_agent_output": False})
