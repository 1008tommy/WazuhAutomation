"""Local control console for the Wazuh BAS pipeline (localhost only). Python 3.11+.

Serves the dashboard and launches scenarios on WIN11-TEST01 through run_scenario.py. It binds to
127.0.0.1 only and reuses run_scenario's guardrails (group and host allowlist, plain-text obfuscator,
cleanup verification). Credentials are entered once at startup and passed to the child processes via
the environment; they are never written to disk. Start it from the collector folder:

    python serve_dashboard.py      then open http://127.0.0.1:8787
"""
import getpass
import json
import os
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import build_dashboard as bd

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"
SCENARIOS = HERE / "scenarios"
JOBS = {}


def render_page():
    runs = bd.load_runs(RUNS) if RUNS.exists() else []
    data = bd.build_data(runs, bd.load_scenarios(SCENARIOS))
    return bd.render_html(data, served=True).encode("utf-8")


def valid_scenarios():
    return {s["scenario"] for s in bd.load_scenarios(SCENARIOS) if s.get("scenario")}


def run_job(job, scenario):
    JOBS[job] = {"state": "running", "log": [f"Launching {scenario} ..."]}
    spec = SCENARIOS / f"{scenario}.json"
    try:
        process = subprocess.Popen(
            [sys.executable, str(HERE / "run_scenario.py"), str(spec), "--collect"],
            cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=dict(os.environ))
        for line in process.stdout:
            JOBS[job]["log"].append(line.rstrip())
        process.wait()
        JOBS[job]["state"] = "done" if process.returncode == 0 else "error"
    except Exception as error:  # surface any launch failure to the page
        JOBS[job]["log"].append(f"Error: {error}")
        JOBS[job]["state"] = "error"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlparse(self.path)
        if route.path in ("/", "/index.html"):
            self._send(200, render_page(), "text/html; charset=utf-8")
        elif route.path == "/api/status":
            job = parse_qs(route.query).get("job", [""])[0]
            self._send(200, json.dumps(JOBS.get(job, {"state": "unknown", "log": []})).encode())
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if urlparse(self.path).path != "/api/launch":
            return self._send(404, b'{"error":"not found"}')
        length = int(self.headers.get("Content-Length", 0))
        try:
            scenario = json.loads(self.rfile.read(length) or b"{}").get("scenario")
        except ValueError:
            return self._send(400, b'{"error":"bad json"}')
        if scenario not in valid_scenarios():
            return self._send(400, json.dumps({"error": f"unknown scenario {scenario!r}"}).encode())
        job = uuid.uuid4().hex[:8]
        threading.Thread(target=run_job, args=(job, scenario), daemon=True).start()
        self._send(200, json.dumps({"job": job}).encode())

    def log_message(self, *args):
        return  # quiet; job logs are shown in the page


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11+ required.")
    if "BAS_CALDERA_KEY" not in os.environ:
        os.environ["BAS_CALDERA_KEY"] = getpass.getpass("CALDERA red API key: ").strip()
    if "BAS_SSH_PASSWORD" not in os.environ:
        os.environ["BAS_SSH_PASSWORD"] = getpass.getpass("Ubuntu SSH password: ")
    if "BAS_SUDO_PASSWORD" not in os.environ:
        os.environ["BAS_SUDO_PASSWORD"] = getpass.getpass("Ubuntu sudo password: ")
    port = int(os.environ.get("BAS_PORT", "8787"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Control console on http://127.0.0.1:{port}  (localhost only; Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
