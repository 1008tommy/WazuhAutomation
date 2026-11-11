"""Local control console for the Wazuh BAS pipeline (localhost only). Python 3.11+.

Serves the dashboard and launches scenarios on WIN11-TEST01 through run_scenario.py. It binds to
127.0.0.1 only and reuses run_scenario's guardrails (group and host allowlist, plain-text obfuscator,
cleanup verification). Credentials are entered once at startup and passed to the child processes via
the environment; they are never written to disk. Each job's activity log is kept in console-logs/
(gitignored). Start it from the collector folder:

    python serve_dashboard.py      then open http://127.0.0.1:8787
"""
import argparse
import getpass
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import build_dashboard as bd
import collect_operation
from caldera_api import Caldera
from run_scenario import check_target

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"
SCENARIOS = HERE / "scenarios"
CONFIG = HERE / "config.json"
LOGS = None  # set by main(); finished job logs are written there
JOBS = {}
JOB_LOCK = threading.Lock()


def latest_job(running_only=False):
    """Newest job id (or the newest one still running), or None."""
    with JOB_LOCK:
        return next((job for job, item in reversed(list(JOBS.items()))
                     if not running_only or item["state"] == "running"), None)


def render_page():
    runs = bd.load_runs(RUNS) if RUNS.exists() else []
    data = bd.build_data(runs, bd.load_scenarios(SCENARIOS))
    data["active_job"] = latest_job(running_only=True)
    data["last_job"] = latest_job()  # the page shows this job's log again after any reload
    return bd.render_html(data, served=True).encode("utf-8")


def save_log(job, scenario):
    """Write a finished job's log to console-logs/ so it outlives the console."""
    if LOGS is None:
        return
    item = JOBS.get(job, {})
    try:
        LOGS.mkdir(exist_ok=True)
        name = f"{item.get('started', 'unknown')}-{scenario}-{job}.log"
        (LOGS / name).write_text("\n".join(item.get("log", [])) + "\n", encoding="utf-8")
    except OSError as error:
        item.setdefault("log", []).append(f"(could not save this log: {error})")


def check(name, probe):
    """Run one read-only lab probe; any failure becomes a failed check with its message."""
    try:
        return {"name": name, "ok": True, "detail": probe()}
    except Exception as error:  # urllib and paramiko raise many types; all mean "not ready"
        return {"name": name, "ok": False, "detail": str(error) or type(error).__name__}


def wazuh_agent_status(config):
    """Read-only: the manager's view of the endpoint's agent, which must be Active before a run."""
    agent_id = str(config["wazuh_agent_id"])
    ssh = collect_operation.connect(config)
    try:
        out = collect_operation.remote(ssh, shlex.join(["sudo", "-k", "-S", "-p", "", "--",
                                       "/var/ossec/bin/agent_control", "-i", agent_id]),
                                       os.environ.get("BAS_SUDO_PASSWORD", ""))
    finally:
        ssh.close()
    status = re.search(r"Status:\s*(\w+)", out)
    state = status.group(1) if status else "unknown"
    if state != "Active":
        raise ValueError(f"agent {agent_id} is {state}; start WAZUH-MGR first and wait for the agent")
    return f"agent {agent_id} is Active"


def preflight():
    """Lab checks shown before Launch: Caldera, the Sandcat agent and the Wazuh agent."""
    config = json.loads(CONFIG.read_text(encoding="utf-8-sig"))
    host, group = config["windows_host"], config.get("caldera_group", "red")
    client = Caldera(config["caldera_url"], os.environ.get("BAS_CALDERA_KEY", ""))

    def caldera():
        client.health()
        return "API reachable"

    def sandcat():
        agent = check_target(client.agents(), group, host)
        return f"{agent.get('paw')} on {host}, last seen {agent.get('last_seen')}"
    return [check("Caldera", caldera), check("Sandcat agent", sandcat),
            check("Wazuh agent", lambda: wazuh_agent_status(config))]


def valid_scenarios():
    return {s["scenario"] for s in bd.load_scenarios(SCENARIOS) if s.get("scenario")}


def run_job(job, scenario):
    spec = SCENARIOS / f"{scenario}.json"
    try:
        process = subprocess.Popen(
            [sys.executable, str(HERE / "run_scenario.py"), str(spec),
             "--config", str(CONFIG), "--collect"],
            cwd=str(HERE), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=dict(os.environ))
        for line in process.stdout:
            JOBS[job]["log"].append(line.rstrip())
        process.wait()
        JOBS[job]["state"] = "done" if process.returncode == 0 else "error"
    except Exception as error:  # surface any launch failure to the page
        JOBS[job]["log"].append(f"Error: {error}")
        JOBS[job]["state"] = "error"
    finally:
        save_log(job, scenario)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
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
        elif route.path == "/api/preflight":
            if not CONFIG.is_file():
                return self._send(503, b'{"error":"config.json is missing"}')
            self._send(200, json.dumps({"checks": preflight()}).encode())
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
        if not CONFIG.is_file():
            return self._send(503, b'{"error":"config.json is missing; copy and edit config.example.json first"}')
        with JOB_LOCK:
            active_job = next((job for job, item in reversed(list(JOBS.items()))
                               if item["state"] == "running"), None)
            if active_job:
                return self._send(409, json.dumps({
                    "error": "A scenario is already running; showing its progress",
                    "job": active_job,
                }).encode())
            job = uuid.uuid4().hex[:8]
            JOBS[job] = {"state": "running", "log": [f"Launching {scenario} ..."], "scenario": scenario,
                         "started": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")}
        threading.Thread(target=run_job, args=(job, scenario), daemon=True).start()
        self._send(200, json.dumps({"job": job}).encode())

    def log_message(self, *args):
        return  # quiet; job logs are shown in the page


def main():
    global CONFIG, LOGS
    LOGS = HERE / "console-logs"
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11+ required.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG,
                        help="Configuration file for the scenario runner and Wazuh collector")
    args = parser.parse_args()
    CONFIG = args.config.expanduser().resolve()
    if not CONFIG.is_file():
        raise SystemExit(f"Configuration file not found: {CONFIG}")
    config = json.loads(CONFIG.read_text(encoding="utf-8-sig"))
    for field in ("caldera_url", "wazuh_host", "wazuh_user", "windows_host", "wazuh_agent_id"):
        if not config.get(field):
            raise SystemExit(f"Missing {field} in {CONFIG}")
    if not os.environ.get("BAS_CALDERA_KEY"):
        os.environ["BAS_CALDERA_KEY"] = getpass.getpass("CALDERA red API key: ").strip()
    if not os.environ.get("BAS_CALDERA_KEY"):
        raise SystemExit("A CALDERA API key is required")
    if not os.environ.get("BAS_SSH_PASSWORD"):
        os.environ["BAS_SSH_PASSWORD"] = getpass.getpass(
            f"Wazuh SSH password for {config['wazuh_user']}@{config['wazuh_host']}: ")
    if not os.environ.get("BAS_SSH_PASSWORD"):
        raise SystemExit("A Wazuh SSH password is required")
    if not os.environ.get("BAS_SUDO_PASSWORD"):
        os.environ["BAS_SUDO_PASSWORD"] = getpass.getpass("Ubuntu sudo password: ")
    if not os.environ.get("BAS_SUDO_PASSWORD"):
        raise SystemExit("A Wazuh sudo password is required")
    port = int(os.environ.get("BAS_PORT", "8787"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Control console on http://127.0.0.1:{port}  (localhost only; Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
