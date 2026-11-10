"""Retrieve CALDERA report and Wazuh alerts, select time window, and correlate."""
import argparse
import base64
import getpass
import hashlib
import json
import shlex
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from match_results import time_value

HERE = Path(__file__).resolve().parent

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected API redirect; check the configured CALDERA URL")

def api(base, key, path, body=None):
    request = Request(base.rstrip("/") + "/api/v2/" + path,
                      headers={"KEY": key, "Accept": "application/json", "Content-Type": "application/json"},
                      data=None if body is None else json.dumps(body).encode(),
                      method="GET" if body is None else "POST")
    try:
        # Local lab calls should not send credentials through a configured HTTP proxy.
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=30) as reply:
            return json.load(reply)
    except HTTPError as error:
        raise ValueError(f"CALDERA API HTTP {error.code}; check URL, API key and operation ID") from None

def select_window(report, host, before=30, after=90):
    if not report.get("finish"):
        raise ValueError("Operation is still open. After all abilities finish, finish the operation in CALDERA and retry.")
    finish = time_value(report["finish"])
    paws = {h["paw"] for h in report["host_group"] if h.get("host", "").casefold() == host.casefold()}
    steps = [s for paw, group in report["steps"].items() if paw in paws for s in group["steps"]]
    if not steps:
        raise ValueError("No operation steps found for the configured Windows hostname")
    starts, ends = [], []
    for step in steps:
        if not step.get("run"):
            raise ValueError("A step has no completion timestamp; this pilot cannot finalize its collection")
        # In CALDERA 5.3.0 report(), run is link.finish, not its start.
        end = time_value(step["run"])
        start = time_value(step.get("delegated") or step.get("agent_reported_time") or step["run"])
        if end < start:
            raise ValueError("Step timestamps are reversed; check VM clocks")
        starts.append(start)
        ends.append(end)
    if max(ends) > finish:
        raise ValueError("Step finishes after operation finish; review timestamps")
    start, end = min(starts)-timedelta(seconds=before), max(ends)+timedelta(seconds=after)
    if (end-start).total_seconds() > 86400:
        raise ValueError("Operation window exceeds this pilot's one-day limit")
    return start, end, steps

def connect(config):
    try:
        import paramiko
    except ImportError:
        raise ValueError("Install dependency first: python -m pip install -r requirements.txt")
    known = Path(config.get("known_hosts", "~/.ssh/known_hosts")).expanduser()
    if not known.is_file():
        raise ValueError("No SSH known_hosts file. First connect using Windows ssh and verify the server fingerprint.")
    client = paramiko.SSHClient()
    client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    password = getpass.getpass(f"Ubuntu SSH password for {config['wazuh_user']}@{config['wazuh_host']}: ")
    try:
        client.connect(config["wazuh_host"], port=config.get("wazuh_port",22),
                       username=config["wazuh_user"], password=password,
                       allow_agent=False, look_for_keys=False, timeout=15, auth_timeout=20)
    except Exception:
        client.close()
        raise
    return client

def remote(client, command, password=None):
    stdin, stdout, stderr = client.exec_command(command, timeout=120)
    if password is not None:
        stdin.write(password + "\n")
        stdin.flush()
    stdin.channel.shutdown_write()
    # Drain both streams so a long response cannot deadlock on a full SSH window.
    out, err = bytearray(), bytearray()
    channel = stdout.channel
    deadline = time.monotonic() + 120
    while True:
        if channel.recv_ready():
            out.extend(channel.recv(65536))
        if channel.recv_stderr_ready():
            err.extend(channel.recv_stderr(65536))
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if time.monotonic() > deadline:
            channel.close()
            raise TimeoutError("SSH collection timed out")
        time.sleep(0.02)
    code = channel.recv_exit_status()
    if code:
        raise ValueError("Remote collection failed: " + err.decode(errors="replace")[-2000:])
    return out.decode("utf-8")

def save(path, data):
    with path.open("x", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def run(args):
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    url = config["caldera_url"]
    parts = urlsplit(url)
    if parts.scheme not in ("http","https") or not parts.hostname or parts.username or parts.query or parts.fragment:
        raise ValueError("Invalid CALDERA URL")
    key = getpass.getpass("CALDERA red API key (not dashboard password): ").strip()
    if not key:
        raise ValueError("An API key is required")
    if args.list:
        operations = api(url, key, "operations")
        if not isinstance(operations, list):
            raise ValueError("Unexpected operation listing format")
        for op in operations:
            print(op.get("id"), "|", op.get("name"), "|", op.get("state"))
        return
    if not args.operation:
        raise ValueError("Supply --operation ID or --list")
    operation = str(uuid.UUID(args.operation))
    report = api(url, key, f"operations/{quote(operation)}/report", {"enable_agent_output": True})
    if not isinstance(report, dict):
        raise ValueError("CALDERA returned no report")
    before, after = int(config.get("before_seconds",30)), int(config.get("after_seconds",90))
    grace = int(config.get("ingestion_grace_seconds",30))
    if min(before, after, grace) < 0:
        raise ValueError("Window settings must be nonnegative")
    start, end, steps = select_window(report, config["windows_host"], before, after)
    print("Config:", args.config.resolve())
    print("Wazuh:", config["wazuh_host"], "agent:", config["wazuh_agent_id"])
    print("Operation:", report["name"])
    print("Collection window (UTC):", start.isoformat(), "to", end.isoformat())
    wait = (end + timedelta(seconds=grace)-datetime.now(timezone.utc)).total_seconds()
    if wait > 600:
        raise ValueError("Window is more than 10 minutes in the future; check clocks")
    while wait > 0:
        print(f"Waiting {int(wait)+1}s for the window and ingestion allowance...", flush=True)
        time.sleep(min(wait,15))
        wait = (end + timedelta(seconds=grace)-datetime.now(timezone.utc)).total_seconds()

    client = connect(config)
    try:
        clock = float(remote(client, "date -u +%s").strip())
        if abs(clock-datetime.now(timezone.utc).timestamp()) > 30:
            raise ValueError("Wazuh and this computer differ by over 30 seconds; synchronize clocks")
        sudo_password = getpass.getpass("Ubuntu sudo password (normally the same Ubuntu password): ")
        program = (HERE/"remote_collect.py").read_bytes()
        encoded = base64.b64encode(program).decode("ascii")
        # Only trusted bundled collector code is executed, never content from reports.
        bootstrap = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<collector>','exec'))"
        command = shlex.join(["sudo", "-k", "-S", "-p", "", "--", "python3", "-c", bootstrap,
                              "--agent", str(config["wazuh_agent_id"]),
                              "--start", start.isoformat(), "--end", end.isoformat()])
        collected = json.loads(remote(client, command, sudo_password))
        print("Collected alerts:", collected.get("alert_count"), flush=True)
        try:
            archives = json.loads(remote(client, command + " --source archives", sudo_password))
        except (ValueError, OSError, EOFError) as error:
            archives = {
                "collection_status": "error", "agent_id": str(config["wazuh_agent_id"]),
                "start": start.isoformat(), "end": end.isoformat(),
                "source": "/var/ossec/logs/archives", "event_count": 0, "events": [],
                "files_scanned": [], "error": str(error),
                "collected_at": datetime.now(timezone.utc).isoformat()
            }
        print("Archive collection:", archives.get("collection_status"),
              "events:", archives.get("event_count"), flush=True)
        if archives.get("incomplete_tail_files"):
            print("Archive snapshot skipped an unfinished trailing record in:",
                  ", ".join(archives["incomplete_tail_files"]), flush=True)
        if archives.get("collection_status") != "success":
            print("Archive evidence unavailable:", archives.get("error", "unknown reason"))
    finally:
        client.close()
    if collected.get("collection_status") != "success":
        raise ValueError("Remote collection did not succeed")
    # Refetch: refuse to correlate a report that changed during collection.
    latest = api(url, key, f"operations/{operation}/report", {"enable_agent_output": True})
    if report.get("steps") != latest.get("steps") or report.get("finish") != latest.get("finish"):
        raise ValueError("Operation changed while collecting; retry once it is finalized")

    root = args.out or Path("runs") / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+"-"+operation[:8])
    root.mkdir(parents=True, exist_ok=False)
    save(root/"caldera-report.json", report)
    save(root/"wazuh-alerts.json", collected)
    save(root/"wazuh-archives.json", archives)
    save(root/"run-metadata.json", {
        "operation_id": operation, "caldera_url": url,
        "windows_host": config["windows_host"], "wazuh_agent_id": str(config["wazuh_agent_id"]),
        "window_start": start.isoformat(), "window_end": end.isoformat(),
        "before_seconds": before, "after_seconds": after, "ingestion_grace_seconds": grace,
        "collected_at": collected.get("collected_at"),
        "collection_method": "CALDERA v2 report API and read-only Wazuh SSH collector",
        "limitations": ["Ingestion allowance is not proof of complete telemetry.",
                        "Available alert and archive files only; absent evidence does not establish a miss.",
                        "Only configured endpoint is evaluated; all raw report steps are preserved."],
        "archive_collection_status": archives.get("collection_status"),
        "archive_incomplete_tail_files": archives.get("incomplete_tail_files", []),
        "wazuh_host": config["wazuh_host"],
        "config_path": str(args.config.resolve()),
        "collector_sha256": hashlib.sha256(program).hexdigest(),
    })
    completed = subprocess.run([sys.executable, str(HERE/"match_results.py"),
        "--caldera", str(root/"caldera-report.json"), "--wazuh", str(root/"wazuh-alerts.json"),
        "--archives", str(root/"wazuh-archives.json"),
        "--agent", str(config["wazuh_agent_id"]), "--host", config["windows_host"],
        "--out", str(root/"results")])
    if completed.returncode:
        raise ValueError(f"Exports saved in {root}, but matching failed; inspect the error above")
    print("Finished. Evidence and results:", root.resolve())

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, default=HERE/"config.json")
    p.add_argument("--list", action="store_true", help="List operation IDs without changing them")
    p.add_argument("--operation")
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        raise SystemExit("Cancelled")
    except Exception as e:
        raise SystemExit(f"ERROR: {e}")

if __name__ == "__main__":
    main()
