"""Run one or more lab scenarios through the Caldera v2 API, then collect and score. Python 3.11+.

Each scenario spec (JSON) names an adversary that the portable bundle already installed in Caldera
(see Scenarios/portable/install_bundle.py), so this runner wires the existing scenarios to the API
without defining any new techniques or payloads. Guardrails are enforced in code: only the configured
group and host, the plain-text obfuscator only, and cleanup is verified after every run.

Usage:
  python run_scenario.py scenarios/discovery.json [more.json ...] [--collect]
"""
import argparse
import getpass
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from caldera_api import Caldera

HERE = Path(__file__).resolve().parent
STOCK_BASIC_SOURCE = "ed32b9c3-9593-4c33-b0db-e2007315096b"
FINISHED_STATES = {"finished", "out_of_time"}


def parse_time(text):
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def validate_spec(spec):
    for key in ("scenario", "name", "adversary_id", "planner"):
        if not spec.get(key):
            raise ValueError(f"Scenario spec is missing required field {key!r}")
    try:
        uuid.UUID(str(spec["adversary_id"]))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("adversary_id must be a UUID") from None
    if spec.get("obfuscator", "plain-text") != "plain-text":
        raise ValueError("Only the plain-text obfuscator is allowed: the goal is to measure detection, not evade it")
    if spec.get("platform", "windows") != "windows":
        raise ValueError("Only the windows platform is supported")
    return spec


def load_spec(path):
    path = Path(path)
    if path.parent.name != "scenarios":
        raise ValueError(f"Scenario specs must live under a scenarios/ directory: {path}")
    return validate_spec(json.loads(path.read_text(encoding="utf-8-sig")))


def check_target(agents, group, host, max_age_seconds=180, now=None):
    """Target allowlist: the group must contain only the configured host, trusted and recently seen."""
    now = now or datetime.now(timezone.utc)
    group_agents = [a for a in (agents or []) if a.get("group") == group]
    if not group_agents:
        raise ValueError(f"No agent in group {group!r}; relaunch the Sandcat agent on {host}")
    hosts = sorted({str(a.get("host")) for a in group_agents})
    if hosts != [host]:
        raise ValueError(f"Group {group!r} must contain only {host!r}; found {hosts}. Refusing to run.")
    for agent in group_agents:
        if not agent.get("trusted"):
            raise ValueError(f"Agent {agent.get('paw')} is not trusted; refusing to run")
        seen = parse_time(agent.get("last_seen"))
        if seen is None or (now - seen).total_seconds() > max_age_seconds:
            raise ValueError(f"Agent {agent.get('paw')} last seen {agent.get('last_seen')}, "
                             f"not within {max_age_seconds}s; let it settle or relaunch it")
    return group_agents[0]


def operation_fields(spec, planner_id, source_id, group):
    return {
        "name": f"{spec['scenario']}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "adversary": {"adversary_id": spec["adversary_id"]},
        "planner": planner_id,
        "source": source_id,
        "group": group,
        "autonomous": 1,
        "auto_close": True,
        "state": "running",
        "obfuscator": "plain-text",
        "jitter": spec.get("jitter", "2/8"),
        "visibility": 51,
        "use_learning_parsers": True,
    }


def cleanup_status(links):
    """Return (ok, cleanup_links, failed_links). Every cleanup link must have status 0."""
    cleanup = [l for l in (links or []) if l.get("cleanup")]
    failed = [l for l in cleanup if str(l.get("status")) != "0"]
    return (not failed), cleanup, failed


def wait_for_operation(client, operation_id, timeout_seconds, poll=10, sleeper=time.sleep):
    deadline = time.monotonic() + timeout_seconds
    while True:
        op = client.operation(operation_id)
        state = op.get("state")
        if state in FINISHED_STATES or time.monotonic() >= deadline:
            return op, state
        sleeper(poll)


def run_one(client, spec, group, host, config):
    validate_spec(spec)
    if not client.adversary(spec["adversary_id"]):
        raise ValueError(f"Adversary {spec['adversary_id']} not found; run install_bundle.py on Caldera first")
    planner_id = client.planner_id(spec["planner"])
    source_id = spec.get("source") or STOCK_BASIC_SOURCE
    fields = operation_fields(spec, planner_id, source_id, group)
    print(f"[{spec['scenario']}] starting operation {fields['name']} (adversary {spec['adversary_id']})", flush=True)
    created = client.create_operation(fields)
    operation_id = created.get("id")
    if not operation_id:
        raise ValueError(f"Caldera did not return an operation id: {created}")
    timeout = int(config.get("operation_timeout_seconds", 600))
    op, state = wait_for_operation(client, operation_id, timeout)
    print(f"[{spec['scenario']}] operation {operation_id} ended in state {state}", flush=True)
    ok, cleanup, failed = cleanup_status(client.operation_links(operation_id))
    if not ok:
        print(f"[{spec['scenario']}] CLEANUP FAILED on {len(failed)} link(s); "
              f"revert {host} to its snapshot before the next scenario", flush=True)
    else:
        print(f"[{spec['scenario']}] cleanup verified ({len(cleanup)} link(s) succeeded)", flush=True)
    return operation_id, state, ok


def run(args):
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    url = config["caldera_url"]
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.query or parts.fragment:
        raise ValueError("Invalid CALDERA URL in config")
    group = config.get("caldera_group", "red")
    host = config["windows_host"]
    specs = [load_spec(p) for p in args.specs]
    key = getpass.getpass("CALDERA red API key (not dashboard password): ").strip()
    if not key:
        raise ValueError("An API key is required")
    client = Caldera(url, key)
    if not client.health():
        raise ValueError("Caldera health check failed")
    check_target(client.agents(), group, host)   # refuses any host other than the configured one
    for spec in specs:
        operation_id, state, ok = run_one(client, spec, group, host, config)
        if args.collect:
            print(f"[{spec['scenario']}] collecting and scoring operation {operation_id}...", flush=True)
            collected = subprocess.run([sys.executable, str(HERE / "collect_operation.py"),
                                        "--config", str(args.config), "--operation", operation_id])
            if collected.returncode == 0:
                subprocess.run([sys.executable, str(HERE / "build_dashboard.py")])
        else:
            print(f"[{spec['scenario']}] next: python collect_operation.py --operation {operation_id}", flush=True)


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11+ required.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("specs", nargs="+", type=Path, help="Scenario spec JSON files under scenarios/")
    parser.add_argument("--config", type=Path, default=HERE / "config.json")
    parser.add_argument("--collect", action="store_true",
                        help="After each run, collect, score and rebuild the dashboard")
    args = parser.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        raise SystemExit("Cancelled")
    except Exception as error:
        raise SystemExit(f"ERROR: {error}")


if __name__ == "__main__":
    main()
