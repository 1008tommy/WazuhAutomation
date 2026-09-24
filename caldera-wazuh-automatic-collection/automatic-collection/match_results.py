"""Offline CALDERA report / Wazuh collector correlation. Python 3.10+; no dependencies."""
import argparse
import csv
import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

def time_value(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Timestamp must include timezone: " + value)
    return result.astimezone(timezone.utc)

def normalize(value):
    # Wazuh's eventdata may contain additional backslash and HTML escaping.
    value = html.unescape(str(value))
    value = re.sub(r'\\+(?=["\'])', '', value)
    value = re.sub(r'\\+', r'\\', value)
    return " ".join(value.split())

def valid_pid(value):
    return str(value).isdigit() and int(value) > 0

def correlate(report, collected, agent_id, window_seconds=120, host_filter=None):
    if collected.get("collection_status") != "success":
        raise ValueError("Wazuh collection was not successful")
    if str(collected.get("agent_id")) != agent_id:
        raise ValueError("Requested agent differs from collector agent")
    alerts = collected["alerts"]
    if not isinstance(alerts, list) or collected.get("alert_count") != len(alerts):
        raise ValueError("Invalid alerts array or alert_count")
    begin, end = time_value(collected["start"]), time_value(collected["end"])
    if end <= begin:
        raise ValueError("Invalid collection window")
    hosts = {h["paw"]: h for h in report["host_group"]}
    steps = []
    for paw, group in report["steps"].items():
        for step in group["steps"]:
            host = hosts.get(paw)
            if not host:
                raise ValueError("Missing host mapping for " + paw)
            if host_filter and host.get("host", "").casefold() != host_filter.casefold():
                continue
            steps.append((paw, host, step))

    # One candidate alert can belong to several steps: never silently choose.
    candidates = [[] for _ in steps]
    rejected = []
    for index, alert in enumerate(alerts):
        win = alert.get("data", {}).get("win", {})
        ev = win.get("eventdata", {})
        system = win.get("system", {})
        agent = alert.get("agent", {})
        owners = []
        for si, (paw, host, step) in enumerate(steps):
            if not step.get("run") or not step.get("command"):
                continue
            if str(agent.get("id")) != agent_id:
                continue
            if str(agent.get("name", "")).casefold() != str(host.get("host", "")).casefold():
                continue
            if host.get("host_ip_addrs") and agent.get("ip") not in host["host_ip_addrs"]:
                continue
            if str(system.get("eventID")) != "1" or system.get("providerName") != "Microsoft-Windows-Sysmon":
                continue
            alert_time = time_value(alert["timestamp"])
            event_time = time_value(system["systemTime"])
            run_time = time_value(step["run"])
            if not begin <= alert_time <= end:
                continue
            # CALDERA report run is link.finish; use delegation-to-finish bounds.
            started = time_value(step.get("delegated") or step["run"])
            if not -window_seconds <= (event_time-started).total_seconds():
                continue
            if (event_time-run_time).total_seconds() > window_seconds:
                continue
            pid = step.get("pid")
            if not valid_pid(pid):
                continue
            command = normalize(step["command"])
            relation = None
            if str(ev.get("processId")) == str(pid) and command in normalize(ev.get("commandLine", "")):
                relation = "executor_process"
            elif str(ev.get("parentProcessId")) == str(pid) and command in normalize(ev.get("parentCommandLine", "")):
                relation = "direct_child"
            if relation:
                owners.append(si)
                candidates[si].append({
                    "alert_index": index,
                    "alert_id": alert.get("id"),
                    "rule_id": str(alert.get("rule", {}).get("id", "")),
                    "rule_description": alert.get("rule", {}).get("description"),
                    "relation": relation,
                    "alert_time_utc": alert_time.isoformat(),
                    "event_time_utc": event_time.isoformat(),
                    "event_minus_run_seconds": (event_time - run_time).total_seconds(),
                    "process_id": ev.get("processId"),
                    "parent_process_id": ev.get("parentProcessId"),
                    "process_guid": ev.get("processGuid"),
                    "parent_process_guid": ev.get("parentProcessGuid"),
                    "command_line": ev.get("commandLine"),
                    "matched_on": ["agent_id", "hostname", "host_ip_if_present",
                                   "event_time_window", "process_or_parent_pid",
                                   "full_executor_command"],
                })
        if not owners:
            rejected.append(index)
        for si in owners:
            candidates[si][-1]["ambiguous"] = len(owners) > 1

    rows = []
    for (paw, host, step), evidence in zip(steps, candidates):
        unique = [e for e in evidence if not e["ambiguous"]]
        ambiguous = any(e["ambiguous"] for e in evidence)
        status = step.get("status")
        execution = ("reported_success" if status == 0 else
                     "nonzero_status_review" if status is not None else "unknown")
        run_time = time_value(step["run"]) if step.get("run") else None
        in_range = bool(run_time and begin <= run_time <= end)
        detection = ("observed" if unique else "ambiguous_review" if ambiguous
                     else "not_assessable" if not in_range else "no_matching_alert_observed")
        notes = [
            "No absence of prevention/response is inferred from this alert export.",
            "Collection success does not verify endpoint telemetry completeness or ingestion delay.",
        ]
        if report.get("finish") is None:
            notes.append("Operation finish is null; do not describe the operation as completed.")
        if "output" not in step:
            notes.append("Step output is absent; decoding content was not independently verified here.")
        if not in_range:
            notes.append("Step run time is missing or outside the collection window.")
        if not valid_pid(step.get("pid")):
            notes.append("Missing usable executor PID; this matcher cannot correlate the step.")
        if ambiguous:
            notes.append("At least one alert also matches another step; review required.")
        rows.append({
            "operation_name": report.get("name"),
            "link_id": step.get("link_id"),
            "ability_id": step.get("ability_id"),
            "ability_name": step.get("name"),
            "technique_id": step.get("attack", {}).get("technique_id"),
            "host": host.get("host"),
            "caldera_agent": paw,
            "wazuh_agent_id": agent_id,
            "run_utc": step.get("run"),
            "delegated_utc": step.get("delegated"),
            "run_field_meaning": "CALDERA link finish timestamp",
            "caldera_pid": step.get("pid"),
            "caldera_status": status,
            "execution": execution,
            "detection": detection,
            "prevention": "not_established",
            "response": "not_assessed",
            "rule_ids": ";".join(sorted({e["rule_id"] for e in unique})),
            "matched_alert_count": len(unique),
            "output_present": "output" in step,
            "step_output": step.get("output"),
            "evidence": evidence,
            "notes": notes,
        })
    return {
        "schema_version": "0.1",
        "matcher_scope": "Sysmon process-creation alerts for executor or direct child; offline prototype",
        "window_seconds": window_seconds,
        "collection_window": {"start": collected["start"], "end": collected["end"]},
        "limitations": [
            "Not a universal TTP or EDR evaluator.",
            "Does not read host_group.links as operation steps.",
            "No-match results are not automatically classified as missed.",
            "Collection metadata cannot independently prove telemetry completeness.",
            "Process GUIDs are retained; correlation also requires host, time, PID and full executor command.",
        ],
        "unmatched_alert_indices": rejected,
        "results": rows,
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera", required=True, type=Path)
    parser.add_argument("--wazuh", required=True, type=Path)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--host", help="Evaluate only this CALDERA hostname")
    parser.add_argument("--window-seconds", type=int, default=120)
    args = parser.parse_args()
    if args.window_seconds <= 0:
        parser.error("--window-seconds must be positive")
    try:
        report = json.loads(args.caldera.read_text(encoding="utf-8-sig"))
        collected = json.loads(args.wazuh.read_text(encoding="utf-8-sig"))
        result = correlate(report, collected, args.agent, args.window_seconds, args.host)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        result["sources"] = [
            {"filename": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in (args.caldera, args.wazuh)
        ]
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        columns = ["operation_name", "link_id", "ability_id", "ability_name", "technique_id",
                   "host", "caldera_agent", "wazuh_agent_id", "run_utc", "caldera_pid",
                   "caldera_status", "execution", "detection", "prevention", "response",
                   "rule_ids", "matched_alert_count", "output_present"]
        with (args.out / "results.csv").open("w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(result["results"])
        for row in result["results"]:
            print(f'{row["ability_name"]}: {row["execution"]}; detection={row["detection"]}; rules={row["rule_ids"]}')
        print("Results saved to", args.out.resolve())
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"ERROR: {error}\n")

if __name__ == "__main__":
    main()
