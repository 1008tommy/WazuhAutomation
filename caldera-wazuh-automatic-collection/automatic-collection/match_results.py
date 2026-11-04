"""Offline CALDERA report / Wazuh collector correlation. Python 3.10+; no dependencies."""
import argparse
import csv
import hashlib
import html
import json
import re
from datetime import datetime, timedelta, timezone
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

def output_reports_file(output, target_path):
    """Require a complete target path in successful command output."""
    if not isinstance(output, dict) or not target_path:
        return False
    stdout, target = normalize(output.get("stdout", "")), normalize(target_path)
    if not stdout or not target:
        return False
    return re.search(r'(?<![\w\\])' + re.escape(target) + r'(?![\w.\\])',
                     stdout, re.IGNORECASE) is not None

def schtasks_option(command, option):
    match = re.search(r'(?i)(?<!\S)' + re.escape(option) + r'\s+(?:"([^"]+)"|(\S+))', command)
    return (match.group(1) or match.group(2)) if match else None

def action_command(value):
    # Task Scheduler may quote the executable when it records the process event.
    return normalize(value).replace('"', '').casefold()

def scheduled_run_actions(steps):
    """Find a successful /Run and its most recent same-agent /Create /TN /TR."""
    creations = {}
    for paw, _, step in steps:
        command = step.get("command", "")
        if step.get("status") != 0 or not step.get("run") or not re.search(r'(?i)\bschtasks(?:\.exe)?\s+/create\b', command):
            continue
        name, action = schtasks_option(command, "/TN"), schtasks_option(command, "/TR")
        if name and action:
            creations.setdefault((paw, name.casefold()), []).append((time_value(step["run"]), action))
    actions = {}
    for index, (paw, _, step) in enumerate(steps):
        command = step.get("command", "")
        if step.get("status") != 0 or not step.get("run") or not re.search(r'(?i)\bschtasks(?:\.exe)?\s+/run\b', command):
            continue
        name = schtasks_option(command, "/TN")
        if not name:
            continue
        eligible = [(when, action) for when, action in creations.get((paw, name.casefold()), [])
                    if when <= time_value(step["run"])]
        if eligible:
            when = max(t for t, _ in eligible)
            latest = {action for t, action in eligible if t == when}
            if len(latest) == 1:
                actions[index] = (name, latest.pop())
    return actions

def _match_records(report, collected, agent_id, window_seconds=120, host_filter=None):
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
    task_actions = scheduled_run_actions(steps)

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
            event_id = str(system.get("eventID"))
            if event_id not in {"1", "11"} or system.get("providerName") != "Microsoft-Windows-Sysmon":
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
            if event_id == "1":
                if str(ev.get("processId")) == str(pid) and command in normalize(ev.get("commandLine", "")):
                    relation = "executor_process"
                elif str(ev.get("parentProcessId")) == str(pid) and command in normalize(ev.get("parentCommandLine", "")):
                    relation = "direct_child"
            else:
                output = step.get("output")
                output_path = output.get("stdout", "") if isinstance(output, dict) else ""
                target_path = ev.get("targetFilename", "")
                technique = step.get("attack", {}).get("technique_id")
                exact_download_path = (technique == "T1105" and output_path and target_path
                                       and normalize(output_path).casefold() == normalize(target_path).casefold())
                reported_staged_path = (technique == "T1036.003"
                                        and re.search(r'(?i)\bCopy-Item\b.*\s-Destination\b', command)
                                        and output_reports_file(output, target_path))
                if (step.get("status") == 0 and str(ev.get("processId")) == str(pid)
                    and (exact_download_path or reported_staged_path)):
                    relation = "file_created_by_executor"
            task_action = task_actions.get(si)
            if event_id == "1" and relation is None and task_action:
                _, registered_action = task_action
                parent = normalize(ev.get("parentCommandLine", ""))
                if (started <= event_time <= run_time + timedelta(seconds=5)
                    and normalize(ev.get("parentImage", "")).casefold().endswith(r"\svchost.exe")
                    and re.search(r'(?i)(?:^|\s)-s\s+Schedule(?:\s|$)', parent)
                    and action_command(ev.get("commandLine", "")) == action_command(registered_action)):
                    relation = "scheduled_task_action"
            if relation:
                if relation == "scheduled_task_action":
                    matched_on = ["agent_id", "hostname", "host_ip_if_present", "event_time_window",
                                  "registered_task_name", "registered_action_command", "task_scheduler_parent"]
                elif relation == "file_created_by_executor":
                    matched_on = ["agent_id", "hostname", "host_ip_if_present", "event_time_window",
                                  "executor_pid", "exact_output_file_path", "sysmon_file_create"]
                else:
                    matched_on = ["agent_id", "hostname", "host_ip_if_present", "event_time_window",
                                  "process_or_parent_pid", "full_executor_command"]
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
                    "event_id": event_id,
                    "command_line": ev.get("commandLine"),
                    "target_filename": ev.get("targetFilename"),
                    "matched_on": matched_on,
                    "task_name": task_action[0] if relation == "scheduled_task_action" else None,
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
            "Collection success does not verify endpoint telemetry completeness or ingestion delay.",
        ]
        if report.get("finish") is None:
            notes.append("Operation finish is null; do not describe the operation as completed.")
        if "output" not in step:
            notes.append("Step output is absent; intended procedure outcome was not independently verified here.")
        if not in_range:
            notes.append("Step run time is missing or outside the collection window.")
        if not valid_pid(step.get("pid")):
            notes.append("Missing usable executor PID; this matcher cannot correlate the step.")
        if ambiguous:
            notes.append("At least one alert also matches another step; review required.")
        if any(e["relation"] == "file_created_by_executor" for e in evidence):
            notes.append("Matched file creation confirms the reported file was written by the executor; it does not prove technique-specific recognition.")
            if step.get("attack", {}).get("technique_id") == "T1105":
                notes.append("File creation alone does not prove the transfer source.")
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
            "rule_ids": ";".join(sorted({e["rule_id"] for e in unique})),
            "matched_alert_count": len(unique),
            "output_present": "output" in step,
            "step_output": step.get("output"),
            "evidence": evidence,
            "notes": notes,
        })
    return {
        "schema_version": "0.1",
        "matcher_scope": "Sysmon process creation for executor, direct child, or scheduled-task action, plus reported T1105 and T1036.003 file creation; offline prototype",
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

def correlate(report, collected, agent_id, window_seconds=120, host_filter=None, archives=None):
    """Match each source independently; an archived rule field is never an alert."""
    result = _match_records(report, collected, agent_id, window_seconds, host_filter)
    archive_result = None
    archive_status = "not_requested" if archives is None else archives.get("collection_status")
    if archives is not None:
        if str(archives.get("agent_id")) != agent_id:
            raise ValueError("Archive agent differs from requested agent")
        if any(time_value(archives[k]) != time_value(collected[k]) for k in ("start", "end")):
            raise ValueError("Alert and archive windows differ")
        if archive_status not in {"success", "unavailable", "error"}:
            raise ValueError("Invalid archive collection status")
        if archive_status == "success":
            adapted = dict(archives, alerts=archives.get("events"), alert_count=archives.get("event_count"))
            archive_result = _match_records(report, adapted, agent_id, window_seconds, host_filter)
    result["schema_version"] = "0.4"
    result["matcher_scope"] = "Sysmon process creation for executor, direct child, or scheduled-task action, plus reported T1105 and T1036.003 file creation; alerts and archives matched separately"
    result["archive_collection_status"] = archive_status
    result["archive_collection_error"] = archives.get("error") if archives else None
    result["unmatched_archive_indices"] = archive_result["unmatched_alert_indices"] if archive_result else []
    result["limitations"].extend([
        "Related alerts do not establish technique-specific recognition.",
        "Archive matches confirm only the matched process or file-creation events, not complete procedure telemetry.",
        "Scheduled-task action matching requires a successful same-agent task creation, a successful /Run step, an exact action command, and the Task Scheduler service parent.",
        "Grandchildren and other event types are outside this matcher scope.",
        "Archive and alert counts overlap and must not be added as unique event counts."
    ])
    for index, row in enumerate(result["results"]):
        evidence = []
        if archive_result:
            for original in archive_result["results"][index]["evidence"]:
                item = dict(original)
                item["event_index"] = item.pop("alert_index")
                item["record_id"] = item.pop("alert_id")
                item["received_time_utc"] = item.pop("alert_time_utc")
                item.pop("rule_id", None)
                item.pop("rule_description", None)
                evidence.append(item)
        unique = [e for e in evidence if not e["ambiguous"]]
        sources = []
        if row["matched_alert_count"]:
            sources.append("alerts")
        if unique:
            sources.append("archives")
        ambiguous = any(e["ambiguous"] for e in evidence + row["evidence"])
        row["event_collection"] = "confirmed" if sources else "ambiguous_review" if ambiguous else "not_confirmed"
        row["collection_evidence_sources"] = ";".join(sources)
        row["archive_collection_status"] = archive_status
        row["matched_archive_event_count"] = len(unique)
        row["archive_evidence"] = evidence
        row["alert_interpretation"] = "related_alert_observed" if row["matched_alert_count"] else "no_unique_alert_match"
        row["notes"].append("Event collection and alert detection are evaluated separately.")
        if archive_status != "success":
            row["notes"].append("Archive evidence unavailable: " + str(archive_status))
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caldera", required=True, type=Path)
    parser.add_argument("--wazuh", required=True, type=Path)
    parser.add_argument("--archives", type=Path, help="Optional raw-event export from remote collector")
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
        archives = json.loads(args.archives.read_text(encoding="utf-8-sig")) if args.archives else None
        result = correlate(report, collected, args.agent, args.window_seconds, args.host, archives)
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        result["sources"] = [
            {"filename": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in ([args.caldera, args.wazuh] + ([args.archives] if args.archives else []))
        ]
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        columns = ["operation_name", "link_id", "ability_id", "ability_name", "technique_id",
                   "host", "caldera_agent", "wazuh_agent_id", "run_utc", "caldera_pid",
                   "caldera_status", "execution", "detection",
                   "rule_ids", "matched_alert_count", "output_present", "event_collection",
                   "collection_evidence_sources", "archive_collection_status",
                   "matched_archive_event_count", "alert_interpretation"]
        with (args.out / "results.csv").open("w", newline="", encoding="utf-8-sig") as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(result["results"])
        for row in result["results"]:
            print(f'{row["ability_name"]}: {row["execution"]}; collection={row["event_collection"]}; detection={row["detection"]}; rules={row["rule_ids"]}')
        print("Results saved to", args.out.resolve())
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"ERROR: {error}\n")

if __name__ == "__main__":
    main()
