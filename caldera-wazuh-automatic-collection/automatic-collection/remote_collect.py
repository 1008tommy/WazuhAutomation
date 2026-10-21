"""Read-only Wazuh JSON collector; executed over SSH by collect_operation.py."""
import argparse
import gzip
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

def stamp(text):
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("Timezone required")
    return dt.astimezone(timezone.utc)

def collect(root, agent, start, end, source="alerts"):
    if end <= start:
        raise ValueError("Invalid collection interval")
    if end > datetime.now(timezone.utc):
        raise ValueError("Collection end is in the future on Wazuh; check clocks")
    # Wazuh standard daily JSON archives plus current alerts.json.
    paths = [root / ("alerts.json" if source == "alerts" else "archives.json")]
    prefix = "ossec-alerts" if source == "alerts" else "ossec-archive"
    day = (start - timedelta(days=1)).date()
    last = (end + timedelta(days=1)).date()
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    while day <= last:
        base = root / str(day.year) / months[day.month-1] / f"{prefix}-{day.day:02}.json"
        paths.extend([base, Path(str(base) + ".gz")])
        day += timedelta(days=1)
    matches, seen, scanned = [], set(), []
    for path in paths:
        if not path.exists():
            continue
        # Bound current-file reads to the size at open time; avoid chasing a writer.
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rb") as stream:
            remaining = path.stat().st_size if path.suffix != ".gz" else None
            for number in range(1, 1000000000):
                raw = stream.readline() if remaining is None else stream.readline(remaining)
                if not raw:
                    break
                if remaining is not None:
                    remaining -= len(raw)
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw)
                    alert_time = stamp(record["timestamp"])
                except (ValueError, KeyError, TypeError) as error:
                    raise ValueError(f"Cannot parse {path}, line {number}; retry collection: {error}") from error
                if str(record.get("agent", {}).get("id")) != agent or not start <= alert_time <= end:
                    continue
                # Wazuh IDs can be shared by distinct events in the same second.
                # Only collapse identical records duplicated across current/rotated files.
                identity = json.dumps(record, sort_keys=True, separators=(",", ":"))
                if identity not in seen:
                    seen.add(identity)
                    matches.append(record)
        scanned.append(str(path))
    if not scanned:
        raise FileNotFoundError("No Wazuh JSON files found for requested source")
    matches.sort(key=lambda a: stamp(a["timestamp"]))
    return {
        "collection_status": "success", "agent_id": agent,
        "start": start.isoformat(), "end": end.isoformat(),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "source": str(root), "files_scanned": scanned,
        "completeness": "available_files_only; retention and telemetry health not independently verified",
        ("alert_count" if source == "alerts" else "event_count"): len(matches),
        ("alerts" if source == "alerts" else "events"): matches,
    }

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--agent", required=True)
    p.add_argument("--start", required=True)
    p.add_argument("--end", required=True)
    p.add_argument("--source", choices=["alerts", "archives"], default="alerts")
    a = p.parse_args()
    start, end = stamp(a.start), stamp(a.end)
    if (end-start).total_seconds() > 86400:
        p.error("Pilot collector supports a maximum one-day window")
    for attempt in range(3):
        try:
            result = collect(Path("/var/ossec/logs") / a.source, a.agent, start, end, a.source)
            print(json.dumps(result))
            return
        except (OSError, ValueError) as error:
            if attempt == 2:
                if a.source == "archives":
                    print(json.dumps({
                        "collection_status": "unavailable" if isinstance(error, FileNotFoundError) else "error",
                        "agent_id": a.agent, "start": start.isoformat(), "end": end.isoformat(),
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                        "source": "/var/ossec/logs/archives", "files_scanned": [],
                        "event_count": 0, "events": [], "error": str(error),
                        "completeness": "not_established; any partial scan discarded"
                    }))
                    return
                raise SystemExit(str(error))
            time.sleep(1)

if __name__ == "__main__":
    main()
