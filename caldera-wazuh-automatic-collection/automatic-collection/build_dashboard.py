"""Build a self-contained Wazuh BAS dashboard from saved runs. Python 3.11+.

Reads every <runs>/*/results/results.json (plus the sibling run-metadata.json) and writes:
  <out>/index.html            one self-contained page (inline CSS/JS, data embedded, no network)
  <out>/results-combined.csv  every scored row across all runs
  <out>/navigator-wazuh.json  an ATT&CK Navigator layer (enterprise-attack)

The same page is served live by serve_dashboard.py, where the Launch view can start scenarios;
opened as a file it stays a static, air-gapped report and the Launch view shows the exact command.
The page is vanilla JS with no external fetches, so it opens with a double-click offline. PyYAML
(in requirements.txt) reads each scenario's ATT&CK tactics from the CALDERA adversary exports.
"""
import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml   # only the scenario tactics need it; the rest of the report builds without it
except ImportError:
    yaml = None

HERE = Path(__file__).resolve().parent
EXPORTS = HERE.parents[1] / "Scenarios"   # CALDERA adversary exports, one YAML per scenario

NAV_SCORE = {"prevented": 100, "detected_labelled": 100, "detected_unlabelled": 75,
             "telemetry_only": 40, "missed": 0, "not_assessable": 0}
OUTCOME_ORDER = ["prevented", "detected_labelled", "detected_unlabelled",
                 "telemetry_only", "missed", "not_assessable"]
TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution",
                "persistence", "privilege-escalation", "defense-evasion", "credential-access",
                "discovery", "lateral-movement", "collection", "command-and-control",
                "exfiltration", "impact"]


def norm_tactic(value):
    return (value or "").strip().lower().replace(" ", "-").replace("_", "-")


def time_value(text):
    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def time_to_alert_seconds(row):
    best = None
    for ev in row.get("evidence", []):
        alert_t, event_t = time_value(ev.get("alert_time_utc")), time_value(ev.get("event_time_utc"))
        if alert_t and event_t:
            delta = (alert_t - event_t).total_seconds()
            best = delta if best is None else min(best, delta)
    return best


def load_runs(runs_dir):
    runs = []
    for results_file in sorted(Path(runs_dir).glob("*/results/results.json")):
        run_dir = results_file.parent.parent
        try:
            result = json.loads(results_file.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as error:
            print(f"Skipping {results_file}: {error}", file=sys.stderr)
            continue
        meta = {}
        meta_file = run_dir / "run-metadata.json"
        if meta_file.is_file():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError):
                meta = {}
        runs.append({"run_id": run_dir.name, "result": result, "meta": meta})
    return runs


def load_tactics(exports_dir):
    """Map each adversary ID to its ATT&CK tactics, read from the CALDERA adversary exports.

    Tactics follow the step order in atomic_ordering, and a tactic used by several steps appears
    once, so Thief-Lab gives ["collection", "exfiltration"]."""
    if yaml is None:
        print("PyYAML is not installed, so the scenario cards show no tactics: "
              "python -m pip install -r requirements.txt", file=sys.stderr)
        return {}
    tactics = {}
    for path in sorted(Path(exports_dir).glob("*.yaml")):
        try:
            export = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
            abilities = export["abilities"]
            steps = [norm_tactic(abilities[ability_id]["tactic"]) for ability_id in export["atomic_ordering"]]
            tactics[export["id"]] = list(dict.fromkeys(t for t in steps if t))
        except (OSError, yaml.YAMLError, KeyError, TypeError) as error:
            print(f"Skipping {path.name}: {error!r}", file=sys.stderr)
    return tactics


def load_scenarios(scenarios_dir, exports_dir=EXPORTS):
    tactics = load_tactics(exports_dir)
    specs = []
    for path in sorted(Path(scenarios_dir).glob("*.json")):
        try:
            spec = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        specs.append({"scenario": spec.get("scenario"), "name": spec.get("name"),
                      "adversary_id": spec.get("adversary_id"),
                      "tactics": tactics.get(spec.get("adversary_id"), []),
                      "expected_techniques": spec.get("expected_techniques", []),
                      "file": f"scenarios/{path.name}"})
    return specs


def build_data(runs, scenarios):
    rows, run_summaries = [], []
    for run in runs:
        result, meta = run["result"], run["meta"]
        first = result.get("results", [{}])
        operation = first[0].get("operation_name") if first else None
        scenario = meta.get("scenario") or operation or run["run_id"]
        for row in result.get("results", []):
            flat = dict(row)
            flat["run_id"] = run["run_id"]
            flat["scenario"] = scenario
            flat["tactic_norm"] = norm_tactic(row.get("tactic"))
            flat["time_to_alert_s"] = time_to_alert_seconds(row)
            rows.append(flat)
        window = result.get("collection_window", {})
        run_summaries.append({
            "run_id": run["run_id"], "scenario": scenario, "operation": operation,
            "window_start": window.get("start") or meta.get("window_start"),
            "window_end": window.get("end") or meta.get("window_end"),
            "agent_watermark": meta.get("agent_watermark"),
            "archive_watermark": meta.get("archive_watermark"),
            "collection_stop_reason": meta.get("collection_stop_reason"),
            "collection_quiet_seconds": meta.get("collection_quiet_seconds"),
            "collection_complete": meta.get("collection_complete"),
            "queue_alert_rule_ids": meta.get("queue_alert_rule_ids", []),
            "archive_collection_status": result.get("archive_collection_status") or meta.get("archive_collection_status"),
            "harness_rule_ids": result.get("harness_rule_ids", []),
            "defender_state": meta.get("defender_state", "loaded, inert"),
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "control": "Wazuh 4.14.x",
        "rows": rows, "runs": run_summaries, "scenarios": scenarios,
        "outcome_order": OUTCOME_ORDER, "tactic_order": TACTIC_ORDER,
    }


def combined_csv(rows, path):
    columns = ["run_id", "scenario", "technique_id", "technique_name", "tactic", "ability_name",
               "outcome", "technique_match", "execution", "caldera_status", "rule_ids",
               "max_rule_level", "alert_mitre_ids", "response", "time_to_alert_s",
               "collection_complete", "harness_alert_rule_ids", "run_utc"]
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def navigator_layer(rows):
    best = {}
    for row in rows:
        tech = row.get("technique_id")
        if not tech:
            continue
        score = NAV_SCORE.get(row.get("outcome"), 0)
        if tech not in best or score > best[tech]["score"]:
            best[tech] = {"score": score, "rules": row.get("rule_ids", ""), "outcome": row.get("outcome")}
    techniques = [{"techniqueID": tech, "score": info["score"], "enabled": True,
                   "comment": f'{info["outcome"]}; rules: {info["rules"] or "none"}'}
                  for tech, info in sorted(best.items())]
    return {"name": "Wazuh BAS coverage", "domain": "enterprise-attack",
            "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
            "description": "Outcome per tested technique. 100 labelled/prevented, 75 unlabelled, 40 telemetry only, 0 missed.",
            "gradient": {"colors": ["#d03b3b", "#f0efec", "#2a78d6"], "minValue": 0, "maxValue": 100},
            "techniques": techniques}


def render_html(data, served=False):
    payload = dict(data, served=served)
    # Escape "<" so evidence text such as "</script>" from an endpoint cannot end the script block.
    return HTML_TEMPLATE.replace("/*__DATA__*/null", json.dumps(payload).replace("<", "\\u003c"))


def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11+ required.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, default=Path("runs"))
    parser.add_argument("--scenarios", type=Path, default=HERE / "scenarios")
    parser.add_argument("--out", type=Path, default=Path("dashboard"))
    args = parser.parse_args()
    runs = load_runs(args.runs)
    scenarios = load_scenarios(args.scenarios)
    data = build_data(runs, scenarios)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "index.html").write_text(render_html(data), encoding="utf-8")
    combined_csv(data["rows"], args.out / "results-combined.csv")
    (args.out / "navigator-wazuh.json").write_text(json.dumps(navigator_layer(data["rows"]), indent=2), encoding="utf-8")
    print(f"Dashboard: {(args.out / 'index.html').resolve()}")
    print(f"Runs: {len(runs)}  Scored rows: {len(data['rows'])}  Scenarios: {len(scenarios)}")


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Control Validation</title>
<style>
:root{
  color-scheme:light;
  --page:#ffffff; --side:#fdf2f8; --side-line:#f3e1ea; --wash:#fce7f3;
  --sunken:#faf8f9; --line:#ece7ea; --line2:#f3f0f2;
  --ink:#1f2937; --ink2:#4b5563; --muted:#6b7280;
  --accent:#c0267f; --accent-hover:#a51f6c; --accent-ink:#9d174d;
  /* Outcome colours, chosen for colour-blind readers: blue means Wazuh raised an alert (darker is
     stronger), amber a log but no alert, red missed, grey not assessable. Red against green, the
     pair red-green colour blindness merges, is gone. Every pair of the six stays apart under
     protan, deutan and tritan simulation (dataviz check, all pairs, worst dE 9.1, target 8) and
     under normal vision (worst dE 17.6, floor 15). Each outcome also has its own glyph and a text
     label, so colour is never the only cue. Pink is chrome only and never marks data. */
  --prevented:#104281; --detected_labelled:#2a78d6; --detected_unlabelled:#86b6ef;
  --telemetry_only:#eda100; --missed:#d03b3b; --not_assessable:#898781;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--page);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
button,select,input{font:inherit}
.app{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}

/* sidebar */
.side{background:var(--side);border-right:1px solid var(--side-line);padding:0 0 18px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.brand{padding:24px 22px 20px;border-bottom:1px solid var(--side-line)}
.bname{font-weight:650;font-size:16px;line-height:1.25;letter-spacing:-.015em;color:var(--ink)}
.ctx{margin:0;padding:16px 22px;border-bottom:1px solid var(--side-line);display:grid;grid-template-columns:max-content minmax(0,1fr);gap:6px 14px;font-size:12.5px}
.ctx dt{color:var(--muted)}
.ctx dd{margin:0;color:var(--ink);font-weight:500;overflow-wrap:anywhere}
.nav{display:flex;flex-direction:column;gap:2px;padding:16px 12px 0}
.nav a{position:relative;display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:7px;color:var(--ink2);text-decoration:none;font-weight:500}
.nav a svg{flex:none;color:var(--muted)}
.nav a:hover{background:var(--wash)}
.nav a.on{background:var(--wash);color:var(--accent-ink)}
.nav a.on svg{color:var(--accent)}
.nav a.on::before{content:"";position:absolute;left:-12px;top:7px;bottom:7px;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
.live{width:7px;height:7px;border-radius:50%;background:var(--accent);margin-left:auto}
.side-foot{margin-top:auto;padding:14px 22px 0;border-top:1px solid var(--side-line);font-size:12px;color:var(--muted);display:flex;flex-direction:column;gap:3px}
.side-foot b{font-weight:600;color:var(--ink2)}

/* page */
.main{padding:28px 36px 64px;min-width:0}
.inner{max-width:1240px}
.view{display:none}
.view.on{display:block}
.phead{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:16px}
h1{font-size:21px;line-height:1.25;margin:0;font-weight:600;letter-spacing:-.015em}
.sub{margin:4px 0 0;color:var(--muted);font-size:13px}
.actions{display:flex;gap:8px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px}
select,input{font-size:13px;color:var(--ink2);background:#fff;border:1px solid var(--line);border-radius:7px;padding:7px 10px}
input[type=search]{min-width:250px}
#fTechnique{max-width:min(100%,360px)}
.filter-note{margin:-10px 0 18px}
select:focus-visible,input:focus-visible,button:focus-visible,a:focus-visible,.seg:focus-visible,tr.row:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.btn{font-size:13px;font-weight:500;border-radius:7px;padding:7px 14px;cursor:pointer;border:1px solid var(--line);background:#fff;color:var(--ink2)}
.btn:hover{border-color:#d8cfd4;color:var(--ink)}
.btn.pri{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.pri:hover{background:var(--accent-hover);border-color:var(--accent-hover)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.panel{border:1px solid var(--line);border-radius:10px;background:#fff;padding:16px 18px;margin-bottom:18px}
.panel.flush{padding:0}
.ph{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:12px}
.panel.flush .ph{padding:16px 18px 4px;margin:0}
h2{font-size:14px;font-weight:600;margin:0}
.hint,.small,.muted{font-size:12px;color:var(--muted)}
.strong{font-weight:600}
.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12px;color:var(--ink2);font-variant-numeric:tabular-nums}
.badge{display:inline-flex;flex:none}
.badge svg{display:block}
.chip{display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.ico{display:inline-flex;flex:none}

/* stat tiles */
.kpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1px;background:var(--line2);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:18px}
.kpi{background:#fff;padding:14px 16px 13px}
.kpi .l{font-size:12px;color:var(--muted)}
.kpi .n{font-size:24px;font-weight:600;letter-spacing:-.02em;line-height:1.25;margin-top:4px}
.kpi .n small{font-size:13px;color:var(--muted);font-weight:500;letter-spacing:0}
.kpi .s{font-size:12px;color:var(--ink2);margin-top:3px}

/* segmented bars: 2px surface gaps, labels only where they fit */
.split{display:flex;gap:2px;height:28px}
.thin{display:flex;gap:2px;height:8px}
.seg{flex:1 1 0;min-width:4px;border-radius:4px;cursor:default}
.split .seg{display:flex;align-items:center;gap:6px;padding:0 8px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.split .seg.dark{color:#0b0b0b}
.seg.none{background:var(--line2)}
.legend{display:flex;flex-wrap:wrap;gap:10px 22px;margin-top:14px;font-size:13px;color:var(--ink2)}
.legend .li{display:inline-flex;align-items:center;gap:8px}

/* tactic matrix */
.matrix{display:flex;gap:10px;overflow-x:auto;padding-bottom:6px;align-items:flex-start}
.tcol{flex:1 0 212px;max-width:300px;border:1px solid var(--line);border-radius:9px;overflow:hidden;background:#fff}
.tcol .th{padding:11px 12px 12px}
.tcol .tt{font-size:12.5px;font-weight:600}
.tcol .ts{font-size:11.5px;color:var(--muted);margin:1px 0 8px}
.untested{margin:10px 0 0;font-size:12px;color:var(--muted)}
.untested:empty{display:none}
.tcard{display:block;width:100%;text-align:left;background:#fff;border:0;border-top:1px solid var(--line2);padding:9px 12px 10px;cursor:pointer;color:inherit}
.tcard:hover{background:var(--sunken)}
.tid{display:flex;align-items:center;gap:7px;font-weight:600;font-size:12.5px}
.tid .more{display:inline-flex;gap:3px;margin-left:auto}
.tname{font-size:12px;color:var(--ink2);margin:2px 0 0 23px;line-height:1.35}
.tmeta{font-size:11.5px;color:var(--muted);margin:4px 0 0 23px;line-height:1.35}

/* steps table */
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px 14px;border-top:1px solid var(--line2);vertical-align:top}
thead th{border-top:0;font-size:12px;font-weight:500;color:var(--muted);white-space:nowrap;cursor:pointer;user-select:none;padding-top:12px}
thead th:hover{color:var(--ink)}
th .arr{color:var(--accent-ink)}
tr.row{cursor:pointer}
tr.row:hover,tr.row.open{background:var(--sunken)}
tr.det td{background:var(--sunken);border-top:0;padding:4px 14px 16px}
td.empty{color:var(--muted);text-align:center;padding:22px}
td.time{white-space:nowrap}
td.time,td.num{font-variant-numeric:tabular-nums;color:var(--ink2)}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:3px 14px;margin:0 0 10px;font-size:12.5px}
.facts dt{color:var(--muted)}
.facts dd{margin:0;color:var(--ink2)}
.evid{white-space:pre-wrap;font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12px;color:var(--ink2);margin:0;background:#fff;border:1px solid var(--line2);border-radius:7px;padding:10px 12px}

/* gaps and evidence collection */
.two{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:18px;align-items:start}
.two .panel{margin-bottom:0}
.item{padding:11px 0;border-top:1px solid var(--line2)}
.item:first-child{border-top:0;padding-top:0}
.itop{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.itext{margin:5px 0 0;font-size:12.5px;color:var(--ink2)}
.item .facts{margin:9px 0 6px}
.health-details{margin-top:10px;font-size:12.5px;color:var(--ink2)}
.health-details summary{cursor:pointer}
.health-details .facts{margin:10px 0 6px}

/* run view */
.crow{display:grid;grid-template-columns:18px 130px minmax(0,1fr);gap:10px;align-items:start;padding:9px 0;border-top:1px solid var(--line2);font-size:13px}
.crow:first-child{border-top:0;padding-top:2px}
.crow .ico{margin-top:2px}
.crow .cname{font-weight:500}
.crow .cdetail{color:var(--ink2);overflow-wrap:anywhere}
.scn{display:grid;grid-template-columns:repeat(auto-fill,minmax(264px,1fr));gap:12px}
.scard{border:1px solid var(--line);border-radius:9px;padding:14px 15px;display:flex;flex-direction:column;gap:9px}
.scard h3{margin:0;font-size:14px;font-weight:600}
.scard .sid{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:11.5px;color:var(--muted);margin-top:-6px}
.tags{display:flex;flex-wrap:wrap;gap:5px}
.tag{font-size:12px;font-weight:500;color:var(--ink2);background:var(--line2);border-radius:5px;padding:2px 8px}
.pills{display:flex;flex-wrap:wrap;gap:5px}
.pill{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:11.5px;color:var(--ink2);border:1px solid var(--line);border-radius:5px;padding:0 6px}
.last{display:flex;flex-direction:column;gap:6px}
.scard .act{margin-top:auto;padding-top:2px}
.jobstate{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--ink2)}
#log{margin:0;background:var(--sunken);border:1px solid var(--line2);border-radius:8px;padding:12px 14px;max-height:440px;overflow:auto;font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12.5px;line-height:1.55;color:var(--ink2);white-space:pre-wrap}
.lognote{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px;font-size:13px;color:var(--ink2)}
.lognote:empty{display:none}
.guard{font-size:12px;color:var(--muted);margin:0}

#tip{position:fixed;z-index:30;pointer-events:none;background:#fff;border:1px solid var(--line);border-radius:7px;box-shadow:0 4px 14px rgba(31,41,55,.08);padding:6px 10px;font-size:12px;color:var(--ink2);max-width:280px}
#tip b{color:var(--ink);font-size:13px;margin-right:4px}

@media (max-width:1180px){.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:860px){
  .app{grid-template-columns:minmax(0,1fr)}
  .side{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center;gap:10px 18px;padding:12px 16px;border-right:0;border-bottom:1px solid var(--side-line)}
  .brand{padding:0;border:0}
  .ctx{display:none}
  .nav{flex-direction:row;flex-wrap:wrap;padding:0}
  .nav a.on::before{display:none}
  .side-foot{display:none}
  .main{padding:20px 16px 48px}
  .two{grid-template-columns:1fr}
  .kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
  input[type=search]{min-width:0;flex:1 1 200px}
  .crow{grid-template-columns:18px minmax(0,1fr)}
  .crow .cdetail{grid-column:2}
}
</style>
</head>
<body>
<div class="app">
  <aside class="side">
    <div class="brand"><div class="bname">Security Control<br>Validation</div></div>
    <dl class="ctx" id="ctx"></dl>
    <nav class="nav" aria-label="Views">
      <a href="#results" data-v="results"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M3 13V8M8 13V3M13 13V6"/></svg>Results</a>
      <a href="#run" data-v="run"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><circle cx="8" cy="8" r="6.2"/><path d="M6.7 5.6l3.6 2.4-3.6 2.4z" fill="currentColor"/></svg>Run a scenario<span class="live" id="liveDot" hidden title="A scenario is running"></span></a>
    </nav>
    <div class="side-foot" id="sideFoot"></div>
  </aside>

  <main class="main"><div class="inner">
    <section class="view" id="view-results" aria-labelledby="h-results">
      <div class="phead">
        <div><h1 id="h-results">Results</h1></div>
        <div class="actions"><button class="btn" id="dlCsv" type="button">Export CSV</button><button class="btn" id="dlNav" type="button">Navigator layer</button></div>
      </div>
      <div class="filters" role="group" aria-label="Filters">
        <select id="fRun" aria-label="Run"></select><select id="fScenario" aria-label="Scenario"></select>
        <select id="fTactic" aria-label="ATT&amp;CK tactic"></select><select id="fTechnique" aria-label="ATT&amp;CK technique"></select>
        <select id="fOutcome" aria-label="Outcome"></select>
        <input id="search" type="search" placeholder="Search ability, technique or rule" aria-label="Search">
        <button class="btn" id="clearFilters" type="button">Clear filters</button>
      </div>
      <p class="small filter-note">ATT&amp;CK filters use the technique assigned to each CALDERA step; Wazuh alert tags are shown separately.</p>
      <div class="kpis" id="kpis"></div>
      <section class="panel">
        <div class="ph"><h2>Outcome split</h2><span class="hint" id="splitHint"></span></div>
        <div id="split"></div><div class="legend" id="legend"></div>
      </section>
      <section class="panel">
        <div class="ph"><h2>ATT&amp;CK coverage by tactic</h2><span class="hint">Select a technique to filter the steps</span></div>
        <div class="matrix" id="map"></div><p class="untested" id="untested"></p>
      </section>
      <section class="panel flush" id="steps">
        <div class="ph"><h2>Steps</h2><span class="hint" id="tblHint"></span></div>
        <div class="tablewrap"><table><thead><tr id="thead"></tr></thead><tbody id="tbody"></tbody></table></div>
      </section>
      <div class="two">
        <section class="panel"><div class="ph"><h2>Detection gaps</h2></div><div id="gaps"></div></section>
        <section class="panel"><div class="ph"><h2>Evidence collection</h2></div><div id="health"></div></section>
      </div>
    </section>

    <section class="view" id="view-run" aria-labelledby="h-run">
      <div class="phead"><div><h1 id="h-run">Run a scenario</h1><p class="sub" id="runMode"></p></div></div>
      <section class="panel">
        <div class="ph"><h2>Lab status</h2><span class="hint"><span id="preTime"></span> <button class="btn" id="recheck" type="button">Check again</button></span></div>
        <div id="pre"></div>
      </section>
      <section class="panel">
        <div class="ph"><h2>Scenarios</h2><span class="hint">One scenario at a time</span></div>
        <div class="scn" id="scn"></div>
      </section>
      <section class="panel">
        <div class="ph"><h2>Activity</h2><span class="jobstate" id="jobState"></span></div>
        <pre id="log" hidden></pre>
        <div class="lognote" id="logNote"></div>
      </section>
      <p class="guard">Guardrails: only group <b>red</b> on <b>WIN11-TEST01</b>, the plain-text obfuscator, and cleanup verified after every run. Revert the VM snapshot if cleanup fails.</p>
    </section>
  </div></main>
</div>
<div id="tip" role="tooltip" hidden></div>
<script>
const DATA = /*__DATA__*/null;
const OUT = DATA.outcome_order;
const SERVED = !!DATA.served;
const LABELS = {prevented:"Prevented", detected_labelled:"Detected (labelled)", detected_unlabelled:"Detected (unlabelled)",
  telemetry_only:"Telemetry only", missed:"Missed", not_assessable:"Not assessable"};
const ADVICE = {
  detected_unlabelled: r => `An alert fired, but its ATT&CK tag is ${r.alert_mitre_ids || "empty"} rather than ${r.technique_id}. Review the rule's tag.`,
  telemetry_only: () => "The event reached Wazuh but no rule fired. Candidate for a custom rule on the command line or script block.",
  missed: () => "Nothing reached Wazuh although collection was complete: a logging or visibility gap.",
  not_assessable: () => "Not assessable: check the executor PID, the time window and collection completeness.",
};
const ICONS = {
  ok: '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="var(--detected_labelled)"/><path d="M4.8 8.3l2.1 2.1 4.3-4.6" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  bad: '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="var(--missed)"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>',
  warn: '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5l6.8 12.3H1.2z" fill="var(--telemetry_only)" stroke="var(--telemetry_only)" stroke-linejoin="round"/><path d="M8 6v3.7" stroke="#0b0b0b" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="11.8" r=".95" fill="#0b0b0b"/></svg>',
  wait: '<svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.3" fill="none" stroke="var(--not_assessable)" stroke-width="1.6"/><circle cx="8" cy="8" r="2" fill="var(--not_assessable)"/></svg>',
};
const $ = id => document.getElementById(id);
function el(tag, cls, text){ const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; }
const pct = (n, d) => d ? Math.round(100 * n / d) : 0;
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const fmtTime = s => { if (!s) return ""; const d = new Date(s); return isNaN(d) ? String(s) : d.toLocaleString([], {dateStyle: "medium", timeStyle: "short"}); };
const fmtSec = s => { if (!s) return "?"; const d = new Date(s); return isNaN(d) ? String(s) : d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"}); };
const fmtStamp = s => { const m = /^(\d{4})(\d\d)(\d\d)T(\d\d)(\d\d)(\d\d)Z$/.exec(s || ""); return m ? fmtTime(new Date(Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6])).toISOString()) : (s || ""); };
const tta = v => v == null ? "" : (v >= 90 ? Math.round(v / 60) + " min" : Math.round(v) + " s");
const fmtShort = s => { if (!s) return ""; const d = new Date(s); return isNaN(d) ? String(s) : d.toLocaleString([], {day: "numeric", month: "short", hour: "2-digit", minute: "2-digit"}); };
const isDetected = o => o === "detected_labelled" || o === "detected_unlabelled";
const TACTICS = {"reconnaissance": "Reconnaissance", "resource-development": "Resource Development", "initial-access": "Initial Access",
  "execution": "Execution", "persistence": "Persistence", "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access", "discovery": "Discovery", "lateral-movement": "Lateral Movement", "collection": "Collection",
  "command-and-control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact"};
const tacticName = t => TACTICS[t] || String(t || "unknown").replace(/-/g, " ");
/* operation names are "<scenario>-<UTC stamp>"; show the scenario's own name */
const specFor = op => (DATA.scenarios || []).find(sp => sp.scenario && String(op || "").startsWith(sp.scenario + "-"));
const scenarioName = op => { const sp = specFor(op); return sp ? (sp.name || sp.scenario) : String(op || ""); };
const runLabel = id => { const m = /^(\d{8}T\d{6}Z)-(\w+)$/.exec(id || ""); return m ? `${fmtStamp(m[1])} · ${m[2]}` : String(id || ""); };
/* Every outcome has a glyph as well as a colour, so no outcome depends on colour alone:
   bar = prevented, tick = labelled, ! = unlabelled, eye = telemetry only, cross = missed, ? = not assessable. */
const GLYPHS = {
  prevented: '<path d="M4.6 8h6.8"/>',
  detected_labelled: '<path d="M4.7 8.3l2.2 2.2 4.4-4.7"/>',
  detected_unlabelled: '<path d="M8 4.5v4.2"/><circle cx="8" cy="11.5" r=".4"/>',
  telemetry_only: '<path d="M3.2 8c1.3-2 2.9-3 4.8-3s3.5 1 4.8 3c-1.3 2-2.9 3-4.8 3S4.5 10 3.2 8z" stroke-width="1.5"/><circle cx="8" cy="8" r=".6"/>',
  missed: '<path d="M5.5 5.5l5 5M10.5 5.5l-5 5"/>',
  not_assessable: '<path d="M6.1 6.4a1.9 1.9 0 1 1 2.8 1.7c-.6.3-.9.7-.9 1.3v.3"/><circle cx="8" cy="11.7" r=".4"/>',
};
const DARK_INK = ["detected_unlabelled", "telemetry_only"];   // the two light fills take a near-black glyph
function badge(o, size, bare){
  const k = GLYPHS[o] ? o : "not_assessable", ink = DARK_INK.includes(k) ? "#0b0b0b" : "#fff", s = el("span", "badge");
  const disc = bare ? "" : `<circle cx="8" cy="8" r="8" fill="var(--${k})"/>`;
  s.innerHTML = `<svg width="${size}" height="${size}" viewBox="0 0 16 16" aria-hidden="true">${disc}<g fill="none" stroke="${ink}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${GLYPHS[k]}</g></svg>`;
  return s;
}
function chip(o){ const c = el("span", "chip"); c.append(badge(o, 16), document.createTextNode(LABELS[o] || o)); return c; }
function icon(kind){ const s = el("span", "ico"); s.innerHTML = ICONS[kind]; return s; }

/* one tooltip for every bar segment; labels go in as text, never as markup */
const tip = $("tip");
function attachTip(node, value, label){
  node.tabIndex = 0;
  node.setAttribute("aria-label", `${label}: ${value}`);
  const place = e => {
    const r = node.getBoundingClientRect(), x = e && e.clientX ? e.clientX : r.left + r.width / 2;
    tip.style.left = Math.max(8, Math.min(innerWidth - tip.offsetWidth - 8, x - tip.offsetWidth / 2)) + "px";
    tip.style.top = Math.max(8, r.top - tip.offsetHeight - 8) + "px";
  };
  const show = e => { tip.replaceChildren(el("b", null, value), document.createTextNode(label)); tip.hidden = false; place(e); };
  node.addEventListener("pointerenter", show); node.addEventListener("pointermove", place);
  node.addEventListener("focus", () => show()); ["pointerleave", "blur"].forEach(k => node.addEventListener(k, () => { tip.hidden = true; }));
}
function segBar(rows, tall){
  const bar = el("div", tall ? "split" : "thin"), n = rows.length;
  if (!n) { bar.append(el("div", "seg none")); return bar; }
  OUT.forEach(o => {
    const k = rows.filter(r => r.outcome === o).length;
    if (!k) return;
    const s = el("div", "seg"); s.style.flexGrow = k; s.style.background = `var(--${o})`;
    if (tall) { s.append(badge(o, 14, true), el("span", "pc", pct(k, n) + "%")); if (DARK_INK.includes(o)) s.classList.add("dark"); }
    attachTip(s, pct(k, n) + "%", `${LABELS[o]}, ${k} of ${n}`);
    bar.append(s);
  });
  return bar;
}
/* a segment too narrow for its label drops the share first, then the glyph */
function fitLabels(root){ requestAnimationFrame(() => root.querySelectorAll(".split .seg").forEach(s => {
  [".pc", ".badge"].forEach(part => { if (s.scrollWidth > s.clientWidth + 1) s.querySelector(part)?.remove(); });
})); }

/* results view */
const state = {run: "", scenario: "", tactic: "", technique: "", outcome: "", search: "", sort: "run_utc", dir: -1};
function filtered(){
  const q = state.search.toLowerCase();
  return DATA.rows.filter(r => (!state.run || r.run_id === state.run) && (!state.scenario || r.scenario === state.scenario)
    && (!state.tactic || r.tactic_norm === state.tactic) && (!state.technique || r.technique_id === state.technique)
    && (!state.outcome || r.outcome === state.outcome)
    && (!q || [r.ability_name, r.technique_id, r.technique_name, r.rule_ids, r.alert_mitre_ids].join(" ").toLowerCase().includes(q)));
}
function renderKpis(rows){
  const n = rows.length, c = o => rows.filter(r => r.outcome === o).length;
  const lab = c("detected_labelled"), det = lab + c("detected_unlabelled"), vis = det + c("telemetry_only"), prev = c("prevented");
  const times = rows.map(r => r.time_to_alert_s).filter(v => v != null).sort((a, b) => a - b);
  const med = times.length ? times[Math.floor((times.length - 1) / 2)] : null;
  const runs = new Set(rows.map(r => r.run_id)).size;
  const tiles = [
    ["Steps scored", String(n), "", plural(runs, "run")],
    ["Detected", String(det), `/ ${n}`, `${pct(det, n)}% raised an alert`],
    ["Correct technique", String(lab), `/ ${n}`, `${pct(lab, n)}% tagged as tested`],
    ["Visible in Wazuh", String(vis), `/ ${n}`, `${pct(vis, n)}% alert or log`],
    ["Prevented", String(prev), `/ ${n}`, "Wazuh is detection-only"],
    ["Median time to alert", med != null ? tta(med) : "n/a", "", med != null && med > 120 ? "late: was the manager up?" : "event to alert"],
  ];
  const w = $("kpis"); w.replaceChildren();
  tiles.forEach(([label, big, of, sub]) => {
    const t = el("div", "kpi"), v = el("div", "n", big);
    if (of) v.append(el("small", null, " " + of));
    t.append(el("div", "l", label), v, el("div", "s", sub)); w.append(t);
  });
}
function renderSplit(rows){
  const box = $("split"); box.replaceChildren(segBar(rows, true)); fitLabels(box);
  const lg = $("legend"); lg.replaceChildren();
  OUT.forEach(o => { const i = el("span", "li"); i.append(badge(o, 20), document.createTextNode(LABELS[o])); lg.append(i); });
  $("splitHint").textContent = n_steps(rows);
}
const n_steps = rows => rows.length ? plural(rows.length, "step") : "No steps";
function renderMatrix(rows){
  const m = $("map"); m.replaceChildren();
  const by = {};
  rows.forEach(r => (by[r.tactic_norm] = by[r.tactic_norm] || []).push(r));
  const order = DATA.tactic_order.concat(Object.keys(by).filter(t => t && !DATA.tactic_order.includes(t)));
  const tested = new Set(DATA.rows.map(r => r.tactic_norm));
  const untested = DATA.tactic_order.filter(t => !tested.has(t));
  $("untested").textContent = DATA.rows.length && untested.length ? "No saved tests for: " + untested.map(tacticName).join(", ") : "";
  if (!rows.length) m.append(el("p", "muted", "No steps match the filters."));
  order.filter(t => by[t]).forEach(t => {
    const list = by[t], col = el("div", "tcol"), head = el("div", "th");
    head.append(el("div", "tt", tacticName(t)));
    col.append(head); m.append(col);
    const det = list.filter(r => isDetected(r.outcome)).length;
    head.append(el("div", "ts", `${plural(list.length, "step")} · ${pct(det, list.length)}% detected`), segBar(list, false));
    const byTech = {};
    list.forEach(r => (byTech[r.technique_id || "?"] = byTech[r.technique_id || "?"] || []).push(r));
    Object.entries(byTech).forEach(([tech, rs]) => {
      rs.sort((a, b) => String(b.run_utc).localeCompare(String(a.run_utc)));
      const r = rs[0], card = el("button", "tcard"), id = el("div", "tid");
      card.type = "button";
      id.append(badge(r.outcome, 16), document.createTextNode(tech));
      if (rs.length > 1) { const more = el("span", "more"); rs.slice(1, 6).forEach(x => more.append(badge(x.outcome, 12))); id.append(more); }
      card.append(id, el("div", "tname", r.technique_name || r.ability_name || ""),
        el("div", "tmeta", LABELS[r.outcome] + (r.rule_ids ? " · rules " + r.rule_ids.replace(/;/g, ", ") : "")));
      card.title = rs.length > 1 ? `Latest of ${rs.length} steps; the small circles are older results` : (r.ability_name || "");
      card.onclick = () => {
        state.tactic = t; updateAttackFilters();
        state.technique = r.technique_id || ""; $("fTechnique").value = state.technique;
        state.search = ""; $("search").value = "";
        render(); $("steps").scrollIntoView({behavior: "smooth", block: "start"});
      };
      col.append(card);
    });
  });
}
const COLS = [["run_utc", "Time"], ["scenario", "Scenario"], ["ability_name", "Ability"], ["technique_id", "Technique"],
  ["outcome", "Outcome"], ["rule_ids", "Rules"], ["alert_mitre_ids", "Alert tag"], ["time_to_alert_s", "Time to alert"]];
function details(r){
  const box = el("div"), facts = el("dl", "facts");
  [["Tactic", tacticName(r.tactic_norm)], ["Execution", r.execution], ["Caldera status", r.caldera_status],
   ["Technique match", r.technique_match], ["Rule levels", r.rule_levels], ["Response", r.response],
   ["Operation", r.operation_name], ["Run", r.run_id]]
    .forEach(([k, v]) => { if (v == null || v === "") return; facts.append(el("dt", null, k), el("dd", null, String(v))); });
  const lines = (r.evidence || []).map(e => `rule ${e.rule_id} L${e.rule_level ?? "?"} [${(e.rule_mitre_ids || []).join(",")}] ${e.relation} | event ${e.event_time_utc} | alert ${e.alert_time_utc}`);
  if ((r.archive_evidence || []).length) lines.push(`${plural(r.archive_evidence.length, "telemetry event")} matched in the archives`);
  (r.notes || []).forEach(t => lines.push("note: " + t));
  box.append(facts, el("pre", "evid", lines.join("\n") || "No correlated evidence."));
  return box;
}
function renderTable(rows){
  const head = $("thead"); head.replaceChildren();
  COLS.forEach(([k, label]) => {
    const th = el("th", null, label);
    if (state.sort === k) th.append(el("span", "arr", state.dir > 0 ? " ↑" : " ↓"));
    th.onclick = () => { state.dir = state.sort === k ? -state.dir : 1; state.sort = k; render(); };
    head.append(th);
  });
  const tb = $("tbody"); tb.replaceChildren();
  const sorted = [...rows].sort((a, b) => { const x = a[state.sort] ?? "", y = b[state.sort] ?? ""; return (x > y ? 1 : x < y ? -1 : 0) * state.dir; });
  if (!sorted.length) { const tr = el("tr"), td = el("td", "empty", "No steps match the filters."); td.colSpan = COLS.length; tr.append(td); tb.append(tr); }
  sorted.forEach(r => {
    const tr = el("tr", "row"), tech = el("td"), oc = el("td"), tag = el("td", "num", (r.alert_mitre_ids || "").replace(/;/g, ", "));
    tr.tabIndex = 0;
    tech.append(el("div", "strong", r.technique_id || ""), el("div", "small", r.technique_name || ""));
    oc.append(chip(r.outcome));
    if (r.alert_mitre_ids && r.technique_match === "different") tag.append(el("div", "small", "tested as " + (r.technique_id || "")));
    tr.append(el("td", "time", fmtShort(r.run_utc)), el("td", null, scenarioName(r.scenario)), el("td", null, r.ability_name || ""),
      tech, oc, el("td", "num", (r.rule_ids || "").replace(/;/g, ", ")), tag, el("td", "num", tta(r.time_to_alert_s)));
    const det = el("tr", "det"), td = el("td");
    det.hidden = true; td.colSpan = COLS.length; td.append(details(r)); det.append(td);
    const toggle = () => { det.hidden = !det.hidden; tr.classList.toggle("open", !det.hidden); };
    tr.onclick = toggle;
    tr.onkeydown = e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } };
    tb.append(tr, det);
  });
  $("tblHint").textContent = sorted.length ? `${plural(sorted.length, "step")} · select a row for its evidence` : "";
}
function renderGaps(rows){
  const g = $("gaps"); g.replaceChildren();
  const gaps = rows.filter(r => r.outcome !== "detected_labelled" && r.outcome !== "prevented");
  if (!gaps.length) { g.append(el("p", "muted", rows.length ? "Every scored step was detected and tagged with the tested technique." : "No scored steps yet.")); return; }
  gaps.forEach(r => {
    const d = el("div", "item"), top = el("div", "itop");
    top.append(chip(r.outcome), el("span", "strong", r.technique_id || "?"), el("span", "muted", r.ability_name || ""));
    d.append(top, el("p", "itext", (ADVICE[r.outcome] || (() => ""))(r))); g.append(d);
  });
}
function renderHealth(){
  const h = $("health"); h.replaceChildren();
  const runs = DATA.runs.filter(r => !state.run || r.run_id === state.run);
  if (!runs.length) { h.append(el("p", "muted", "No runs yet.")); return; }
  const at = v => v ? fmtSec(v) : "not recorded";
  runs.forEach(r => {
    const d = el("div", "item"), top = el("div", "itop"), facts = el("dl", "facts"), noise = [...new Set(r.harness_rule_ids || [])];
    const steps = DATA.rows.filter(row => row.run_id === r.run_id);
    const observed = steps.filter(row => row.event_collection === "confirmed" ||
      ["prevented", "detected_labelled", "detected_unlabelled", "telemetry_only"].includes(row.outcome)).length;
    const missing = steps.length - observed;
    const queueIssue = (r.queue_alert_rule_ids || []).length > 0;
    const archiveIssue = !!r.archive_collection_status && r.archive_collection_status !== "success";
    const issue = queueIssue || archiveIssue;
    const headline = steps.length ? `${observed} of ${steps.length} steps have Wazuh evidence` : "No scored steps";
    top.append(icon(issue ? "warn" : !steps.length || missing ? "wait" : "ok"), el("span", "strong", headline), el("span", "muted", scenarioName(r.scenario)));
    d.append(top);
    if (queueIssue) d.append(el("p", "itext", "Wazuh reported an agent queue warning; review whether telemetry was lost."));
    if (archiveIssue) d.append(el("p", "itext", "Raw archive evidence was unavailable; review this run before comparing coverage."));
    if (!issue && missing) d.append(el("p", "itext", r.collection_complete
      ? `${missing} step${missing === 1 ? "" : "s"} had no matching evidence; review the scored outcomes.`
      : `${missing} step${missing === 1 ? "" : "s"} without matching evidence remain not assessable.`));
    const technical = el("details", "health-details");
    technical.append(el("summary", null, "Collection timing and checks"));
    [["Window", `${at(r.window_start)} to ${at(r.window_end)}`], ["Latest alert event", at(r.agent_watermark)], ["Latest archive event", at(r.archive_watermark)],
     ["Wait ended", r.collection_stop_reason ? r.collection_stop_reason.replaceAll("_", " ") : "not recorded"],
     ["Agent queue alerts", (r.queue_alert_rule_ids || []).join(", ") || "none"], ["Harness rules excluded", noise.join(", ") || "none"]]
      .forEach(([k, v]) => facts.append(el("dt", null, k), el("dd", null, v)));
    technical.append(facts, el("p", "small", r.run_id));
    if (!r.collection_complete) technical.append(el("p", "small",
      !r.agent_watermark || new Date(r.agent_watermark) < new Date(r.window_end)
        ? "No later alert event was observed after the window end. This limits no-evidence scoring; it does not indicate a collection error."
        : "A collection check limited no-evidence scoring; review the archive and queue details above."));
    d.append(technical);
    h.append(d);
  });
}
function fill(id, label, values, show){
  const s = $(id); s.replaceChildren(el("option", null, label)); s.firstChild.value = "";
  values.forEach(v => { if (!v) return; const o = el("option", null, show ? show(v) : v); o.value = v; s.append(o); });
}
function updateAttackFilters(){
  const scope = DATA.rows.filter(r => (!state.run || r.run_id === state.run) && (!state.scenario || r.scenario === state.scenario));
  const rank = t => { const n = DATA.tactic_order.indexOf(t); return n < 0 ? DATA.tactic_order.length : n; };
  const tactics = [...new Set(scope.map(r => r.tactic_norm).filter(Boolean))]
    .sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  if (state.tactic && !tactics.includes(state.tactic)) state.tactic = "";
  fill("fTactic", "All ATT&CK tactics", tactics, tacticName);
  $("fTactic").value = state.tactic;
  const techniqueRows = scope.filter(r => !state.tactic || r.tactic_norm === state.tactic);
  const names = new Map(techniqueRows.filter(r => r.technique_id).map(r => [r.technique_id, r.technique_name || ""]));
  const techniques = [...names.keys()].sort((a, b) => a.localeCompare(b, undefined, {numeric: true}));
  if (state.technique && !names.has(state.technique)) state.technique = "";
  fill("fTechnique", "All ATT&CK techniques", techniques, id => names.get(id) ? `${id} · ${names.get(id)}` : id);
  $("fTechnique").value = state.technique;
}
function render(){
  const rows = filtered();
  renderKpis(rows); renderSplit(rows); renderMatrix(rows); renderTable(rows); renderGaps(rows); renderHealth();
}

/* exports, built from the filtered rows */
function toCsv(rows){
  const cols = ["run_id", "scenario", "technique_id", "technique_name", "tactic", "ability_name", "outcome", "technique_match", "execution", "caldera_status",
    "rule_ids", "max_rule_level", "alert_mitre_ids", "response", "time_to_alert_s", "collection_complete", "harness_alert_rule_ids", "run_utc"];
  const q = v => { v = v == null ? "" : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return "﻿" + cols.join(",") + "\n" + rows.map(r => cols.map(c => q(r[c])).join(",")).join("\n");
}
function navLayer(rows){
  const S = {prevented: 100, detected_labelled: 100, detected_unlabelled: 75, telemetry_only: 40, missed: 0, not_assessable: 0}, best = {};
  rows.forEach(r => { if (!r.technique_id) return; const s = S[r.outcome] || 0;
    if (!best[r.technique_id] || s > best[r.technique_id].score) best[r.technique_id] = {score: s, comment: r.outcome + "; rules " + (r.rule_ids || "none")}; });
  return JSON.stringify({name: "Wazuh BAS coverage", domain: "enterprise-attack", versions: {layer: "4.5", navigator: "4.9.1", attack: "15"},
    gradient: {colors: ["#d03b3b", "#f0efec", "#2a78d6"], minValue: 0, maxValue: 100},
    techniques: Object.entries(best).map(([t, i]) => ({techniqueID: t, score: i.score, comment: i.comment, enabled: true}))}, null, 2);
}
function download(name, text, type){ const u = URL.createObjectURL(new Blob([text], {type})); const a = el("a"); a.href = u; a.download = name; document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(u); }

/* run view */
const STATES = {running: ["wait", "Running"], done: ["ok", "Finished"], error: ["bad", "Finished with a problem"], unknown: ["wait", "No record of this run in the console"]};
let polling = null;
function setJob(kind, label, text){
  $("jobState").replaceChildren(icon(kind), document.createTextNode(label));
  const log = $("log"); log.textContent = text || ""; log.hidden = !text; log.scrollTop = log.scrollHeight;
}
function busy(on){ document.querySelectorAll(".launch").forEach(b => { b.disabled = on; }); $("liveDot").hidden = !on; }
function showJob(j){
  const [kind, label] = STATES[j.state] || ["wait", String(j.state)];
  setJob(kind, label + (j.scenario ? " · " + j.scenario : "") + (j.started ? " · started " + fmtStamp(j.started) : ""), (j.log || []).join("\n"));
  const note = $("logNote"); note.replaceChildren();
  if (j.state === "done") {
    const b = el("button", "btn", "View results"); b.type = "button"; b.onclick = () => { location.hash = "#results"; };
    note.append(el("span", null, "The results now include this run."), b);
  } else if (j.state === "error") note.append(el("span", null, "The run reported a problem; the last lines above say what. Check it before trusting its results."));
}
async function poll(job, live){
  try {
    const r = await fetch("api/status?job=" + encodeURIComponent(job)), j = await r.json();
    showJob(j);
    if (j.state === "running") { busy(true); setTimeout(() => poll(job, true), 2000); return; }
    busy(false); polling = null;
    if (live && j.state === "done") { location.hash = "#run"; setTimeout(() => location.reload(), 1500); }
  } catch (e) { busy(false); polling = null; setJob("bad", "Lost contact with the console", e.message); }
}
function follow(job){ if (polling === job) return; polling = job; poll(job, true); }
async function preflight(){
  const box = $("pre");
  box.replaceChildren(checkRow("wait", "Checking", "Caldera, the Sandcat agent and the Wazuh agent"));
  let checks;
  try { const r = await fetch("api/preflight"), j = await r.json(); if (!r.ok) throw new Error(j.error || "HTTP " + r.status); checks = j.checks; }
  catch (e) { checks = [{name: "Lab check", ok: false, detail: e.message}]; }
  box.replaceChildren(...checks.map(c => checkRow(c.ok ? "ok" : "bad", c.name, c.detail)));
  $("preTime").textContent = "Checked " + new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  return checks;
}
function checkRow(kind, name, detail){ const row = el("div", "crow"); row.append(icon(kind), el("span", "cname", name), el("span", "cdetail", detail)); return row; }
async function launch(sp){
  if (!confirm(`Launch ${sp.name || sp.scenario} on WIN11-TEST01? This runs the scenario in the lab.`)) return;
  setJob("wait", "Checking the lab before launch", "");
  const failed = (await preflight()).filter(c => !c.ok);
  if (failed.length) { setJob("bad", "Not launched", failed.map(c => `${c.name}: ${c.detail}`).join("\n")); return; }
  try {
    const r = await fetch("api/launch", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({scenario: sp.scenario})});
    const j = await r.json();
    if (r.status === 409 && j.job) { follow(j.job); return; }
    if (!r.ok) throw new Error(j.error || "HTTP " + r.status);
    follow(j.job);
  } catch (e) { setJob("bad", "Launch failed", e.message); }
}
function showCmd(sp){ setJob("wait", "Command for " + (sp.name || sp.scenario), `Run in the collector folder on the lab laptop:\n\n    python run_scenario.py ${sp.file} --collect\n\nThen rebuild this report with python build_dashboard.py.`); }
function lastRun(sp){
  const mine = DATA.rows.filter(r => String(r.scenario || "").startsWith(sp.scenario + "-"));
  if (!mine.length) return null;
  const latest = mine.map(r => r.run_id).sort().pop();
  return mine.filter(r => r.run_id === latest);
}
function renderScenarios(){
  const wrap = $("scn"); wrap.replaceChildren();
  (DATA.scenarios || []).forEach(sp => {
    const card = el("div", "scard"), tags = el("div", "tags"), pills = el("div", "pills"), last = el("div", "last"), act = el("div", "act"), rows = lastRun(sp);
    (sp.tactics || []).forEach(t => tags.append(el("span", "tag", tacticName(t))));   // from the scenario's CALDERA export
    (sp.expected_techniques || []).forEach(t => pills.append(el("span", "pill", t)));
    if (rows) last.append(segBar(rows, false), el("div", "small", `Last run ${fmtTime(rows[0].run_utc)} · ${rows.filter(r => isDetected(r.outcome)).length} of ${rows.length} detected`));
    else last.append(el("div", "small", "Not run yet"));
    const b = el("button", SERVED ? "btn pri launch" : "btn", SERVED ? "Launch" : "Show command");
    b.type = "button"; b.onclick = () => SERVED ? launch(sp) : showCmd(sp); act.append(b);
    card.append(el("h3", null, sp.name || sp.scenario), el("div", "sid", sp.file || sp.scenario));
    if (tags.childElementCount) card.append(tags);
    card.append(pills, last, act);
    wrap.append(card);
  });
}
function renderRun(){
  $("runMode").textContent = SERVED
    ? "Connected to the local control console. Each launch runs on WIN11-TEST01 after a lab check and your confirmation."
    : "Static report opened as a file. Start python serve_dashboard.py to check the lab and launch from this page.";
  renderScenarios();
  if (!SERVED) {
    $("recheck").hidden = true;
    $("pre").replaceChildren(checkRow("wait", "Not connected", "Lab checks need the control console"));
    setJob("wait", "Idle", "");
    return;
  }
  $("recheck").onclick = preflight;
  preflight();
  if (DATA.active_job) follow(DATA.active_job);
  else if (DATA.last_job) poll(DATA.last_job, false);
  else setJob("wait", "Idle", "");
}

/* navigation and start-up */
function showView(){
  const v = location.hash === "#run" ? "run" : "results";
  document.querySelectorAll(".view").forEach(x => x.classList.toggle("on", x.id === "view-" + v));
  document.querySelectorAll(".nav a").forEach(a => {
    a.classList.toggle("on", a.dataset.v === v);
    if (a.dataset.v === v) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
}
addEventListener("hashchange", showView);
fill("fRun", "All runs", [...new Set(DATA.rows.map(r => r.run_id))], runLabel);
fill("fScenario", "All scenarios", [...new Set(DATA.rows.map(r => r.scenario))], op => `${scenarioName(op)} · ${String(op).split("-").pop()}`);
updateAttackFilters();
fill("fOutcome", "All outcomes", OUT, o => LABELS[o]);
$("fRun").onchange = e => { state.run = e.target.value; updateAttackFilters(); render(); };
$("fScenario").onchange = e => { state.scenario = e.target.value; updateAttackFilters(); render(); };
$("fTactic").onchange = e => { state.tactic = e.target.value; updateAttackFilters(); render(); };
$("fTechnique").onchange = e => { state.technique = e.target.value; render(); };
$("fOutcome").onchange = e => { state.outcome = e.target.value; render(); };
$("search").oninput = e => { state.search = e.target.value; render(); };
$("clearFilters").onclick = () => {
  state.run = state.scenario = state.tactic = state.technique = state.outcome = state.search = "";
  ["fRun", "fScenario", "fOutcome", "search"].forEach(id => { $(id).value = ""; });
  updateAttackFilters(); render();
};
$("dlCsv").onclick = () => download("results-combined.csv", toCsv(filtered()), "text/csv");
$("dlNav").onclick = () => download("navigator-wazuh.json", navLayer(filtered()), "application/json");
const hosts = [...new Set(DATA.rows.map(r => r.host).filter(Boolean))];
[["Control", DATA.control], ["Endpoint", hosts.join(", ") || "No runs yet"], ["Scored", `${plural(DATA.rows.length, "step")}, ${plural(DATA.runs.length, "run")}`]]
  .forEach(([k, v]) => $("ctx").append(el("dt", null, k), el("dd", null, v)));
$("sideFoot").append(el("b", null, SERVED ? "Live console" : "Static report"), el("span", null, "Updated " + fmtTime(DATA.generated_at)));
showView(); render(); renderRun();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
