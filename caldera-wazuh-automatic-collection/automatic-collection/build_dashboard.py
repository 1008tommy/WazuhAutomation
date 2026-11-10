"""Build a self-contained Wazuh BAS dashboard from saved runs. Python 3.11+.

Reads every <runs>/*/results/results.json (plus the sibling run-metadata.json) and writes:
  <out>/index.html            one self-contained page (inline CSS/JS, data embedded, no network)
  <out>/results-combined.csv  every scored row across all runs
  <out>/navigator-wazuh.json  an ATT&CK Navigator layer (enterprise-attack)

The same page is served live by serve_dashboard.py, where the Launch view can start scenarios;
opened as a file it stays a static, air-gapped report and the Launch view shows the exact command.
No third-party packages; vanilla JS so it opens with a double-click offline.
"""
import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent

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


def load_scenarios(scenarios_dir):
    specs = []
    for path in sorted(Path(scenarios_dir).glob("*.json")):
        try:
            spec = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        specs.append({"scenario": spec.get("scenario"), "name": spec.get("name"),
                      "adversary_id": spec.get("adversary_id"),
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
            "gradient": {"colors": ["#dc2626", "#f3f4f6", "#16a34a"], "minValue": 0, "maxValue": 100},
            "techniques": techniques}


def render_html(data, served=False):
    payload = dict(data, served=served)
    return HTML_TEMPLATE.replace("/*__DATA__*/null", json.dumps(payload))


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
  --bg:#ffffff; --panel:#ffffff; --sunken:#f8fafc; --ink:#111827; --ink2:#4b5563; --muted:#9ca3af;
  --line:#e5e7eb; --line2:#eef1f4; --accent:#4f46e5; --accent-weak:#eef2ff; --track:#eef1f4;
  --prevented:#4f46e5; --detected_labelled:#16a34a; --detected_unlabelled:#0891b2;
  --telemetry_only:#d97706; --missed:#dc2626; --not_assessable:#9ca3af;
}
:root[data-theme="dark"]{
  --bg:#0f1420; --panel:#151b28; --sunken:#111725; --ink:#e7ecf3; --ink2:#aab4c2; --muted:#6b7585;
  --line:#243043; --line2:#1c2636; --accent:#8b93f8; --accent-weak:#1b2236; --track:#1c2636;
  --detected_labelled:#34d07f; --detected_unlabelled:#2bb6d6; --telemetry_only:#e0a74a;
  --missed:#ef5a52; --prevented:#8b93f8; --not_assessable:#6b7585;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink);font:14px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px}
header{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:5}
.hrow{display:flex;align-items:center;gap:16px;padding:14px 0}
.brand{font-weight:600;letter-spacing:-.01em;font-size:16px}
.brand small{display:block;color:var(--muted);font-weight:400;font-size:12px;letter-spacing:0}
.tools{margin-left:auto;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
select,input,button{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 11px}
select,input{color:var(--ink2)}
button{cursor:pointer;color:var(--ink2)}
button:hover{border-color:var(--muted)}
button.pri{background:var(--accent);color:#fff;border-color:transparent;font-weight:500}
button.pri:hover{filter:brightness(1.05)}
button.pri:disabled{opacity:.5;cursor:not-allowed}
.tabs{display:flex;gap:4px;padding-bottom:0}
.tab{padding:9px 14px;border:0;background:none;color:var(--ink2);border-bottom:2px solid transparent;border-radius:0;font-weight:500}
.tab.on{color:var(--ink);border-bottom-color:var(--accent)}
main{padding:22px 0 60px}
.view{display:none}
.view.on{display:block}
h2{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:26px 0 12px;font-weight:600}
h2:first-child{margin-top:0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.kpi{background:var(--panel);padding:16px 16px 14px}
.kpi .n{font-size:27px;font-weight:650;letter-spacing:-.02em}
.kpi .n small{font-size:14px;color:var(--muted);font-weight:500}
.kpi .l{font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);margin-top:3px}
.kpi .s{font-size:12px;color:var(--ink2);margin-top:7px}
.legend{display:flex;flex-wrap:wrap;gap:16px;margin:4px 2px 0;font-size:12px;color:var(--ink2)}
.legend span{display:inline-flex;align-items:center;gap:7px}
.dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.map{display:grid;grid-auto-flow:column;grid-auto-columns:minmax(168px,1fr);gap:12px;overflow-x:auto;padding-bottom:8px}
.tcol{border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:hidden;min-width:168px}
.tcol .th{padding:12px 12px 11px;border-bottom:1px solid var(--line2)}
.tcol .tt{font-size:12.5px;font-weight:600;text-transform:capitalize}
.tcol .ts{font-size:11px;color:var(--muted);margin-top:1px}
.mbar{height:6px;border-radius:4px;background:var(--track);margin-top:9px;overflow:hidden;display:flex}
.mbar>i{display:block;height:100%}
.mcap{font-size:11px;color:var(--ink2);margin-top:6px}
.tcell{padding:10px 12px;border-top:1px solid var(--line2);cursor:pointer}
.tcell:hover{background:var(--sunken)}
.tcell .ci{display:flex;align-items:center;gap:7px;font-weight:600;font-size:12.5px}
.tcell .cn{font-size:11px;color:var(--muted);margin:2px 0 0 16px}
.tcell .cb{font-size:11px;color:var(--ink2);margin:5px 0 0 16px;font-variant-numeric:tabular-nums}
.card{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:10px 10px;border-bottom:1px solid var(--line2);vertical-align:top}
th{position:relative;cursor:pointer;color:var(--muted);font-size:11px;letter-spacing:.04em;text-transform:uppercase;font-weight:600;white-space:nowrap}
tbody tr:hover{background:var(--sunken)}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--ink);white-space:nowrap}
.mono{font-family:ui-monospace,"Cascadia Mono",Consolas,monospace;font-size:12px;color:var(--ink2)}
.bad{color:var(--missed)}
.exp td{background:var(--sunken)}
.exp .box{white-space:pre-wrap;font-size:12px;color:var(--ink2);font-family:ui-monospace,Consolas,monospace}
tr.det{display:none}
.note{border:1px solid var(--line);border-left:3px solid var(--telemetry_only);border-radius:10px;background:var(--panel);padding:11px 13px;margin-bottom:10px;font-size:13px}
.note b{font-weight:600}
.muted{color:var(--muted)}
.scn{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:14px}
.scard{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:16px;display:flex;flex-direction:column;gap:9px}
.scard h3{margin:0;font-size:14.5px;font-weight:600}
.scard .tech{display:flex;flex-wrap:wrap;gap:5px}
.pill{font-size:11px;color:var(--ink2);background:var(--sunken);border:1px solid var(--line);border-radius:999px;padding:1px 8px;font-variant-numeric:tabular-nums}
.scard .act{margin-top:auto;display:flex;gap:8px;align-items:center}
.flow{display:flex;flex-wrap:wrap;gap:8px;margin:2px 0 16px;font-size:12.5px;color:var(--ink2);align-items:center}
.flow .step{border:1px solid var(--line);border-radius:999px;padding:4px 11px;background:var(--panel)}
.flow .arr{color:var(--muted)}
#log{border:1px solid var(--line);border-radius:12px;background:var(--sunken);padding:13px 15px;min-height:54px;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:var(--ink2);white-space:pre-wrap}
.gnote{font-size:12.5px;color:var(--muted);margin-top:10px}
@media (max-width:640px){.wrap{padding:0 14px}.hrow{flex-wrap:wrap}}
</style>
</head>
<body>
<header><div class="wrap">
  <div class="hrow">
    <div class="brand">Security Control Validation<small id="meta"></small></div>
    <div class="tools">
      <select id="fRun"></select><select id="fScenario"></select><select id="fOutcome"></select>
      <button id="dlCsv">Export CSV</button><button id="dlNav">Navigator layer</button>
      <button id="theme" title="Toggle theme">&#9680;</button>
    </div>
  </div>
  <div class="tabs">
    <button class="tab on" data-v="results">Results</button>
    <button class="tab" data-v="launch">Run a scenario</button>
  </div>
</div></header>
<main><div class="wrap">

  <div class="view on" id="view-results">
    <h2>Coverage</h2><div class="kpis" id="kpis"></div>
    <div class="legend" id="legend"></div>
    <h2>ATT&amp;CK coverage by tactic</h2><div class="map" id="map"></div>
    <h2>Results</h2>
    <div style="margin-bottom:10px"><input id="search" placeholder="Search ability, technique, rule..." style="width:100%;max-width:340px"></div>
    <div class="card" style="padding:0;overflow-x:auto"><table id="tbl"><thead><tr>
      <th data-k="run_utc">Time</th><th data-k="scenario">Scenario</th><th data-k="ability_name">Ability</th>
      <th data-k="technique_id">Technique</th><th data-k="tactic">Tactic</th><th data-k="execution">Exec</th>
      <th data-k="outcome">Outcome</th><th data-k="rule_ids">Rules</th><th data-k="alert_mitre_ids">Alert tag</th>
      <th data-k="time_to_alert_s">Time to alert</th><th data-k="response">Response</th>
    </tr></thead><tbody id="tbody"></tbody></table></div>
    <h2>Detection gaps</h2><div id="gaps"></div>
    <h2>Run health &amp; excluded noise</h2><div id="health"></div>
  </div>

  <div class="view" id="view-launch">
    <h2>Workflow</h2>
    <div class="flow"><span class="step">Pick a scenario</span><span class="arr">&rarr;</span>
      <span class="step">Launch on WIN11-TEST01</span><span class="arr">&rarr;</span>
      <span class="step">Collect &amp; score</span><span class="arr">&rarr;</span>
      <span class="step">Results update</span></div>
    <div id="mode" class="gnote"></div>
    <h2>Scenarios</h2><div class="scn" id="scn"></div>
    <h2>Activity</h2><div id="log">Idle.</div>
    <div class="gnote" id="guard"></div>
  </div>

</div></main>
<script>
const DATA = /*__DATA__*/null;
const OUT = DATA.outcome_order;
const LABELS={prevented:"Prevented",detected_labelled:"Detected (labelled)",detected_unlabelled:"Detected (unlabelled)",telemetry_only:"Telemetry only",missed:"Missed",not_assessable:"Not assessable"};
const css=n=>getComputedStyle(document.documentElement).getPropertyValue('--'+n).trim();
const el=(t,p={})=>Object.assign(document.createElement(t),p);
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pct=(n,d)=>d?Math.round(100*n/d):0;
const fmtTime=s=>{if(!s)return "";const d=new Date(s);return isNaN(d)?s:d.toLocaleString([], {dateStyle:"medium",timeStyle:"short"});};
const tta=v=>v==null?"":(v>=90?Math.round(v/60)+" min":Math.round(v)+" s");
let state={run:"",scenario:"",outcome:"",search:"",sort:"run_utc",dir:1};

function dot(o){const d=el("span",{className:"dot"});d.style.background=css(o);return d;}
function filtered(){return DATA.rows.filter(r=>(!state.run||r.run_id===state.run)&&(!state.scenario||r.scenario===state.scenario)&&(!state.outcome||r.outcome===state.outcome)&&(!state.search||JSON.stringify([r.ability_name,r.technique_id,r.technique_name,r.rule_ids,r.alert_mitre_ids]).toLowerCase().includes(state.search.toLowerCase())));}

function renderKpis(rows){
  const n=rows.length,c=o=>rows.filter(r=>r.outcome===o).length;
  const lab=c("detected_labelled"),unl=c("detected_unlabelled"),tel=c("telemetry_only"),prev=c("prevented");
  const det=lab+unl,vis=lab+unl+tel,resp=rows.filter(r=>r.response==="executed").length;
  const t=rows.map(r=>r.time_to_alert_s).filter(v=>v!=null).sort((a,b)=>a-b),med=t.length?t[Math.floor((t.length-1)/2)]:null;
  const cards=[
    ["Techniques tested",`${n}`,"","across "+DATA.runs.length+" run(s)"],
    ["Detection rate",`${det} <small>/ ${n}</small>`,`${pct(det,n)}% detected`,""],
    ["Correct technique",`${lab} <small>/ ${n}</small>`,`${pct(lab,n)}% labelled`,""],
    ["Visibility",`${vis} <small>/ ${n}</small>`,`${pct(vis,n)}% alert or log`,""],
    ["Prevention",`${prev} <small>/ ${n}</small>`,"Wazuh is detection-only",""],
    ["Median time to alert",med!=null?tta(med):"n/a","",med!=null&&med>120?"driven by ingest lag":""],
  ];
  const w=document.getElementById("kpis");w.innerHTML="";
  cards.forEach(([l,big,s1,s2])=>{const d=el("div",{className:"kpi"});
    d.innerHTML=`<div class="n">${big}</div><div class="l">${esc(l)}</div>`+(s1?`<div class="s">${esc(s1)}</div>`:"")+(s2?`<div class="s muted">${esc(s2)}</div>`:"");
    w.append(d);});
  const lg=document.getElementById("legend");lg.innerHTML="";
  OUT.forEach(o=>{const s=el("span");s.append(dot(o),document.createTextNode(LABELS[o]));lg.append(s);});
}
function renderMap(rows){
  const m=document.getElementById("map");m.innerHTML="";
  const by={};rows.forEach(r=>{(by[r.tactic_norm]=by[r.tactic_norm]||[]).push(r);});
  const order=DATA.tactic_order.filter(t=>by[t]).concat(Object.keys(by).filter(t=>!DATA.tactic_order.includes(t)));
  order.forEach(t=>{const list=by[t],n=list.length;
    const det=list.filter(r=>r.outcome==="detected_labelled"||r.outcome==="detected_unlabelled").length;
    const col=el("div",{className:"tcol"});
    const seg=OUT.map(o=>{const k=list.filter(r=>r.outcome===o).length;return k?`<i style="width:${100*k/n}%;background:${css(o)}"></i>`:"";}).join("");
    col.innerHTML=`<div class="th"><div class="tt">${esc(t.replace(/-/g," "))}</div><div class="ts">${n} technique${n>1?"s":""}</div>
      <div class="mbar">${seg}</div><div class="mcap">${pct(det,n)}% detected</div></div>`;
    list.forEach(r=>{const c=el("div",{className:"tcell"});
      c.innerHTML=`<div class="ci"></div><div class="cn">${esc(r.technique_name||r.ability_name||"")}</div><div class="cb">${r.rule_ids?"rules "+esc(r.rule_ids):esc(LABELS[r.outcome])}</div>`;
      c.querySelector(".ci").append(dot(r.outcome),document.createTextNode(r.technique_id||"?"));
      c.onclick=()=>{setFilter("fOutcome","outcome","");state.search=r.technique_id;document.getElementById("search").value=r.technique_id;render();};
      col.append(c);});
    m.append(col);});
}
function chip(o){const c=el("span",{className:"chip"});c.append(dot(o),document.createTextNode(LABELS[o]||o));return c;}
function renderTable(rows){
  const tb=document.getElementById("tbody");tb.innerHTML="";
  const s=[...rows].sort((a,b)=>{const x=a[state.sort]??"",y=b[state.sort]??"";return (x>y?1:x<y?-1:0)*state.dir;});
  s.forEach(r=>{const tr=el("tr");const mis=(r.technique_match==="different"||r.technique_match==="none")&&r.alert_mitre_ids;
    tr.innerHTML=`<td class="mono">${esc(fmtTime(r.run_utc))}</td><td>${esc(r.scenario)}</td><td>${esc(r.ability_name)}</td>
      <td><b>${esc(r.technique_id)}</b><div class="muted">${esc(r.technique_name||"")}</div></td>
      <td>${esc((r.tactic||"").replace(/-/g," "))}</td><td>${esc(r.execution||"")}</td>
      <td class="oc"></td><td class="mono">${esc(r.rule_ids||"")}</td>
      <td class="mono ${mis?"bad":""}">${esc(r.alert_mitre_ids||"")}</td>
      <td class="mono">${esc(tta(r.time_to_alert_s))}</td><td>${esc(r.response||"")}</td>`;
    tr.querySelector(".oc").append(chip(r.outcome));
    tr.style.cursor="pointer";tr.onclick=()=>{d.style.display=d.style.display==="table-row"?"none":"table-row";};
    const d=el("tr",{className:"det"});const td=el("td");td.colSpan=11;
    const parts=[];
    if(r.evidence&&r.evidence.length)parts.push("Alerts:\n"+r.evidence.map(e=>`  rule ${e.rule_id} L${e.rule_level??"?"} [${(e.rule_mitre_ids||[]).join(",")}] ${e.relation} | event ${e.event_time_utc} seen ${e.alert_time_utc}`).join("\n"));
    if(r.archive_evidence&&r.archive_evidence.length)parts.push("Telemetry events: "+r.archive_evidence.length);
    if(r.notes&&r.notes.length)parts.push("Notes:\n  "+r.notes.join("\n  "));
    td.innerHTML=`<div class="box">${esc(parts.join("\n\n")||"No correlated evidence.")}</div>`;
    d.append(td);tb.append(tr);tb.append(d);});
}
function renderGaps(rows){
  const g=document.getElementById("gaps");g.innerHTML="";
  const gaps=rows.filter(r=>r.outcome!=="detected_labelled");
  if(!gaps.length){g.innerHTML='<div class="muted">Every scored technique was detected and labelled.</div>';return;}
  gaps.forEach(r=>{let s="";
    if(r.outcome==="telemetry_only")s="Log exists but no rule fired; candidate for a custom Wazuh rule on the script-block or command.";
    else if(r.outcome==="detected_unlabelled")s="Detected but mislabelled; review the rule's ATT&CK tag ("+(r.alert_mitre_ids||"none")+") versus "+(r.technique_id||"?")+".";
    else if(r.outcome==="missed")s="No telemetry with collection complete; a logging or visibility gap.";
    else s="Not assessable; check PID, window and collection completeness.";
    const d=el("div",{className:"note"});
    d.innerHTML=`<b>${esc(r.technique_id||"?")}</b> ${esc(r.ability_name||"")} <span class="muted">[${LABELS[r.outcome]}]</span><br>${esc(s)}`;g.append(d);});
}
function renderHealth(){
  const h=document.getElementById("health");h.innerHTML="";
  if(!DATA.runs.length){h.innerHTML='<div class="muted">No runs yet.</div>';return;}
  DATA.runs.forEach(r=>{const d=el("div",{className:"note"});d.style.borderLeftColor=css(r.collection_complete?"detected_labelled":"missed");
    d.innerHTML=`<b>${esc(r.run_id)}</b> <span class="muted">(${esc(r.scenario||"")})</span><br>
      <span class="muted">Window</span> ${esc(r.window_start||"?")} &rarr; ${esc(r.window_end||"?")} ·
      <span class="muted">watermark</span> ${esc(r.agent_watermark||"?")} ·
      collection ${r.collection_complete?"complete":"<b class='bad'>incomplete</b> (missed not scored)"} ·
      <span class="muted">queue</span> ${(r.queue_alert_rule_ids||[]).join(",")||"none"} ·
      <span class="muted">harness excluded</span> ${(r.harness_rule_ids||[]).join(",")||"none"}`;
    h.append(d);});
}
function renderLaunch(){
  const served=!!DATA.served;
  document.getElementById("mode").innerHTML=served
    ? "Connected to the local control server: launching runs on <b>WIN11-TEST01</b>. Each launch is confirmed first."
    : "Static report (opened as a file). Launch shows the exact command; start the control server (<span class='mono'>python serve_dashboard.py</span>) to launch from here.";
  document.getElementById("guard").innerHTML="Guardrails: only group <b>red</b> on <b>WIN11-TEST01</b>, plain-text obfuscator, cleanup verified after every run. Revert the VM snapshot if cleanup fails.";
  const wrap=document.getElementById("scn");wrap.innerHTML="";
  (DATA.scenarios||[]).forEach(sp=>{const c=el("div",{className:"scard"});
    const tech=(sp.expected_techniques||[]).map(t=>`<span class="pill">${esc(t)}</span>`).join("");
    c.innerHTML=`<h3>${esc(sp.name||sp.scenario)}</h3><div class="muted" style="font-size:12px">${esc(sp.scenario)}</div>
      <div class="tech">${tech}</div><div class="act"></div>`;
    const b=el("button",{className:"pri",textContent:served?"Launch":"Show command"});
    b.onclick=()=>served?launch(sp):showCmd(sp);
    c.querySelector(".act").append(b);wrap.append(c);});
}
function showCmd(sp){document.getElementById("log").textContent="Run on the lab laptop:\n\n    python "+sp.file.replace("scenarios/","run_scenario.py scenarios/")+" --collect\n\nThen reopen this page to see the results.";}
async function launch(sp){
  if(!confirm("Launch "+(sp.name||sp.scenario)+" on WIN11-TEST01? This runs the scenario in the lab."))return;
  const log=document.getElementById("log");log.textContent="Launching "+sp.scenario+"...\n";
  try{
    const r=await fetch("api/launch",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scenario:sp.scenario})});
    const j=await r.json();if(!r.ok)throw new Error(j.error||("HTTP "+r.status));
    poll(j.job);
  }catch(e){log.textContent+="\nError: "+e.message;}
}
async function poll(job){
  const log=document.getElementById("log");
  try{
    const r=await fetch("api/status?job="+encodeURIComponent(job));const j=await r.json();
    log.textContent=(j.log||[]).join("\n");
    if(j.state==="running"){setTimeout(()=>poll(job),2000);}
    else if(j.state==="done"){log.textContent+="\n\nDone. Refreshing results...";setTimeout(()=>location.reload(),1200);}
    else log.textContent+="\n\n["+j.state+"]";
  }catch(e){log.textContent+="\nError polling: "+e.message;}
}
function toCsv(rows){const cols=["run_id","scenario","technique_id","technique_name","tactic","ability_name","outcome","technique_match","execution","caldera_status","rule_ids","max_rule_level","alert_mitre_ids","response","time_to_alert_s","collection_complete","harness_alert_rule_ids","run_utc"];
  const q=v=>{v=v==null?"":String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  return "﻿"+cols.join(",")+"\n"+rows.map(r=>cols.map(c=>q(r[c])).join(",")).join("\n");}
function navLayer(rows){const S={prevented:100,detected_labelled:100,detected_unlabelled:75,telemetry_only:40,missed:0,not_assessable:0},best={};
  rows.forEach(r=>{if(!r.technique_id)return;const s=S[r.outcome]||0;if(!best[r.technique_id]||s>best[r.technique_id].score)best[r.technique_id]={score:s,comment:r.outcome+"; rules "+(r.rule_ids||"none")};});
  return JSON.stringify({name:"Wazuh BAS coverage",domain:"enterprise-attack",versions:{layer:"4.5",navigator:"4.9.1",attack:"15"},gradient:{colors:["#dc2626","#f3f4f6","#16a34a"],minValue:0,maxValue:100},techniques:Object.entries(best).map(([t,i])=>({techniqueID:t,score:i.score,comment:i.comment,enabled:true}))},null,2);}
function dl(name,text,type){const u=URL.createObjectURL(new Blob([text],{type}));const a=el("a",{href:u,download:name});document.body.append(a);a.click();a.remove();URL.revokeObjectURL(u);}
function fill(id,label,vals){const s=document.getElementById(id);s.innerHTML="";s.append(el("option",{value:"",textContent:label}));vals.forEach(v=>v&&s.append(el("option",{value:v,textContent:v})));}
function setFilter(id,key,val){state[key]=val;document.getElementById(id).value=val;}
function render(){
  document.getElementById("meta").textContent=`${DATA.control} · ${DATA.rows.length} scored rows · ${DATA.runs.length} run(s) · ${fmtTime(DATA.generated_at)}`;
  const rows=filtered();renderKpis(rows);renderMap(rows);renderTable(rows);renderGaps(rows);renderHealth();
}
fill("fRun","All runs",[...new Set(DATA.rows.map(r=>r.run_id))]);
fill("fScenario","All scenarios",[...new Set(DATA.rows.map(r=>r.scenario))]);
fill("fOutcome","All outcomes",OUT);
document.getElementById("fRun").onchange=e=>{state.run=e.target.value;render();};
document.getElementById("fScenario").onchange=e=>{state.scenario=e.target.value;render();};
document.getElementById("fOutcome").onchange=e=>{state.outcome=e.target.value;render();};
document.getElementById("search").oninput=e=>{state.search=e.target.value;render();};
document.querySelectorAll("th[data-k]").forEach(th=>th.onclick=()=>{const k=th.dataset.k;state.dir=state.sort===k?-state.dir:1;state.sort=k;render();});
document.getElementById("dlCsv").onclick=()=>dl("results-combined.csv",toCsv(filtered()),"text/csv");
document.getElementById("dlNav").onclick=()=>dl("navigator-wazuh.json",navLayer(filtered()),"application/json");
document.getElementById("theme").onclick=()=>{const r=document.documentElement;r.dataset.theme=r.dataset.theme==="dark"?"light":"dark";render();};
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));t.classList.add("on");
  document.querySelectorAll(".view").forEach(v=>v.classList.remove("on"));document.getElementById("view-"+t.dataset.v).classList.add("on");});
renderLaunch();render();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
