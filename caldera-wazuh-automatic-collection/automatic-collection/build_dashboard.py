"""Build a self-contained, air-gapped Wazuh BAS dashboard from saved runs. Python 3.11+.

Reads every <runs>/*/results/results.json (plus the sibling run-metadata.json) and writes:
  <out>/index.html            one self-contained page (inline CSS/JS, data embedded, no network)
  <out>/results-combined.csv  every scored row across all runs
  <out>/navigator-wazuh.json  an ATT&CK Navigator layer (enterprise-attack)

No third-party packages; the page uses vanilla JS so it opens with a double-click offline.
"""
import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

OUTCOME_ORDER = ["prevented", "detected_labelled", "detected_unlabelled",
                 "telemetry_only", "missed", "not_assessable"]
# Navigator per-technique score by best outcome (plan section 5).
NAV_SCORE = {"prevented": 100, "detected_labelled": 100, "detected_unlabelled": 75,
             "telemetry_only": 40, "missed": 0, "not_assessable": 0}
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

def build_data(runs):
    rows, run_summaries = [], []
    for run in runs:
        result, meta = run["result"], run["meta"]
        operation = result.get("results", [{}])[0].get("operation_name") if result.get("results") else None
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
            "run_id": run["run_id"],
            "scenario": scenario,
            "operation": operation,
            "window_start": window.get("start") or meta.get("window_start"),
            "window_end": window.get("end") or meta.get("window_end"),
            "agent_watermark": meta.get("agent_watermark"),
            "collection_complete": meta.get("collection_complete"),
            "queue_alert_rule_ids": meta.get("queue_alert_rule_ids", []),
            "archive_collection_status": result.get("archive_collection_status") or meta.get("archive_collection_status"),
            "harness_rule_ids": result.get("harness_rule_ids", []),
            "defender_state": meta.get("defender_state", "loaded, inert"),
            "schema_version": result.get("schema_version"),
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "control": "Wazuh 4.14.x",
        "rows": rows,
        "runs": run_summaries,
        "outcome_order": OUTCOME_ORDER,
        "tactic_order": TACTIC_ORDER,
    }

def combined_csv(rows, path):
    columns = ["run_id", "scenario", "technique_id", "technique_name", "tactic", "ability_name",
               "outcome", "technique_match", "execution", "caldera_status", "rule_ids",
               "max_rule_level", "alert_mitre_ids", "response", "time_to_alert_s",
               "collection_complete", "harness_alert_rule_ids", "run_utc"]
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

def navigator_layer(rows):
    best = {}
    for row in rows:
        tech = row.get("technique_id")
        if not tech:
            continue
        score = NAV_SCORE.get(row.get("outcome"), 0)
        current = best.get(tech)
        if current is None or score > current["score"]:
            best[tech] = {"score": score, "rules": row.get("rule_ids", ""), "outcome": row.get("outcome")}
    techniques = [{
        "techniqueID": tech,
        "score": info["score"],
        "comment": f'{info["outcome"]}; rules: {info["rules"] or "none"}',
        "enabled": True,
    } for tech, info in sorted(best.items())]
    return {
        "name": "Wazuh BAS coverage",
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "description": "Outcome per tested technique. 100 labelled/prevented, 75 unlabelled, 40 telemetry only, 0 missed.",
        "gradient": {"colors": ["#d7191c", "#ffffbf", "#1a9641"], "minValue": 0, "maxValue": 100},
        "techniques": techniques,
    }

def render_html(data):
    return HTML_TEMPLATE.replace("/*__DATA__*/null", json.dumps(data))

def main():
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11+ required.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, default=Path("runs"), help="Directory of run folders")
    parser.add_argument("--out", type=Path, default=Path("dashboard"), help="Output directory")
    args = parser.parse_args()
    runs = load_runs(args.runs)
    if not runs:
        raise SystemExit(f"No runs found under {args.runs.resolve()} (expected */results/results.json)")
    data = build_data(runs)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "index.html").write_text(render_html(data), encoding="utf-8")
    combined_csv(data["rows"], args.out / "results-combined.csv")
    (args.out / "navigator-wazuh.json").write_text(json.dumps(navigator_layer(data["rows"]), indent=2), encoding="utf-8")
    print(f"Dashboard: {(args.out / 'index.html').resolve()}")
    print(f"Runs: {len(runs)}  Scored rows: {len(data['rows'])}")

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wazuh BAS Dashboard</title>
<style>
:root{
  --bg:#f6f7f9; --panel:#ffffff; --ink:#1b1f24; --muted:#5a636e; --line:#e2e6ea; --accent:#2b6cb0;
  --prevented:#2b6cb0; --detected_labelled:#2e8b57; --detected_unlabelled:#2fa4a6;
  --telemetry_only:#d9962b; --missed:#c0392b; --not_assessable:#8a929b;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#12161b; --panel:#1b2129; --ink:#e8ecf1; --muted:#9aa4b0; --line:#2b333d; --accent:#6aa9e0;
  --prevented:#4a90d9; --detected_labelled:#44b67a; --detected_unlabelled:#3fc0c2;
  --telemetry_only:#e0a84a; --missed:#e05a4b; --not_assessable:#9aa4b0;
}}
:root[data-theme="dark"]{
  --bg:#12161b; --panel:#1b2129; --ink:#e8ecf1; --muted:#9aa4b0; --line:#2b333d; --accent:#6aa9e0;
  --prevented:#4a90d9; --detected_labelled:#44b67a; --detected_unlabelled:#3fc0c2;
  --telemetry_only:#e0a84a; --missed:#e05a4b; --not_assessable:#9aa4b0;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:18px 16px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between}
h1{font-size:18px;margin:0}
h2{font-size:15px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
main{max-width:1200px;margin:0 auto;padding:16px}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
select,input,button{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:7px 10px}
button{cursor:pointer}
button.primary{background:var(--accent);color:#fff;border-color:transparent}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:10px;padding:14px}
.card .num{font-size:26px;font-weight:700}
.card .lab{color:var(--muted);font-size:12px;margin-top:2px}
.card .sub{color:var(--muted);font-size:12px;margin-top:6px}
.bar{display:flex;height:26px;border-radius:6px;overflow:hidden;border:1px solid var(--line)}
.bar>div{display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;min-width:0}
.legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;font-size:12px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px}
.sw{width:12px;height:12px;border-radius:3px;display:inline-block}
.matrix{display:flex;gap:10px;overflow-x:auto;padding-bottom:6px}
.col{min-width:150px;flex:0 0 auto}
.col h3{font-size:12px;margin:0 0 8px;color:var(--muted);text-transform:capitalize}
.cell{border:1px solid var(--line);border-left-width:5px;border-radius:7px;padding:8px;margin-bottom:8px;cursor:pointer}
.cell:hover{outline:2px solid var(--accent)}
.cell .id{font-weight:700;font-size:12px}
.cell .nm{font-size:11px;color:var(--muted)}
.cell .bd{font-size:10px;margin-top:4px;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{cursor:pointer;color:var(--muted);font-size:12px;white-space:nowrap}
.chip{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:11px;white-space:nowrap}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}
.mismatch{color:var(--missed);font-weight:600}
.exp{background:var(--bg);border-radius:7px;padding:10px;margin-top:6px;font-size:12px;white-space:pre-wrap}
tr.det{display:none}
.muted{color:var(--muted)}
.gap{border-left:4px solid var(--telemetry_only);padding:8px 10px;margin-bottom:8px;background:var(--bg);border-radius:6px}
.right{margin-left:auto}
@media (max-width:640px){main{padding:12px}section{padding:12px}}
</style>
</head>
<body>
<header>
  <div><h1>Wazuh BAS Dashboard</h1><div class="muted" id="sub"></div></div>
  <div class="controls">
    <select id="fRun"></select>
    <select id="fScenario"></select>
    <select id="fOutcome"></select>
    <button id="dlCsv">Download CSV</button>
    <button id="dlNav">Download Navigator layer</button>
    <button id="theme">Theme</button>
  </div>
</header>
<main>
  <section><h2>Coverage</h2><div class="cards" id="cards"></div></section>
  <section><h2>Outcome distribution</h2><div class="bar" id="obar"></div><div class="legend" id="legend"></div></section>
  <section><h2>ATT&amp;CK matrix (tested techniques)</h2><div class="matrix" id="matrix"></div></section>
  <section><h2>Results</h2>
    <div class="controls" style="margin-bottom:10px"><input id="search" placeholder="Search ability, technique, rule..." style="flex:1;min-width:180px"></div>
    <div style="overflow-x:auto"><table id="tbl"><thead><tr>
      <th data-k="run_utc">Time</th><th data-k="scenario">Scenario</th><th data-k="ability_name">Ability</th>
      <th data-k="technique_id">Technique</th><th data-k="tactic">Tactic</th><th data-k="execution">Exec</th>
      <th data-k="outcome">Outcome</th><th data-k="rule_ids">Rules</th><th data-k="alert_mitre_ids">Alert ATT&amp;CK</th>
      <th data-k="time_to_alert_s">TTA</th><th data-k="response">Response</th>
    </tr></thead><tbody id="tbody"></tbody></table></div>
  </section>
  <section><h2>Detection gaps</h2><div id="gaps"></div></section>
  <section><h2>Run health &amp; excluded noise</h2><div id="health"></div></section>
</main>
<script>
const DATA = /*__DATA__*/null;
const OUT = DATA.outcome_order;
const LABELS = {prevented:"Prevented",detected_labelled:"Detected (labelled)",detected_unlabelled:"Detected (unlabelled)",telemetry_only:"Telemetry only",missed:"Missed",not_assessable:"Not assessable"};
const css = n => getComputedStyle(document.documentElement).getPropertyValue('--'+n).trim();
const el = (t,p={})=>Object.assign(document.createElement(t),p);
function fmtTime(s){if(!s)return "";const d=new Date(s);if(isNaN(d))return s;return d.toLocaleString();}
function tta(v){if(v==null)return "";const m=Math.round(v/60);return m>=1?m+" min":Math.round(v)+" s";}

let state={run:"",scenario:"",outcome:"",search:"",sort:"run_utc",dir:1};

function filtered(){
  return DATA.rows.filter(r=>
    (!state.run||r.run_id===state.run)&&
    (!state.scenario||r.scenario===state.scenario)&&
    (!state.outcome||r.outcome===state.outcome)&&
    (!state.search||JSON.stringify([r.ability_name,r.technique_id,r.technique_name,r.rule_ids,r.alert_mitre_ids]).toLowerCase().includes(state.search.toLowerCase()))
  );
}
function pct(n,d){return d?Math.round(100*n/d):0;}

function renderCards(rows){
  const n=rows.length;
  const c=o=>rows.filter(r=>r.outcome===o).length;
  const lab=c("detected_labelled"),unl=c("detected_unlabelled"),tel=c("telemetry_only"),prev=c("prevented");
  const det=lab+unl, vis=lab+unl+tel;
  const resp=rows.filter(r=>r.response==="executed").length;
  const ttas=rows.map(r=>r.time_to_alert_s).filter(v=>v!=null).sort((a,b)=>a-b);
  const med=ttas.length?ttas[Math.floor((ttas.length-1)/2)]:null;
  const cards=[
    ["Detection rate",`${det} of ${n}`,`${pct(det,n)}%`,"labelled + unlabelled"],
    ["Correct technique",`${lab} of ${n}`,`${pct(lab,n)}%`,"alert carried the technique"],
    ["Visibility",`${vis} of ${n}`,`${pct(vis,n)}%`,"alert or telemetry"],
    ["Prevention",`${prev} of ${n}`,`${pct(prev,n)}%`,"Wazuh is detection-only"],
    ["Response",`${resp} of ${n}`,`${pct(resp,n)}%`,resp?"active response":"active response not configured"],
    ["Median time to alert",med!=null?tta(med):"n/a","",med!=null&&med>120?"driven by ingest lag":""],
  ];
  const wrap=document.getElementById("cards");wrap.innerHTML="";
  cards.forEach(([lb,big,p,sub])=>{const d=el("div",{className:"card"});
    d.append(el("div",{className:"num",textContent:big}));
    d.append(el("div",{className:"lab",textContent:lb+(p?" ("+p+")":"")}));
    if(sub)d.append(el("div",{className:"sub",textContent:sub}));wrap.append(d);});
}
function renderBar(rows){
  const bar=document.getElementById("obar");bar.innerHTML="";
  const n=rows.length||1;
  OUT.forEach(o=>{const k=rows.filter(r=>r.outcome===o).length;if(!k)return;
    const seg=el("div",{title:`${LABELS[o]}: ${k}`});seg.style.background=css(o);seg.style.width=(100*k/n)+"%";
    seg.textContent=k;bar.append(seg);});
  const lg=document.getElementById("legend");lg.innerHTML="";
  OUT.forEach(o=>{const s=el("span");const sw=el("span",{className:"sw"});sw.style.background=css(o);
    s.append(sw,document.createTextNode(LABELS[o]));lg.append(s);});
}
function renderMatrix(rows){
  const m=document.getElementById("matrix");m.innerHTML="";
  const byT={};rows.forEach(r=>{(byT[r.tactic_norm]=byT[r.tactic_norm]||[]).push(r);});
  const tactics=DATA.tactic_order.filter(t=>byT[t]);
  Object.keys(byT).forEach(t=>{if(!tactics.includes(t))tactics.push(t);});
  tactics.forEach(t=>{const col=el("div",{className:"col"});col.append(el("h3",{textContent:t.replace(/-/g," ")}));
    byT[t].forEach(r=>{const cell=el("div",{className:"cell"});cell.style.borderLeftColor=css(r.outcome);
      cell.append(el("div",{className:"id",textContent:r.technique_id||"?"}));
      cell.append(el("div",{className:"nm",textContent:r.technique_name||r.ability_name||""}));
      cell.append(el("div",{className:"bd",textContent:(r.rule_ids?"rules "+r.rule_ids:LABELS[r.outcome])}));
      cell.onclick=()=>{state.outcome="";document.getElementById("fOutcome").value="";state.search=r.technique_id;document.getElementById("search").value=r.technique_id;render();};
      col.append(cell);});
    m.append(col);});
}
function chip(o){const c=el("span",{className:"chip",textContent:LABELS[o]||o});c.style.background=css(o);return c;}
function renderTable(rows){
  const tb=document.getElementById("tbody");tb.innerHTML="";
  const s=[...rows].sort((a,b)=>{const x=a[state.sort],y=b[state.sort];return (x>y?1:x<y?-1:0)*state.dir;});
  s.forEach((r,i)=>{const tr=el("tr");
    const techMis=r.technique_match==="different"||r.technique_match==="none";
    tr.innerHTML=`<td>${fmtTime(r.run_utc)}</td><td>${r.scenario||""}</td><td>${r.ability_name||""}</td>
      <td><b>${r.technique_id||""}</b><div class="muted">${r.technique_name||""}</div></td>
      <td>${(r.tactic||"").replace(/-/g," ")}</td><td>${r.execution||""}</td>
      <td></td><td class="mono">${r.rule_ids||""}</td>
      <td class="mono ${techMis&&r.alert_mitre_ids?"mismatch":""}">${r.alert_mitre_ids||""}</td>
      <td>${tta(r.time_to_alert_s)}</td><td>${r.response||""}</td>`;
    tr.children[6].append(chip(r.outcome));
    tr.style.cursor="pointer";tr.onclick=()=>{det.style.display=det.style.display==="table-row"?"none":"table-row";};
    const det=el("tr",{className:"det"});const td=el("td");td.colSpan=11;
    const parts=[];
    if(r.evidence&&r.evidence.length)parts.push("Alerts:\n"+r.evidence.map(e=>`  rule ${e.rule_id} L${e.rule_level??"?"} ${(e.rule_mitre_ids||[]).join(",")} ${e.relation} event ${e.event_time_utc} seen ${e.alert_time_utc}`).join("\n"));
    if(r.archive_evidence&&r.archive_evidence.length)parts.push("Telemetry events: "+r.archive_evidence.length);
    if(r.notes&&r.notes.length)parts.push("Notes:\n  "+r.notes.join("\n  "));
    td.append(el("div",{className:"exp",textContent:parts.join("\n\n")||"No correlated evidence."}));
    det.append(td);tb.append(tr);tb.append(det);});
}
function renderGaps(rows){
  const g=document.getElementById("gaps");g.innerHTML="";
  const gaps=rows.filter(r=>r.outcome!=="detected_labelled");
  if(!gaps.length){g.innerHTML='<div class="muted">Every scored technique was detected and labelled.</div>';return;}
  gaps.forEach(r=>{const d=el("div",{className:"gap"});let sug="";
    if(r.outcome==="telemetry_only")sug="Log exists but no rule fired: candidate for a custom Wazuh rule keyed on the script-block / command.";
    else if(r.outcome==="detected_unlabelled")sug="Detected but mislabelled: review the rule's ATT&CK tag ("+(r.alert_mitre_ids||"none")+") versus "+(r.technique_id||"?")+".";
    else if(r.outcome==="missed")sug="No telemetry and collection complete: a logging or visibility gap.";
    else sug="Not assessable: check PID, window and collection completeness.";
    d.innerHTML=`<b>${r.technique_id||"?"}</b> ${r.ability_name||""} <span class="muted">[${LABELS[r.outcome]}]</span><br>${sug}`;
    g.append(d);});
}
function renderHealth(){
  const h=document.getElementById("health");h.innerHTML="";
  DATA.runs.forEach(rn=>{const d=el("div",{className:"gap"});d.style.borderLeftColor=css("prevented");
    d.innerHTML=`<b>${rn.run_id}</b> (${rn.scenario||""})<br>
      Window ${rn.window_start||"?"} to ${rn.window_end||"?"}; watermark ${rn.agent_watermark||"?"};
      collection ${rn.collection_complete?"complete":"INCOMPLETE (missed not scored)"};
      archives ${rn.archive_collection_status||"?"};
      queue alerts ${(rn.queue_alert_rule_ids||[]).join(",")||"none"};
      harness excluded ${(rn.harness_rule_ids||[]).join(",")||"none"};
      defender ${rn.defender_state||""}`;
    h.append(d);});
}
function render(){
  const rows=filtered();
  document.getElementById("sub").textContent=`${DATA.control} | ${DATA.rows.length} scored rows across ${DATA.runs.length} run(s) | generated ${fmtTime(DATA.generated_at)}`;
  renderCards(rows);renderBar(rows);renderMatrix(rows);renderTable(rows);renderGaps(rows);renderHealth();
}
function fillSelect(id,label,values){const s=document.getElementById(id);s.innerHTML="";
  s.append(el("option",{value:"",textContent:label}));
  values.forEach(v=>s.append(el("option",{value:v,textContent:v})));}
function download(name,text,type){const b=new Blob([text],{type});const u=URL.createObjectURL(b);
  const a=el("a",{href:u,download:name});document.body.append(a);a.click();a.remove();URL.revokeObjectURL(u);}
function toCsv(rows){const cols=["run_id","scenario","technique_id","technique_name","tactic","ability_name","outcome","technique_match","execution","caldera_status","rule_ids","max_rule_level","alert_mitre_ids","response","time_to_alert_s","collection_complete","harness_alert_rule_ids","run_utc"];
  const esc=v=>{v=v==null?"":String(v);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  return "﻿"+cols.join(",")+"\n"+rows.map(r=>cols.map(c=>esc(r[c])).join(",")).join("\n");}
function navLayer(rows){const best={};rows.forEach(r=>{if(!r.technique_id)return;const sc={prevented:100,detected_labelled:100,detected_unlabelled:75,telemetry_only:40,missed:0,not_assessable:0}[r.outcome]||0;
  if(!best[r.technique_id]||sc>best[r.technique_id].score)best[r.technique_id]={score:sc,comment:r.outcome+"; rules "+(r.rule_ids||"none")};});
  return JSON.stringify({name:"Wazuh BAS coverage",domain:"enterprise-attack",versions:{layer:"4.5",navigator:"4.9.1",attack:"15"},
    gradient:{colors:["#d7191c","#ffffbf","#1a9641"],minValue:0,maxValue:100},
    techniques:Object.entries(best).map(([t,i])=>({techniqueID:t,score:i.score,comment:i.comment,enabled:true}))},null,2);}

fillSelect("fRun","All runs",[...new Set(DATA.rows.map(r=>r.run_id))]);
fillSelect("fScenario","All scenarios",[...new Set(DATA.rows.map(r=>r.scenario))]);
fillSelect("fOutcome","All outcomes",OUT);
document.getElementById("fRun").onchange=e=>{state.run=e.target.value;render();};
document.getElementById("fScenario").onchange=e=>{state.scenario=e.target.value;render();};
document.getElementById("fOutcome").onchange=e=>{state.outcome=e.target.value;render();};
document.getElementById("search").oninput=e=>{state.search=e.target.value;render();};
document.querySelectorAll("th[data-k]").forEach(th=>th.onclick=()=>{const k=th.dataset.k;state.dir=state.sort===k?-state.dir:1;state.sort=k;render();});
document.getElementById("dlCsv").onclick=()=>download("results-combined.csv",toCsv(filtered()),"text/csv");
document.getElementById("dlNav").onclick=()=>download("navigator-wazuh.json",navLayer(filtered()),"application/json");
document.getElementById("theme").onclick=()=>{const r=document.documentElement;r.dataset.theme=r.dataset.theme==="dark"?"light":"dark";render();};
render();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
