# Wazuh BAS automation

Runs ATT&CK-mapped lab scenarios through the Caldera API, collects the matching Wazuh evidence,
scores each technique, and shows the result as a dashboard. It is read-only toward Wazuh (a bundled
collector over SSH, nothing installed on the server) and launches only the lab scenarios in
`scenarios/` against group `red` on `WIN11-TEST01`.

## Setup (Windows laptop)

1. Python 3.11+ (Wazuh's `+0800` offsets and 7-digit fractions need 3.11).
2. `python -m pip install -r requirements.txt`
3. Copy `config.example.json` to `config.json` and set your lab values, including the Wazuh SSH
   username in `wazuh_user`. `config.json` is gitignored.
4. Trust the Wazuh SSH host key once: `ssh <wazuh_user>@<Wazuh server IP>`, verifying the fingerprint on the
   VM with `sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`, then exit.

The Caldera API key and the SSH/sudo passwords are entered at hidden prompts, never stored.

## Use

Prerequisites in the lab: Caldera running in tmux, the scenario bundle installed
(`Scenarios/portable/install_bundle.py`), and the Sandcat agent checked in on `WIN11-TEST01`.

- **Control console (launch from the browser):** `python serve_dashboard.py`, then open
  `http://127.0.0.1:8787`. The *Run a scenario* tab launches a scenario on the endpoint, verifies
  cleanup, collects, scores and refreshes the results. Localhost only.
- **One scenario from the CLI:** `python run_scenario.py scenarios/discovery.json --collect`
- **Score an operation that already ran:** `python collect_operation.py --list`, then
  `python collect_operation.py --operation <id>`
- **Rebuild the static report:** `python build_dashboard.py` writes `dashboard/index.html` (a
  self-contained, air-gapped page), a combined CSV and an ATT&CK Navigator layer.

### Try a dashboard launch

The generated `dashboard/index.html` (or `dashboard-preview/index.html`) is an offline report and
shows **Show command**. To get a **Launch** button, start the local control server from this folder:

```powershell
python serve_dashboard.py
```

The dashboard reads this folder's `config.json` by default. To use a config file in another folder,
start it with `python serve_dashboard.py --config 'C:\path\to\config.json'`. The same selected config
is passed to both the CALDERA runner and the Wazuh collector. The SSH password prompt shows the
configured username and host, so verify them before entering the password.

For example, if your `config.json` lives in another checkout of this repo:

```powershell
python serve_dashboard.py --config "<that checkout>\caldera-wazuh-automatic-collection\automatic-collection\config.json"
```

Enter the CALDERA red API key and Wazuh SSH/sudo passwords at the hidden terminal prompts, keep
that terminal open, then visit `http://127.0.0.1:8787` in the same PC's browser. Choose **Run a
scenario** and start with **Discovery Scenario**. The server allows one scenario at a time and shows
progress in **Activity**. Before each launch the page runs read-only lab checks (Caldera API, the Sandcat
agent, and the Wazuh agent's status on the manager) and does not launch while one fails. The last
run's activity log stays on the page after it reloads, and every log is saved in `console-logs/`. It uses CALDERA's API to run on the configured Windows agent, then saves
the CALDERA report, Wazuh evidence, and scored results under `runs/`. When collection succeeds, the
page refreshes with the new result. Operation, cleanup, collection, or rebuild failures appear in
**Activity** and are not reported as successful runs.

## How scoring works

Correlation is on the Windows **event time** (`data.win.system.systemTime`), never the manager
`timestamp`, which records when Wazuh processed the event. That is normally a few seconds later, but
while the agent cannot reach the manager it holds its events and sends them when the manager is back,
so a run made with the manager down was stamped about 20 minutes late. Start the Wazuh manager first
and check that the agent is active before a run. The collector waits up to five minutes for the agent's
alert watermark to pass the window end. If it does not advance (for example, because there are no
later alerts), collection continues with `collection_complete=false`; a step without evidence is
`not_assessable`, not `missed`. The collector checks the watermark every 15 seconds by default;
`watermark_poll_seconds` and `max_ingest_wait_seconds` in `config.json` control polling and the
maximum wait. Each step gets one outcome:

`prevented` · `detected_labelled` (alert carries the technique) · `detected_unlabelled` (alert, wrong
tag) · `telemetry_only` (log, no alert) · `missed` (nothing, collection verified complete) ·
`not_assessable`.

Evidence adapters: PowerShell 4104 script blocks, Sysmon process creation (executor, child,
scheduled-task action), and reported file creation. The `__PSScriptPolicyTest_` / rule 92213 harness
artifact is recorded but never scored.

## Guardrails

- Read-only toward Wazuh; Caldera writes limited to the scenarios in `scenarios/`.
- Runs only group `red` on `WIN11-TEST01`; refuses any other host, an untrusted or stale agent, or any
  obfuscator but `plain-text`. Cleanup is verified after every run; revert the VM snapshot if it fails.
- Never calls `/api/v2/operations/summary` (HTTP 500 on 5.3.0) and never starts Caldera with `--fresh`.

## Tests

`python -m unittest` from this folder runs `test_workflow.py` and `test_dashboard_flow.py` (offline;
no server contact).
