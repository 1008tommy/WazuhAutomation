# Wazuh BAS automation

Runs ATT&CK-mapped lab scenarios through the Caldera API, collects the matching Wazuh evidence,
scores each technique, and shows the result as a dashboard. It is read-only toward Wazuh (a bundled
collector over SSH, nothing installed on the server) and launches only the lab scenarios in
`scenarios/` against group `red` on `WIN11-TEST01`.

## Setup (Windows laptop)

1. Python 3.11+ (Wazuh's `+0800` offsets and 7-digit fractions need 3.11).
2. `python -m pip install -r requirements.txt`
3. Copy `config.example.json` to `config.json` and set your lab values. `config.json` is gitignored.
4. Trust the Wazuh SSH host key once: `ssh labadmin@(Wazuh server IP)`, verifying the fingerprint on the
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

## How scoring works

Correlation is on the Windows **event time** (`data.win.system.systemTime`), never the manager
`timestamp`, which lags about 20 minutes here. The collector waits until the agent's event watermark
passes the window end before scoring, so a lagged detection is never mistaken for a miss. Each step
gets one outcome:

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

`python -m unittest test_workflow` (offline; no server contact).
