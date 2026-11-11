# Security Architecture Control Evaluation — own-PC handover

**Prepared:** 10 November 2026 (Singapore time)  
**Scope:** Recreate the isolated CALDERA–Wazuh lab on another PC and continue the detection evaluation. This is a project handover, not proof that a new installation has been tested.

## 1. Project goal and current boundary

Run a fixed set of ATT&CK-mapped CALDERA abilities on a Windows 11 lab VM, keep CALDERA's execution record, collect Wazuh alerts and raw events, and compare the two. The mentor's current priority is **detection**. Prevention and response are not being scored until the other endpoint products have suitable access and policy configuration.

Keep these outcomes separate:

| Outcome | Evidence needed |
| --- | --- |
| Executed | CALDERA output plus a behavior-specific artifact or other ground truth where relevant |
| Event collected | A matching Wazuh archive event from the intended endpoint and time window |
| Related alert | A Wazuh alert attributable to the same action |
| Technique-specific detection | An alert whose rule and event content actually identify the tested behavior |
| Unverified | Evidence source, agent health, timing, or correlation is insufficient |

An ATT&CK tag or generic process-creation alert is not automatically a technique-specific detection. A missing matched alert is not automatically a missed detection.

## 2. Source files to take to the new PC

The project repository is `https://github.com/1008tommy/WazuhAutomation`. Its `main` branch contains:

```text
README.md                                               CALDERA 5.3.0 installation notes
Scenarios/README.md                                     Scenario purpose and prerequisites
Scenarios/*.yaml                                        Five CALDERA adversary UI exports
Scenarios/portable/README.md                            Portable bundle installation and update guide
Scenarios/portable/install_bundle.py                    Copies abilities, profiles, fact source and payload into CALDERA
Scenarios/portable/check_bundle.py                      Offline structural check
Scenarios/required-payloads/lab-note.ps1                Harmless file-delivery test payload
caldera-wazuh-automatic-collection/automatic-collection/
  README.md                                             Collector instructions and limits
  collect_operation.py                                  Retrieves a finished operation and Wazuh evidence
  match_results.py                                      Matches supported Sysmon evidence
  remote_collect.py                                     Read-only Wazuh manager collection code
  test_workflow.py                                      Offline tests
  requirements.txt
```

On the **new Windows host**, clone the repo in PowerShell:

```powershell
git clone --branch main --single-branch https://github.com/1008tommy/WazuhAutomation.git "$HOME\WazuhAutomation"
```

If the directory already exists, use `git -C "$HOME\WazuhAutomation" pull --ff-only` after checking for local changes. The repository's `config.json` was committed earlier and contains **historical lab addresses and endpoint mapping**; replace those values for the new PC. A `.gitignore` entry does not untrack an already committed file. Credentials are requested at runtime, and `runs/` evidence is local; copy past run artifacts separately only if needed and permitted. Do not put secrets or real sensitive files in Git.

## 3. Recreate the isolated lab

Use a host PC with sufficient resources for an Ubuntu CALDERA VM, an Ubuntu Wazuh VM, and a Windows 11 test VM. Keep the three VMs on an isolated lab network where the Windows VM can reach both servers. Record the **new** IP addresses, VM names, and time zones. Historical `192.168.234.x` addresses and historical Wazuh agent IDs are examples, not new-PC settings.

1. **CALDERA VM:** Follow the repository's root `README.md` for the lab's CALDERA 5.3.0, Git submodules, Python environment, Node.js 22, and `tmux` setup. Confirm Stockpile is present and enabled. Wait for `All systems ready` and verify the dashboard opens from the Windows host. The initial `--build` launch is documented there.
2. **Wazuh VM:** The prior lab used the Wazuh 4.14 all-in-one installation assistant. Follow the [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html) and record the installed version and new dashboard address. Install and enroll the [Windows Wazuh agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html) against this manager. Verify the new endpoint appears as **active** and record its agent ID.
3. **Windows 11 test VM:** Install Sysmon with a known configuration and configure the Wazuh agent to collect `Microsoft-Windows-Sysmon/Operational`, as described in the [Wazuh Sysmon guide](https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html). Verify the Sysmon channel and Wazuh agent service. Create `C:\BASLab` for the synthetic scenario inputs. Install a CALDERA agent with `cmd` and `psh` executors and confirm it is visible in the CALDERA dashboard.
4. **Wazuh archive evidence:** On the manager, check that JSON archives are enabled with `<logall_json>yes</logall_json>` in `/var/ossec/etc/ossec.conf` and that `/var/ossec/logs/archives/archives.json` receives events. Alerts are in `/var/ossec/logs/alerts/alerts.json`. Follow the [Wazuh event logging guide](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html) if archive collection is not configured. The collector needs SSH access and the account's normal sudo rights to read these files.
5. **Time and identity:** Check that the host, Windows VM, and both Ubuntu VMs have synchronized clocks. Record the Windows hostname from `hostname` and the corresponding Wazuh agent ID from the dashboard. The latest saved run on the old machine used `WIN11-TEST01` and agent `003`, but a rebuilt VM will have its own identity.

Read-only checks after setup:

```powershell
# On the Windows test VM
hostname
Get-Service WazuhSvc
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
    Select-Object LogName, RecordCount, IsEnabled
```

```bash
# On the Wazuh VM
sudo systemctl status wazuh-manager --no-pager
sudo grep -n '<logall_json>' /var/ossec/etc/ossec.conf
sudo ls -lh /var/ossec/logs/alerts/alerts.json /var/ossec/logs/archives/archives.json
```

These checks establish service and file state at the time of inspection; a controlled test is still needed to prove end-to-end collection.

## 4. Install the five CALDERA scenarios

On the **CALDERA Ubuntu VM**, clone the same repository outside the CALDERA checkout, stop the server, install the bundle, then restart CALDERA:

```bash
git clone --branch main --single-branch https://github.com/1008tommy/WazuhAutomation.git "$HOME/WazuhAutomation"
python3 "$HOME/WazuhAutomation/Scenarios/portable/install_bundle.py" --caldera-root "$HOME/caldera"
```

Use the actual checkout path if it is not `$HOME/caldera`. The installer checks for a CALDERA checkout and Stockpile; it installs **five profiles, fifteen custom abilities, a Thief-Lab fact source, and `lab-note.ps1`**. Two Thief-Lab abilities come from Stockpile. Restart CALDERA and confirm each adversary shows named abilities, not `Undefined Ability`. Do not import the standalone adversary YAML as the only migration step: those exports reference ability IDs and do not supply every ability definition.

For an existing bundle installation, stop CALDERA, then run:

```bash
git -C "$HOME/WazuhAutomation" pull --ff-only
python3 "$HOME/WazuhAutomation/Scenarios/portable/install_bundle.py" --caldera-root "$HOME/caldera" --upgrade
```

Restart afterward. `--upgrade` only replaces known earlier bundle files; it rejects independently edited conflicting files. Details are in `Scenarios/portable/README.md`.

| Scenario | Purpose | Setup before each run |
| --- | --- | --- |
| Discovery Scenario | Six read-only Windows discovery abilities | Working `cmd`/`psh`; Defender cmdlets for final step; no input fact or payload |
| Scheduled Task Creation | Create and trigger `CALDERA-Lab-Test` | Ensure that task and `C:\BASLab\task-executed` are absent |
| Renamed Utility Lab | Copy and run `whoami.exe` as `lab-helper.exe` | Ensure `C:\BASLab\masquerade-test` is absent |
| File Delivery and Execution Lab | Download and run harmless `lab-note.ps1` | Reachable CALDERA server, bundled payload present, `C:\BASLab\delivery-test` absent |
| Thief-Lab | Stage, archive, and upload one synthetic file to the lab server | Exactly one synthetic file in `C:\BASLab\input`; select **Thief-Lab** fact source; set `file.sensitive.extension` without the dot; staged directory/zip absent |

Use one profile at a time, the intended Windows agent, the atomic planner, and the ability cleanup configured in the bundle. Check the scenario README for further prerequisites and expected artifacts.

## 5. Configure the Windows evidence collector

On the **new Windows host**, open PowerShell in:

```powershell
Set-Location "$HOME\WazuhAutomation\caldera-wazuh-automatic-collection\automatic-collection"
```

The collector README says to copy `config.example.json`, but **that file is absent from the inspected checkout**. The checkout already contains a tracked `config.json` with old lab settings. Edit that file for the new lab using this shape, replacing every placeholder with the new lab's values:

```json
{
  "caldera_url": "http://<CALDERA_VM_IP>:8888",
  "wazuh_host": "<WAZUH_VM_IP>",
  "wazuh_port": 22,
  "wazuh_user": "<UBUNTU_SSH_USER>",
  "windows_host": "<WINDOWS_VM_HOSTNAME>",
  "wazuh_agent_id": "<WAZUH_AGENT_ID>",
  "before_seconds": 30,
  "after_seconds": 90,
  "ingestion_grace_seconds": 30
}
```

Keep the Wazuh agent ID as a **string**, including any leading zeros. Because `config.json` is tracked, local changes will appear in `git status`; do not commit machine-specific values. Alternatively, save the new configuration outside the checkout and pass its path with `collect_operation.py --config <PATH>`. The CALDERA red API key is requested at runtime and must not be added to either file.

Install the Python dependencies and run the offline tests from that folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\test_workflow.py
```

If `py` is unavailable, use an installed `python` executable. Before live collection, SSH from the **same Windows account** to the Wazuh VM and verify its host-key fingerprint against the VM; the collector rejects unknown or changed keys. Ensure the SSH user has the required sudo access. See the collector README for the three credential prompts and exact trust procedure.

## 6. Run, collect, and interpret one scenario

1. Check the scenario-specific starting state and create only synthetic inputs.
2. Start a CALDERA operation with the correct adversary, Windows agent, and fact source (for Thief-Lab). Inspect every ability's output and any expected marker or archive. Finish the operation after all steps complete.
3. In the collector folder on the Windows host, list and collect the finished operation:

   ```powershell
   .\.venv\Scripts\python.exe .\collect_operation.py --list
   .\.venv\Scripts\python.exe .\collect_operation.py --operation YOUR-OPERATION-ID
   ```

4. Enter the CALDERA red API key, Wazuh SSH password, and sudo password when prompted. The collector saves a new `runs/<UTC-time>-<operation-prefix>/` folder containing `caldera-report.json`, `wazuh-alerts.json`, `wazuh-archives.json`, `run-metadata.json`, and `results/results.json` plus `results/results.csv`.
5. Review **both** `event_collection` and `detection` for each ability. Check the matched evidence, rule IDs, command, endpoint identity, and time window before assigning a technique-level verdict. Retain the raw files with the evaluation record. The matcher has defined Sysmon process and selected file-creation coverage; it is not a universal technique evaluator.

If the collector says **“No operation steps found for the configured Windows hostname”**, compare `windows_host` with the exact host in that CALDERA operation's report. Do not assume an old VM name or agent ID. If archives are empty, check Sysmon, Wazuh agent health, archive configuration, time sync, and ingestion delay before scoring a miss.

## 7. Findings and limitations carried forward

- The five scenario profiles have been developed and earlier runs were collected on the old lab. The saved November 4 run folders are local, ignored artifacts; their existence does not mean a new PC has reproduced them.
- Wazuh often collected related Sysmon process or file events, but many alerts were **generic**. Report telemetry and related alerts separately from a specific ATT&CK-technique detection.
- CALDERA's shared Atomic PowerShell parser caused a previous Defender-enumeration ability to show `failed` despite stdout. The portable Discovery bundle includes a separate **Lab Windows Defender Enumeration** ability without that parser. Preserve the original link status when reviewing historical runs.
- SentinelOne local history showed an EICAR detection and quarantine, but the checked CALDERA activity was not visible as a local threat. Without console or API evidence, its CALDERA detection outcome remains **unverified**.
- Carbon Black's `Sensor.LOG` showed a registration timeout (`0x80072EE2`) and process-context diagnostics. Its local `EventLogs` files require Carbon Black EDR server processing; neither the local diagnostic log nor a running sensor service proves whether CALDERA actions were detected. Confirm server connectivity and obtain server-side events/alerts before scoring Carbon Black. See [Broadcom's local-event explanation](https://knowledge.broadcom.com/external/article/288258/cb-response-can-local-sensor-eventlogs-t.html).
- The current project scope remains Wazuh detection. Avoid comparing controls or claiming overlap until their evidence access and test conditions are comparable.

## 8. Next work on the new PC

1. Record the VM inventory: OS, addresses, CALDERA/Wazuh versions, Windows hostname, Wazuh agent ID, agent health, clock status, and Sysmon configuration.
2. Install and validate the portable bundle. Confirm all five profiles, ability names, Thief-Lab fact source, and payload.
3. Recreate `config.json` with the new endpoint mapping; run offline tests and one controlled scenario. Verify that CALDERA ground truth, Wazuh archives, and any alerts refer to the **same** VM and operation window.
4. Build a scenario-by-control matrix with execution, event collection, related alert, technique-specific alert, evidence path, and limitations. Keep unavailable EDR evidence marked **unverified**.
5. When the mentor provides management-console or API access for other products, repeat comparable scenarios with documented policy and agent health. Do not infer a negative detection verdict from local threat history alone.

## Reference documents

- Repository root: `README.md`
- Scenario setup: `Scenarios/README.md`
- Bundle installation: `Scenarios/portable/README.md`
- Collection: `caldera-wazuh-automatic-collection/automatic-collection/README.md`
- This handover was prepared from the project files and the discussion through 10 November 2026. Verify all environment-specific facts on the new PC before using them in the final report.

