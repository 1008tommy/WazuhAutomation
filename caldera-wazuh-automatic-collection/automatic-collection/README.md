# Automatic CALDERA / Wazuh evidence retrieval

This version replaces manual report downloads, alert export, SCP, and time entry. Start and finish your approved test in CALDERA yourself, then supply its operation ID. The script retrieves evidence and runs the matching script. It does not launch TTPs, stop operations, alter detection rules, change sudo privileges, or install anything on either server.

## Setup on the Windows laptop
1. Extract this ZIP and open PowerShell in the automatic-collection folder (the folder containing collect_operation.py).
2. Install the SSH library:

    python -m pip install -r requirements.txt

3. Copy config.example.json to config.json in the same folder, then set your own lab's values in config.json. config.json is gitignored, so each user keeps their own:
   - CALDERA: http://(Whatever your IP address for the CALDERA server is):8888
   - Wazuh SSH: labadmin@(Whatever your IP address for the Wazuh server is), port 22
   - Windows hostname: WIN11-TEST01; Wazuh agent ID: "001" (keep quotation marks)
4. This Windows account must already trust the Wazuh SSH host key. You previously connected via SSH; if using a different Windows account, first connect:

    ssh labadmin@(Whatever your IP address for the Wazuh server is)

   Verify the server fingerprint against the Ubuntu VM before accepting a new key. On Ubuntu, display it with:

    sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

   Exit SSH afterward. The script uses your Windows user's .ssh/known_hosts file and rejects unknown or changed keys. Do not remove key checking to resolve a mismatch.

## Find your CALDERA API key
This is not the red account's dashboard password.
For the existing server started with --insecure, CALDERA 5.3.0 uses conf/default.yml.
Run locally in the CALDERA Ubuntu console:

    cd ~/caldera
    grep '^api_key_red:' conf/default.yml

Use the value after the colon, without surrounding YAML quotes, when prompted on Windows. Do not paste the key in chat or screenshots. If you use another environment/configuration, obtain its active api_key_red instead.

The existing HTTP lab address does not encrypt the API key in transit. Use it only on your controlled lab network. The script supports HTTPS with normal certificate validation if configured; it does not disable TLS validation.

## List operation IDs
From the extracted folder on Windows:

    python .\collect_operation.py --list

Enter the CALDERA red API key at the hidden prompt. It prints operation IDs, names and states. Copy the ID of the intended run.

## Collect a completed test
Wait until the ability has completed and inspect its execution result in CALDERA. Finish/close the operation in CALDERA when ready. Do not stop a still-running ability simply to satisfy the collector. The supplied older report had finish=null; this version refuses an unfinished operation.

    python .\collect_operation.py --operation YOUR-OPERATION-ID

Replace YOUR-OPERATION-ID with the UUID printed by --list. Enter:
1. CALDERA API key.
2. Ubuntu SSH password.
3. Ubuntu sudo password (normally the same Ubuntu account password).

Characters are hidden. Credentials are held only for the running process and are not written into files. The SSH collector uses normal sudo authorization; no sudoers changes are required.

The first version automates work after these prompts; it is not an unattended credential setup.

## What happens
- Request POST /api/v2/operations/{id}/report with enable_agent_output=true.
- Require a finalized operation and completed steps for the configured endpoint.
- Start window: earliest step delegation minus 30 seconds.
- End window: latest step completion plus 90 seconds.
- Wait until the end plus a further 30-second ingestion allowance.
- Check Wazuh server clock against the collector computer (within 30 seconds).
- Execute the bundled read-only Python collector via SSH with sudo; collect alerts for the configured agent.
- Read current alerts.json and available Wazuh standard daily JSON/gzip alert files for the relevant dates; remove duplicate alert IDs. A partially written final line in a live JSON file is skipped and reported in `incomplete_tail_files`; malformed complete lines still fail collection.
- Refetch the report and reject a changed operation snapshot.
- Save inputs, run metadata, and matching results locally.

CALDERA 5.3.0's report field run is link.finish. It is not a precise process-start timestamp. This version explicitly records that meaning and matches event times within delegation-to-completion bounds plus the matcher's tolerance.

Example for the existing pilot:
delegation 02:35:25Z; completion 02:35:37Z;
collection window 02:34:55Z through 02:37:07Z;
collection permitted after 02:37:37Z.
These values are calculated, not typed by the operator.

## Output
Each invocation creates a new runs/<UTC timestamp>-<operation ID prefix> folder containing:
- caldera-report.json (command output when available from CALDERA)
- wazuh-alerts.json (with collection time and files scanned)
- run-metadata.json
- results/results.csv
- results/results.json

Run folders are never overwritten. If using the same operation twice within one second, wait or supply --out a-new-folder.

The matching behavior covers Sysmon process-creation alerts for the executor/direct child, using endpoint, time, PID and full normalized command. The endpoint check requires the configured Wazuh agent ID, its IP when CALDERA supplies one, and the Windows event's `data.win.system.computer` matching the CALDERA hostname. Older exports without `computer` fall back to `agent.name`. Wazuh's enrollment name may differ from the Windows hostname. It also links a scheduled-task action to a successful same-agent `schtasks /Create` and `/Run` sequence when the task name and full registered action match, and Sysmon identifies the Task Scheduler service as the action's parent. For a successful T1105 step that outputs one downloaded file path, it can link a Sysmon Event ID 11 file-creation alert when the endpoint, time, executor PID, and exact target path match. A T1036.003 staging step using `Copy-Item` can likewise match an Event ID 11 file creation when its successful CALDERA output reports the exact target path and the same endpoint, time, and executor PID match. Other file writes by that PowerShell process are not counted. File creation does not prove technique-specific recognition, and T1105 file creation alone does not prove the transfer source. Other types of TTP evidence require additional adapters. Raw operation evidence is preserved; evaluation is restricted to the configured Windows hostname.

Results focus on detection: `event_collection` records whether matching process or file-creation events were collected, while `detection` records whether a related Wazuh alert was observed. A related alert does not by itself prove that Wazuh recognized the specific ATT&CK technique.

## Limits and troubleshooting
- Live access to your servers has NOT been tested here. Offline regression tests cover mocked API/SSH orchestration, window selection, open/incomplete operation rejection, scheduled-task action, T1105 download-file and T1036.003 staged-file matching, daily gzip de-duplication and malformed JSON handling. Saved runs can also be reprocessed locally with the matcher.
- HTTP 401/403: verify active API key. HTTP 404: check URL/operation ID/version.
- Operation still open: finish it in CALDERA after execution completes, then retry.
- SSH authentication failed: verify Ubuntu credentials and configured IP.
- Unknown SSH host key: use normal SSH and verify the fingerprint on your VM.
- Sudo denied: your account needs the same sudo authorization used by the existing manual collector. The script does not bypass it.
- Time errors: synchronize Windows host, Windows test VM and Ubuntu VMs.
- The wait allowance does not prove every alert arrived. Increase the configured allowance for known delays; do not label empty results as missed without confirming telemetry health.
- Historical missing/rotated/deleted files cannot be recovered by this script. files_scanned and completeness report what was available.
- One-day maximum collection window in this prototype; multi-endpoint operations need separate endpoint mappings/invocations.
- Missing output remains missing evidence; a nonzero execution status needs review.
- This version does not infer full ATT&CK coverage.
- Logs and exports may contain command strings. The matcher treats them as data and never executes them.

## Offline tests
    python .\test_workflow.py

test-fixtures contains the previously supplied evidence for reproducibility.

## Implementation references
Verified against CALDERA 5.3.0 source:
https://github.com/mitre/caldera/blob/5.3.0/app/api/v2/handlers/operation_api.py
https://github.com/mitre/caldera/blob/5.3.0/app/objects/c_operation.py
https://github.com/mitre/caldera/blob/5.3.0/app/service/auth_svc.py
https://github.com/mitre/caldera/blob/5.3.0/server.py
SSH client / host-key behavior:
https://docs.paramiko.org/en/stable/api/client.html
