# Wazuh Automation

This automation retrieves CALDERA execution evidence and Wazuh alerts, selects the collection window, correlates the records and generates CSV/JSON results.

The operator starts the test and finishes the operation in CALDERA. The automation then retrieves and processes its evidence after the operator supplies the operation ID and credentials.

## 1. Requirements and deployment

The automation runs on the Windows laptop. Test actions execute on the Windows test VM, and Wazuh detection evidence is collected from the Ubuntu Wazuh server.

| Component | Requirement |
|---|---|
| Windows laptop | Python 3.10 or newer, PowerShell and Paramiko, installed through requirements.txt |
| CALDERA Ubuntu VM | Running API and active red API key |
| Wazuh Ubuntu VM | Running Wazuh services, SSH and sudo access to alert files |
| Windows test VM | CALDERA agent, Wazuh agent, Sysmon and configured event forwarding for the current workflow |

The laptop must reach the CALDERA API and Wazuh SSH service. Keep the laptop and VM clocks synchronized.

### Install Sysmon and configure Wazuh event collection

Sysmon is required for the current CertUtil detection and matching workflow. It provides process-creation events containing executable paths, command lines, process IDs and parent-process information.

Perform these steps inside the **Windows test VM**, using **PowerShell as Administrator**. Sysmon does not need to be installed on the Windows laptop or Ubuntu servers.

#### 1. Check whether Sysmon is already installed

```powershell
Get-Service -Name '*Sysmon*'
```

If a Sysmon service exists and is running, skip installation and verify event collection below. Do not replace an existing configuration without reviewing it.

#### 2. Download and install Sysmon

For the lab's 64-bit Windows test VM:

```powershell
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$env:TEMP\Sysmon.zip"

Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force

& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i
```

This installs Sysmon using its default configuration and accepts the Microsoft licence terms. Internet access is required for the download.

The default configuration was used for this pilot. Other test procedures may require additional event types or configuration changes.

Verify the service:

```powershell
Get-Service -Name '*Sysmon*'
```

The installed service should show **Running**.

#### 3. Configure the Wazuh agent to collect Sysmon events

Back up the existing agent configuration:

```powershell
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$backupPath = "$configPath.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -LiteralPath $configPath -Destination $backupPath
```

Open it:

```powershell
notepad.exe $configPath
```

Add the following block **inside the existing `<ossec_config>` element**, before its closing `</ossec_config>` tag:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

If this channel is already configured, do not add a duplicate block. Keep the other existing settings.

Save the file, close Notepad and restart the Wazuh agent:

```powershell
Restart-Service -Name WazuhSvc
Get-Service -Name WazuhSvc
```

The service should show **Running**.

#### 4. Verify local process-event recording

Generate a harmless process event:

```powershell
whoami.exe
```

Display recent Sysmon process-creation events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
    StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 10 | Format-List TimeCreated, Id, Message
```

Look for an event containing `whoami.exe`.

This verifies local recording; it does not by itself prove that Wazuh received the event or generated an alert.

#### 5. Check Wazuh collection startup

```powershell
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 100 |
    Select-String -Pattern 'Sysmon|ERROR|WARNING'
```

Look for a message indicating that the agent is analysing the `Microsoft-Windows-Sysmon/Operational` channel, and review any errors.

During the subsequent CALDERA test, use the collected Wazuh evidence to confirm server-side receipt and detection. Not every recorded process event generates an alert.

Retain the Sysmon version and configuration used for the evaluation so later results can be compared against the same baseline.

## 2. Framework files

Extract caldera-wazuh-automatic-collection.zip and keep these files together in the automatic-collection folder:

| File | Purpose |
|---|---|
| collect_operation.py | Retrieves the report, derives the window, collects alerts and invokes matching |
| remote_collect.py | Reads Wazuh alert files and is executed remotely through SSH |
| match_results.py | Matches evidence and generates results |
| config.json | Stores addresses, endpoint mapping and timing settings |
| requirements.txt | Declares the Paramiko dependency |
| test_workflow.py | Runs offline checks |

The remote collector does not need to be manually installed on the Wazuh VM.

## 3. One-time setup

### 3.1 Open PowerShell in the extracted folder

Open the folder containing collect_operation.py in File Explorer. Click the address bar, type powershell and press Enter.

Alternatively, use the actual extracted folder path:

~~~powershell
cd "PASTE THE EXTRACTED FOLDER PATH HERE"
dir
python --version
~~~

Confirm that collect_operation.py and config.json appear in the listing and Python is version 3.10 or newer.

### 3.2 Create a virtual environment and install dependencies

Run these commands from the extracted `automatic-collection` folder on the Windows laptop:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Use the virtual environment’s Python to execute the automation:

```powershell
.\.venv\Scripts\python.exe .\collect_operation.py --list
```

```powershell
.\.venv\Scripts\python.exe .\collect_operation.py --operation YOUR-OPERATION-ID
```

Calling the virtual environment’s Python directly avoids needing to activate it or change PowerShell’s execution policy.

Create the environment once. Reuse it for subsequent runs.

### 3.3 Establish SSH host trust

From the same Windows account that will run the automation, connect to the Wazuh server:

~~~powershell
ssh test@192.168.134.133
~~~

Replace the username and address if they differ in your environment.

Before accepting a new host key, verify its fingerprint against the Wazuh VM. For an ED25519 host key, run this command in the Ubuntu VM console:

~~~bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
~~~

After verifying and successfully connecting, return to Windows PowerShell:

~~~bash
exit
~~~

If this Windows account has already connected to the same server and verified its key, this step need not be repeated. The automation reads the Windows user's .ssh/known_hosts file and rejects unknown or changed server keys.

### 3.4 Obtain the CALDERA API key

For the current CALDERA 5.3.0 server started with --insecure, run in the CALDERA Ubuntu VM:

~~~bash
cd ~/caldera
grep '^api_key_red:' conf/default.yml
~~~

Enter the **value associated with api_key_red**, excluding surrounding quotes, when prompted by the automation. This is different from the CALDERA dashboard password.

If CALDERA uses another configuration, obtain the key from that active configuration instead. Do not include the API key in documentation or screenshots.

### 3.5 Check config.json

~~~json
{
  "caldera_url": "http://192.168.134.131:8888",
  "wazuh_host": "192.168.134.133",
  "wazuh_port": 22,
  "wazuh_user": "test",
  "windows_host": "Test",
  "wazuh_agent_id": "001",
  "before_seconds": 30,
  "after_seconds": 90,
  "ingestion_grace_seconds": 30
}
~~~

Update the following values for your environment:

- **caldera_url:** CALDERA server URL, including the protocol and port.
- **wazuh_host:** Wazuh SSH hostname or IP address, without http:// or https://.
- **wazuh_port:** SSH port, normally 22.
- **wazuh_user:** Ubuntu account used to access the Wazuh server.
- **windows_host:** Target hostname as recorded in CALDERA and Wazuh.
- **wazuh_agent_id:** Wazuh agent ID for that target.

Keep the agent ID as the string "001" to preserve its leading zeros. Do not add passwords or API keys to this file.

The supplied HTTP CALDERA address is intended for the controlled lab network; it does not encrypt the API key in transit.

## 4. Commands for each collection

### 4.1 Complete the test operation

Run the selected test in CALDERA. Wait for the intended abilities to complete, review execution status, then finish/close the operation. Do not interrupt an executing ability just to satisfy the collector.

The script rejects an operation without a finish timestamp or a selected step without a completion timestamp.

### 4.2 List operation IDs

From Windows PowerShell in the automatic-collection folder:

~~~powershell
python .\collect_operation.py --list
~~~

Enter the CALDERA red API key at the hidden prompt. Copy the UUID for the intended operation from the listing.

### 4.3 Run automated collection

~~~powershell
python .\collect_operation.py --operation YOUR-OPERATION-ID
~~~

Replace YOUR-OPERATION-ID with the UUID from the listing.

Enter the credentials when prompted:

1. CALDERA red API key.
2. Ubuntu SSH password for the configured Wazuh user.
3. Ubuntu sudo password, normally the same Ubuntu account password.

Typed characters are hidden. Credentials are not written to the output files.

To specify a destination:

~~~powershell
python .\collect_operation.py --operation YOUR-OPERATION-ID --out .\runs\certutil-validation-001
~~~

The output folder must not already exist. Choose a new name for another collection.

## 5. Automatic collection window and matching scope

By default, collection covers **30 seconds before the earliest step delegation through 90 seconds after the latest step completion**. The script waits a further **30 seconds for ingestion** before collecting alerts. If that time has already passed, no additional wait is needed.

These timings are derived from the CALDERA report and the settings in config.json. The operator does not need to enter timestamps manually.

The current matcher supports **Sysmon process-creation evidence for the executor and its direct child processes**. It checks endpoint identity, compatible timestamps, process relationships and the full normalized execution command. An ATT&CK technique ID alone is not sufficient to establish a match.

Other event types and EDR platforms require additional collection and matching logic. The ingestion allowance does not guarantee that every event has arrived.

## 6. Output files

The default destination is a new folder under runs, named using a UTC timestamp and operation ID prefix.

| File | Contents |
|---|---|
| caldera-report.json | Execution report and available command output |
| wazuh-alerts.json | Alerts, collection timestamp and scanned files |
| run-metadata.json | Operation ID, endpoint mapping and calculated window |
| results/results.csv | Summary rows for review in Excel |
| results/results.json | Matching evidence and limitations |

Retain the entire run folder so each summary remains traceable to its source evidence.

## 7. Result interpretation

| Value | Meaning |
|---|---|
| execution: reported_success | CALDERA reported status 0 |
| detection: observed | At least one alert satisfied matching conditions |
| no_matching_alert_observed | No match in available records; not automatically a missed detection |
| ambiguous_review | Evidence may correspond to multiple steps |
| prevention: not_established | A blocking outcome has not been established |
| response: not_assessed | Automated response evaluation is not implemented |
| matched_alert_count | Alerts uniquely matched to the step |
| output_present | Whether the step export includes an output field |

Output presence does not by itself establish that the output satisfies the procedure's intended outcome.

The current version evaluates one configured endpoint per invocation and supports a maximum one-day collection window. Missing telemetry, expired log retention or ingestion delays must be considered before reporting a detection gap.


