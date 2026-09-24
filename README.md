# WazuhAutomation
This automation retrieves CALDERA execution evidence and Wazuh alerts, selects the collection window, correlates the records and generates CSV/JSON results.

## 1. Requirements and deployment

The automation runs on the Windows laptop. Test actions execute on the Windows test VM, Wazuh detection evidence is collected from the Ubuntu Wazuh server.

| Component | Requirement |
|---|---|
| Windows laptop | Python 3.10 or newer and PowerShell |
| CALDERA Ubuntu VM | Running API and active red API key |
| Wazuh Ubuntu VM | Running Wazuh services, SSH and sudo access to alert files |
| Windows test VM | CALDERA agent, Wazuh agent and required event collection |

## 2. Framework files

Extract caldera-wazuh-automatic-collection.zip and keep these files together in the automatic-collection folder:

| File | Purpose |
|---|---|
| collect_operation.py | Retrieves the report, derives the window, collects alerts and invokes matching |
| remote_collect.py | Reads Wazuh alert files and executed remotely through SSH |
| match_results.py | Matches evidence and generates results |
| config.json | Stores addresses, endpoint mapping and timing settings |
| requirements.txt | Declares the dependency |
| test_workflow.py | Runs offline checks |

The remote collector does not need to be manually installed on the Wazuh VM.

## 4. One-time setup

### 4.1 Open PowerShell in the extracted folder

Open the folder containing collect_operation.py in File Explorer. Click the address bar, type powershell and press Enter.

Alternatively, use the actual extracted folder path:

~~~powershell
cd "PASTE THE EXTRACTED FOLDER PATH HERE"
dir
python --version
~~~

Confirm that collect_operation.py and config.json appear in the listing and Python is version 3.10 or newer.

### 4.2 Install the dependency

Run on the Windows laptop:

~~~powershell
python -m pip install -r requirements.txt
~~~

Normal script execution does not require administrator privileges on the laptop.

### 4.3 Obtain the CALDERA API key

For the current CALDERA 5.3.0 server started with --insecure, run in the CALDERA Ubuntu VM:

~~~bash
cd ~/caldera
grep '^api_key_red:' conf/default.yml
~~~

Use the api_key_red

### 4.4 Check config.json

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

Keep the agent ID as the string "001" to preserve its leading zeros. The hostname and agent ID must identify the intended endpoint. Do not add passwords or API keys to this file.
Change the wazuh and caldera url to your own set.

## 5. Commands for each collection

### 5.1 Complete the test operation

Run the selected test in CALDERA. Wait for the intended abilities to complete, review execution status, then finish/close the operation. Do not interrupt an executing ability just to satisfy the collector.

The script rejects an operation without a finish timestamp or a selected step without a completion timestamp.

### 5.2 List operation IDs

From Windows PowerShell in the automatic-collection folder:

~~~powershell
python .\collect_operation.py --list
~~~

Enter the CALDERA red API key at the hidden prompt. Copy the UUID for the intended operation from the listing.

### 5.3 Run automated collection

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


