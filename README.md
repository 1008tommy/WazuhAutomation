# WazuhAutomation

This repository contains [CALDERA lab scenarios](Scenarios/README.md), a [portable scenario bundle](Scenarios/portable/README.md), and [scripts for collecting CALDERA and Wazuh detection evidence](caldera-wazuh-automatic-collection/automatic-collection/README.md).

## CALDERA 5.3.0 lab installation

These are the steps used to set up the isolated Ubuntu CALDERA lab. They are installation notes for a fresh VM; an existing CALDERA server does not need to be reinstalled to use the scenario bundle.

1. Update Ubuntu, then reconnect after the reboot:

   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo reboot
   ```

2. Install the prerequisites, including Go for building Sandcat agents and `tmux` for keeping the server session alive:

   ```bash
   sudo apt install -y git curl ca-certificates build-essential python3-pip python3-venv golang-go tmux
   ```

3. Install Node.js 22 from NodeSource and check its version:

   ```bash
   curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/nodesource_setup.sh
   sudo -E bash /tmp/nodesource_setup.sh
   sudo apt install -y nodejs
   node --version
   ```

   This lab used Node.js 22 after the Ubuntu-packaged Node.js 18 failed its frontend build. CALDERA's published v5.3.0 minimum is Node.js 16; Node.js 22 is the version used for this lab, not a general minimum.

4. Clone the CALDERA 5.3.0 release and its plugin submodules:

   ```bash
   cd "$HOME"
   git clone --recursive --branch 5.3.0 https://github.com/mitre/caldera.git
   cd caldera
   ```

   `--recursive` fetches plugins such as Stockpile. The release tag pins CALDERA and its submodule revisions.

5. Install Python dependencies in a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   python -m pip install -r requirements.txt
   ```

   The virtual environment keeps CALDERA's Python packages separate from the system installation.

6. Start a `tmux` session, then build and start CALDERA inside it:

   ```bash
   tmux new -s caldera
   ```

   In the new `tmux` session:

   ```bash
   cd "$HOME/caldera"
   source venv/bin/activate
   python3 server.py --insecure --build
   ```

   Wait for `All systems ready`. `--build` builds the web interface on first start or after frontend changes. `--insecure` uses `conf/default.yml` and its default credentials, so this mode is for the isolated lab only. To leave the server running after SSH disconnects, detach with **Ctrl+B**, then **D**. Reconnect with `tmux attach -t caldera`.

CALDERA installation and configuration references: [v5.3.0 installation guide](https://caldera.readthedocs.io/en/5.3.0/Installing-Caldera.html) and [server configuration](https://caldera.readthedocs.io/en/5.3.0/Server-Configuration.html).

## Windows Sysmon and Wazuh event collection

Use these steps on the Windows test VM after its Wazuh agent is installed and active. Sysmon must record the events locally, and the Wazuh agent must collect the Sysmon event channel. This lab configuration records process creation (Event ID 1), process termination (Event ID 5), and file creation (Event ID 11).

1. Download [Sysmon from Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), extract `Sysmon64.exe` to `C:\Tools\Sysmon`, and open **PowerShell as Administrator**.

2. Create the lab configuration:

   ```powershell
   New-Item -ItemType Directory -Path 'C:\Tools\Sysmon' -Force | Out-Null
   @'
   <Sysmon schemaversion="4.82">
     <HashAlgorithms>SHA256</HashAlgorithms>
     <EventFiltering>
       <ProcessCreate onmatch="exclude" />
       <ProcessTerminate onmatch="exclude" />
       <FileCreate onmatch="exclude" />
     </EventFiltering>
   </Sysmon>
   '@ | Set-Content -LiteralPath 'C:\Tools\Sysmon\sysmon-baslab.xml' -Encoding UTF8
   ```

   The empty `exclude` filters log all events of those three types. File creation can generate many events, so use this broad configuration for the isolated lab and tune it before wider use.

3. If Sysmon is **not installed**, install it with the configuration:

   ```powershell
   & 'C:\Tools\Sysmon\Sysmon64.exe' -accepteula -i 'C:\Tools\Sysmon\sysmon-baslab.xml'
   ```

   If the `Sysmon64` service is **already running**, update its configuration instead of reinstalling:

   ```powershell
   & "$env:WINDIR\Sysmon64.exe" -c 'C:\Tools\Sysmon\sysmon-baslab.xml'
   & "$env:WINDIR\Sysmon64.exe" -c
   ```

   The last command displays the active configuration. Confirm that it lists rules for ProcessCreate, ProcessTerminate, and FileCreate. The update takes effect without a restart.

4. In the Windows Wazuh agent file `C:\Program Files (x86)\ossec-agent\ossec.conf`, add this block inside the existing `<ossec_config>` element if an equivalent Sysmon entry is not already present:

   ```xml
   <localfile>
     <location>Microsoft-Windows-Sysmon/Operational</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```

   After changing that file, restart the Wazuh agent from Administrator PowerShell:

   ```powershell
   Restart-Service -Name Wazuh
   ```

5. For the evidence collector to find events that did not trigger alerts, enable JSON archives on the Wazuh manager. In `/var/ossec/etc/ossec.conf` on the Ubuntu Wazuh VM, set `<logall_json>yes</logall_json>` inside the existing `<global>` element, then run `sudo systemctl restart wazuh-manager`. If JSON archives are already enabled, leave the setting as it is.

6. Verify Event ID 11 on the Windows VM by creating a unique test file:

   ```powershell
   $probe = Join-Path $env:TEMP "sysmon-probe-$([guid]::NewGuid().ToString('N')).txt"
   New-Item -ItemType File -Path $probe | Out-Null
   Start-Sleep -Seconds 2
   Get-WinEvent -FilterHashtable @{
     LogName = 'Microsoft-Windows-Sysmon/Operational'
     Id = 11
     StartTime = (Get-Date).AddMinutes(-5)
   } | Where-Object { $_.Message.Contains($probe) } |
     Select-Object -First 1 TimeCreated, Id, Message
   ```

   The command should return an Event ID 11 `File created` record. If it does not, check the active Sysmon configuration from step 3.

7. After allowing time for forwarding, check the Wazuh manager's JSON archive:

   ```bash
   sudo grep -F 'sysmon-probe-' /var/ossec/logs/archives/archives.json | tail -n 1
   ```

   If the local Windows event exists but no archive record appears, check the Wazuh agent's Sysmon `<localfile>` entry, its service status, and the manager archive setting. An archived event confirms collection; it does not necessarily produce a Wazuh alert. Detection alerts depend on Wazuh rules. Start a **new** CALDERA operation after changing Sysmon, because earlier runs cannot contain events that were not logged at the time.

References: [Microsoft Sysmon usage and configuration](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Wazuh Windows event channel collection](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), and [Wazuh event archiving](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html).
