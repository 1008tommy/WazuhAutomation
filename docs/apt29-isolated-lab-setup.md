# APT29 isolated lab setup (two-host example)

This guide describes a reusable two-host lab based on the setup tested in November 2026 for CALDERA APT29 emulation and Wazuh detection testing. The VM names and private addresses below are an **example allocation**; choose unused addresses on one private subnet when recreating it. The [root README](../README.md) documents the earlier five portable CALDERA scenarios and a separate standalone Sysinternals Sysmon setup; those instructions remain available.

The APT29 profile has **not** been run end to end. SentinelOne has **not** yet been deployed or validated in this lab. This guide does not claim that every ability in the profile is ready to execute.

## Lab inventory

| Host | VM / role | Example lab IPv4 | Confirmed state in this lab |
| --- | --- | --- | --- |
| Host A (server host) | Ubuntu CALDERA server | `10.77.29.10/24` | CALDERA VM can be reached from a lab Windows VM; existing CALDERA 5.3.0 installation is documented in the root README. |
| Host A | Ubuntu Wazuh server | `10.77.29.11/24` | Wazuh manager, indexer, and dashboard were active; Sysmon events from both Windows clients reached `archives.json`. |
| Host B (Windows VM host) | Windows 11 Enterprise Evaluation, `SCRANTON` | `10.77.29.20/24` | Domain joined to `apt29.test`; built-in Sysmon and Wazuh agent installed. Wazuh enrollment name `WindowsHost1`, ID `004` before the domain join. |
| Host B | Windows 11 Enterprise Evaluation, `NASHUA` | `10.77.29.21/24` | Domain joined to `apt29.test`; built-in Sysmon and Wazuh agent installed. Wazuh enrollment name `WindowsHost2`, ID `005` before the domain join. |
| Host B | Windows Server 2022 Standard Evaluation (Desktop Experience), `NEWYORK` | `10.77.29.30/24` | Active Directory Domain Services and DNS for `apt29.test`; `Get-ADDomain` and `Get-ADDomainController` returned the expected domain and controller. |

The Windows client build shown during setup was `26100`, which is Windows 11 24H2. `Get-ComputerInfo.WindowsProductName` showed a stale `Windows 10 Enterprise Evaluation` registry value on one client; the Windows 11 watermark and build identify the installed OS. See [Microsoft's Windows 11 release information](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information) and the [PowerShell property reference](https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.computerinfo).

The Wazuh **agent enrollment name**, Windows **computer name**, and CALDERA **agent name** are separate identifiers. Record the agent ID and Windows hostname in each test run instead of assuming they match.

## Isolated network between the two hosts

1. Connect the two hosts directly with a dedicated Ethernet cable. In VMware's **Virtual Network Editor** on each host, bridge the lab VMnet (VMnet2 in this example) to that host's **physical Ethernet adapter connected to the cable**. The adapter's vendor and display name vary by computer; identify it from the Windows Ethernet connection or `Get-NetAdapter`. Select it explicitly instead of auto-bridging to Wi-Fi, Wi-Fi Direct, or another virtual adapter.
2. Connect **one network adapter per lab VM** to the custom lab VMnet (**Custom: VMnet2** in this example). Do not attach an Internet-connected bridge, NAT, a second adapter, or a shared Internet connection to a lab VM. The physical hosts may use Wi-Fi separately; Internet Connection Sharing, Windows Network Bridge, and host IP forwarding must remain off.
3. On each physical Ethernet adapter used for the cable, the lab setup retained the **VMware Bridge Protocol** binding and disabled the host's IPv4/IPv6 bindings. This leaves the hosts without an IP address on the lab cable. It also means Host A's browser is not expected to reach the CALDERA guest IP; use a browser inside a lab VM or the VMware console to administer CALDERA.
4. Give the VMs distinct static addresses on the same private subnet, using the inventory table as an example. Do **not** set a default gateway. After the domain controller exists, set both Windows clients' DNS server to its private address (`10.77.29.30` in this example); the domain controller uses itself for DNS. For the Ubuntu VMs, preserve the existing `/etc/netplan/00-installer-config.yaml` interface match while setting static addresses on the lab interface.
5. Before an APT29 run, verify each guest's address and routes. On Ubuntu use `ip -br addr`, `ip route`, and `ip -6 route`; on Windows use `ipconfig /all`, `route print -4`, and `route print -6`. There should be no IPv4 or IPv6 default route. From a Windows lab VM, check `ping 10.77.29.10`, `ping 10.77.29.11`, and `Test-NetConnection 10.77.29.10 -Port 8888`.

When a host's Ethernet cable is reconnected to a normal home or office network, **the lab VMnet must not remain bridged to that network**. In the tested setup, VMnet2 was changed to host-only for that use. Before the next lab session, reconnect the direct cable, restore the physical Ethernet bridge on both hosts, check the host bindings, and repeat the guest route and connectivity checks. A working ping alone does not prove that the guests have no other route.

### Configure IPv4 when starting a new Windows VM

On a fresh Windows guest, the private link may not provide DHCP. If `ipconfig` shows no usable IPv4 address or a `169.254.x.x` address, set the address manually before testing connectivity:

1. Confirm the VM has one network adapter connected to the lab VMnet. Start Windows, press **Win+R**, enter `ncpa.cpl`, and open the active **Ethernet** adapter's **Properties**.
2. Select **Internet Protocol Version 4 (TCP/IPv4) > Properties**, then **Use the following IP address**. Enter an unused address for that VM (`10.77.29.20`, `.21`, or `.30` in the example table) and subnet mask `255.255.255.0`. Leave **Default gateway** empty.
3. For the domain controller, set **Preferred DNS server** to its own private address. For a Windows client, set DNS to the domain controller's private address after DNS is running; until then, it can be left blank. Do not use a public DNS server on the isolated guest.
4. Click **OK** to close both dialogs. In PowerShell, run `ipconfig /all` and `route print -4` to confirm the chosen address, mask, and absence of a default gateway. Then test access to the other lab VMs. If this is a domain client, also check `Resolve-DnsName '_ldap._tcp.dc._msdcs.apt29.test' -Type SRV` before joining the domain.

## VMware guest integration and snapshots

VMware Tools remained installed for normal VM functions. On each Windows test VM, **VM > Settings > Options > Guest Isolation** had copy/paste and drag/drop disabled, and **Options > Shared Folders** was disabled after the offline installer transfer. Disconnect USB devices passed through to a test VM before an emulation run. These settings reduce ordinary host/guest transfer paths; they are not a guarantee against every host exposure.

The two Windows clients were snapshotted after Sysmon/Wazuh event collection worked. A later three-VM snapshot set was recommended after the clients joined the domain; its completion was not independently confirmed. For repeatable test resets, shut down the clients first and the domain controller last, snapshot all three at the same state, and restore **all three together**; start `NEWYORK` before the clients. Restoring only an old domain controller state can leave clients and domain accounts out of sync. Treat snapshots as lab reset points, not as a substitute for an [AD DS system-state backup](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/introduction-to-active-directory-domain-services-ad-ds-virtualization-level-100).

## Windows Server domain controller

Host B's Windows Server VM was installed from the Windows Server 2022 ISO using **Standard Evaluation (Desktop Experience)**, not Server Core. The tested VM had 4 GB RAM, a 60 GB virtual disk, and only the lab VMnet. Creating the VMware VM with **I will install the operating system later**, then attaching the ISO manually, avoided a `No images are available` setup screen associated with VMware's automated installation path. The Server was assigned `10.77.29.30/24`, DNS `10.77.29.30`, and no gateway. It could ping both Ubuntu servers before promotion.

The domain was created in an elevated PowerShell session with these commands, with reboots after the rename and forest creation:

```powershell
Rename-Computer -NewName 'NEWYORK' -Restart
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName 'apt29.test' -DomainNetbiosName 'APT29' -InstallDNS
```

The forest command prompts for a separate Directory Services Restore Mode password. Do not put that password, the domain Administrator password, or an evaluation key in this repository. Validation on `NEWYORK`:

```powershell
Get-ADDomain
Get-ADDomainController
ipconfig /all
```

The observed result identified `NEWYORK.apt29.test` at `10.77.29.30` as the domain controller and global catalog. See [Microsoft's AD DS installation guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-).

On each Windows client, set DNS to the domain controller, confirm the AD DNS record resolves, then join with domain Administrator credentials. The original emulation content refers to `scranton`, so the first client was named `SCRANTON`; the second was named `NASHUA`.

```powershell
$labAdapter = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).Name
Set-DnsClientServerAddress -InterfaceAlias $labAdapter -ServerAddresses '10.77.29.30'
Resolve-DnsName '_ldap._tcp.dc._msdcs.apt29.test' -Type SRV
# Run on the first client; use NASHUA as -NewName on the second client.
Add-Computer -DomainName 'apt29.test' -NewName 'SCRANTON' -Credential (Get-Credential 'APT29\Administrator') -Restart
```

After the restart, sign in again and confirm the join:

```powershell
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, PartOfDomain
```

The two client joins were reported successful. DNS discovery and an AD secure-channel check should be repeated after a snapshot restore. See [Microsoft's domain join guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/join-computer-to-domain).

**Evaluation license:** Microsoft states that Windows Server 2022 Evaluation lasts 180 days and must activate over the Internet within its first 10 days to avoid automatic shutdown. Activation status was **not** verified during this setup. Handle any required activation during clean preparation, then restore the isolated VMnet2-only configuration and verify the routes before testing. See the [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022).

## Windows Sysmon and Wazuh collection

These **new Windows 11 clients used built-in Sysmon**, available as a Windows optional feature. This differs from the standalone `Sysmon64.exe` method in the root README. Built-in and standalone Sysmon should not coexist on one endpoint. The observed setup enabled the optional feature, installed the service, and checked the local Operational log:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Sysmon
sysmon -i
Get-Service -Name 'Sysmon*'
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 10 |
  Select-Object TimeCreated, Id
```

The local event list showed process creation (Event ID `1`) and process termination (Event ID `5`). A custom Sysmon XML policy and file creation Event ID `11` have **not** been verified on these two new clients. See [Microsoft's built-in Sysmon instructions](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon).

The isolated Windows VMs could not resolve `packages.wazuh.com`. The Wazuh agent MSI was downloaded on a host with Internet access and transferred to each clean guest before guest sharing was disabled. Install the MSI on each client with the manager's private address (`10.77.29.11` here) and a **unique** enrollment name, then start the agent. For example, from an elevated PowerShell prompt with the MSI already on the guest:

```powershell
msiexec.exe /i 'C:\Install\wazuh-agent-4.14.10-1.msi' /q WAZUH_MANAGER='10.77.29.11' WAZUH_AGENT_NAME='WindowsHost1'
Start-Service WazuhSvc
Get-Service -Name 'Wazuh*'
```

Replace the MSI path with the actual local path; use `WindowsHost2` on the second client. The current [Wazuh Windows agent installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html) shows the supported MSI properties. The dashboard showed the agents active. From a client, TCP ports `1514` and `1515` on the manager had previously tested reachable on the isolated link.

Add this block **once** within the existing `<ossec_config>` section of `C:\Program Files (x86)\ossec-agent\ossec.conf` on **each client**:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent after saving:

```powershell
Restart-Service WazuhSvc
```

On the Wazuh manager, `<logall_json>yes</logall_json>` within `<global>` in `/var/ossec/etc/ossec.conf` is required for `/var/ossec/logs/archives/archives.json` to retain all collected events, including those without alerts. Restart `wazuh-manager` after changing that setting. The existing [Sysmon/Wazuh section](../README.md#windows-sysmon-and-wazuh-event-collection) explains archives and alerts in more detail; see also [Wazuh event channel collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html).

### Evidence that the two client pipelines worked

On the first client, PowerShell ran `cmd.exe /c echo wazuh-sysmon-probe-241124`; the second used `wazuh-sysmon-probe-vm2-241124`. On the manager, these lookups returned JSON archive records:

```bash
sudo grep -F 'wazuh-sysmon-probe-241124' /var/ossec/logs/archives/archives.json
sudo grep -F 'wazuh-sysmon-probe-vm2-241124' /var/ossec/logs/archives/archives.json
```

The first record had agent ID `004`, enrollment name `WindowsHost1`, IP `10.77.29.20`; the second had ID `005`, `WindowsHost2`, IP `10.77.29.21`. Both included a Sysmon process creation Event ID `1` and Wazuh rule `92004`, level `4`, for PowerShell spawning `cmd.exe`. This proves collection and one **generic process-chain alert**. It does **not** establish APT29 technique coverage. After a domain join or snapshot restore, repeat a unique marker test and confirm the correct agent ID, hostname, timestamp, and Wazuh service state.

## Remaining work before an APT29 run

- Inspect the CALDERA Emu APT29 profile ability by ability and map each step to a lab host, required facts, payloads, expected telemetry, and destination. The local `APT29.yaml` includes a hard-coded `scranton` reference, a GitHub-hosted credential-dumping script download, WinRM/PsExec movement, collection/upload steps, and OneDrive-related inputs. The external fetch and OneDrive stages cannot work unchanged on VMs with no default route. A profile listed in the UI is not proof that its payloads or prerequisites are present.
- Confirm CALDERA agents, command-and-control address, and target roles on the lab network. An active **Wazuh** agent is separate from a **CALDERA** agent.
- Create only the lab domain users and facts required by the selected APT29 steps. The profile's `profile_user`, `profile_user_day2`, and credential facts have not been validated against this new domain; local Windows accounts are not automatically domain accounts.
- Decide whether to instrument `NEWYORK` with Sysmon and Wazuh. Its AD events are not covered by the two client agents. Verify clock alignment across CALDERA, Wazuh, the domain controller, and the Windows clients before correlating timestamps.
- Set up and validate SentinelOne separately. No SentinelOne console telemetry or agent event export is established in this guide. Keep Wazuh-only and SentinelOne test states distinguishable when comparing controls.
- The existing [automatic collector](../caldera-wazuh-automatic-collection/automatic-collection/README.md) was built for one configured Windows endpoint and selected Wazuh evidence types. Its output must not be presented as complete multi-host APT29 coverage without extending and validating the matching logic.

Record a fresh CALDERA operation ID, the snapshot set, host/agent IDs, start/end times, ability statuses, archived events, alerts, and any missing data for each reviewed run. A new operation is required after changing logging or agent configuration.
