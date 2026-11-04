# CALDERA lab scenarios

These four profiles simulate small, repeatable techniques on an isolated Windows test VM. The YAML files in this folder are adversary exports. For another CALDERA server, install the [portable bundle](portable/README.md), which includes the ability definitions, the Thief-Lab fact source, and the required script payload.

## Before any scenario

- Use a Windows lab VM with an active CALDERA agent that supports the PowerShell (`psh`) executor.
- Ensure `C:\BASLab` exists on the VM. Use synthetic test data only.
- If measuring Wazuh detection, confirm that Sysmon and the Wazuh agent are collecting events from this VM.
- Start each operation with the intended Windows agent group and the atomic planner. Check each scenario's specific setup below.

## Scheduled Task Creation

**Profile:** [Scheduled Task Creation.yaml](Scheduled%20Task%20Creation.yaml)

**What it does:** Creates a task named `CALDERA-Lab-Test` with an `ONLOGON` trigger. The task's action creates an empty `C:\BASLab\task-executed` directory. A second ability starts the task immediately and verifies that the directory appears. This tests scheduled-task creation and execution (T1053.005).

**Before running:**

- Confirm `C:\BASLab` exists and the Windows agent can create and run scheduled tasks.
- Confirm that the `CALDERA-Lab-Test` task and `C:\BASLab\task-executed` directory are absent, so an earlier run cannot affect the result.

## Renamed Utility Lab

**Profile:** [Renamed Utility Lab.yaml](Renamed%20Utility%20Lab.yaml)

**What it does:** Copies Windows `whoami.exe` to `C:\BASLab\masquerade-test\lab-helper.exe`, then executes the renamed copy and prints its original filename and output. This tests renamed-system-utility masquerading (T1036.003). The original `whoami.exe` is not changed.

**Before running:**

- Confirm `C:\BASLab` exists and `C:\Windows\System32\whoami.exe` is available.
- Confirm `C:\BASLab\masquerade-test` is absent before starting the operation.

## File Delivery and Execution Lab

**Profile:** [File Delivery and Execution Lab.yaml](File%20Delivery%20and%20Execution%20Lab.yaml)

**What it does:** Downloads the harmless [lab-note.ps1](required-payloads/lab-note.ps1) script from CALDERA to `C:\BASLab\delivery-test\lab-note.ps1` (T1105). The next ability runs that downloaded file (T1059.001) and verifies that it wrote an `executed.marker` file containing `LAB_EXECUTED`.

**Before running:**

- Put `lab-note.ps1` in the CALDERA server's `plugins/stockpile/payloads` directory. The portable bundle installer does this.
- Confirm that the Windows VM can reach the CALDERA server. The portable ability uses CALDERA's `#{server}` value; the standalone adversary export contains the original lab server address and needs that address updated on a different server.
- Confirm `C:\BASLab` exists and `C:\BASLab\delivery-test` is absent.
- Confirm the download ability has a parser that records its output as `host.file.downloaded`. The portable ability includes this parser.

## Thief-Lab

**Profile:** [Thief-Lab.yaml](Thief-Lab.yaml)

**What it does:** Creates `C:\BASLab\staged`, finds one synthetic input file, copies it into the staging directory, compresses it into `C:\BASLab\staged.zip`, and uploads the archive to the lab CALDERA server. This covers local collection, staging, archiving, and exfiltration over the CALDERA channel (T1005, T1074.001, T1560.001, T1041).

**Before running:**

- Place exactly one synthetic file with the chosen extension in `C:\BASLab\input`. For example, `secretInfo.txt` matches the default `txt` value.
- In **Fact Sources**, open **Thief-Lab** and set `file.sensitive.extension` to the file's extension **without the dot**. Change `txt` to `csv` if the test file is a `.csv`. The portable source starts with `txt` and score `11`.
- Select the **Thief-Lab** fact source when creating the operation. Installing the source does not automatically attach it to an operation.
- Confirm `C:\BASLab\staged` and `C:\BASLab\staged.zip` are absent. Confirm Stockpile is enabled, since the compression and upload abilities come from it, and the Windows VM can reach the CALDERA server.
