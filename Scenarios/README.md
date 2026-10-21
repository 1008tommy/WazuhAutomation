# CALDERA lab scenarios

These YAML files are CALDERA adversary exports for the isolated Windows BAS lab. The
`atomic_ordering` entries list the abilities to run. The exports contain the
execution commands but **do not contain the cleanup commands** configured on the
abilities in CALDERA. They also do not include the complete fact-source, parser,
and requirement configuration. Check those settings after importing an export.

Use synthetic test data only. Confirm the Windows test VM, CALDERA agent, and
required telemetry are ready before each operation. Record the operation ID and
preserve its report and control evidence before cleanup. Reset the VM or complete
the cleanup below before a repeat run.

## Add cleanup to the CALDERA abilities

The cleanup belongs to an **ability's Windows `psh` executor**, not to the
adversary profile export. In CALDERA, open **Abilities**, search for the exact
ability name below, select **Edit Ability**, scroll to its **Windows / psh**
executor, then use **Cleanup → + Add Cleanup Command**. Paste the corresponding
one-line command, save the ability, and check that the command appears when you
reopen it. Replace an older or duplicate cleanup command rather than adding a
second copy. The commands below can be used after importing these YAML files.

| Scenario | Ability to edit | Cleanup to add |
| --- | --- | --- |
| Scheduled Task Creation | `Lab Scheduled Task Creation` | Delete the task, then its marker directory. |
| Renamed Utility Lab | `Stage renamed lab utility` | Delete the copied executable, then its empty directory. |
| Thief-Lab | `Create BAS lab staging directory` | Delete the copied synthetic file and archive, then the empty staging directory. |

**Scheduled Task Creation — paste one cleanup command into `Lab Scheduled Task Creation`:**

```powershell
schtasks.exe /Query /TN "CALDERA-Lab-Test" *> $null; if ($LASTEXITCODE -eq 0) { schtasks.exe /Delete /TN "CALDERA-Lab-Test" /F; if ($LASTEXITCODE -ne 0) { throw 'Scheduled task deletion failed' } }; $marker='C:\BASLab\task-executed'; if (Test-Path -LiteralPath $marker -PathType Container) { [System.IO.Directory]::Delete($marker) }
```

**Renamed Utility Lab — paste one cleanup command into `Stage renamed lab utility`:**

```powershell
$dir='C:\BASLab\masquerade-test'; $file=Join-Path $dir 'lab-helper.exe'; if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force -ErrorAction Stop }; if (Test-Path -LiteralPath $dir -PathType Container) { [System.IO.Directory]::Delete($dir) }
```

**Thief-Lab — paste one cleanup command into `Create BAS lab staging directory`:**

```powershell
$dir='C:\BASLab\staged'; $files=@(Get-ChildItem -LiteralPath 'C:\BASLab\input' -File -Filter '*.#{file.sensitive.extension}' -ErrorAction Stop); if ($files.Count -ne 1) { throw 'Expected exactly one synthetic file for cleanup' }; $copy=Join-Path $dir $files[0].Name; if (Test-Path -LiteralPath $copy -PathType Leaf) { Remove-Item -LiteralPath $copy -Force -ErrorAction Stop }; $archive='C:\BASLab\staged.zip'; if (Test-Path -LiteralPath $archive -PathType Leaf) { Remove-Item -LiteralPath $archive -Force -ErrorAction Stop }; if (Test-Path -LiteralPath $dir -PathType Container) { [System.IO.Directory]::Delete($dir) }
```

The Thief cleanup uses the starting `file.sensitive.extension` fact, rather
than a `host.file.path` fact produced by a later ability. Confirm that the
fact source supplies the extension and that exactly one input file matches it.
If the input file changed after the run, use the manual Thief cleanup below
with the actual copied filename.

CALDERA runs cleanup after an operation in reverse ability order, and an
operation may be configured to skip cleanup. Start a new lab operation with
cleanup enabled, then inspect the cleanup results and verify the task and
directories are gone before repeating the scenario. See the
[CALDERA ability documentation](https://caldera.readthedocs.io/en/5.1.0/Basic-Usage.html#abilities).

## Scheduled Task Creation

File: `Scheduled Task Creation.yaml`. Requires `C:\BASLab` to exist. The first
ability creates the `CALDERA-Lab-Test` task with an `ONLOGON` trigger; the second
starts it explicitly and checks for the empty `C:\BASLab\task-executed` marker
directory. Before starting, check that neither the task nor marker remains from
an earlier run.

After the operation, delete the task **before** removing its marker, so the task
cannot recreate the marker. Run on the Windows test VM:

```powershell
schtasks.exe /Query /TN "CALDERA-Lab-Test" *> $null
if ($LASTEXITCODE -eq 0) {
    schtasks.exe /Delete /TN "CALDERA-Lab-Test" /F
    if ($LASTEXITCODE -ne 0) { throw 'Scheduled task deletion failed' }
}
$marker = 'C:\BASLab\task-executed'
if (Test-Path -LiteralPath $marker -PathType Container) {
    [System.IO.Directory]::Delete($marker) # Only succeeds if empty
}
```

Verify that a task query fails and `Test-Path -LiteralPath $marker` returns
`False`. If the marker directory is not empty, inspect it before removing files.

## Renamed Utility Lab

File: `Renamed Utility Lab.yaml`. Requires `C:\BASLab` to exist and
`C:\BASLab\masquerade-test` to be absent. The scenario copies the Windows
`whoami.exe` utility to `lab-helper.exe` and executes that renamed copy. It does
not alter the original utility.

After the operation, remove only the copied utility and then its empty directory:

```powershell
$dir = 'C:\BASLab\masquerade-test'
$file = Join-Path $dir 'lab-helper.exe'
if (Test-Path -LiteralPath $file -PathType Leaf) {
    Remove-Item -LiteralPath $file -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $dir -PathType Container) {
    [System.IO.Directory]::Delete($dir) # Only succeeds if empty
}
Test-Path -LiteralPath $dir # Expected: False
```

If directory deletion fails, inspect it with
`Get-ChildItem -LiteralPath $dir -Force`; do not remove unexpected contents.

## Thief-Lab

File: `Thief-Lab.yaml`. Requires `C:\BASLab\input` to contain exactly one
synthetic file matching the CALDERA `file.sensitive.extension` fact. Verify the
fact value, ability parsers and requirements before running. The scenario creates
`C:\BASLab\staged`, copies the selected input file there, creates
`C:\BASLab\staged.zip`, and uploads the archive to the lab CALDERA server.

After preserving the report and uploaded artifact, inspect the staged directory
and remove the **specific copied synthetic file** from this run. For example,
replace `<synthetic-file-name>` with the actual name before running:

```powershell
$staged = 'C:\BASLab\staged'
$archive = 'C:\BASLab\staged.zip'
Get-ChildItem -LiteralPath $staged -Force
$copiedFile = Join-Path $staged '<synthetic-file-name>'
if (Test-Path -LiteralPath $copiedFile -PathType Leaf) {
    Remove-Item -LiteralPath $copiedFile -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $archive -PathType Leaf) {
    Remove-Item -LiteralPath $archive -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $staged -PathType Container) {
    [System.IO.Directory]::Delete($staged) # Only succeeds if empty
}
```

Verify that `staged` and `staged.zip` are absent. Keep the original synthetic
file in `C:\BASLab\input` for later repeat tests. If `staged` contains anything
unexpected, inspect it before deleting files.

## Reusing these exports

The adversary YAML exports still do not carry cleanup commands. Follow the
ability-editing steps above after importing them, then test a full operation
and its cleanup on a reset VM. The scenario sections also provide manual
recovery commands if automatic cleanup does not run.
