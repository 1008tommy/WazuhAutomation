#requires -Version 5.1
<#
.SYNOPSIS
Checks the Windows endpoint prerequisites for the five CALDERA lab scenarios.

.DESCRIPTION
Run on the isolated Windows test VM. The default mode is read-only. -Prepare
creates C:\BASLab\input\secretInfo.txt with a synthetic marker if the input
directory is empty. The script never removes or overwrites existing lab data.
CALDERA server files are installed separately by portable/install_bundle.py.

.EXAMPLE
.\prepare-windows-lab.ps1 -CheckOnly -CalderaUrl http://YOUR-CALDERA-SERVER:8888

.EXAMPLE
.\prepare-windows-lab.ps1 -Prepare -CalderaUrl http://YOUR-CALDERA-SERVER:8888
#>
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Prepare,
    [ValidateNotNullOrEmpty()][string]$LabRoot = 'C:\BASLab',
    [string]$CalderaUrl
)

if ($CheckOnly -and $Prepare) {
    throw 'Choose either -CheckOnly or -Prepare.'
}
if ($env:OS -ne 'Windows_NT') {
    throw 'Run this script on the Windows test VM.'
}
if (-not [System.IO.Path]::IsPathRooted($LabRoot)) {
    throw 'LabRoot must be an absolute Windows path.'
}
$LabRoot = [System.IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
if ($LabRoot -eq [System.IO.Path]::GetPathRoot($LabRoot).TrimEnd('\')) {
    throw 'LabRoot cannot be a drive root.'
}

$checks = New-Object 'System.Collections.Generic.List[object]'
function Add-Check {
    param([string]$Name, [string]$Status, [string]$Detail)
    $checks.Add([pscustomobject]@{ Check = $Name; Status = $Status; Detail = $Detail })
}

$fixtureName = 'secretInfo.txt'
$fixtureMarker = 'BASLAB_SYNTHETIC_TEST_DATA'
$inputDir = Join-Path $LabRoot 'input'
$fixture = Join-Path $inputDir $fixtureName

try {
    foreach ($directory in @($LabRoot, $inputDir)) {
        if (Test-Path -LiteralPath $directory) {
            $item = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                throw "Expected a normal directory: $directory"
            }
        } elseif ($Prepare) {
            [void][System.IO.Directory]::CreateDirectory($directory)
        }
    }
    if ((Test-Path -LiteralPath $LabRoot -PathType Container) -and
        (Test-Path -LiteralPath $inputDir -PathType Container)) {
        Add-Check 'Lab directories' 'PASS' "$LabRoot and input exist"
    } else {
        Add-Check 'Lab directories' 'BLOCKED' 'Run with -Prepare to create C:\BASLab and input.'
    }
} catch {
    Add-Check 'Lab directories' 'BLOCKED' $_.Exception.Message
}

if (Test-Path -LiteralPath $inputDir -PathType Container) {
    try {
        $files = @(Get-ChildItem -LiteralPath $inputDir -File -Force -ErrorAction Stop)
        if ($Prepare -and $files.Count -eq 0) {
            Set-Content -LiteralPath $fixture -Value $fixtureMarker -Encoding ASCII -ErrorAction Stop
            $files = @(Get-ChildItem -LiteralPath $inputDir -File -Force -ErrorAction Stop)
        }
        if ($files.Count -ne 1 -or $files[0].Name -ne $fixtureName) {
            Add-Check 'Thief-Lab input' 'BLOCKED' "Expected only $fixtureName in $inputDir; review existing files without deleting them automatically."
        } else {
            $lines = @(Get-Content -LiteralPath $fixture -ErrorAction Stop)
            if ($lines.Count -eq 1 -and $lines[0] -ceq $fixtureMarker) {
                Add-Check 'Thief-Lab input' 'PASS' "Exactly one synthetic .txt file: $fixture"
            } else {
                Add-Check 'Thief-Lab input' 'BLOCKED' "Existing $fixtureName does not have the expected synthetic marker; it was not overwritten."
            }
        }
    } catch {
        Add-Check 'Thief-Lab input' 'BLOCKED' $_.Exception.Message
    }
} else {
    Add-Check 'Thief-Lab input' 'BLOCKED' 'Input directory is absent.'
}

foreach ($name in @('task-executed', 'masquerade-test', 'delivery-test', 'staged', 'staged.zip')) {
    $path = Join-Path $LabRoot $name
    if (Test-Path -LiteralPath $path) {
        Add-Check "Previous artifact: $name" 'BLOCKED' "Review $path before rerunning its scenario."
    } else {
        Add-Check "Previous artifact: $name" 'PASS' 'Absent'
    }
}

try {
    $task = @(Get-ScheduledTask -TaskName 'CALDERA-Lab-Test' -ErrorAction SilentlyContinue)
    if ($task.Count) {
        Add-Check 'CALDERA-Lab-Test task' 'BLOCKED' 'Task already exists; review it before running Scheduled Task Creation.'
    } else {
        Add-Check 'CALDERA-Lab-Test task' 'PASS' 'Absent'
    }
} catch {
    Add-Check 'CALDERA-Lab-Test task' 'BLOCKED' "Could not check scheduled tasks: $($_.Exception.Message)"
}

foreach ($command in @('whoami.exe', 'schtasks.exe', 'Compress-Archive', 'Get-CimInstance',
                        'Get-MpComputerStatus', 'Get-MpThreat')) {
    if (Get-Command -Name $command -ErrorAction SilentlyContinue) {
        Add-Check "Command: $command" 'PASS' 'Available'
    } else {
        Add-Check "Command: $command" 'BLOCKED' 'Unavailable on this endpoint.'
    }
}

$wazuhService = Get-Service -Name 'WazuhSvc', 'Wazuh' -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
if ($wazuhService) {
    Add-Check 'Wazuh agent' 'PASS' "Running service: $($wazuhService.Name)"
} else {
    Add-Check 'Wazuh agent' 'BLOCKED' 'No running Wazuh agent service found.'
}

$sysmonService = Get-Service -Name 'Sysmon64', 'Sysmon' -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Running' } | Select-Object -First 1
if ($sysmonService) {
    Add-Check 'Sysmon service' 'PASS' "Running service: $($sysmonService.Name)"
} else {
    Add-Check 'Sysmon service' 'BLOCKED' 'No running Sysmon service found.'
}

try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction Stop
    if ($sysmonLog.IsEnabled) {
        Add-Check 'Sysmon event channel' 'PASS' 'Enabled; confirm required Event IDs 1 and 11 in the active Sysmon configuration.'
    } else {
        Add-Check 'Sysmon event channel' 'BLOCKED' 'The Sysmon Operational channel is disabled.'
    }
} catch {
    Add-Check 'Sysmon event channel' 'BLOCKED' "Could not read Sysmon Operational channel: $($_.Exception.Message)"
}

$agentConfig = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent\ossec.conf'
if (Test-Path -LiteralPath $agentConfig -PathType Leaf) {
    try {
        $configText = Get-Content -LiteralPath $agentConfig -Raw -ErrorAction Stop
        if ($configText.Contains('Microsoft-Windows-Sysmon/Operational')) {
            Add-Check 'Wazuh Sysmon collection' 'PASS' 'Sysmon channel appears in ossec.conf; verify ingestion on the Wazuh manager.'
        } else {
            Add-Check 'Wazuh Sysmon collection' 'BLOCKED' 'Sysmon channel is not listed in the local ossec.conf.'
        }
    } catch {
        Add-Check 'Wazuh Sysmon collection' 'BLOCKED' "Could not read ossec.conf: $($_.Exception.Message)"
    }
} else {
    Add-Check 'Wazuh Sysmon collection' 'BLOCKED' 'Local Wazuh ossec.conf was not found.'
}

if ($CalderaUrl) {
    $uri = $null
    if (-not [Uri]::TryCreate($CalderaUrl, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http', 'https')) {
        Add-Check 'CALDERA reachability' 'BLOCKED' 'Pass an absolute http:// or https:// URL with -CalderaUrl.'
    } else {
        try {
            $reachable = Test-NetConnection -ComputerName $uri.DnsSafeHost -Port $uri.Port -InformationLevel Quiet -WarningAction SilentlyContinue
            if ($reachable) {
                Add-Check 'CALDERA reachability' 'PASS' "$($uri.Host):$($uri.Port) accepts TCP connections."
            } else {
                Add-Check 'CALDERA reachability' 'BLOCKED' "$($uri.Host):$($uri.Port) did not accept a TCP connection."
            }
        } catch {
            Add-Check 'CALDERA reachability' 'BLOCKED' "Connection check failed: $($_.Exception.Message)"
        }
    }
}

$checks | Format-Table -AutoSize -Wrap
if (@($checks | Where-Object Status -eq 'BLOCKED').Count -gt 0) {
    exit 1
}

