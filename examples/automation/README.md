# Automation examples

These examples use synthetic hostnames and documentation-only network ranges. Replace them only with systems you are authorized to administer. Run commands from the repository root unless an example sets another working directory.

## Local inventory to stdout JSON

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -JsonOutputPath -
```

## One remote target over WinRM

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action DiskSpace `
  -ComputerName server01.example.com `
  -Transport WinRM `
  -JsonOutputPath C:\Ops\Results\server01-disk.json
```

## Validated computer-list file

Create `C:\Ops\targets.txt` with one target per line:

```text
# Authorized production targets
server01.example.com
server02.example.com
192.0.2.10
```

Then run:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action PendingReboot `
  -ComputerListPath C:\Ops\targets.txt `
  -JsonOutputPath C:\Ops\Results\pending-reboot.json
```

For more than 25 validated targets, also provide `-TargetListConfirmationText 'USE TARGET LIST'`.

## Kerberos and WinRM over HTTPS

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action EventLogQuery `
  -ComputerName server01.example.com `
  -Transport WinRM `
  -Authentication Kerberos `
  -UseSsl `
  -EventLogName System `
  -EventLevel Error,Warning `
  -EntryCount 50 `
  -JsonOutputPath C:\Ops\Results\server01-events.json
```

This example assumes the environment is already configured for Kerberos and WinRM HTTPS. The toolkit does not change those settings.

## Read-only RMM execution

Configure the RMM tool to launch this process, capture stdout as JSON, and use the process exit code as the job result:

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive `
  -File C:\ProgramData\WindowsAdminToolkit\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SoftwareInventory `
  -Local `
  -JsonOutputPath STDOUT
```

## Guarded state-changing RMM execution

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive `
  -File C:\ProgramData\WindowsAdminToolkit\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action ServiceManagement `
  -Local `
  -ServiceName Spooler `
  -ServiceAction Restart `
  -ConfirmationText 'CHANGE SERVICE' `
  -JsonOutputPath STDOUT
```

The RMM policy should separately restrict who can edit or launch this job. The confirmation phrase is an authorization gate, not a credential or substitute for access control.

## State-changing WhatIf preview

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action ScheduleReboot `
  -ComputerName server01.example.com `
  -RebootDelaySeconds 300 `
  -WhatIf `
  -JsonOutputPath -
```

No confirmation text is required for the preview, and no target connection is opened.

## Apply a read-only local policy

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action RunningProcesses `
  -Local `
  -TopCount 25 `
  -PolicyPath .\examples\policies\read-only-local.json `
  -JsonOutputPath -
```

The example profile permits selected local query actions, denies state-changing and expert actions, and narrows runtime and action-input limits. Protect production policy files with least-privilege NTFS permissions.

## Remote capability preflight under policy

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action EventLogQuery `
  -ComputerName server01.example.com `
  -Transport WinRM `
  -EventLogName System `
  -EntryCount 50 `
  -PolicyPath .\examples\policies\helpdesk-winrm.json `
  -Preflight `
  -JsonOutputPath -
```

This validates the complete request, evaluates policy, checks connectivity, and discovers capabilities in the selected execution context. It does not execute the Event Log Query action.

## Windows scheduled task

This registration example uses an explicit working directory and a unique output path. Create the two directories and grant the scheduled-task identity only the access it needs before registering the task.

```powershell
$toolkitDirectory = 'C:\Program Files\WindowsAdminToolkit'
$powerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$taskCommand = @'
$resultDirectory = 'C:\ProgramData\WindowsAdminToolkit\Results'
$resultName = 'nightly-system-info-{0}-{1}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$resultPath = Join-Path $resultDirectory $resultName
& '.\WindowsAdminToolkit.ps1' -Automation -Action SystemInfo -Local -JsonOutputPath $resultPath
exit $LASTEXITCODE
'@
$encodedTaskCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($taskCommand))
$taskArguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedTaskCommand"

$action = New-ScheduledTaskAction `
  -Execute $powerShellPath `
  -Argument $taskArguments `
  -WorkingDirectory $toolkitDirectory
$trigger = New-ScheduledTaskTrigger -Daily -At 2am

Register-ScheduledTask `
  -TaskName 'Windows Admin Toolkit - Nightly Inventory' `
  -Action $action `
  -Trigger $trigger `
  -User 'EXAMPLE\AuthorizedAutomationAccount'
```

The task creates a timestamped result with a random suffix on every run. The toolkit still refuses to overwrite an existing JSON file. Archive or remove old results only through a separately reviewed retention job.

## CI failure on partial or failed results

This step launches a child Windows PowerShell process, preserves its exact exit code, uploads or archives the JSON separately, and fails for every nonzero outcome:

```powershell
$resultPath = Join-Path $env:RUNNER_TEMP 'windows-admin-toolkit-result.json'

& powershell.exe -NoLogo -NoProfile -NonInteractive `
  -File .\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action FirewallStatus `
  -ComputerListPath .\ci\authorized-targets.txt `
  -JsonOutputPath $resultPath

$toolkitExitCode = $LASTEXITCODE
$result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json

if ($toolkitExitCode -ne 0) {
  throw "Windows Admin Toolkit failed with outcome $($result.outcome) and exit code $toolkitExitCode."
}
```

Exit code 1 is partial success and must not be treated as a passing CI result.

## Enumerate actions and inputs

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -ListActions `
  -JsonOutputPath C:\Ops\Results\action-catalog.json
```

The action catalog is also available on stdout by replacing the path with `-`.

Apply `-PolicyPath` to annotate every catalog entry with its allow or deny decision:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -ListActions `
  -PolicyPath .\examples\policies\read-only-local.json `
  -JsonOutputPath -
```

## Committed result examples

The [`results`](results) directory contains schema version 1.1 examples for complete success, partial success, validation failure, execution failure, timeout, `WhatIf`, policy denial, and capability preflight. The examples use synthetic hostnames and contain no credentials or private environment data.
