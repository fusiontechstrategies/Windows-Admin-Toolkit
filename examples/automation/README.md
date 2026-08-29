# Automation examples

These examples use synthetic hostnames and documentation-only network ranges. Replace them only with systems you are authorized to administer. Run commands from the repository root unless an example sets another working directory.

For a no-connection first look, start with the [sanitized JSON and HTML demo](../demo/README.md).

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

## Per-run enterprise audit

Create a unique result and JSON Lines audit file for each run:

```powershell
$runSuffix = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))

.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -AuditPath "C:\Ops\Audit\system-info-$runSuffix.jsonl" `
  -JsonOutputPath "C:\Ops\Results\system-info-$runSuffix.json"
```

The audit path must be a new `.jsonl` file. The result's `audit.complete` must be true before a collector treats the terminal summary as complete. Each target uses the same stable `targetId` across the result envelope and every target-specific audit event.

## Existing Windows Event Log source

When an administrator has separately pre-registered and approved the `WindowsAdminToolkit` source, bounded audit events can be sent to it as well:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -AuditPath C:\Ops\Audit\system-info-20260822.jsonl `
  -AuditEventLog `
  -AuditEventSource WindowsAdminToolkit `
  -JsonOutputPath -
```

The toolkit does not register the source or change Windows Event Log configuration. If either explicitly configured sink fails, the run cannot report complete audit delivery.

## Select the authoritative SIEM summary

A normal run has one `run.summary`. A post-execution JSON result-delivery failure can append `audit.failure` and a replacement summary, so collectors should select the highest sequence:

```powershell
$records = Get-Content -LiteralPath C:\Ops\Audit\system-info-20260822.jsonl |
  Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
  ForEach-Object { $_ | ConvertFrom-Json }

$summary = $records |
  Where-Object eventType -eq 'run.summary' |
  Sort-Object sequence |
  Select-Object -Last 1

if (-not $summary -or $summary.summary.outcome -ne 'CompleteSuccess') {
  throw 'The authoritative audit summary is missing or unsuccessful.'
}
```

Verify sequence continuity and the documented summary hash before long-term ingestion. See [../../AUDITING.md](../../AUDITING.md).

## Windows scheduled task

This registration example uses an explicit working directory plus unique result and audit paths. Create the directories and grant the scheduled-task identity only the access it needs before registering the task.

```powershell
$toolkitDirectory = 'C:\Program Files\WindowsAdminToolkit'
$powerShellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$taskCommand = @'
$resultDirectory = 'C:\ProgramData\WindowsAdminToolkit\Results'
$auditDirectory = 'C:\ProgramData\WindowsAdminToolkit\Audit'
$runSuffix = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$resultName = "nightly-system-info-$runSuffix.json"
$auditName = "nightly-system-info-$runSuffix.jsonl"
$resultPath = Join-Path $resultDirectory $resultName
$auditPath = Join-Path $auditDirectory $auditName
& '.\WindowsAdminToolkit.ps1' -Automation -Action SystemInfo -Local -AuditPath $auditPath -JsonOutputPath $resultPath
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

The task creates timestamped result and audit files with a random suffix on every run. The toolkit refuses to overwrite either file. Archive or remove old evidence only through a separately reviewed retention job.

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

The [`results`](results) directory contains schema version 1.2 examples for complete success, audited success, partial success, validation failure, execution failure, timeout, `WhatIf`, policy denial, and capability preflight. The complete audit stream for the audited result is in [`../audit/audited-success.jsonl`](../audit/audited-success.jsonl). The examples use synthetic hostnames and contain no credentials or private environment data.

Controlled plan creation, approval, execution, and resume use a separate orchestration result contract. See [`../../ORCHESTRATION.md`](../../ORCHESTRATION.md) and the correlated synthetic artifacts in [`../orchestration`](../orchestration).
