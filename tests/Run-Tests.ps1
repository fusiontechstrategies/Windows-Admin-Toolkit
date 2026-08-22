<#
.SYNOPSIS
    Runs dependency-free offline tests for Windows Admin Toolkit.
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$toolkitPath = Join-Path $projectRoot 'WindowsAdminToolkit.ps1'

if (-not (Test-Path -LiteralPath $toolkitPath -PathType Leaf)) {
    throw "Toolkit script not found: $toolkitPath"
}

. $toolkitPath
Set-StrictMode -Version 2.0

$Script:TestCount = 0
$Script:Failures = New-Object 'System.Collections.Generic.List[string]'

function Test-ToolkitAssertion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $Script:TestCount++
    if ($Condition) {
        Write-Host "PASS: $Name" -ForegroundColor Green
    }
    else {
        Write-Host "FAIL: $Name" -ForegroundColor Red
        $Script:Failures.Add($Name) | Out-Null
    }
}

function Test-ToolkitThrow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $threw = $false
    try {
        & $Action
    }
    catch {
        $threw = $true
    }

    Test-ToolkitAssertion -Condition $threw -Name $Name
}

function Invoke-ToolkitChildProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$EnginePath,

        [Parameter(Mandatory = $true)]
        [string]$InvocationText,

        [Parameter()]
        [ValidateRange(5, 120)]
        [int]$TimeoutSeconds = 60,

        [Parameter()]
        [switch]$FileMode,

        [Parameter()]
        [switch]$OmitNonInteractive
    )

    if ($FileMode) {
        $commandText = $null
    }
    else {
        $escapedToolkitPath = $toolkitPath.Replace("'", "''")
        $commandText = @"
`$ProgressPreference = 'SilentlyContinue'
`$VerbosePreference = 'SilentlyContinue'
`$DebugPreference = 'SilentlyContinue'
`$InformationPreference = 'SilentlyContinue'
& '$escapedToolkitPath' $InvocationText
exit `$LASTEXITCODE
"@
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $EnginePath
    $nonInteractiveArgument = if ($OmitNonInteractive) { '' } else { '-NonInteractive ' }
    if ($FileMode) {
        $startInfo.Arguments = "-NoLogo -NoProfile $nonInteractiveArgument-File `"$toolkitPath`" $InvocationText"
    }
    else {
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($commandText))
        $startInfo.Arguments = "-NoLogo -NoProfile $nonInteractiveArgument-EncodedCommand $encodedCommand"
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw 'Unable to start the child PowerShell process.'
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { Write-Verbose $_.Exception.Message }
            throw "The child PowerShell process exceeded $TimeoutSeconds seconds."
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut   = $stdout
            StdErr   = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

Test-ToolkitAssertion -Condition ($Script:ToolkitVersion -eq '2.1.0') -Name 'Version is 2.1.0'
Test-ToolkitAssertion -Condition ($Script:ActionCatalog.Count -eq 20) -Name 'Action catalog contains 20 actions'
Test-ToolkitAssertion -Condition ($Script:ActionScripts.Count -eq 20) -Name 'Action script registry contains 20 scripts'
Test-ToolkitAssertion -Condition ($Script:AutomationSchemaVersion -eq '1.0') -Name 'Automation schema version is 1.0'

$expectedActionIds = @(
    'SystemInfo',
    'DiskSpace',
    'HardwareInfo',
    'NetworkConfig',
    'LoggedOnUsers',
    'RunningProcesses',
    'SoftwareInventory',
    'LicenseStatus',
    'WindowsUpdate',
    'ScheduleReboot',
    'PendingReboot',
    'ServiceManagement',
    'TerminateProcess',
    'ClearTempFiles',
    'ScheduledTasks',
    'FirewallStatus',
    'EventLogQuery',
    'RegistryRead',
    'CustomCommand',
    'CustomPowerShell'
)
$actualActionIds = @($Script:ActionCatalog.GetEnumerator() | ForEach-Object { $_.Value.Id })
Test-ToolkitAssertion -Condition (($actualActionIds -join '|') -ceq ($expectedActionIds -join '|')) -Name 'Stable action identifiers retain their documented order'
Test-ToolkitAssertion -Condition (@($actualActionIds | Sort-Object -Unique).Count -eq 20) -Name 'Stable action identifiers are unique'
for ($actionIndex = 0; $actionIndex -lt $expectedActionIds.Count; $actionIndex++) {
    $menuNumber = $actionIndex + 1
    $menuItem = Get-AdminActionCatalogItemByMenuNumber -MenuNumber $menuNumber
    Test-ToolkitAssertion -Condition ($menuItem.Id -ceq $expectedActionIds[$actionIndex]) -Name "Action position $menuNumber retains identifier $($expectedActionIds[$actionIndex])"
}

$expectedClassifications = [ordered]@{
    SystemInfo        = 'ReadOnly'
    DiskSpace         = 'ReadOnly'
    HardwareInfo      = 'ReadOnly'
    NetworkConfig     = 'ReadOnly'
    LoggedOnUsers     = 'ReadOnly'
    RunningProcesses  = 'ReadOnly'
    SoftwareInventory = 'ReadOnly'
    LicenseStatus     = 'ReadOnly'
    WindowsUpdate     = 'StateChanging'
    ScheduleReboot    = 'StateChanging'
    PendingReboot     = 'ReadOnly'
    ServiceManagement = 'Conditional'
    TerminateProcess  = 'StateChanging'
    ClearTempFiles    = 'StateChanging'
    ScheduledTasks    = 'ReadOnly'
    FirewallStatus    = 'ReadOnly'
    EventLogQuery     = 'ReadOnly'
    RegistryRead      = 'ReadOnly'
    CustomCommand     = 'StateChanging'
    CustomPowerShell  = 'StateChanging'
}
foreach ($actionId in $expectedClassifications.Keys) {
    $catalogItem = Get-AdminActionCatalogItem -ActionId $actionId
    Test-ToolkitAssertion -Condition ($catalogItem.Classification -ceq $expectedClassifications[$actionId]) -Name "Action $actionId retains classification $($expectedClassifications[$actionId])"
}

$expectedExitCodes = [ordered]@{
    CompleteSuccess      = 0
    PartialSuccess       = 1
    ValidationFailure    = 2
    AuthorizationFailure = 3
    ExecutionFailure     = 4
    Timeout              = 5
    InternalFailure      = 10
}
foreach ($outcomeName in $expectedExitCodes.Keys) {
    Test-ToolkitAssertion -Condition ([int]$Script:AutomationExitCodes[$outcomeName] -eq $expectedExitCodes[$outcomeName]) -Name "Exit code for $outcomeName is stable"
}

foreach ($entry in $Script:ActionCatalog.GetEnumerator()) {
    Test-ToolkitAssertion -Condition ($Script:ActionScripts.Contains($entry.Value.Script)) -Name "Catalog action $($entry.Key) has a registered script"
}

foreach ($entry in $Script:ActionScripts.GetEnumerator()) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($entry.Value.ToString(), [ref]$tokens, [ref]$parseErrors)
    Test-ToolkitAssertion -Condition (@($parseErrors).Count -eq 0) -Name "Action script $($entry.Key) parses in this engine"
    Test-ToolkitAssertion -Condition ($entry.Value.ToString() -notmatch '\bRead-Host\b') -Name "Action script $($entry.Key) is noninteractive"
}

$automationCatalog = @(Get-AdminAutomationActionCatalog)
Test-ToolkitAssertion -Condition ($automationCatalog.Count -eq 20) -Name 'Automation catalog enumerates 20 actions'
Test-ToolkitAssertion -Condition (($automationCatalog.id -join '|') -ceq ($expectedActionIds -join '|')) -Name 'Automation catalog uses stable action identifiers'
Test-ToolkitAssertion -Condition (@($automationCatalog | Where-Object { $_.id -eq 'ServiceManagement' }).inputs.Count -eq 2) -Name 'Automation catalog describes conditional service inputs'
Test-ToolkitAssertion -Condition (@($automationCatalog | Where-Object { $_.id -eq 'CustomPowerShell' }).inputs.Count -eq 2) -Name 'Automation catalog describes both PowerShell input sources'

$validAutomationRequests = [ordered]@{
    SystemInfo        = @{ Action = 'SystemInfo'; Local = $true }
    DiskSpace         = @{ Action = 'DiskSpace'; Local = $true }
    HardwareInfo      = @{ Action = 'HardwareInfo'; Local = $true }
    NetworkConfig     = @{ Action = 'NetworkConfig'; Local = $true }
    LoggedOnUsers     = @{ Action = 'LoggedOnUsers'; Local = $true }
    RunningProcesses  = @{ Action = 'RunningProcesses'; Local = $true; TopCount = 1 }
    SoftwareInventory = @{ Action = 'SoftwareInventory'; Local = $true }
    LicenseStatus     = @{ Action = 'LicenseStatus'; Local = $true }
    WindowsUpdate     = @{ Action = 'WindowsUpdate'; Local = $true; IncludeKB = @('KB5034441'); WhatIf = $true }
    ScheduleReboot    = @{ Action = 'ScheduleReboot'; Local = $true; RebootDelaySeconds = 60; WhatIf = $true }
    PendingReboot     = @{ Action = 'PendingReboot'; Local = $true }
    ServiceManagement = @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'wuauserv'; ServiceAction = 'Query' }
    TerminateProcess  = @{ Action = 'TerminateProcess'; Local = $true; ProcessName = 'notepad.exe'; WhatIf = $true }
    ClearTempFiles    = @{ Action = 'ClearTempFiles'; Local = $true; MinimumAgeDays = 2; MaximumFiles = 100; WhatIf = $true }
    ScheduledTasks    = @{ Action = 'ScheduledTasks'; Local = $true; TaskPath = '\Microsoft\Windows\'; MaximumTasks = 1 }
    FirewallStatus    = @{ Action = 'FirewallStatus'; Local = $true }
    EventLogQuery     = @{ Action = 'EventLogQuery'; Local = $true; EventLogName = 'System'; EntryCount = 1; EventLevel = @('Error', 'Warning') }
    RegistryRead      = @{ Action = 'RegistryRead'; Local = $true; RegistryPath = 'HKLM:'; RegistryValueName = '' }
    CustomCommand     = @{ Action = 'CustomCommand'; Local = $true; CommandText = 'ver'; WhatIf = $true }
    CustomPowerShell  = @{ Action = 'CustomPowerShell'; Local = $true; PowerShellText = 'Get-Date'; WhatIf = $true }
}
foreach ($actionId in $validAutomationRequests.Keys) {
    $resolution = Resolve-AdminAutomationRequest -Parameters $validAutomationRequests[$actionId]
    Test-ToolkitAssertion -Condition ($resolution.Success -and $resolution.Request.ActionId -ceq $actionId) -Name "Automation request validates action $actionId without prompting"
}
$updateArrayResolution = Resolve-AdminAutomationRequest -Parameters $validAutomationRequests.WindowsUpdate
Test-ToolkitAssertion -Condition ($updateArrayResolution.Request.Arguments.Count -eq 1 -and @($updateArrayResolution.Request.Arguments[0]).Count -eq 1 -and $updateArrayResolution.Request.Arguments[0][0] -ceq 'KB5034441') -Name 'Windows Update preserves its KB list as one array argument'
$eventArrayResolution = Resolve-AdminAutomationRequest -Parameters $validAutomationRequests.EventLogQuery
Test-ToolkitAssertion -Condition ($eventArrayResolution.Request.Arguments.Count -eq 3 -and (@($eventArrayResolution.Request.Arguments[2]) -join '|') -ceq 'Error|Warning') -Name 'Event Log Query preserves every event level as one array argument'

$unknownActionResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'NoSuchAction'; Local = $true }
Test-ToolkitAssertion -Condition (-not $unknownActionResolution.Success -and $unknownActionResolution.Category -eq 'Validation') -Name 'Automation rejects an unknown action identifier'
$missingActionResolution = Resolve-AdminAutomationRequest -Parameters @{ Local = $true }
Test-ToolkitAssertion -Condition (-not $missingActionResolution.Success -and $missingActionResolution.Category -eq 'Validation') -Name 'Automation requires a named action'
$missingTargetResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo' }
Test-ToolkitAssertion -Condition (-not $missingTargetResolution.Success -and $missingTargetResolution.Category -eq 'Validation') -Name 'Automation requires an explicit target source'
$conflictingTargetResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; Local = $true; ComputerName = 'server01.example.com' }
Test-ToolkitAssertion -Condition (-not $conflictingTargetResolution.Success -and $conflictingTargetResolution.Category -eq 'Validation') -Name 'Automation rejects conflicting target selectors'
$invalidRemoteResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server&whoami' }
Test-ToolkitAssertion -Condition (-not $invalidRemoteResolution.Success -and $invalidRemoteResolution.Category -eq 'Validation') -Name 'Automation rejects an invalid single remote target'
$validRemoteResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com' }
Test-ToolkitAssertion -Condition ($validRemoteResolution.Success -and $validRemoteResolution.Request.TargetMode -eq 'Remote' -and @($validRemoteResolution.Request.Computers).Count -eq 1 -and $validRemoteResolution.Request.Computers[0] -ceq 'server01.example.com') -Name 'Automation resolves one validated remote target without connecting'
$winRmPsExecPathResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com'; Transport = 'WinRM'; PsExecPath = 'PsExec64.exe' }
Test-ToolkitAssertion -Condition (-not $winRmPsExecPathResolution.Success -and $winRmPsExecPathResolution.Category -eq 'Validation') -Name 'WinRM automation rejects a PsExec-only executable path'
$originalTransport = $Script:State.Transport
try {
    $Script:State.Transport = 'PsExec'
    $psExecAuthenticationResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com'; Transport = 'PsExec'; Authentication = 'Kerberos' }
    Test-ToolkitAssertion -Condition (-not $psExecAuthenticationResolution.Success -and $psExecAuthenticationResolution.Category -eq 'Validation') -Name 'PsExec automation rejects WinRM authentication controls'
    $psExecSslResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com'; Transport = 'PsExec'; UseSsl = $true }
    Test-ToolkitAssertion -Condition (-not $psExecSslResolution.Success -and $psExecSslResolution.Category -eq 'Validation') -Name 'PsExec automation rejects WinRM SSL controls'
}
finally {
    $Script:State.Transport = $originalTransport
}
$incompatibleInputResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; Local = $true; TopCount = 1 }
Test-ToolkitAssertion -Condition (-not $incompatibleInputResolution.Success -and $incompatibleInputResolution.Category -eq 'Validation') -Name 'Automation rejects an action input supplied to the wrong action'
$confirmPromptResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; Local = $true; Confirm = $true }
Test-ToolkitAssertion -Condition (-not $confirmPromptResolution.Success -and $confirmPromptResolution.Category -eq 'Validation') -Name 'Automation rejects an interactive Confirm prompt'
$originalCredential = $Script:State.Credential
try {
    $Script:State.Credential = 'synthetic-user'
    $stringCredentialResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com'; Credential = 'synthetic-user' }
    Test-ToolkitAssertion -Condition (-not $stringCredentialResolution.Success -and $stringCredentialResolution.Category -eq 'Validation' -and $stringCredentialResolution.Message -match 'PSCredential') -Name 'Automation rejects username strings before credential prompting'
}
finally {
    $Script:State.Credential = $originalCredential
}
$emptySecureString = New-Object System.Security.SecureString
$syntheticCredential = New-Object System.Management.Automation.PSCredential -ArgumentList 'synthetic-user', $emptySecureString
try {
    $Script:State.Credential = $syntheticCredential
    $objectCredentialResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com'; Credential = $syntheticCredential }
    Test-ToolkitAssertion -Condition $objectCredentialResolution.Success -Name 'Automation accepts an in-memory PSCredential object for WinRM'
}
finally {
    $Script:State.Credential = $originalCredential
}

$invalidInputCases = [ordered]@{
    'RunningProcesses rejects TopCount below its limit' = @{ Action = 'RunningProcesses'; Local = $true; TopCount = 0 }
    'RunningProcesses rejects TopCount above its limit' = @{ Action = 'RunningProcesses'; Local = $true; TopCount = 101 }
    'WindowsUpdate rejects an unsafe KB identifier' = @{ Action = 'WindowsUpdate'; Local = $true; IncludeKB = @('KB1;whoami'); WhatIf = $true }
    'ScheduleReboot rejects a delay below its limit' = @{ Action = 'ScheduleReboot'; Local = $true; RebootDelaySeconds = 1; WhatIf = $true }
    'ScheduleReboot rejects a delay above its limit' = @{ Action = 'ScheduleReboot'; Local = $true; RebootDelaySeconds = 3601; WhatIf = $true }
    'ServiceManagement requires ServiceName' = @{ Action = 'ServiceManagement'; Local = $true; ServiceAction = 'Query' }
    'ServiceManagement rejects an unsafe ServiceName' = @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'bad service'; ServiceAction = 'Query' }
    'ServiceManagement rejects an unknown ServiceAction' = @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'wuauserv'; ServiceAction = 'Delete' }
    'TerminateProcess requires ProcessName' = @{ Action = 'TerminateProcess'; Local = $true; WhatIf = $true }
    'TerminateProcess rejects a process path' = @{ Action = 'TerminateProcess'; Local = $true; ProcessName = 'C:\Windows\notepad.exe'; WhatIf = $true }
    'ClearTempFiles rejects an age below its limit' = @{ Action = 'ClearTempFiles'; Local = $true; MinimumAgeDays = 0; WhatIf = $true }
    'ClearTempFiles rejects an age above its limit' = @{ Action = 'ClearTempFiles'; Local = $true; MinimumAgeDays = 31; WhatIf = $true }
    'ClearTempFiles rejects an unsafe file limit' = @{ Action = 'ClearTempFiles'; Local = $true; MaximumFiles = 1; WhatIf = $true }
    'ClearTempFiles rejects a file limit above its maximum' = @{ Action = 'ClearTempFiles'; Local = $true; MaximumFiles = 100001; WhatIf = $true }
    'ScheduledTasks rejects path traversal' = @{ Action = 'ScheduledTasks'; Local = $true; TaskPath = '\Microsoft\..\' }
    'ScheduledTasks rejects a task count below its limit' = @{ Action = 'ScheduledTasks'; Local = $true; MaximumTasks = 0 }
    'ScheduledTasks rejects a task count above its limit' = @{ Action = 'ScheduledTasks'; Local = $true; MaximumTasks = 501 }
    'EventLogQuery rejects an unsafe channel' = @{ Action = 'EventLogQuery'; Local = $true; EventLogName = 'System;whoami' }
    'EventLogQuery rejects an entry count below its limit' = @{ Action = 'EventLogQuery'; Local = $true; EntryCount = 0 }
    'EventLogQuery rejects an entry count above its limit' = @{ Action = 'EventLogQuery'; Local = $true; EntryCount = 1001 }
    'EventLogQuery rejects an unknown level' = @{ Action = 'EventLogQuery'; Local = $true; EventLevel = @('Audit') }
    'EventLogQuery requires at least one level' = @{ Action = 'EventLogQuery'; Local = $true; EventLevel = @() }
    'EventLogQuery bounds level input size' = @{ Action = 'EventLogQuery'; Local = $true; EventLevel = @(('E' * 1025) -join '') }
    'RegistryRead requires RegistryPath' = @{ Action = 'RegistryRead'; Local = $true }
    'RegistryRead rejects a non-registry path' = @{ Action = 'RegistryRead'; Local = $true; RegistryPath = 'FileSystem::C:\' }
    'RegistryRead rejects a newline in the value name' = @{ Action = 'RegistryRead'; Local = $true; RegistryPath = 'HKLM:'; RegistryValueName = "bad`nvalue" }
    'CustomCommand requires CommandText' = @{ Action = 'CustomCommand'; Local = $true; WhatIf = $true }
    'CustomCommand bounds command text length' = @{ Action = 'CustomCommand'; Local = $true; CommandText = ('x' * 32768); WhatIf = $true }
    'CustomPowerShell requires one source' = @{ Action = 'CustomPowerShell'; Local = $true; WhatIf = $true }
    'CustomPowerShell rejects two source forms' = @{ Action = 'CustomPowerShell'; Local = $true; PowerShellText = 'Get-Date'; PowerShellFile = 'missing.ps1'; WhatIf = $true }
    'CustomPowerShell rejects invalid syntax' = @{ Action = 'CustomPowerShell'; Local = $true; PowerShellText = 'if ('; WhatIf = $true }
    'CustomPowerShell bounds source text length' = @{ Action = 'CustomPowerShell'; Local = $true; PowerShellText = ('x' * 1048577); WhatIf = $true }
}
foreach ($caseName in $invalidInputCases.Keys) {
    $resolution = Resolve-AdminAutomationRequest -Parameters $invalidInputCases[$caseName]
    Test-ToolkitAssertion -Condition (-not $resolution.Success -and $resolution.Category -eq 'Validation') -Name $caseName
}

$protectedProcessResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'TerminateProcess'; Local = $true; ProcessName = 'lsass.exe'; WhatIf = $true }
Test-ToolkitAssertion -Condition (-not $protectedProcessResolution.Success -and $protectedProcessResolution.Category -eq 'Authorization') -Name 'Automation blocks protected process termination before execution'
$readOnlyConfirmationResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; Local = $true; ConfirmationText = 'UNUSED' }
Test-ToolkitAssertion -Condition (-not $readOnlyConfirmationResolution.Success -and $readOnlyConfirmationResolution.Category -eq 'Validation') -Name 'Automation rejects confirmation text for a read-only request'
$excessiveKbResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'WindowsUpdate'; Local = $true; IncludeKB = @(1..101 | ForEach-Object { 'KB{0:d6}' -f $_ }); WhatIf = $true }
Test-ToolkitAssertion -Condition (-not $excessiveKbResolution.Success -and $excessiveKbResolution.Message -match 'at most 100') -Name 'Automation bounds Windows Update KB filter counts'

$guardedRequestCases = @(
    [pscustomobject]@{ Id = 'WindowsUpdate'; Base = @{ Action = 'WindowsUpdate'; Local = $true }; Token = 'INSTALL UPDATES' },
    [pscustomobject]@{ Id = 'ScheduleReboot'; Base = @{ Action = 'ScheduleReboot'; Local = $true }; Token = 'SCHEDULE REBOOT' },
    [pscustomobject]@{ Id = 'ServiceManagement'; Base = @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'wuauserv'; ServiceAction = 'Start' }; Token = 'CHANGE SERVICE' },
    [pscustomobject]@{ Id = 'TerminateProcess'; Base = @{ Action = 'TerminateProcess'; Local = $true; ProcessName = 'notepad.exe' }; Token = 'TERMINATE PROCESS' },
    [pscustomobject]@{ Id = 'ClearTempFiles'; Base = @{ Action = 'ClearTempFiles'; Local = $true }; Token = 'DELETE TEMP FILES' },
    [pscustomobject]@{ Id = 'CustomCommand'; Base = @{ Action = 'CustomCommand'; Local = $true; CommandText = 'ver' }; Token = 'RUN COMMAND' },
    [pscustomobject]@{ Id = 'CustomPowerShell'; Base = @{ Action = 'CustomPowerShell'; Local = $true; PowerShellText = 'Get-Date' }; Token = 'RUN SCRIPT' }
)
foreach ($guardedCase in $guardedRequestCases) {
    $missingResolution = Resolve-AdminAutomationRequest -Parameters $guardedCase.Base
    Test-ToolkitAssertion -Condition (-not $missingResolution.Success -and $missingResolution.Category -eq 'Authorization') -Name "Action $($guardedCase.Id) rejects missing exact confirmation"

    $wrongParameters = @{} + $guardedCase.Base
    $wrongParameters.ConfirmationText = $guardedCase.Token.ToLowerInvariant()
    $wrongResolution = Resolve-AdminAutomationRequest -Parameters $wrongParameters
    Test-ToolkitAssertion -Condition (-not $wrongResolution.Success -and $wrongResolution.Category -eq 'Authorization') -Name "Action $($guardedCase.Id) treats confirmation as case-sensitive"

    $correctParameters = @{} + $guardedCase.Base
    $correctParameters.ConfirmationText = $guardedCase.Token
    $correctResolution = Resolve-AdminAutomationRequest -Parameters $correctParameters
    Test-ToolkitAssertion -Condition ($correctResolution.Success -and -not $correctResolution.Request.ReadOnly) -Name "Action $($guardedCase.Id) accepts its exact confirmation"

    $whatIfParameters = @{} + $guardedCase.Base
    $whatIfParameters.WhatIf = $true
    $whatIfResolution = Resolve-AdminAutomationRequest -Parameters $whatIfParameters
    Test-ToolkitAssertion -Condition $whatIfResolution.Success -Name "Action $($guardedCase.Id) permits a confirmation-free WhatIf preview"
}

$serviceQueryResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'wuauserv'; ServiceAction = 'Query' }
$serviceStartResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'wuauserv'; ServiceAction = 'Start'; ConfirmationText = 'CHANGE SERVICE' }
Test-ToolkitAssertion -Condition $serviceQueryResolution.Request.ReadOnly -Name 'Service Query is classified read-only at request time'
Test-ToolkitAssertion -Condition (-not $serviceStartResolution.Request.ReadOnly) -Name 'Service Start is classified state-changing at request time'

$Script:State.RetryCount = 3
Test-ToolkitAssertion -Condition ((Get-AdminEffectiveRetryCount -ReadOnly $true) -eq 3) -Name 'Read-only automation retains configured retries'
Test-ToolkitAssertion -Condition ((Get-AdminEffectiveRetryCount -ReadOnly $false) -eq 0) -Name 'State-changing automation disables retries'
$Script:State.RetryCount = 1

$syntheticTime = [datetime]::UtcNow
$syntheticSuccess = ConvertTo-AdminDetailedTargetResult -Index 0 -ComputerName 'server01.example.com' -Transport WinRM -StartedAtUtc $syntheticTime -FinishedAtUtc $syntheticTime -Status Success -Attempts 1 -Data @([pscustomobject]@{ Status = 'Success' })
$syntheticPartial = ConvertTo-AdminDetailedTargetResult -Index 1 -ComputerName 'server02.example.com' -Transport WinRM -StartedAtUtc $syntheticTime -FinishedAtUtc $syntheticTime -Status Partial -Attempts 1 -Data @([pscustomobject]@{ Status = 'Partial' })
$syntheticFailure = ConvertTo-AdminDetailedTargetResult -Index 1 -ComputerName 'server02.example.com' -Transport WinRM -StartedAtUtc $syntheticTime -FinishedAtUtc $syntheticTime -Status Failed -Attempts 1 -ErrorCategory Execution -ErrorMessage 'Synthetic failure'
$syntheticTimeout = ConvertTo-AdminDetailedTargetResult -Index 0 -ComputerName 'server03.example.com' -Transport WinRM -StartedAtUtc $syntheticTime -FinishedAtUtc $syntheticTime -Status TimedOut -Attempts 1 -ErrorCategory Timeout -ErrorMessage 'Synthetic timeout'
Test-ToolkitAssertion -Condition ((Get-AdminAutomationOutcome -TargetResults @($syntheticSuccess)).ExitCode -eq 0) -Name 'Aggregation maps complete success to exit code 0'
Test-ToolkitAssertion -Condition ((Get-AdminAutomationOutcome -TargetResults @($syntheticSuccess, $syntheticFailure)).ExitCode -eq 1) -Name 'Aggregation maps mixed target results to partial exit code 1'
Test-ToolkitAssertion -Condition ((Get-AdminAutomationOutcome -TargetResults @($syntheticPartial)).ExitCode -eq 1) -Name 'Aggregation maps action partial status to exit code 1'
Test-ToolkitAssertion -Condition ((Get-AdminTargetStatusFromData -Data @([pscustomobject]@{ Status = 'ChecksWithErrors' })) -eq 'Partial') -Name 'Pending reboot check errors map to a partial target result'
Test-ToolkitAssertion -Condition ((Get-AdminAutomationOutcome -TargetResults @($syntheticFailure)).ExitCode -eq 4) -Name 'Aggregation maps execution failure to exit code 4'
Test-ToolkitAssertion -Condition ((Get-AdminAutomationOutcome -TargetResults @($syntheticTimeout)).ExitCode -eq 5) -Name 'Aggregation maps an all-timeout run to exit code 5'

$safeJsonObject = ConvertTo-AdminJsonSafeValue -Value ([pscustomobject]@{
        DateValue      = [datetime]'2026-08-22T12:34:56Z'
        Values         = @(1)
        Credential     = [System.Management.Automation.PSCredential]::Empty
        ScriptBlock    = { Get-Date }
        Exception      = (New-Object System.InvalidOperationException -ArgumentList 'synthetic')
        PSComputerName = 'server01.example.com'
    })
$safeJsonText = ConvertTo-Json -InputObject $safeJsonObject -Compress -Depth 10
Test-ToolkitAssertion -Condition ($safeJsonText -match '"Values":\[1\]') -Name 'JSON normalization preserves one-item arrays'
Test-ToolkitAssertion -Condition ($safeJsonText -match '2026-08-22T12:34:56\.000Z') -Name 'JSON normalization emits UTC ISO 8601 dates'
Test-ToolkitAssertion -Condition ($safeJsonText -notmatch 'Credential|ScriptBlock|Exception|PSComputerName') -Name 'JSON normalization excludes sensitive and remoting fields'
$nonfiniteJsonText = ConvertTo-Json -InputObject (ConvertTo-AdminJsonSafeValue -Value ([pscustomobject]@{ NaN = [double]::NaN; Positive = [double]::PositiveInfinity; Negative = [single]::NegativeInfinity })) -Compress
Test-ToolkitAssertion -Condition ($nonfiniteJsonText -ceq '{"NaN":"NaN","Negative":"-Infinity","Positive":"Infinity"}') -Name 'JSON normalization makes nonfinite numbers valid and edition-stable'
$dictionaryValue = @{}
$dictionaryValue.Add([int]1, 'integer key')
$dictionaryValue.Add([string]'1', 'string key')
$dictionaryValue.Add([int]2, 'second integer key')
$dictionaryJsonText = ConvertTo-Json -InputObject (ConvertTo-AdminJsonSafeValue -Value $dictionaryValue) -Compress
Test-ToolkitAssertion -Condition ($dictionaryJsonText -ceq '{"1":"integer key","1#2":"string key","2":"second integer key"}') -Name 'JSON normalization preserves values for non-string and colliding dictionary keys'

$automationSourceText = Get-Content -LiteralPath $toolkitPath -Raw
$automationTokens = $null
$automationParseErrors = $null
$automationSourceAst = [System.Management.Automation.Language.Parser]::ParseInput($automationSourceText, [ref]$automationTokens, [ref]$automationParseErrors)
$automationFunctionAsts = @(
    $automationSourceAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Invoke-AdminAutomation', 'Resolve-AdminAutomationRequest') }, $true)
)
$automationFunctionText = ($automationFunctionAsts | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
Test-ToolkitAssertion -Condition ($automationFunctionText -notmatch '\bRead-Host\b|\bGet-Credential\b|\bShow-AdminMenu\b|\bSelect-AdminTargetContext\b|\bExport-AdminResult\b') -Name 'Automation implementation does not call interactive input or export paths'

Test-ToolkitAssertion -Condition (Test-AdminHostname -ComputerName 'SERVER01') -Name 'Accepts a NetBIOS-style computer name'
Test-ToolkitAssertion -Condition (Test-AdminHostname -ComputerName 'server-01.example.com') -Name 'Accepts a valid FQDN'
Test-ToolkitAssertion -Condition (Test-AdminHostname -ComputerName '192.0.2.10') -Name 'Accepts canonical IPv4'
Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName '010.0.0.1')) -Name 'Rejects ambiguous IPv4 notation'
Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName '127.1')) -Name 'Rejects abbreviated IPv4 notation'
Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName '::1')) -Name 'Rejects unsupported IPv6 targets'
Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName '-server')) -Name 'Rejects a leading hyphen'
Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName 'server&whoami')) -Name 'Rejects command metacharacters in targets'
Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName 'server_name')) -Name 'Rejects invalid underscore labels'
Test-ToolkitAssertion -Condition (-not (Test-AdminTcpPort -ComputerName 'server&whoami' -Port 5985 -TimeoutSeconds 1)) -Name 'TCP probe rejects an invalid target before connecting'

Test-ToolkitAssertion -Condition (Test-AdminServiceName -ServiceName 'wuauserv') -Name 'Accepts a valid service name'
Test-ToolkitAssertion -Condition (-not (Test-AdminServiceName -ServiceName 'service & whoami')) -Name 'Rejects an unsafe service name'
Test-ToolkitAssertion -Condition (Test-AdminProcessName -ProcessName 'notepad.exe') -Name 'Accepts a valid process name'
Test-ToolkitAssertion -Condition (-not (Test-AdminProcessName -ProcessName '..\notepad.exe')) -Name 'Rejects a process path'
Test-ToolkitThrow -Action { & $Script:ActionScripts.TerminateProcess 'svchost.exe' | Out-Null } -Name 'Process action blocks termination of svchost'

Test-ToolkitAssertion -Condition (Test-AdminRegistryPath -RegistryPath 'HKLM:') -Name 'Accepts a registry hive root'
Test-ToolkitAssertion -Condition (Test-AdminRegistryPath -RegistryPath 'HKLM:\SOFTWARE\Microsoft') -Name 'Accepts a registry provider path'
Test-ToolkitAssertion -Condition (Test-AdminRegistryPath -RegistryPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft') -Name 'Accepts a long registry hive path'
Test-ToolkitAssertion -Condition (-not (Test-AdminRegistryPath -RegistryPath 'HKLM:unsafe')) -Name 'Rejects a malformed registry provider path'
Test-ToolkitAssertion -Condition (-not (Test-AdminRegistryPath -RegistryPath 'HKLM:\SOFTWARE\..\SAM')) -Name 'Rejects registry provider traversal notation'
Test-ToolkitAssertion -Condition (-not (Test-AdminRegistryPath -RegistryPath "HKLM:\SOFTWARE$([char]10)Bad")) -Name 'Rejects a registry path containing a newline'
Test-ToolkitAssertion -Condition (Test-AdminRegistryValueName -ValueName 'Display Name') -Name 'Accepts a registry value containing spaces'
Test-ToolkitAssertion -Condition (-not (Test-AdminRegistryValueName -ValueName "Bad$([char]0)Name")) -Name 'Rejects a registry value containing a null character'

Test-ToolkitAssertion -Condition (Test-AdminEventLogName -LogName 'Microsoft-Windows-PowerShell/Operational') -Name 'Accepts a valid event log channel'
Test-ToolkitAssertion -Condition (-not (Test-AdminEventLogName -LogName 'System;whoami')) -Name 'Rejects event log metacharacters'
Test-ToolkitAssertion -Condition (Test-AdminTaskPath -TaskPath '\Microsoft\Windows\') -Name 'Accepts a valid scheduled-task path'
Test-ToolkitAssertion -Condition (-not (Test-AdminTaskPath -TaskPath '\Microsoft\..\')) -Name 'Rejects scheduled-task traversal notation'
Test-ToolkitAssertion -Condition (Test-AdminKbNumber -KbNumber 'KB5034441') -Name 'Accepts a valid KB number'
Test-ToolkitAssertion -Condition (-not (Test-AdminKbNumber -KbNumber 'KB1;whoami')) -Name 'Rejects an unsafe KB number'
Test-ToolkitAssertion -Condition (Test-AdminLiteralFilePathText -LiteralPath 'C:\Ops\Results\result.json') -Name 'Accepts a safe absolute literal file path'
Test-ToolkitAssertion -Condition (-not (Test-AdminLiteralFilePathText -LiteralPath '..\Results\result.json')) -Name 'Rejects parent traversal in external file paths'
Test-ToolkitAssertion -Condition (-not (Test-AdminLiteralFilePathText -LiteralPath 'C:\Ops\targets.txt:hidden')) -Name 'Rejects alternate data streams in external file paths'
Test-ToolkitAssertion -Condition (-not (Test-AdminLiteralFilePathText -LiteralPath 'C:\Ops\CON.report.json')) -Name 'Rejects Windows device names in external file paths'
Test-ToolkitAssertion -Condition (-not (Test-AdminLiteralFilePathText -LiteralPath '\\.\pipe\result.json') -and -not (Test-AdminLiteralFilePathText -LiteralPath '\\server01\pipe\result.json')) -Name 'Rejects Win32 device and named-pipe file paths'

$validSyntax = Test-AdminPowerShellText -ScriptText 'Get-Date'
$invalidSyntax = Test-AdminPowerShellText -ScriptText 'if ('
Test-ToolkitAssertion -Condition $validSyntax.IsValid -Name 'Accepts valid PowerShell syntax'
Test-ToolkitAssertion -Condition (-not $invalidSyntax.IsValid) -Name 'Rejects invalid PowerShell syntax'

Test-ToolkitAssertion -Condition ((ConvertTo-AdminCsvSafeValue -Value '=1+1').StartsWith("'")) -Name 'Neutralizes equals-prefixed CSV formulas'
Test-ToolkitAssertion -Condition ((ConvertTo-AdminCsvSafeValue -Value '  -2+3').StartsWith("'")) -Name 'Neutralizes whitespace-prefixed CSV formulas'
Test-ToolkitAssertion -Condition ((ConvertTo-AdminCsvSafeValue -Value 'ordinary text') -eq 'ordinary text') -Name 'Preserves ordinary CSV text'
Test-ToolkitAssertion -Condition ((ConvertTo-AdminHtmlEncoded -Value '<script>') -eq '&lt;script&gt;') -Name 'HTML-encodes report values'

$sourceText = Get-Content -LiteralPath $toolkitPath -Raw
Test-ToolkitAssertion -Condition ($sourceText -match '#Requires -Version 5\.1') -Name 'Declares Windows PowerShell 5.1 compatibility'
Test-ToolkitAssertion -Condition ($sourceText -match 'SupportsShouldProcess\s*=\s*\$true') -Name 'Enables ShouldProcess safeguards'
Test-ToolkitAssertion -Condition ($sourceText -notmatch '\bInvoke-Expression\b|\biex\b') -Name 'Does not use Invoke-Expression'
Test-ToolkitAssertion -Condition ($sourceText -notmatch 'GetNetworkCredential\(\)') -Name 'Does not convert credentials to plaintext'
Test-ToolkitAssertion -Condition ($sourceText -notmatch '(?i)ExecutionPolicy\s+Bypass') -Name 'Does not bypass execution policy'
Test-ToolkitAssertion -Condition ($sourceText -notmatch '[''"]-p[''"]') -Name 'Does not pass a PsExec password switch'
Test-ToolkitAssertion -Condition ($sourceText -notmatch '(?i)\bEnable-PSRemoting\b|\bSet-WSManQuickConfig\b|\bSet-ExecutionPolicy\b|\bNew-NetFirewallRule\b|\bSet-NetFirewallProfile\b|winrm\s+quickconfig|netsh\s+advfirewall|WSMan:\\localhost\\Client\\TrustedHosts') -Name 'Does not automatically alter remoting, firewall, TrustedHosts, or execution policy settings'
Test-ToolkitAssertion -Condition ($sourceText.IndexOf([char]0x2014) -lt 0) -Name 'Contains no em dashes'
Test-ToolkitAssertion -Condition ($sourceText -notmatch '[^\x00-\x7F]') -Name 'Application script is ASCII-compatible'

$repositoryTextExtensions = @('.md', '.ps1', '.psd1', '.txt', '.yml', '.yaml')
$repositoryTextNames = @('.editorconfig', '.gitattributes', '.gitignore', 'LICENSE')
$emDashFiles = @(
    Get-ChildItem -LiteralPath $projectRoot -Recurse -File -ErrorAction Stop |
        Where-Object {
            $_.FullName -notmatch '[\\/]\.git[\\/]' -and
            ($_.Extension -in $repositoryTextExtensions -or $_.Name -in $repositoryTextNames)
        } |
        Where-Object { (Get-Content -LiteralPath $_.FullName -Raw).IndexOf([char]0x2014) -ge 0 }
)
Test-ToolkitAssertion -Condition ($emDashFiles.Count -eq 0) -Name 'Repository text contains no em dashes'

$dangerousValue = "safe'; Write-Output 'not executed'; #"
$testAction = 'param([string]$Value) [pscustomobject]@{Value=$Value;Status=''Success''}'
$payload = ConvertTo-AdminEncodedPayload -ActionText $testAction -ArgumentList @($dangerousValue)
$payloadOutput = @(& powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $payload)
$payloadMatch = [regex]::Match(($payloadOutput -join [Environment]::NewLine), '(?m)^ADMINRESULT:(?<Data>[A-Za-z0-9+/=]+)\s*$')
$utf8 = New-Object System.Text.UTF8Encoding($false)
Test-ToolkitAssertion -Condition $payloadMatch.Success -Name 'Encoded payload returns a result envelope'
if ($payloadMatch.Success) {
    $payloadJson = $utf8.GetString([Convert]::FromBase64String($payloadMatch.Groups['Data'].Value))
    $payloadEnvelope = ConvertFrom-Json -InputObject $payloadJson
    Test-ToolkitAssertion -Condition ([bool]$payloadEnvelope.Success) -Name 'Encoded payload reports success'
    Test-ToolkitAssertion -Condition ($payloadEnvelope.Data[0].Value -ceq $dangerousValue) -Name 'Encoded payload preserves argument data without execution'
}

$nestedValues = [string[]]@('KB5000001', 'KB5000002')
$nestedArgumentList = , $nestedValues
$encodedArgumentEnvelope = ConvertTo-AdminArgumentEnvelope -ArgumentList $nestedArgumentList
$decodedArgumentList = @(ConvertFrom-AdminArgumentEnvelope -EncodedEnvelope $encodedArgumentEnvelope)
Test-ToolkitAssertion -Condition ($decodedArgumentList.Count -eq 1) -Name 'Typed argument envelope preserves a single outer array argument'
Test-ToolkitAssertion -Condition ((@($decodedArgumentList[0]) -join '|') -ceq 'KB5000001|KB5000002') -Name 'Typed argument envelope preserves nested array values and ordering'
$winRmBindingProbe = Invoke-Command -ScriptBlock { param([string[]]$Values) [pscustomobject]@{ Count = @($Values).Count; Values = (@($Values) -join '|') } } -ArgumentList @($decodedArgumentList)
Test-ToolkitAssertion -Condition ($winRmBindingProbe.Count -eq 2 -and $winRmBindingProbe.Values -ceq 'KB5000001|KB5000002') -Name 'WinRM-style ArgumentList binding preserves nested array inputs'

$nestedAction = 'param([string[]]$Values) [pscustomobject]@{Count=@($Values).Count;Values=(@($Values)-join ''|'');Status=''Success''}'
$nestedPayload = ConvertTo-AdminEncodedPayload -ActionText $nestedAction -ArgumentList $nestedArgumentList
$payloadEnginePath = (Get-Process -Id $PID -ErrorAction Stop).Path
$nestedPayloadOutput = @(& $payloadEnginePath -NoLogo -NoProfile -NonInteractive -EncodedCommand $nestedPayload)
$nestedPayloadMatch = [regex]::Match(($nestedPayloadOutput -join [Environment]::NewLine), '(?m)^ADMINRESULT:(?<Data>[A-Za-z0-9+/=]+)\s*$')
$nestedPayloadEnvelope = $null
if ($nestedPayloadMatch.Success) {
    $nestedPayloadJson = $utf8.GetString([Convert]::FromBase64String($nestedPayloadMatch.Groups['Data'].Value))
    $nestedPayloadEnvelope = ConvertFrom-Json -InputObject $nestedPayloadJson
}
Test-ToolkitAssertion -Condition $nestedPayloadMatch.Success -Name 'Encoded remote payload returns a result for nested array arguments'
Test-ToolkitAssertion -Condition ($null -ne $nestedPayloadEnvelope -and [bool]$nestedPayloadEnvelope.Success -and $nestedPayloadEnvelope.Data[0].Count -eq 2 -and $nestedPayloadEnvelope.Data[0].Values -ceq 'KB5000001|KB5000002') -Name 'Encoded remote payload preserves nested array arguments in the current edition'

$argumentJob = $null
try {
    $argumentJob = Start-Job -ScriptBlock {
        param($ToolkitPath, $ArgumentEnvelope)
        . $ToolkitPath
        $jobArguments = @(ConvertFrom-AdminArgumentEnvelope -EncodedEnvelope $ArgumentEnvelope)
        [pscustomobject]@{
            OuterCount = $jobArguments.Count
            InnerValues = (@($jobArguments[0]) -join '|')
        }
    } -ArgumentList @($toolkitPath, $encodedArgumentEnvelope) -ErrorAction Stop
    $completedArgumentJob = Wait-Job -Job $argumentJob -Timeout 30 -ErrorAction Stop
    $argumentJobResult = @(if ($completedArgumentJob) { Receive-Job -Job $argumentJob -ErrorAction Stop })
    Test-ToolkitAssertion -Condition ($argumentJobResult.Count -eq 1 -and $argumentJobResult[0].OuterCount -eq 1 -and $argumentJobResult[0].InnerValues -ceq 'KB5000001|KB5000002') -Name 'Background-job boundary preserves typed nested action arguments'
}
finally {
    if ($argumentJob) {
        Stop-Job -Job $argumentJob -ErrorAction SilentlyContinue
        Remove-Job -Job $argumentJob -Force -ErrorAction SilentlyContinue
    }
}

$localSystemInfo = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName SystemInfo)
Test-ToolkitAssertion -Condition ($localSystemInfo.Count -eq 1 -and $localSystemInfo[0].Status -eq 'Success') -Name 'Local system-information action succeeds'
$localProcesses = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName RunningProcesses -ArgumentList @(1))
Test-ToolkitAssertion -Condition ($localProcesses.Count -eq 1 -and $localProcesses[0].Status -eq 'Success') -Name 'Local process action honors its limit'
$localService = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName ServiceManagement -ArgumentList @('wuauserv', 'Query'))
Test-ToolkitAssertion -Condition ($localService.Count -eq 1 -and $localService[0].Status -eq 'Success') -Name 'Local service query succeeds without changing state'
$localFailure = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName CustomPowerShell -ArgumentList @("throw 'expected test failure'"))
Test-ToolkitAssertion -Condition ($localFailure.Count -eq 1 -and $localFailure[0].Status -eq 'Failed') -Name 'Local action failures are normalized'
$failedRecordResult = @(Invoke-AdminTargetDetailed -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName CustomCommand -ArgumentList @('exit /b 7') -ReadOnly $false)
Test-ToolkitAssertion -Condition ($failedRecordResult.Count -eq 1 -and $failedRecordResult[0].Status -eq 'Failed' -and $failedRecordResult[0].ErrorCategory -eq 'Execution' -and -not [string]::IsNullOrWhiteSpace($failedRecordResult[0].ErrorMessage)) -Name 'Failed action records receive a normalized target error'
Test-ToolkitThrow -Action { Invoke-AdminTarget -TargetMode Remote -Computers @('server&whoami') -ActionName SystemInfo | Out-Null } -Name 'Remote dispatcher rejects an invalid target before starting jobs'

$invalidWinRm = Invoke-AdminWinRmTarget -ComputerName 'server&whoami' -ActionText 'param()'
Test-ToolkitAssertion -Condition (-not $invalidWinRm.Success -and $invalidWinRm.ErrorMessage -match 'invalid') -Name 'WinRM transport rejects an invalid target before connecting'
$invalidPsExec = Invoke-AdminPsExecTarget -ComputerName 'server&whoami' -PsExecFullPath 'C:\missing\PsExec64.exe' -ActionText 'param()'
Test-ToolkitAssertion -Condition (-not $invalidPsExec.Success -and $invalidPsExec.ErrorMessage -match 'invalid') -Name 'PsExec transport rejects an invalid target before launching a process'

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('WindowsAdminToolkit.Tests.' + [guid]::NewGuid().ToString('N'))
$resolvedTempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
if (-not $resolvedTemporaryRoot.StartsWith($resolvedTempBase, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe test directory resolution: $resolvedTemporaryRoot"
}

try {
    [void][System.IO.Directory]::CreateDirectory($resolvedTemporaryRoot)
    $outputProbePath = Join-Path $resolvedTemporaryRoot 'preflight-result.json'
    $resolvedOutputProbePath = Resolve-AdminAutomationOutputPath -LiteralPath $outputProbePath
    $leftoverOutputProbes = @(Get-ChildItem -LiteralPath $resolvedTemporaryRoot -Filter '.admin-json-probe-*.tmp' -File -ErrorAction Stop)
    Test-ToolkitAssertion -Condition ($resolvedOutputProbePath -eq $outputProbePath -and -not (Test-Path -LiteralPath $outputProbePath) -and $leftoverOutputProbes.Count -eq 0) -Name 'Automation output preflight verifies write access without leaving a file'
    Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath (Join-Path $resolvedTemporaryRoot 'CON.report.json') | Out-Null } -Name 'Automation output preflight rejects a Windows reserved file name'

    $computerFile = Join-Path $resolvedTemporaryRoot 'computers.txt'
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($computerFile, @('# synthetic targets', 'server01.example.com', 'SERVER01.EXAMPLE.COM', '192.0.2.10', 'bad&host'), $encoding)
    $importResult = Import-AdminComputerList -LiteralPath $computerFile
    Test-ToolkitAssertion -Condition ($importResult.Computers.Count -eq 2) -Name 'Computer import deduplicates targets case-insensitively'
    Test-ToolkitAssertion -Condition ($importResult.InvalidLines.Count -eq 1) -Name 'Computer import reports invalid line numbers'
    Test-ToolkitThrow -Action { Import-AdminComputerList -LiteralPath $computerFile -MaximumTargets 1 | Out-Null } -Name 'Computer import enforces its target limit'
    $oversizedComputerFile = Join-Path $resolvedTemporaryRoot 'oversized-computers.txt'
    $oversizedComputerStream = [System.IO.File]::Open($oversizedComputerFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $oversizedComputerStream.SetLength(1048577) } finally { $oversizedComputerStream.Dispose() }
    Test-ToolkitThrow -Action { Import-AdminComputerList -LiteralPath $oversizedComputerFile | Out-Null } -Name 'Computer import rejects files over the 1 MiB input limit'
    $invalidUtf8ComputerFile = Join-Path $resolvedTemporaryRoot 'invalid-utf8-computers.txt'
    [System.IO.File]::WriteAllBytes($invalidUtf8ComputerFile, [byte[]]@(0xC3, 0x28))
    Test-ToolkitThrow -Action { Import-AdminComputerList -LiteralPath $invalidUtf8ComputerFile | Out-Null } -Name 'Computer import rejects invalid UTF-8 input deterministically'

    $exportPath = Join-Path $resolvedTemporaryRoot 'result.txt'
    $writtenPath = Write-AdminUtf8File -LiteralPath $exportPath -Content 'test content'
    Test-ToolkitAssertion -Condition ($writtenPath -eq $exportPath -and (Test-Path -LiteralPath $exportPath -PathType Leaf)) -Name 'Atomic UTF-8 writer creates a new file'
    $bytes = [System.IO.File]::ReadAllBytes($exportPath)
    Test-ToolkitAssertion -Condition ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) -Name 'Export writer emits an explicit UTF-8 BOM'
    Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath $exportPath -Content 'replacement' | Out-Null } -Name 'Export writer refuses to overwrite an existing file'

    $validComputerFile = Join-Path $resolvedTemporaryRoot 'valid-computers.txt'
    $validTargets = @(1..26 | ForEach-Object { 'server{0:d2}.example.com' -f $_ })
    [System.IO.File]::WriteAllLines($validComputerFile, $validTargets, $encoding)
    $largeListMissingAuthorization = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerListPath = $validComputerFile }
    Test-ToolkitAssertion -Condition (-not $largeListMissingAuthorization.Success -and $largeListMissingAuthorization.Category -eq 'Authorization') -Name 'Automation requires exact authorization for more than 25 targets'
    $largeListAuthorized = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerListPath = $validComputerFile; TargetListConfirmationText = 'USE TARGET LIST' }
    Test-ToolkitAssertion -Condition ($largeListAuthorized.Success -and $largeListAuthorized.Request.Computers.Count -eq 26) -Name 'Automation accepts an authorized validated target list'
    $invalidListResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerListPath = $computerFile }
    Test-ToolkitAssertion -Condition (-not $invalidListResolution.Success -and $invalidListResolution.Message -match 'line') -Name 'Automation fails the complete request when a target-list line is invalid'
    $wildcardListResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerListPath = (Join-Path $resolvedTemporaryRoot '*.txt') }
    Test-ToolkitAssertion -Condition (-not $wildcardListResolution.Success -and $wildcardListResolution.Category -eq 'Validation') -Name 'Automation rejects wildcard input paths'
    $traversalListResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'SystemInfo'; ComputerListPath = (Join-Path $resolvedTemporaryRoot 'child\..\computers.txt') }
    Test-ToolkitAssertion -Condition (-not $traversalListResolution.Success -and $traversalListResolution.Category -eq 'Validation') -Name 'Automation rejects target-list traversal paths'

    $validPowerShellFile = Join-Path $resolvedTemporaryRoot 'valid-custom.ps1'
    [System.IO.File]::WriteAllText($validPowerShellFile, 'Get-Date', $encoding)
    $validPowerShellFileResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'CustomPowerShell'; Local = $true; PowerShellFile = $validPowerShellFile; WhatIf = $true }
    Test-ToolkitAssertion -Condition ($validPowerShellFileResolution.Success -and $validPowerShellFileResolution.Request.Arguments.Count -eq 1 -and $validPowerShellFileResolution.Request.Arguments[0] -ceq 'Get-Date') -Name 'Automation validates and loads a literal PowerShell source file'
    $oversizedPowerShellFile = Join-Path $resolvedTemporaryRoot 'oversized-custom.ps1'
    $oversizedPowerShellStream = [System.IO.File]::Open($oversizedPowerShellFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try { $oversizedPowerShellStream.SetLength(1048577) } finally { $oversizedPowerShellStream.Dispose() }
    $oversizedPowerShellFileResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'CustomPowerShell'; Local = $true; PowerShellFile = $oversizedPowerShellFile; WhatIf = $true }
    Test-ToolkitAssertion -Condition (-not $oversizedPowerShellFileResolution.Success -and $oversizedPowerShellFileResolution.Category -eq 'Validation' -and $oversizedPowerShellFileResolution.Message -match '1048576 byte') -Name 'Automation rejects PowerShell source files over the 1 MiB limit'
    $invalidUtf8PowerShellFile = Join-Path $resolvedTemporaryRoot 'invalid-utf8-custom.ps1'
    [System.IO.File]::WriteAllBytes($invalidUtf8PowerShellFile, [byte[]]@(0xC3, 0x28))
    $invalidUtf8PowerShellFileResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'CustomPowerShell'; Local = $true; PowerShellFile = $invalidUtf8PowerShellFile; WhatIf = $true }
    Test-ToolkitAssertion -Condition (-not $invalidUtf8PowerShellFileResolution.Success -and $invalidUtf8PowerShellFileResolution.Category -eq 'Validation' -and $invalidUtf8PowerShellFileResolution.Message -match 'UTF-8') -Name 'Automation rejects invalid UTF-8 PowerShell source files deterministically'

    $schemaPath = Join-Path $projectRoot 'schemas\automation-result-v1.schema.json'
    $schema = Get-Content -LiteralPath $schemaPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($schema.properties.schemaVersion.const -eq '1.0') -Name 'Committed JSON schema describes schema version 1.0'
    Test-ToolkitAssertion -Condition (@($schema.required).Count -eq 22) -Name 'Committed JSON schema requires every stable root field'
    Test-ToolkitAssertion -Condition (@($schema.properties.exitCode.enum).Count -eq 7) -Name 'Committed JSON schema contains every stable exit code'
    Test-ToolkitAssertion -Condition (@($schema.allOf).Count -eq 7) -Name 'Committed JSON schema locks every outcome to its stable status and exit code'
    Test-ToolkitAssertion -Condition (@($schema.'$defs'.stableActionId.enum).Count -eq 20) -Name 'Committed JSON schema contains every stable action identifier'

    $exampleDirectory = Join-Path $projectRoot 'examples\automation\results'
    $exampleFiles = @(Get-ChildItem -LiteralPath $exampleDirectory -Filter '*.json' -File | Sort-Object -Property Name)
    Test-ToolkitAssertion -Condition ($exampleFiles.Count -eq 6) -Name 'Repository includes six documented automation outcome examples'
    $requiredRootFields = @('schemaVersion', 'toolkitVersion', 'runId', 'startedAtUtc', 'finishedAtUtc', 'durationMs', 'actionId', 'actionName', 'readOnly', 'stateChanging', 'targetMode', 'transport', 'status', 'outcome', 'exitCode', 'targetCount', 'recordCount', 'targets', 'warnings', 'errors', 'reportPaths', 'actions')
    $expectedExampleOutcomes = @{
        'execution-failure'  = 'ExecutionFailure'
        'partial'            = 'PartialSuccess'
        'success'            = 'CompleteSuccess'
        'timeout'            = 'Timeout'
        'validation-failure' = 'ValidationFailure'
        'whatif'             = 'CompleteSuccess'
    }
    foreach ($exampleFile in $exampleFiles) {
        $example = Get-Content -LiteralPath $exampleFile.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $presentFields = @($example.PSObject.Properties.Name)
        Test-ToolkitAssertion -Condition (@($requiredRootFields | Where-Object { $_ -notin $presentFields }).Count -eq 0) -Name "Example $($exampleFile.Name) contains all stable root fields"
        Test-ToolkitAssertion -Condition ($example.outcome -eq $expectedExampleOutcomes[$exampleFile.BaseName]) -Name "Example $($exampleFile.Name) uses its documented outcome"
        Test-ToolkitAssertion -Condition (@($example.targets).Count -eq [int]$example.targetCount) -Name "Example $($exampleFile.Name) preserves target arrays"
    }

    $currentEnginePath = (Get-Process -Id $PID -ErrorAction Stop).Path
    $automationLogPath = Join-Path $resolvedTemporaryRoot 'automation-tests.log'
    $escapedAutomationLogPath = $automationLogPath.Replace("'", "''")

    $successProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action SystemInfo -Local -LogFile '$escapedAutomationLogPath'"
    $successJsonText = $successProcess.StdOut.Trim()
    $successEnvelope = $null
    try { $successEnvelope = ConvertFrom-Json -InputObject $successJsonText -ErrorAction Stop } catch { Write-Verbose $_.Exception.Message }
    Test-ToolkitAssertion -Condition ($successProcess.ExitCode -eq 0) -Name 'Automation child process returns exit code 0 for complete success'
    Test-ToolkitAssertion -Condition ($null -ne $successEnvelope -and $successJsonText.StartsWith('{') -and $successJsonText.EndsWith('}')) -Name 'Automation stdout contains exactly one parseable JSON document'
    Test-ToolkitAssertion -Condition ($successJsonText -match '^\{"schemaVersion":"1\.0","toolkitVersion":"2\.1\.0"') -Name 'Automation JSON root field ordering is deterministic'
    Test-ToolkitAssertion -Condition ($successEnvelope.outcome -eq 'CompleteSuccess' -and $successEnvelope.exitCode -eq 0) -Name 'Automation success envelope agrees with the process exit code'
    Test-ToolkitAssertion -Condition (@($successEnvelope.targets).Count -eq 1 -and @($successEnvelope.targets[0].data).Count -eq 1) -Name 'Automation success preserves target and data arrays for one item'
    Test-ToolkitAssertion -Condition ($successJsonText -match '"startedAtUtc":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"') -Name 'Automation success uses a normalized UTC start timestamp'
    Test-ToolkitAssertion -Condition ($successJsonText -notmatch 'PSComputerName|RunspaceId|PSShowComputerName|Credential|SecureString|ScriptBlock') -Name 'Automation success excludes sensitive and remoting metadata'

    $fileModeStdoutProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action SystemInfo -Local -JsonOutputPath STDOUT -LogFile `"$automationLogPath`"" -FileMode
    $fileModeStdoutEnvelope = ConvertFrom-Json -InputObject $fileModeStdoutProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($fileModeStdoutProcess.ExitCode -eq 0 -and $fileModeStdoutEnvelope.outcome -eq 'CompleteSuccess') -Name 'STDOUT alias works through the native PowerShell File command line'

    $catalogProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -ListActions'
    $catalogEnvelope = ConvertFrom-Json -InputObject $catalogProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($catalogProcess.ExitCode -eq 0 -and @($catalogEnvelope.actions).Count -eq 20) -Name 'ListActions returns all stable actions without execution'
    Test-ToolkitAssertion -Condition (@($catalogEnvelope.targets).Count -eq 0 -and $catalogEnvelope.targetCount -eq 0) -Name 'ListActions does not create target results'

    $catalogActionProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -ListActions -Action ''"
    $catalogActionEnvelope = ConvertFrom-Json -InputObject $catalogActionProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($catalogActionProcess.ExitCode -eq 2 -and $catalogActionEnvelope.outcome -eq 'ValidationFailure') -Name 'ListActions rejects a bound Action even when its value is empty'

    $catalogControlProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -ListActions -Transport WinRM'
    $catalogControlEnvelope = ConvertFrom-Json -InputObject $catalogControlProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($catalogControlProcess.ExitCode -eq 2 -and $catalogControlEnvelope.errors[0].message -match 'ListActions') -Name 'ListActions rejects unrelated execution controls'

    $missingActionProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Local'
    $missingActionEnvelope = ConvertFrom-Json -InputObject $missingActionProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($missingActionProcess.ExitCode -eq 2 -and $missingActionEnvelope.outcome -eq 'ValidationFailure') -Name 'Missing action returns validation exit code 2 and an envelope'

    $unknownProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action NoSuchAction -Local'
    $unknownEnvelope = ConvertFrom-Json -InputObject $unknownProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($unknownProcess.ExitCode -eq 2 -and $unknownEnvelope.exitCode -eq 2 -and $null -eq $unknownEnvelope.actionId) -Name 'Unknown action returns stable validation exit code 2 without claiming a canonical identifier'

    $malformedActionProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action 'Bad;Action' -Local"
    $malformedActionEnvelope = ConvertFrom-Json -InputObject $malformedActionProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($malformedActionProcess.ExitCode -eq 2 -and $null -eq $malformedActionEnvelope.actionId -and $malformedActionEnvelope.errors[0].message -match 'format') -Name 'Malformed action identifiers are bounded and excluded from the envelope'

    $invalidTransportProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action SystemInfo -Local -Transport SSH'
    $invalidTransportEnvelope = ConvertFrom-Json -InputObject $invalidTransportProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($invalidTransportProcess.ExitCode -eq 2 -and $invalidTransportEnvelope.errors[0].message -match 'Unsupported transport' -and $invalidTransportEnvelope.targetMode -ceq 'Local' -and $invalidTransportEnvelope.transport.name -ceq 'Local') -Name 'Unsupported transport returns a schema-valid JSON validation envelope'

    $invalidAuthenticationProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action SystemInfo -ComputerName server01.example.com -Authentication Basic'
    $invalidAuthenticationEnvelope = ConvertFrom-Json -InputObject $invalidAuthenticationProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($invalidAuthenticationProcess.ExitCode -eq 2 -and $invalidAuthenticationEnvelope.transport.name -ceq 'WinRM' -and $null -eq $invalidAuthenticationEnvelope.transport.authentication) -Name 'Unsupported authentication returns a schema-valid JSON validation envelope'

    $stringCredentialProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action SystemInfo -ComputerName server01.example.com -Credential synthetic-user' -FileMode -OmitNonInteractive -TimeoutSeconds 5
    $stringCredentialEnvelope = ConvertFrom-Json -InputObject $stringCredentialProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($stringCredentialProcess.ExitCode -eq 2 -and $stringCredentialEnvelope.outcome -eq 'ValidationFailure' -and $stringCredentialEnvelope.errors[0].message -match 'PSCredential') -Name 'Native automation rejects a username string without opening credential UI'

    $invalidConcurrencyProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action SystemInfo -Local -MaxConcurrentJobs 0'
    $invalidConcurrencyEnvelope = ConvertFrom-Json -InputObject $invalidConcurrencyProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($invalidConcurrencyProcess.ExitCode -eq 2 -and $invalidConcurrencyEnvelope.errors[0].message -match 'MaxConcurrentJobs') -Name 'Out-of-range execution controls return a JSON validation envelope'

    $canonicalTransportProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action SystemInfo -ComputerName 'bad&host' -Transport winrm -Authentication kerberos"
    $canonicalTransportEnvelope = ConvertFrom-Json -InputObject $canonicalTransportProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($canonicalTransportProcess.ExitCode -eq 2 -and $canonicalTransportEnvelope.transport.name -ceq 'WinRM' -and $canonicalTransportEnvelope.transport.authentication -ceq 'Kerberos') -Name 'Automation normalizes transport values to schema-stable casing'

    $localRemoteControlProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action SystemInfo -Local -Transport WinRM'
    $localRemoteControlEnvelope = ConvertFrom-Json -InputObject $localRemoteControlProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($localRemoteControlProcess.ExitCode -eq 2 -and $localRemoteControlEnvelope.errors[0].message -match 'not valid with -Local') -Name 'Local automation rejects explicitly bound remote execution controls'

    $authorizationProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText '-Automation -Action ScheduleReboot -Local'
    $authorizationEnvelope = ConvertFrom-Json -InputObject $authorizationProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($authorizationProcess.ExitCode -eq 3 -and $authorizationEnvelope.outcome -eq 'AuthorizationFailure' -and $authorizationEnvelope.targetMode -ceq 'Local' -and $authorizationEnvelope.targetCount -eq 1) -Name 'Missing exact confirmation returns authorization exit code 3 with the requested target summary'

    $whatIfProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action ScheduleReboot -Local -WhatIf -LogFile '$escapedAutomationLogPath'"
    $whatIfJsonText = $whatIfProcess.StdOut.Trim()
    $whatIfEnvelope = ConvertFrom-Json -InputObject $whatIfJsonText -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($whatIfProcess.ExitCode -eq 0 -and $whatIfEnvelope.status -eq 'WhatIf') -Name 'State-changing WhatIf returns a successful preview'
    Test-ToolkitAssertion -Condition ($whatIfJsonText -notmatch '(?m)^What if:' -and @($whatIfEnvelope.targets).Count -eq 1) -Name 'WhatIf keeps stdout clean and preserves preview targets'

    $customFailureMarker = 'synthetic-execution-failure'
    $customFailureInvocation = "-Automation -Action CustomPowerShell -Local -PowerShellText `"Write-Error '$customFailureMarker'`" -ConfirmationText 'RUN SCRIPT' -LogFile '$escapedAutomationLogPath'"
    $executionFailureProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText $customFailureInvocation
    $executionFailureEnvelope = ConvertFrom-Json -InputObject $executionFailureProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($executionFailureProcess.ExitCode -eq 4 -and $executionFailureEnvelope.outcome -eq 'ExecutionFailure') -Name 'Execution failure returns stable exit code 4'
    Test-ToolkitAssertion -Condition ($executionFailureEnvelope.targets[0].errorCategory -eq 'Execution') -Name 'Execution failure includes a normalized target error category'
    Test-ToolkitAssertion -Condition ($executionFailureEnvelope.targets[0].errorMessage -notmatch [regex]::Escape($customFailureMarker)) -Name 'Expert-action error fields omit operator-supplied exception text'
    $automationLogText = Get-Content -LiteralPath $automationLogPath -Raw -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($automationLogText -notmatch [regex]::Escape($customFailureMarker)) -Name 'Automation log excludes custom code and custom output'

    $timeoutInvocation = "-Automation -Action CustomPowerShell -Local -PowerShellText `"throw 'synthetic timeout'`" -ConfirmationText 'RUN SCRIPT' -LogFile '$escapedAutomationLogPath'"
    $timeoutProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText $timeoutInvocation
    $timeoutEnvelope = ConvertFrom-Json -InputObject $timeoutProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($timeoutProcess.ExitCode -eq 5 -and $timeoutEnvelope.outcome -eq 'Timeout' -and $timeoutEnvelope.targets[0].errorCategory -eq 'Timeout') -Name 'All-timeout execution returns stable process exit code 5'

    $remoteFailureProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action SystemInfo -ComputerName 192.0.2.10 -ConnectivityTimeoutSeconds 1 -LogFile '$escapedAutomationLogPath'" -TimeoutSeconds 15
    $remoteFailureEnvelope = ConvertFrom-Json -InputObject $remoteFailureProcess.StdOut.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($remoteFailureProcess.ExitCode -eq 4 -and $remoteFailureEnvelope.targets[0].errorCategory -eq 'Connectivity') -Name 'Unreachable remote target returns a normalized execution failure'

    $jsonOutputPath = Join-Path $resolvedTemporaryRoot 'automation-output.json'
    $escapedJsonOutputPath = $jsonOutputPath.Replace("'", "''")
    $fileOutputProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action RunningProcesses -Local -TopCount 1 -JsonOutputPath '$escapedJsonOutputPath' -LogFile '$escapedAutomationLogPath'"
    $fileEnvelope = Get-Content -LiteralPath $jsonOutputPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($fileOutputProcess.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($fileOutputProcess.StdOut)) -Name 'File output writes no human text to stdout'
    Test-ToolkitAssertion -Condition (@($fileEnvelope.reportPaths).Count -eq 1 -and $fileEnvelope.reportPaths[0] -eq $jsonOutputPath) -Name 'File output reports only the path actually created'
    $jsonOutputBytes = [System.IO.File]::ReadAllBytes($jsonOutputPath)
    Test-ToolkitAssertion -Condition ($jsonOutputBytes.Length -gt 0 -and $jsonOutputBytes[0] -eq [byte][char]'{' -and -not ($jsonOutputBytes.Length -ge 3 -and $jsonOutputBytes[0] -eq 0xEF -and $jsonOutputBytes[1] -eq 0xBB -and $jsonOutputBytes[2] -eq 0xBF)) -Name 'Automation JSON files use interoperable UTF-8 without a byte-order mark'

    $whatIfOutputPath = Join-Path $resolvedTemporaryRoot 'automation-whatif-output.json'
    $escapedWhatIfOutputPath = $whatIfOutputPath.Replace("'", "''")
    $whatIfFileProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action ScheduleReboot -Local -WhatIf -JsonOutputPath '$escapedWhatIfOutputPath' -LogFile '$escapedAutomationLogPath'"
    $whatIfFileEnvelope = Get-Content -LiteralPath $whatIfOutputPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($whatIfFileProcess.ExitCode -eq 0 -and [string]::IsNullOrWhiteSpace($whatIfFileProcess.StdOut) -and $whatIfFileEnvelope.status -eq 'WhatIf') -Name 'WhatIf still creates its requested machine-readable file without console contamination'

    $fileHashBefore = (Get-FileHash -LiteralPath $jsonOutputPath -Algorithm SHA256).Hash
    $overwriteProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText "-Automation -Action RunningProcesses -Local -TopCount 1 -JsonOutputPath '$escapedJsonOutputPath' -LogFile '$escapedAutomationLogPath'"
    $fileHashAfter = (Get-FileHash -LiteralPath $jsonOutputPath -Algorithm SHA256).Hash
    $overwriteEnvelope = ConvertFrom-Json -InputObject $overwriteProcess.StdErr.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($overwriteProcess.ExitCode -eq 2 -and $overwriteEnvelope.outcome -eq 'ValidationFailure' -and $overwriteEnvelope.actionId -eq 'RunningProcesses' -and $overwriteEnvelope.targetMode -eq 'Local' -and $overwriteEnvelope.targetCount -eq 1) -Name 'Existing JSON output returns validation exit code 2 with the requested action and target summary'
    Test-ToolkitAssertion -Condition ($fileHashBefore -eq $fileHashAfter -and [string]::IsNullOrWhiteSpace($overwriteProcess.StdOut)) -Name 'Existing JSON output remains unchanged and stdout stays empty'

    $internalCollisionPath = Join-Path $resolvedTemporaryRoot 'internal-collision.json'
    $escapedInternalCollisionPath = $internalCollisionPath.Replace("'", "''")
    $internalInvocation = "-Automation -Action CustomPowerShell -Local -PowerShellText `"[void][System.IO.Directory]::CreateDirectory('$escapedInternalCollisionPath')`" -ConfirmationText 'RUN SCRIPT' -JsonOutputPath '$escapedInternalCollisionPath' -LogFile '$escapedAutomationLogPath'"
    $internalProcess = Invoke-ToolkitChildProcess -EnginePath $currentEnginePath -InvocationText $internalInvocation
    $internalEnvelope = ConvertFrom-Json -InputObject $internalProcess.StdErr.Trim() -ErrorAction Stop
    Test-ToolkitAssertion -Condition ($internalProcess.ExitCode -eq 10 -and $internalEnvelope.outcome -eq 'InternalFailure' -and [string]::IsNullOrWhiteSpace($internalProcess.StdOut)) -Name 'Post-execution output sink failure returns stable process exit code 10 on stderr'
    Test-ToolkitAssertion -Condition ($internalEnvelope.actionId -eq 'CustomPowerShell' -and $internalEnvelope.targetCount -eq 1 -and @($internalEnvelope.targets).Count -eq 1 -and $internalEnvelope.targets[0].status -eq 'Success' -and @($internalEnvelope.reportPaths).Count -eq 0) -Name 'Output sink failure preserves completed target evidence without claiming a report path'

    Test-ToolkitThrow -Action { Resolve-AdminPsExec -Path $toolkitPath | Out-Null } -Name 'PsExec validation rejects a non-PsExec executable'
    $localPsExec = Join-Path $projectRoot 'PsExec64.exe'
    if (Test-Path -LiteralPath $localPsExec -PathType Leaf) {
        $resolvedPsExec = Resolve-AdminPsExec -Path $localPsExec
        if ($resolvedPsExec -ne $localPsExec) {
            throw 'PsExec validation did not return the expected signed local executable path.'
        }
        Write-Host 'INFO: Signed local PsExec binary passed the optional environment check.' -ForegroundColor Cyan
    }
    else {
        Write-Host 'INFO: Optional signed local PsExec binary was not present; negative PsExec validation was still tested.' -ForegroundColor Cyan
    }
}
finally {
    if (Test-Path -LiteralPath $resolvedTemporaryRoot -PathType Container) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
if ($Script:Failures.Count -gt 0) {
    Write-Host "$($Script:Failures.Count) of $Script:TestCount tests failed:" -ForegroundColor Red
    foreach ($failure in $Script:Failures) {
        Write-Host "  $failure" -ForegroundColor Red
    }
    exit 1
}

Write-Host "All $Script:TestCount tests passed under PowerShell $($PSVersionTable.PSVersion)." -ForegroundColor Green
exit 0
