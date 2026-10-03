# Offline adversarial fixtures only; no target, service, AWS or host trust changes.
$ErrorActionPreference = 'Stop'
$latestStandalone = -not (Get-Command Test-ToolkitAssertion -ErrorAction SilentlyContinue)
if ($latestStandalone) {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'WindowsAdminToolkit.ps1')
    $Script:TestCount = 0
    $Script:Failures = New-Object 'System.Collections.Generic.List[string]'
    function Test-ToolkitAssertion {
        param([bool]$Condition, [string]$Name)
        $Script:TestCount++
        if (-not $Condition) { $Script:Failures.Add($Name) | Out-Null; Write-Host "FAIL $Name" }
    }
    function Test-ToolkitThrow {
        param([scriptblock]$Action, [string]$Name)
        $threw = $false
        try { & $Action } catch { $threw = $true }
        Test-ToolkitAssertion -Condition $threw -Name $Name
    }
}
Initialize-AdminSafeFileType
$latestRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) ('wat-ten-fixture-' + [guid]::NewGuid().ToString('N'))
[WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($latestRoot)
$latestSinks = New-Object 'System.Collections.Generic.List[object]'
try {
    $retainedParent = Join-Path $latestRoot 'retained'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($retainedParent)
    $retainedPath = Join-Path $retainedParent 'object.jsonl'
    $retained = Open-AdminMutableFile -LiteralPath $retainedPath -Create
    $latestSinks.Add($retained) | Out-Null
    $initialIdentity = $retained.Identity
    $firstBytes = [Text.Encoding]::UTF8.GetBytes('{"revision":1}')
    $retained.ReplaceBytes($firstBytes, 4096)
    Test-ToolkitAssertion -Condition ([Text.Encoding]::UTF8.GetString($retained.ReadBytes(4096)) -ceq '{"revision":1}') -Name 'Relative retained file reads its own durable first revision'
    Test-ToolkitThrow -Action { [IO.File]::WriteAllText($retainedPath, 'same-size evil') } -Name 'Retained leaf rejects concurrent data writer'
    Test-ToolkitThrow -Action { [IO.File]::Move($retainedPath, (Join-Path $retainedParent 'replaced.jsonl')) } -Name 'Retained leaf rejects same-length replacement by rename'
    Test-ToolkitThrow -Action { [IO.Directory]::Move($retainedParent, (Join-Path $latestRoot 'redirected')) } -Name 'Retained ancestor rejects relocation before subsequent revision'
    $retained.ReplaceBytes([Text.Encoding]::UTF8.GetBytes('{"revision":2}'), 4096)
    Test-ToolkitAssertion -Condition ($retained.Identity -ceq $initialIdentity -and [Text.Encoding]::UTF8.GetString($retained.ReadBytes(4096)) -ceq '{"revision":2}') -Name 'Second checkpoint revision retains the same object identity'
    Test-ToolkitThrow -Action { $retained.Append([byte[]]@(1), 0, 4096) } -Name 'Retained append rejects unexpected audit record length'
    $retained.Dispose()

    $preauthorizedPath = Join-Path $retainedParent 'writer.jsonl'
    [WindowsAdminToolkit.Security.StorageSecurity]::AppendPrivateFile($preauthorizedPath, [byte[]]@(1), $true, 1024)
    $preauthorizedWriter = [IO.File]::Open($preauthorizedPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    try {
        Test-ToolkitThrow -Action { Open-AdminMutableFile -LiteralPath $preauthorizedPath | Out-Null } -Name 'Retained file refuses a preauthorized writer still holding the object'
    }
    finally { $preauthorizedWriter.Dispose() }
    $privateAppend = Open-AdminMutableFile -LiteralPath $preauthorizedPath
    $latestSinks.Add($privateAppend) | Out-Null
    $privateAppend.Append([byte[]]@(2), 1, 1024)
    Test-ToolkitAssertion -Condition ($privateAppend.Length -eq 2) -Name 'Trusted private existing file can be explicitly reopened and appended'
    $privateAppend.Dispose()

    $untrustedLog = Join-Path $latestRoot 'preexisting.log'
    [IO.File]::WriteAllText($untrustedLog, 'operator fixture')
    Test-ToolkitThrow -Action { Initialize-AdminLog -RequestedPath $untrustedLog | Out-Null } -Name 'Preexisting caller-selected log requires explicit trusted append mode'
    $logPath = Join-Path $latestRoot 'new.log'
    [void](Initialize-AdminLog -RequestedPath $logPath)
    Write-AdminLog -Message ("record" + [char]27 + '[2J') -NoConsole
    Test-ToolkitThrow -Action { [IO.File]::Move($logPath, (Join-Path $latestRoot 'log-substitute.log')) } -Name 'Log keeps its no-delete object lease between records'
    Test-ToolkitAssertion -Condition ([Text.Encoding]::UTF8.GetString($Script:State.LogContext.ReadBytes(4096)).Contains('\u001b[2J')) -Name 'Log control characters are visible literal escapes'
    $auditPath = Join-Path $latestRoot 'audit.jsonl'
    $audit = Initialize-AdminAuditContext -ResolvedAuditPath $auditPath
    $auditEvent = ConvertTo-AdminAuditEvent -RunId ([guid]::NewGuid()) -Sequence 1 -EventType run.started -TimestampUtc ([datetime]::UtcNow) -Stage Initialization -Outcome Started
    [void](Write-AdminAuditRecord -Context $audit -Event $auditEvent)
    Test-ToolkitThrow -Action { [IO.File]::WriteAllBytes($auditPath, (New-Object byte[] ([int]$audit.BytesWritten))) } -Name 'Audit rejects an equal-length substitute between records'
    Test-ToolkitAssertion -Condition ($audit.Sink.Identity -and $audit.RecordCount -eq 1) -Name 'Audit records use the original retained object'

    foreach ($target in @('server.example.com.', 'SERVER.', '192.0.2.10.')) {
        Test-ToolkitAssertion -Condition (-not (Test-AdminHostname -ComputerName $target)) -Name "Presentation alias rejected: $target"
    }
    Test-ToolkitAssertion -Condition (Test-AdminHostname -ComputerName 'server.example.com') -Name 'Canonical DNS target remains valid'
    $listPath = Join-Path $latestRoot 'targets.txt'
    [IO.File]::WriteAllLines($listPath, @('server.example.com', 'SERVER.EXAMPLE.COM', 'server.example.com.'))
    $list = Import-AdminComputerList -LiteralPath $listPath
    Test-ToolkitAssertion -Condition ($list.Computers.Count -eq 1 -and $list.InvalidLines.Count -eq 1) -Name 'Computer lists never silently dispatch dotted and undotted aliases twice'

    $destination = New-Object 'System.Collections.Generic.List[object]'
    Add-AdminNormalizedData -Destination $destination -ComputerName 'selected.example.com' -Data @([pscustomobject]@{ ComputerName = 'claimed.example.com'; Status = 'Success'; Value = 'fixture' }, @{ ComputerName = 'wrong.example.com'; Status = 'Success' })
    Test-ToolkitAssertion -Condition ($destination[0].ComputerName -ceq 'selected.example.com' -and $destination[1].ComputerName -ceq 'selected.example.com') -Name 'Both object and dictionary producer claims cannot override the selected target'

    foreach ($states in @(@('Unknown'), @('Failed', 'TimedOut'), @('Failed', 'Skipped'), @('Skipped', 'TimedOut'))) {
        $targets = @($states | ForEach-Object { [pscustomobject]@{ state = $_; resultOutcome = 'ExecutionFailure' } })
        $summary = Get-AdminLifecycleSummary -Target $targets
        $outcome = Get-AdminOrchestrationExecutionOutcome -Summary $summary -Target $targets
        Test-ToolkitAssertion -Condition ($outcome.Outcome -cne 'PartialSuccess') -Name ('No zero-success partial claim for ' + ($states -join ','))
        if ($states[0] -ceq 'Unknown') { Test-ToolkitAssertion -Condition ($outcome.Outcome -ceq 'InternalFailure' -and $outcome.ExitCode -eq 10) -Name 'Unknown recovery is authoritative InternalFailure exit10' }
    }
    $mixed = @([pscustomobject]@{ state = 'Completed'; resultOutcome = 'CompleteSuccess' }, [pscustomobject]@{ state = 'Failed'; resultOutcome = 'ExecutionFailure' })
    Test-ToolkitAssertion -Condition ((Get-AdminOrchestrationExecutionOutcome -Summary (Get-AdminLifecycleSummary -Target $mixed) -Target $mixed).Outcome -ceq 'PartialSuccess') -Name 'Actual completed targets permit a truthful mixed PartialSuccess'

    $collision = Join-Path $latestRoot 'collision.json'
    Test-ToolkitThrow -Action { Assert-AdminDistinctConfiguredPath -Parameters @{ LogFile = $collision; JsonOutputPath = $collision.ToUpperInvariant() } } -Name 'Equal new log and JSON paths fail before any sink creation'
    Test-ToolkitAssertion -Condition (-not [IO.File]::Exists($collision)) -Name 'Rejected collision creates no log or JSON file'
    Test-ToolkitThrow -Action { Assert-AdminDistinctConfiguredPath -Parameters @{ LogFile = $collision } -ResolvedOutputPath $collision } -Name 'Library-resolved JSON collision is rejected even without a declared JSON parameter'
    Test-ToolkitThrow -Action { Assert-AdminDistinctConfiguredPath -Parameters @{ JsonOutputPath = $collision } -ResolvedOutputPath (Join-Path $latestRoot 'different.json') } -Name 'Library cannot substitute an output destination after admission'
    Assert-AdminDistinctConfiguredPath -Parameters @{ JsonOutputPath = 'STDOUT'; LogFile = $logPath } -ResolvedOutputPath '-'
    Test-ToolkitAssertion -Condition $true -Name 'STDOUT alias is bound to the resolved stdout sink'
    Assert-AdminDistinctConfiguredPath -Parameters @{ LogFile = $logPath; JsonOutputPath = '-'; AuditPath = $auditPath }
    Test-ToolkitAssertion -Condition $true -Name 'Distinct outputs with stdout remain admitted'
    $controls = [string][char]27 + ']52;c;fake' + [char]7 + [char]0x9b + '2J'
    $literal = ConvertTo-AdminTerminalLiteral -Value $controls
    Test-ToolkitAssertion -Condition ($literal -ceq '\u001b]52;c;fake\u0007\u009b2J' -and $literal -notmatch '[\x00-\x1f\x7f-\x9f]') -Name 'Terminal scalar renderer neutralizes OSC CSI and C1 controls'
    $nestedLiteral = ConvertTo-AdminTerminalLiteral -Value @{ nested = @($controls) }
    Test-ToolkitAssertion -Condition ($nestedLiteral -notmatch '[\x00-\x1f\x7f-\x9f]') -Name 'Nested terminal values contain no raw controls'

    $originalSystemRoot = $env:SystemRoot
    $originalTemp = $env:TEMP
    $originalLocalAppData = $env:LOCALAPPDATA
    $expectedSystem = [WindowsAdminToolkit.Security.SystemPaths]::SystemDirectory()
    $expectedRoots = [WindowsAdminToolkit.Security.SystemPaths]::CleanupRoots()
    try {
        $env:SystemRoot = $latestRoot; $env:TEMP = $latestRoot; $env:LOCALAPPDATA = $latestRoot
        Test-ToolkitAssertion -Condition ([WindowsAdminToolkit.Security.SystemPaths]::SystemDirectory() -ceq $expectedSystem) -Name 'Poisoned SystemRoot cannot redirect the native system directory'
        $actualRoots = [WindowsAdminToolkit.Security.SystemPaths]::CleanupRoots()
        Test-ToolkitAssertion -Condition (($actualRoots -join '|') -ceq ($expectedRoots -join '|') -and $actualRoots -notcontains $latestRoot) -Name 'Poisoned TEMP LOCALAPPDATA and SystemRoot cannot select cleanup roots'
    }
    finally { $env:SystemRoot = $originalSystemRoot; $env:TEMP = $originalTemp; $env:LOCALAPPDATA = $originalLocalAppData }

    $userSid = [WindowsAdminToolkit.Security.StorageSecurity]::CurrentSid
    foreach ($sddl in @("O:${userSid}G:${userSid}D:P(A;;FA;;;$userSid)", "O:BAG:BAD:P(A;;FA;;;$userSid)(A;;FA;;;BA)")) {
        $sd = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
        $sdBytes = New-Object byte[] $sd.BinaryLength; $sd.GetBinaryForm($sdBytes, 0)
        Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($sdBytes, $false, $false, $false, $true) } -Name 'Privileged source rejects same-user ownership or write authority even under admin ownership'
    }
    $adminSd = New-Object Security.AccessControl.RawSecurityDescriptor('O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)')
    $adminBytes = New-Object byte[] $adminSd.BinaryLength; $adminSd.GetBinaryForm($adminBytes, 0)
    [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($adminBytes, $false, $false, $false, $true)
    Test-ToolkitAssertion -Condition $true -Name 'Administrator-owned source with only unprivileged read grants is accepted'
    . (Join-Path $PSScriptRoot 'Source-Trust-Authz.Tests.ps1')

    $loadedFixture = Join-Path $latestRoot 'loaded-toolkit.ps1'
    $markerPath = Join-Path $latestRoot 'replacement-executed.txt'
    $toolkitSource = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) 'WindowsAdminToolkit.ps1'))
    $offlineOverrides = @'

# Owned fixture backends cannot perform a target operation.
function Assert-AdminPrivilegedSourceTrust { }
function Invoke-AdminTargetWithRetry {
    param($Transport, $ComputerName, $Credential, $ActionText, $ArgumentList, $PsExecFullPath, $UseSsl, $Authentication, $RetryCount, $RetryDelaySeconds, $TimeoutSeconds, $MaximumOutputBytes, $MaximumOutputItems)
    [pscustomobject]@{ Success = $true; Attempts = 1; Data = @([pscustomobject]@{ ComputerName = 'spoofed.example.com'; Value = 'original-loaded-source'; Status = 'Success' }) }
}
'@
    [IO.File]::WriteAllText($loadedFixture, $toolkitSource + $offlineOverrides)
    $replacementProbe = Start-Job -ScriptBlock {
        param($FixturePath, $MarkerPath)
        . $FixturePath
        [IO.File]::WriteAllText($FixturePath, "[IO.File]::WriteAllText('$($MarkerPath.Replace("'", "''"))','REPLACEMENT'); throw 'replacement source executed'")
        Invoke-AdminTargetDetailed -TargetMode Remote -Computers @('selected.example.com') -ActionName SystemInfo -RetryCount 0 -OperationTimeoutMinutes 1
    } -ArgumentList $loadedFixture, $markerPath
    try {
        $finished = Wait-Job -Job $replacementProbe -Timeout 30
        if (-not $finished) { Stop-Job -Job $replacementProbe; throw 'Loaded worker fixture timed out.' }
        $workerResult = @(Receive-Job -Job $replacementProbe -ErrorAction Stop)
        Test-ToolkitAssertion -Condition ($workerResult.Count -eq 1 -and $workerResult[0].Status -ceq 'Success' -and $workerResult[0].Data[0].Value -ceq 'original-loaded-source') -Name 'Actual background worker executes original loaded source after pathname replacement'
        Test-ToolkitAssertion -Condition (-not [IO.File]::Exists($markerPath) -and $workerResult[0].Data[0].ComputerName -ceq 'selected.example.com') -Name 'Replacement payload never executes and worker retains selected target attribution'
    }
    finally { Remove-Job -Job $replacementProbe -Force }

    $releaseTool = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\New-ReleaseArtifacts.ps1'
    $releaseSourceRoot = Split-Path -Parent $PSScriptRoot
    $aliasSource = Join-Path $latestRoot 'real-release-source'
    $aliasTools = Join-Path $aliasSource 'tools'
    $sourceAlias = Join-Path $latestRoot 'release-source-alias'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($aliasSource)
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($aliasTools)
    [IO.File]::Copy((Join-Path $releaseSourceRoot 'WindowsAdminToolkit.ps1'), (Join-Path $aliasSource 'WindowsAdminToolkit.ps1'))
    [IO.File]::Copy($releaseTool, (Join-Path $aliasTools 'New-ReleaseArtifacts.ps1'))
    $trustedFixtureTool = Join-Path $aliasTools 'New-ReleaseArtifacts.ps1'
    foreach ($overlapOutput in @($aliasSource, $latestRoot)) {
        $overlapError = ''
        try { & $trustedFixtureTool -OutputDirectory $overlapOutput | Out-Null }
        catch { $overlapError = $_.Exception.Message }
        Test-ToolkitAssertion -Condition ($overlapError -match 'must be disjoint') -Name 'Release equal-root and ancestor outputs fail at the containment guard'
    }
    try {
        [void](New-Item -ItemType Junction -Path $sourceAlias -Target $aliasSource)
        $aliasOutput = Join-Path $aliasTools 'alias-overlap-output'
        $aliasError = ''
        try { & (Join-Path $sourceAlias 'tools\New-ReleaseArtifacts.ps1') -OutputDirectory $aliasOutput | Out-Null }
        catch { $aliasError = $_.Exception.Message }
        Test-ToolkitAssertion -Condition ($aliasError -match 'Reparse points are forbidden') -Name 'Release source junction alias fails at the early native identity guard'
        Test-ToolkitAssertion -Condition (-not [IO.Directory]::Exists($aliasOutput)) -Name 'Source junction alias cannot create an output inside actual source before refusal'
    }
    finally {
        # Remove only the owned junction itself before recursive fixture cleanup.
        if ([IO.Directory]::Exists($sourceAlias)) { [IO.Directory]::Delete($sourceAlias) }
    }
    foreach ($subtree in @('tools', 'tests', 'examples', 'schemas')) {
        $nestedOutput = Join-Path $aliasSource ($subtree + '\wat-ten-overlap-' + [guid]::NewGuid().ToString('N'))
        $nestedError = ''
        try { & $trustedFixtureTool -OutputDirectory $nestedOutput | Out-Null }
        catch { $nestedError = $_.Exception.Message }
        Test-ToolkitAssertion -Condition ($nestedError -match 'must be disjoint') -Name "Release source/output overlap rejected at containment guard under $subtree"
        Test-ToolkitAssertion -Condition (-not [IO.Directory]::Exists($nestedOutput)) -Name "Rejected $subtree overlap creates no release output"
    }
}
finally {
    foreach ($sink in $latestSinks) { $sink.Dispose() }
    Close-AdminRunSink
    if ([IO.Directory]::Exists($latestRoot)) { [IO.Directory]::Delete($latestRoot, $true) }
}
if ($latestStandalone) {
    if ($Script:Failures.Count -gt 0) { throw ($Script:Failures -join "`n") }
    Write-Host "Latest ten fixtures: all $Script:TestCount assertions passed under $($PSVersionTable.PSVersion)."
}
