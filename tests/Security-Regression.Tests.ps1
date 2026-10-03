# Dependency-free security regressions. The main harness supplies assertions.
# All filesystem effects are limited to this unique synthetic fixture directory.

$securityRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ('wat-security-' + [guid]::NewGuid().ToString('N'))))
$securityTempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
if (-not $securityRoot.StartsWith($securityTempPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe security fixture root.' }
[void][IO.Directory]::CreateDirectory($securityRoot)
$securityJunctions = New-Object 'System.Collections.Generic.List[string]'
try {
    Initialize-AdminSafeFileType
    $protectedParent = Join-Path $securityRoot 'protected'
    [void][IO.Directory]::CreateDirectory($protectedParent)
    $protectedFile = Join-Path $protectedParent 'reference.json'
    [IO.File]::WriteAllText($protectedFile, '{"approved":true}')
    $identityLease = Open-AdminSafePath -LiteralPath $protectedFile
    try {
        Test-ToolkitAssertion -Condition ($identityLease.Sha256() -ceq (Get-AdminFileSha256Hex -LiteralPath $protectedFile)) -Name 'Locked reference hash matches exact opened file bytes'
        Test-ToolkitThrow -Action { [IO.File]::WriteAllText($protectedFile, '{"approved":false}') } -Name 'Validated reference cannot be rewritten while consumed'
        Test-ToolkitThrow -Action { [IO.File]::Move($protectedFile, (Join-Path $protectedParent 'replacement.json')) } -Name 'Validated executable or policy leaf cannot be replaced'
        Test-ToolkitThrow -Action { [IO.Directory]::Move($protectedParent, (Join-Path $securityRoot 'moved')) } -Name 'Locked ancestor cannot be swapped before privileged consumption'
        Test-ToolkitAssertion -Condition ((Read-AdminBoundedUtf8File -LiteralPath $protectedFile -Lease $identityLease) -ceq '{"approved":true}') -Name 'Policy consumption reads original locked stream'
    }
    finally { $identityLease.Dispose() }

    $outside = Join-Path $securityRoot 'outside'
    [void][IO.Directory]::CreateDirectory($outside)
    $outsideFile = Join-Path $outside 'keep.txt'
    [IO.File]::WriteAllText($outsideFile, 'outside-marker')
    [IO.File]::SetLastWriteTimeUtc($outsideFile, [datetime]::UtcNow.AddDays(-10))
    foreach ($rootName in @('user-temp', 'windows-temp')) {
        $cleanupRoot = Join-Path $securityRoot $rootName
        [void][IO.Directory]::CreateDirectory($cleanupRoot)
        $junction = Join-Path $cleanupRoot 'escape'
        New-Item -ItemType Junction -Path $junction -Value $outside -ErrorAction Stop | Out-Null
        $securityJunctions.Add($junction) | Out-Null
        Test-ToolkitThrow -Action { Open-AdminSafePath -LiteralPath (Join-Path $junction 'keep.txt') | Out-Null } -Name "No-follow reference reader rejects ancestor junction in $rootName"
        $cleanup = [WindowsAdminToolkit.Security.TempCleanup]::Run([string[]]@($cleanupRoot), [datetime]::UtcNow.AddDays(-2), 100)
        Test-ToolkitAssertion -Condition ($cleanup.FilesExamined -eq 0 -and $cleanup.FilesDeleted -eq 0 -and $cleanup.ErrorCount -eq 1 -and (Test-Path -LiteralPath $outsideFile)) -Name "Cleanup never follows a directory junction in $rootName"
    }
    $ordinaryRoot = Join-Path $securityRoot 'ordinary-temp'
    [void][IO.Directory]::CreateDirectory($ordinaryRoot)
    for ($i = 0; $i -lt 1000; $i++) {
        $file = Join-Path $ordinaryRoot ("item-$i.txt")
        [IO.File]::WriteAllText($file, 'marker')
        [IO.File]::SetLastWriteTimeUtc($file, [datetime]::UtcNow.AddDays(-10))
    }
    $largeCleanup = [WindowsAdminToolkit.Security.TempCleanup]::Run([string[]]@($ordinaryRoot), [datetime]::UtcNow.AddDays(-2), 100)
    Test-ToolkitAssertion -Condition ($largeCleanup.LimitReached -and $largeCleanup.EntriesExamined -eq 100 -and $largeCleanup.FilesExamined -eq 100 -and $largeCleanup.FilesDeleted -eq 100) -Name 'Temp discovery stops at its entry budget and deletes only opened fixture files'
    Test-ToolkitAssertion -Condition ([IO.Directory]::GetFiles($ordinaryRoot).Length -eq 900) -Name 'Large temp tree retains all entries beyond the discovery limit'
    $directoryOnlyRoot = Join-Path $securityRoot 'directory-temp'
    [void][IO.Directory]::CreateDirectory($directoryOnlyRoot)
    for ($i = 0; $i -lt 150; $i++) { [void][IO.Directory]::CreateDirectory((Join-Path $directoryOnlyRoot ("dir-$i"))) }
    $directoryCleanup = [WindowsAdminToolkit.Security.TempCleanup]::Run([string[]]@($directoryOnlyRoot), [datetime]::UtcNow.AddDays(-2), 100)
    Test-ToolkitAssertion -Condition ($directoryCleanup.LimitReached -and $directoryCleanup.EntriesExamined -eq 100 -and $directoryCleanup.FilesExamined -eq 0) -Name 'Directory-only tree is bounded by the same discovery budget'
    $youngFile = Join-Path $ordinaryRoot 'young.txt'
    [IO.File]::WriteAllText($youngFile, 'young-marker')
    $youngCleanup = [WindowsAdminToolkit.Security.TempCleanup]::Run([string[]]@($ordinaryRoot), [datetime]::UtcNow.AddYears(-1), 1000)
    Test-ToolkitAssertion -Condition ($youngCleanup.FilesDeleted -eq 0 -and (Test-Path -LiteralPath $youngFile)) -Name 'Cleanup age is checked from the opened file identity'

    $oversize = Join-Path $securityRoot 'oversize.watplan.json'
    $oversizeStream = [IO.File]::Open($oversize, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $oversizeStream.SetLength(134217728) } finally { $oversizeStream.Dispose() }
    foreach ($limit in @(1048576, 4194304)) {
        $memoryBefore = [GC]::GetTotalMemory($true)
        Test-ToolkitThrow -Action { Read-AdminStrictOrchestrationJson -LiteralPath $oversize -MaximumBytes $limit -ArtifactName Fixture | Out-Null } -Name "Orchestration rejects 128 MiB file before a $limit byte allocation"
        $memoryGrowth = [GC]::GetTotalMemory($false) - $memoryBefore
        Test-ToolkitAssertion -Condition ($memoryGrowth -lt 16777216) -Name "Oversize $limit byte orchestration read keeps allocation bounded"
    }

    $kbPolicyPath = Join-Path $securityRoot 'kb-policy.json'
    [IO.File]::WriteAllText($kbPolicyPath, '{"schemaVersion":"1.0","profileName":"KB policy","actions":{"allow":["WindowsUpdate"]},"transports":{"allow":["Local","WinRM"]},"targetModes":{"allow":["Local","Remote"]},"targets":{"allow":["server01.example.com"]},"actionInputs":{"WindowsUpdate":{"IncludeKB":{"allowedValues":["KB123456"]}}}}')
    foreach ($inputs in @(@{}, @{ IncludeKB = [string[]]@() }, @{ IncludeKB = [string[]]@('KB123456', 'KB999999') })) {
        $parameters = @{ Action = 'WindowsUpdate'; ComputerName = 'server01.example.com'; WhatIf = $true; PolicyPath = $kbPolicyPath }
        foreach ($key in $inputs.Keys) { $parameters[$key] = $inputs[$key] }
        $kbResolution = Resolve-AdminAutomationRequest -Parameters $parameters
        Test-ToolkitAssertion -Condition (-not $kbResolution.Success -and $kbResolution.PolicyDecision.reasonCode -ceq 'ActionInputDenied') -Name 'KB allowlist rejects omitted, empty, or partially unauthorized update selection'
    }
    $allowedKbResolution = Resolve-AdminAutomationRequest -Parameters @{ Action = 'WindowsUpdate'; Local = $true; WhatIf = $true; IncludeKB = [string[]]@('KB123456'); PolicyPath = $kbPolicyPath }
    Test-ToolkitAssertion -Condition $allowedKbResolution.Success -Name 'KB allowlist accepts an explicit fully approved selection'
    $snapshotParameters = @{ Action = 'WindowsUpdate'; Local = $true; WhatIf = $true; IncludeKB = [string[]]@('KB123456'); PolicyPath = $kbPolicyPath }
    $snapshotPlan = ConvertTo-AdminOrchestrationPlan -Request $allowedKbResolution.Request -Parameters $snapshotParameters
    $snapshotReferences = Open-AdminPlanExternalReferenceLock -Plan $snapshotPlan
    $originalPolicyImporter = (Get-Item Function:\Import-AdminPolicyProfile).ScriptBlock
    try {
        Test-ToolkitThrow -Action { [IO.File]::WriteAllText($kbPolicyPath, '{}') } -Name 'Approved orchestration policy remains locked throughout consumption'
        function Import-AdminPolicyProfile { throw 'Validated profile was reopened through a path.' }
        $snapshotRuntimeParameters = ConvertTo-AdminPlanExecutionParameter -Plan $snapshotPlan -OperationParameter @{} -ValidatedPolicyProfile $snapshotReferences.PolicyProfile
        $snapshotResolution = Resolve-AdminAutomationRequest -Parameters $snapshotRuntimeParameters
        Test-ToolkitAssertion -Condition ($snapshotResolution.Success -and [object]::ReferenceEquals($Script:State.PolicyProfile, $snapshotReferences.PolicyProfile)) -Name 'Orchestration resolution uses the exact validated policy object without reopening'
    }
    finally {
        Set-Item Function:\Import-AdminPolicyProfile -Value $originalPolicyImporter
        foreach ($lease in $snapshotReferences.Leases) { $lease.Dispose() }
    }

    # Shadow target helpers with tripwires: even read-only requests must preview.
    $originalDetailed = (Get-Item Function:\Invoke-AdminTargetDetailed).ScriptBlock
    $originalConnectivity = (Get-Item Function:\Test-AdminTargetConnectivity).ScriptBlock
    $originalAuditStart = (Get-Item Function:\Write-AdminAuditExecutionStarted).ScriptBlock
    try {
        function Invoke-AdminTargetDetailed { throw 'Preview invoked action tripwire.' }
        function Test-AdminTargetConnectivity { throw 'Preview invoked connectivity tripwire.' }
        function Write-AdminAuditExecutionStarted { throw 'Preview invoked audit execution-start tripwire.' }
        foreach ($previewParameters in @(
            @{ Action = 'SystemInfo'; Local = $true; WhatIf = $true },
            @{ Action = 'SystemInfo'; ComputerName = 'server01.example.com'; WhatIf = $true },
            @{ Action = 'ServiceManagement'; Local = $true; ServiceName = 'Spooler'; ServiceAction = 'Query'; WhatIf = $true }
        )) {
            $previewParameters.LogFile = Join-Path $securityRoot 'preview.log'
            $preview = Invoke-AdminAutomation -Parameters $previewParameters -ResolvedOutputPath '-' -Confirm:$false
            Test-ToolkitAssertion -Condition ($preview.status -ceq 'WhatIf' -and $preview.targets[0].status -ceq 'WhatIf' -and @($preview.targets[0].data).Count -eq 0) -Name 'Read-only WhatIf reaches no connectivity, action, or execution-start helper'
        }
    }
    finally {
        Set-Item Function:\Invoke-AdminTargetDetailed -Value $originalDetailed
        Set-Item Function:\Test-AdminTargetConnectivity -Value $originalConnectivity
        Set-Item Function:\Write-AdminAuditExecutionStarted -Value $originalAuditStart
    }

    # Stream a synthetic remote producer through the real WinRM collection path.
    # No WinRM connection or remote administrative action is made.
    try {
        Set-Item Function:\New-PSSessionOption -Value {
            param($OpenTimeout, $OperationTimeout, $CancelTimeout, $MaximumReceivedObjectSize, $MaximumReceivedDataSizePerCommand)
            $null = $PSBoundParameters
            $Script:ObservedWinRmQuota = [int]$MaximumReceivedDataSizePerCommand
            if ($null -ne $Script:WireQuotaReservations) { $Script:WireQuotaReservations.Add([int]$MaximumReceivedDataSizePerCommand) | Out-Null }
            return [pscustomobject]@{ MaximumReceivedObjectSize = $MaximumReceivedObjectSize }
        }
        Set-Item Function:\Invoke-Command -Value {
            [CmdletBinding()]
            param($ComputerName, $ScriptBlock, $ArgumentList, $Authentication, $SessionOption)
            $null = $PSBoundParameters
            for ($record = 0; $record -lt $Script:RemoteRecordLimit; $record++) {
                $Script:RemoteProduced++
                if ($Script:RemoteAuxiliaryMode -eq 'Warning') { Write-Warning ('w' * 4096); throw 'Synthetic connection failure after warning.' }
                if ($Script:RemoteAuxiliaryMode -eq 'Information') { Write-Information ('i' * 4096); throw 'Synthetic connection failure after information.' }
                if ($Script:RemoteAuxiliaryMode -eq 'Error') { throw ('Synthetic connection failure ' + ('e' * 4096)) }
                if ($Script:RemoteAuxiliaryMode -eq 'Progress') {
                    $Script:ProgressWasSuppressed = $ProgressPreference -ceq 'SilentlyContinue'
                    Write-Progress -Activity 'Synthetic progress' -Status ('p' * 1000) -PercentComplete 50
                    throw 'Synthetic connection failure after progress.'
                }
                if ($Script:RemoteLargeString) { 'x' * 100000 } else { 'record' }
            }
        }
        $Script:RemoteProduced = 0
        $Script:RemoteRecordLimit = 1000
        $Script:RemoteAuxiliaryMode = ''
        $Script:WireQuotaReservations = $null
        $Script:RemoteLargeString = $false
        $limitedRemote = Invoke-AdminWinRmTarget -ComputerName 'server01.example.com' -ActionText "'unused'" -MaximumOutputItems 10 -MaximumOutputBytes 10000
        Test-ToolkitAssertion -Condition (-not $limitedRemote.Success -and $limitedRemote.ErrorCategory -ceq 'OutputLimit' -and @($limitedRemote.Data).Count -eq 0 -and $Script:RemoteProduced -eq 11) -Name 'WinRM item limit stops producer immediately and returns bounded failure'
        Test-ToolkitAssertion -Condition ($Script:ObservedWinRmQuota -eq 10000) -Name 'WinRM protocol data quota is set before transport invocation'
        $Script:RemoteProduced = 0
        $Script:RemoteLargeString = $true
        $byteLimitedRemote = Invoke-AdminWinRmTarget -ComputerName 'server01.example.com' -ActionText "'unused'" -MaximumOutputBytes 10000
        Test-ToolkitAssertion -Condition (-not $byteLimitedRemote.Success -and $byteLimitedRemote.ErrorCategory -ceq 'OutputLimit' -and $Script:RemoteProduced -eq 1) -Name 'One oversized WinRM string stops output before collection'
        $Script:RemoteProduced = 0
        $Script:RemoteLargeString = $false
        $noOutputRetry = Invoke-AdminTargetWithRetry -Transport WinRM -ComputerName 'server01.example.com' -ActionText "'unused'" -RetryCount 3 -MaximumOutputItems 2
        Test-ToolkitAssertion -Condition ($noOutputRetry.Attempts -eq 1 -and $Script:RemoteProduced -eq 3) -Name 'Output-limit failures are never retried'
        foreach ($auxiliaryMode in @('Warning', 'Information', 'Error')) {
            $Script:RemoteProduced = 0
            $Script:RemoteAuxiliaryMode = $auxiliaryMode
            $auxiliaryResult = Invoke-AdminTargetWithRetry -Transport WinRM -ComputerName 'server01.example.com' -ActionText "'unused'" -RetryCount 3 -RetryDelaySeconds 1 -MaximumOutputBytes 10000
            Test-ToolkitAssertion -Condition (-not $auxiliaryResult.Success -and $auxiliaryResult.ErrorCategory -ceq 'OutputLimit' -and $auxiliaryResult.Attempts -eq 1 -and $Script:RemoteProduced -eq 1) -Name "$auxiliaryMode output is charged before retention and stops retry amplification"
        }
        $Script:RemoteAuxiliaryMode = ''

        $Script:RemoteAuxiliaryMode = 'Progress'
        $Script:WireQuotaReservations = New-Object 'System.Collections.Generic.List[int]'
        $Script:ProgressWasSuppressed = $false
        $Script:RemoteProduced = 0
        $progressResult = Invoke-AdminTargetWithRetry -Transport WinRM -ComputerName 'server01.example.com' -ActionText "'unused'" -RetryCount 3 -RetryDelaySeconds 1 -MaximumOutputBytes 10000
        $reservedWireBytes = ($Script:WireQuotaReservations | Measure-Object -Sum).Sum
        Test-ToolkitAssertion -Condition (-not $progressResult.Success -and $Script:ProgressWasSuppressed -and $progressResult.Attempts -eq 4 -and $reservedWireBytes -le 10000 -and $Script:WireQuotaReservations.Count -eq 4) -Name 'Progress is discarded before job retention and all retry wire quotas share one target reservation'
        $Script:RemoteAuxiliaryMode = ''
        $Script:WireQuotaReservations = $null

        $Script:RemoteRecordLimit = 1
        $Script:WorkerReservations = New-Object 'System.Collections.Generic.List[object]'
        Set-Item Function:\Start-Job -Value {
            [CmdletBinding()]
            param($Name, $ScriptBlock, $ArgumentList)
            $null = $PSBoundParameters
            $Script:WorkerReservations.Add([pscustomobject]@{ Bytes = [int]$ArgumentList[12]; Items = [int]$ArgumentList[13] }) | Out-Null
            # This synchronous job adapter deliberately shares script scope.
            # Restore retained parent objects after the worker loads its own state.
            $parentSinks = $Script:MutableSinks
            $parentState = $Script:State
            $parentCheckpointFiles = $Script:CheckpointFiles
            $parentSource = $Script:ToolkitLoadedSource
            $parentToolkitPath = $Script:ToolkitPath
            try { $envelope = & $ScriptBlock @ArgumentList }
            finally {
                $Script:MutableSinks = $parentSinks
                $Script:State = $parentState
                $Script:CheckpointFiles = $parentCheckpointFiles
                $Script:ToolkitLoadedSource = $parentSource
                $Script:ToolkitPath = $parentToolkitPath
            }
            return [pscustomobject]@{ State = 'Completed'; Envelope = $envelope }
        }
        Set-Item Function:\Receive-Job -Value {
            [CmdletBinding()]
            param($Job)
            return $Job.Envelope
        }
        Set-Item Function:\Remove-Job -Value {
            [CmdletBinding()]
            param($Job, [switch]$Force, [switch]$WhatIf, [switch]$Confirm)
            $null = $PSBoundParameters
        }
        try {
            $Script:State.Transport = 'WinRM'
            $syntheticComputers = [string[]]@(1..17 | ForEach-Object { "server$_.example.com" })
            $concurrentOutput = @(Invoke-AdminTargetDetailed -TargetMode Remote -Computers $syntheticComputers -ActionName SystemInfo -MaxConcurrentJobs 8 -RetryCount 0)
            $reservedBytes = ($Script:WorkerReservations | Measure-Object -Property Bytes -Sum).Sum
            $reservedItems = ($Script:WorkerReservations | Measure-Object -Property Items -Sum).Sum
            Test-ToolkitAssertion -Condition ($concurrentOutput.Count -eq 17 -and @($concurrentOutput | Where-Object { $_.Status -ne 'Success' }).Count -eq 0) -Name 'Concurrent synthetic workers exercise bounded WinRM dispatch without a connection'
            Test-ToolkitAssertion -Condition ($Script:WorkerReservations.Count -eq 17 -and $reservedBytes -le 67108864 -and $reservedItems -le 32768) -Name 'Multiple concurrent targets reserve at most one aggregate run budget'
        }
        finally {
            Remove-Item Function:\Start-Job -ErrorAction SilentlyContinue
            Remove-Item Function:\Receive-Job -ErrorAction SilentlyContinue
            Remove-Item Function:\Remove-Job -ErrorAction SilentlyContinue
        }
    }
    finally {
        Remove-Item Function:\Invoke-Command -ErrorAction SilentlyContinue
        Remove-Item Function:\New-PSSessionOption -ErrorAction SilentlyContinue
    }
    Test-ToolkitThrow -Action { ConvertTo-AdminJsonSafeValue -Value @{ nested = @(1..1000) } -Budget ([pscustomobject]@{ RemainingItems = 20; RemainingBytes = 10000 }) | Out-Null } -Name 'Nested remote enumerable shares the projection item budget'
    Test-ToolkitThrow -Action { ConvertTo-AdminJsonSafeValue -Value ([pscustomobject]@{ nested = 'x' * 10000 }) -Budget ([pscustomobject]@{ RemainingItems = 20; RemainingBytes = 1000 }) | Out-Null } -Name 'Nested property byte limit is propagated through projection'

    $leasePath = Join-Path $securityRoot 'lease.watcheckpoint.json'
    $checkpointTestLease = Open-AdminCheckpointLease -LiteralPath $leasePath
    try {
        Test-ToolkitThrow -Action { Open-AdminCheckpointLease -LiteralPath $leasePath | Out-Null } -Name 'Checkpoint lease rejects same-thread reentry'
        $escapedToolkit = $toolkitPath.Replace("'", "''")
        $escapedLeasePath = $leasePath.Replace("'", "''")
        $leaseCompetitor = Invoke-TestPowerShellCommandProcess -EnginePath $currentEnginePath -CommandText ". '$escapedToolkit'; try { `$lease = Open-AdminCheckpointLease -LiteralPath '$escapedLeasePath'; `$lease.Dispose(); exit 1 } catch { if (`$_.Exception.Message -match 'already leased') { exit 0 }; throw }"
        Test-ToolkitAssertion -Condition ($leaseCompetitor.ExitCode -eq 0) -Name 'Competing process fails checkpoint lease before it can claim a target'
    }
    finally { $checkpointTestLease.Dispose() }
    $recoveredLease = Open-AdminCheckpointLease -LiteralPath $leasePath
    $recoveredLease.Dispose()
    Test-ToolkitAssertion -Condition $true -Name 'Released checkpoint lease can be explicitly resumed'

    $cleanupActionText = $Script:ActionScripts.ClearTempFiles.ToString()
    $cleanupPayload = ConvertTo-AdminEncodedPayload -ActionText $cleanupActionText -ArgumentList @(2, 100)
    Test-ToolkitAssertion -Condition (($cleanupPayload.Length + 1024) -le 32766) -Name 'Native cleanup PsExec payload fits the Windows command-line limit'
    $payloadUserTemp = Join-Path $securityRoot 'payload-user'
    $payloadWindows = Join-Path $securityRoot 'payload-windows'
    $payloadWindowsTemp = Join-Path $payloadWindows 'Temp'
    [void][IO.Directory]::CreateDirectory($payloadUserTemp)
    [void][IO.Directory]::CreateDirectory($payloadWindowsTemp)
    foreach ($payloadRoot in @($payloadUserTemp, $payloadWindowsTemp)) {
        $payloadMarker = Join-Path $payloadRoot 'old-fixture.txt'
        [IO.File]::WriteAllText($payloadMarker, 'synthetic-marker')
        [IO.File]::SetLastWriteTimeUtc($payloadMarker, [datetime]::UtcNow.AddDays(-10))
    }
    # Substitute only cleanup root expressions; the child retains its genuine
    # SystemRoot so Windows PowerShell's Add-Type compiler resolves correctly.
    $fixtureRoots = "[string[]]@('$($payloadUserTemp.Replace("'", "''"))', '$($payloadWindowsTemp.Replace("'", "''"))')"
    $fixtureActionText = $cleanupActionText.Replace('[WindowsAdminToolkit.Security.SystemPaths]::CleanupRoots()', $fixtureRoots)
    if ($fixtureActionText -ceq $cleanupActionText -or $fixtureActionText.Contains('[WindowsAdminToolkit.Security.SystemPaths]::CleanupRoots()')) { throw 'Cleanup fixture did not replace the production root resolver; refuse execution.' }
    $fixturePayload = ConvertTo-AdminEncodedPayload -ActionText $fixtureActionText -ArgumentList @(2, 100)
    $payloadBootstrap = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($fixturePayload))
    $cleanupPayloadResult = Invoke-TestPowerShellCommandProcess -EnginePath $currentEnginePath -CommandText $payloadBootstrap
    $cleanupPayloadMatch = [regex]::Match($cleanupPayloadResult.StdOut, '(?m)^ADMINRESULT:(?<Data>[A-Za-z0-9+/=]+)')
    if (-not $cleanupPayloadMatch.Success) { throw 'Compressed cleanup payload did not return a result.' }
    $cleanupPayloadEnvelope = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($cleanupPayloadMatch.Groups['Data'].Value)) | ConvertFrom-Json
    Test-ToolkitAssertion -Condition ($cleanupPayloadResult.ExitCode -eq 0 -and $cleanupPayloadEnvelope.Success -and $cleanupPayloadEnvelope.Data[0].FilesDeleted -eq 2 -and [IO.Directory]::GetFiles($payloadUserTemp).Length -eq 0 -and [IO.Directory]::GetFiles($payloadWindowsTemp).Length -eq 0) -Name 'Compressed native helper round-trips through the encoded transport in isolated temp fixtures'

    # Run two actual Resume lifecycles. The action stub records one invocation and
    # waits while the second executor attempts to acquire the same checkpoint.
    $concurrentPending = Join-Path $securityRoot 'concurrent-pending.watplan.json'
    $concurrentApproved = Join-Path $securityRoot 'concurrent-approved.watplan.json'
    $concurrentCheckpoint = Join-Path $securityRoot 'concurrent.watcheckpoint.json'
    $concurrentMarker = Join-Path $securityRoot 'invocations.txt'
    $concurrentReady = Join-Path $securityRoot 'executor-ready.txt'
    $concurrentResult = Join-Path $securityRoot 'executor-result.txt'
    $createResult = Invoke-AdminPlanCreate -Parameters @{ PlanPath = $concurrentPending; Action = 'SystemInfo'; Local = $true; WhatIf = $true } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
    $concurrentPlanHash = [string]$createResult.planHash
    [void](Invoke-AdminPlanApprove -Parameters @{ PlanPath = $concurrentPending; ApprovedPlanPath = $concurrentApproved; ApprovedBy = 'Synthetic Security Test'; ApprovalReference = 'TEST-CONCURRENT'; PlanApprovalText = "APPROVE PLAN $concurrentPlanHash" } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-')
    $concurrentPlan = Import-AdminOrchestrationPlan -LiteralPath $concurrentApproved
    $initialCheckpoint = ConvertTo-AdminInitialCheckpoint -Plan $concurrentPlan -RunId ([guid]::NewGuid())
    [void](Write-AdminCheckpoint -LiteralPath $concurrentCheckpoint -Checkpoint $initialCheckpoint -Create)
    $concurrentEscaped = @{}
    foreach ($entry in @{ Toolkit = $toolkitPath; Plan = $concurrentApproved; Checkpoint = $concurrentCheckpoint; Marker = $concurrentMarker; Ready = $concurrentReady; Result = $concurrentResult }.GetEnumerator()) { $concurrentEscaped[$entry.Key] = ([string]$entry.Value).Replace("'", "''") }
    $executorText = @"
. '$($concurrentEscaped.Toolkit)'
function Get-AdminCheckpointRegistryRoot { return '$($Script:OfflineRegistryRoot.Replace("'", "''"))' }
function Invoke-AdminAutomation {
    param(`$Parameters, `$ResolvedOutputPath)
    `$null = `$PSBoundParameters
    [IO.File]::AppendAllText('$($concurrentEscaped.Marker)', 'invocation' + [Environment]::NewLine)
    [IO.File]::WriteAllText('$($concurrentEscaped.Ready)', 'ready')
    `$deadline = [datetime]::UtcNow.AddSeconds(15)
    while (-not [IO.File]::Exists('$($concurrentEscaped.Result)') -and [datetime]::UtcNow -lt `$deadline) { Start-Sleep -Milliseconds 50 }
    throw 'Synthetic interruption after exactly one invocation.'
}
try {
    `$parameters = @{ PlanPath = '$($concurrentEscaped.Plan)'; CheckpointPath = '$($concurrentEscaped.Checkpoint)'; PlanApprovalText = 'RESUME PLAN $concurrentPlanHash' }
    `$result = Invoke-AdminPlanExecution -Operation Resume -Parameters `$parameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
    if (`$result.targets[0].state -ne 'Unknown') { exit 2 }
    exit 0
} catch { [Console]::Error.WriteLine(`$_.Exception.Message); exit 1 }
"@
    $executorStart = New-Object Diagnostics.ProcessStartInfo
    $executorStart.FileName = $currentEnginePath
    $executorStart.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($executorText))
    $executorStart.UseShellExecute = $false
    $executorStart.CreateNoWindow = $true
    $executorStart.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $executor = New-Object Diagnostics.Process
    $executor.StartInfo = $executorStart
    try {
        [void]$executor.Start()
        $readyDeadline = [datetime]::UtcNow.AddSeconds(15)
        while (-not [IO.File]::Exists($concurrentReady) -and -not $executor.HasExited -and [datetime]::UtcNow -lt $readyDeadline) { Start-Sleep -Milliseconds 50 }
        Test-ToolkitAssertion -Condition ([IO.File]::Exists($concurrentReady)) -Name 'First Resume executor exclusively claims pending synthetic target'
        try {
            Test-ToolkitThrow -Action {
                Invoke-AdminPlanExecution -Operation Resume -Parameters @{ PlanPath = $concurrentApproved; CheckpointPath = $concurrentCheckpoint; PlanApprovalText = "RESUME PLAN $concurrentPlanHash" } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null
            } -Name 'Second concurrent Resume aborts before pending target invocation'
        }
        finally { [IO.File]::WriteAllText($concurrentResult, 'competitor finished') }
        if (-not $executor.WaitForExit(15000)) { $executor.Kill(); throw 'Synthetic Resume executor timed out.' }
        Test-ToolkitAssertion -Condition ($executor.ExitCode -eq 0 -and [IO.File]::ReadAllLines($concurrentMarker).Length -eq 1) -Name 'Concurrent Resume operations invoke exactly one target'
        $interruptedCheckpoint = Import-AdminOrchestrationCheckpoint -LiteralPath $concurrentCheckpoint -Plan $concurrentPlan
        Test-ToolkitAssertion -Condition ($interruptedCheckpoint.targets[0].state -ceq 'Unknown') -Name 'Exclusive interrupted claim is retained as Unknown'
    }
    finally {
        if (-not $executor.HasExited) { $executor.Kill() }
        $executor.Dispose()
    }

    # Kill only a helper created by this test while it owns a lease. The next
    # executor acquires the abandoned mutex and recovers InProgress as Unknown.
    $crashLeasePath = Join-Path $securityRoot 'crash.watcheckpoint.json'
    $crashReadyPath = Join-Path $securityRoot 'crash-ready.txt'
    $crashText = ". '$escapedToolkit'; `$lease = Open-AdminCheckpointLease -LiteralPath '$($crashLeasePath.Replace("'", "''"))'; [IO.File]::WriteAllText('$($crashReadyPath.Replace("'", "''"))', 'ready'); Start-Sleep -Seconds 30"
    $executorStart.Arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($crashText))
    $crashExecutor = New-Object Diagnostics.Process
    $crashExecutor.StartInfo = $executorStart
    try {
        [void]$crashExecutor.Start()
        $crashDeadline = [datetime]::UtcNow.AddSeconds(15)
        while (-not [IO.File]::Exists($crashReadyPath) -and -not $crashExecutor.HasExited -and [datetime]::UtcNow -lt $crashDeadline) { Start-Sleep -Milliseconds 50 }
        if (-not [IO.File]::Exists($crashReadyPath)) { throw 'Crash fixture did not acquire its lease.' }
        $crashExecutor.Kill()
        [void]$crashExecutor.WaitForExit(5000)
        $afterCrashLease = Open-AdminCheckpointLease -LiteralPath $crashLeasePath
        $afterCrashLease.Dispose()
        Test-ToolkitAssertion -Condition $true -Name 'Crashed executor releases exclusive checkpoint lease for explicit recovery'
    }
    finally {
        if (-not $crashExecutor.HasExited) { $crashExecutor.Kill() }
        $crashExecutor.Dispose()
    }
}
finally {
    Close-AdminRunSink
    # Remove junction objects explicitly before recursively removing fixtures.
    foreach ($junction in $securityJunctions) { if ([IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) } }
    if ([IO.Directory]::Exists($securityRoot) -and $securityRoot.StartsWith($securityTempPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        [IO.Directory]::Delete($securityRoot, $true)
    }
}
