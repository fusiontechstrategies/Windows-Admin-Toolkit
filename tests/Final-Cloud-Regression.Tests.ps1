# Synthetic local children and in-memory certificate metadata only. No PsExec
# executable or real administrative target is invoked by this regression file.
Initialize-AdminSafeFileType
$approvedSigner = [pscustomobject]@{
    Status = 'Valid'
    SignerSubject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    SignerCertificateSha256 = 'aae358fd90d5500110ee8bf3bd2c668f834559710da7d75c266018bb9506f2f6'
}
Test-ToolkitAssertion -Condition (Test-AdminPsExecPublisher -Signature $approvedSigner) -Name 'PsExec publisher accepts only the reviewed complete certificate policy'
foreach ($subject in @('CN="O=Microsoft Corporation", O=Other Publisher', 'CN=Other Publisher, OU=O=Microsoft Corporation', 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US')) {
    $otherSigner = [pscustomobject]@{ Status = 'Valid'; SignerSubject = $subject; SignerCertificateSha256 = ('b' * 64) }
    Test-ToolkitAssertion -Condition (-not (Test-AdminPsExecPublisher -Signature $otherSigner)) -Name 'Valid general signer or spoofed Microsoft subject cannot satisfy the pinned publisher policy'
}

foreach ($case in @(
    @{ Code = "[Console]::Out.Write('x' * 100000)"; Limit = 1024 },
    @{ Code = "[Console]::Out.Write('x' * 1000); [Console]::Error.Write('e' * 1000)"; Limit = 1500 },
    @{ Code = "[Console]::Error.Write('e' * 100000)"; Limit = 1024 }
)) {
    $arguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([string]$case.Code))
    $captured = Invoke-AdminCapturedProcess -LiteralPath $currentEnginePath -ArgumentText $arguments -TimeoutSeconds 10 -MaximumBytes $case.Limit
    Test-ToolkitAssertion -Condition ($captured.OutputExceeded -and ($captured.Stdout.Length + $captured.Stderr.Length) -le $case.Limit) -Name 'Fast-exit synthetic child cannot bypass the shared bounded stdout/stderr pipes'
}
$emptyArguments = '-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("[Console]::Out.Write('synthetic-ok')"))
$normalCapture = Invoke-AdminCapturedProcess -LiteralPath $currentEnginePath -ArgumentText $emptyArguments -TimeoutSeconds 10 -MaximumBytes 1024
Test-ToolkitAssertion -Condition (-not $normalCapture.OutputExceeded -and -not $normalCapture.TimedOut -and $normalCapture.ExitCode -eq 0 -and [Text.Encoding]::UTF8.GetString($normalCapture.Stdout) -ceq 'synthetic-ok') -Name 'Bounded capture preserves ordinary child output without a redirect file'
Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.ProcessCapture]::CheckJsonBudget(('{"Success":true,"Data":[' + ((1..1000) -join ',') + '],"ErrorMessage":null}'), 10) } -Name 'PsExec JSON structure is rejected before object graph allocation'
Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.ProcessCapture]::CheckJsonBudget((('[' * 30) + '0' + (']' * 30)), 4096) } -Name 'PsExec JSON nesting is bounded before deserialization'

$producerPayload = ConvertTo-AdminEncodedPayload -ActionText '1..1000 | ForEach-Object { $_ }' -MaximumOutputItems 2 -MaximumOutputBytes 10000
$producerCapture = Invoke-AdminCapturedProcess -LiteralPath $currentEnginePath -ArgumentText ('-NoLogo -NoProfile -NonInteractive -EncodedCommand ' + $producerPayload) -TimeoutSeconds 15 -MaximumBytes 16384
$producerMatch = [regex]::Match([Text.Encoding]::UTF8.GetString($producerCapture.Stdout), '(?m)^ADMINRESULT:(?<Data>[A-Za-z0-9+/=]+)')
if (-not $producerMatch.Success) { throw 'Bounded producer returned no synthetic envelope.' }
$producerEnvelope = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($producerMatch.Groups['Data'].Value)) | ConvertFrom-Json
Test-ToolkitAssertion -Condition (-not $producerEnvelope.Success -and $producerEnvelope.ErrorMessage -match 'OutputLimit' -and @($producerEnvelope.Data).Count -eq 0) -Name 'Actual encoded PsExec producer cancels before retaining excess item output'

$finalFixture = Join-Path $env:TEMP ('wat-final-' + [guid]::NewGuid().ToString('N'))
[WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($finalFixture)
try {
    $ownerSid = [WindowsAdminToolkit.Security.StorageSecurity]::CurrentSid
    $otherSid = 'S-1-5-21-111111111-222222222-333333333-1009'
    foreach ($right in @(0x2, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000)) {
        $sddl = 'O:' + $ownerSid + 'D:P(A;;FA;;;' + $ownerSid + ')(A;;0x' + $right.ToString('x') + ';;;' + $otherSid + ')'
        $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
        $descriptorBytes = New-Object byte[] $descriptor.BinaryLength
        $descriptor.GetBinaryForm($descriptorBytes, 0)
        Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($descriptorBytes, $false, $true, $false) } -Name 'Pinned directory trust rejects synthetic second-SID mutation authority'
    }
    $unsafeParent = Join-Path $finalFixture 'unsafe-parent'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($unsafeParent)
    # Modify only the DACL of this new synthetic fixture, never a host parent.
    & (Join-Path $env:SystemRoot 'System32/icacls.exe') $unsafeParent '/grant' '*S-1-5-32-545:(DC)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic directory DACL setup failed.' }
    Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.PathLease]::OpenTrusted($unsafeParent, $true, $false, $false) | Out-Null } -Name 'Actual isolated directory with untrusted Users DELETE_CHILD is refused by handle inspection'

    $mockPsExecPath = Join-Path $finalFixture 'synthetic-launch.exe'
    [WindowsAdminToolkit.Security.StorageSecurity]::AppendPrivateFile($mockPsExecPath, [Text.Encoding]::UTF8.GetBytes('Synthetic fixture. Not executable.'), $true, 1024)
    $savedPsExecResolver = (Get-Command Resolve-AdminPsExec).ScriptBlock
    $savedProcessCapture = (Get-Command Invoke-AdminCapturedProcess).ScriptBlock
    $Script:MockNativeQuotas = New-Object 'System.Collections.Generic.List[int]'
    $Script:MockNativeEnvelope = @{ Success = $true; Data = @(1); ErrorMessage = $null }
    function Resolve-AdminPsExec { param($Path) return [IO.Path]::GetFullPath($Path) }
    function Invoke-AdminCapturedProcess {
        param($LiteralPath, $ArgumentText, $TimeoutSeconds, $MaximumBytes)
        $null = $LiteralPath, $ArgumentText, $TimeoutSeconds
        $Script:MockNativeQuotas.Add([int]$MaximumBytes) | Out-Null
        $resultJson = ConvertTo-Json -InputObject $Script:MockNativeEnvelope -Compress
        $wire = 'ADMINRESULT:' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($resultJson)) + "`r`n"
        return [pscustomobject]@{ TimedOut = $false; OutputExceeded = $false; ExitCode = 0; Stdout = [Text.Encoding]::UTF8.GetBytes($wire); Stderr = [byte[]]@() }
    }
    try {
        $smallPsExecResult = Invoke-AdminPsExecTarget -ComputerName 'synthetic.example.test' -PsExecFullPath $mockPsExecPath -ActionText '1' -MaximumOutputItems 1 -MaximumOutputBytes 1024
        Test-ToolkitAssertion -Condition ($smallPsExecResult.Success -and @($smallPsExecResult.Data).Count -eq 1 -and $smallPsExecResult.Data[0] -eq 1 -and $Script:MockNativeQuotas[0] -eq 1024) -Name 'The full PsExec receiver preserves one permitted scalar under a one-item quota'
        $Script:MockNativeQuotas.Clear()
        $Script:MockNativeEnvelope = @{ Success = $true; Data = @(1..1000); ErrorMessage = $null }
        $overflowPsExecResult = Invoke-AdminTargetWithRetry -Transport PsExec -ComputerName 'synthetic.example.test' -PsExecFullPath $mockPsExecPath -ActionText 'unused' -RetryCount 3 -RetryDelaySeconds 1 -MaximumOutputItems 2 -MaximumOutputBytes 10000
        Test-ToolkitAssertion -Condition (-not $overflowPsExecResult.Success -and $overflowPsExecResult.ErrorCategory -ceq 'OutputLimit' -and $overflowPsExecResult.Attempts -eq 1 -and $Script:MockNativeQuotas.Count -eq 1 -and $Script:MockNativeQuotas[0] -eq 2500) -Name 'PsExec forwards each target slice and refuses structural overflow without retrying'
        $Script:MockNativeQuotas.Clear()
        $Script:MockNativeEnvelope = @{ Success = $false; Data = @(); ErrorMessage = 'network connection reset' }
        $retryPsExecResult = Invoke-AdminTargetWithRetry -Transport PsExec -ComputerName 'synthetic.example.test' -PsExecFullPath $mockPsExecPath -ActionText 'unused' -RetryCount 3 -RetryDelaySeconds 1 -MaximumOutputItems 100 -MaximumOutputBytes 10000
        $nativeQuotaTotal = ($Script:MockNativeQuotas | Measure-Object -Sum).Sum
        Test-ToolkitAssertion -Condition (-not $retryPsExecResult.Success -and $retryPsExecResult.Attempts -eq 4 -and $Script:MockNativeQuotas.Count -eq 4 -and $nativeQuotaTotal -le 10000) -Name 'All PsExec retry capture quotas fit one target-wide byte reservation'
    }
    finally {
        Set-Item -Path Function:Resolve-AdminPsExec -Value $savedPsExecResolver
        Set-Item -Path Function:Invoke-AdminCapturedProcess -Value $savedProcessCapture
    }

    $pendingPlanPath = Join-Path $finalFixture 'identity-pending.watplan.json'
    $approvedPlanPath = Join-Path $finalFixture 'identity-approved.watplan.json'
    $identityCheckpointPath = Join-Path $finalFixture 'identity.watcheckpoint.json'
    $planCreated = Invoke-AdminPlanCreate -Parameters @{ PlanPath = $pendingPlanPath; Action = 'SystemInfo'; Local = $true; WhatIf = $true } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
    [void](Invoke-AdminPlanApprove -Parameters @{ PlanPath = $pendingPlanPath; ApprovedPlanPath = $approvedPlanPath; ApprovedBy = 'Synthetic Offline Test'; ApprovalReference = 'TEST-ID'; PlanApprovalText = ('APPROVE PLAN ' + $planCreated.planHash) } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-')
    $identityPlan = Import-AdminOrchestrationPlan -LiteralPath $approvedPlanPath
    $identityCheckpoint = ConvertTo-AdminInitialCheckpoint -Plan $identityPlan -RunId ([guid]::NewGuid())
    [void](Write-AdminCheckpoint -LiteralPath $identityCheckpointPath -Checkpoint $identityCheckpoint -Create)
    $pendingBytes = [IO.File]::ReadAllBytes($identityCheckpointPath)
    $copiedCheckpointPath = Join-Path $finalFixture 'copy.watcheckpoint.json'
    [IO.File]::WriteAllBytes($copiedCheckpointPath, $pendingBytes)
    $resumeParameters = @{ PlanPath = $approvedPlanPath; CheckpointPath = $copiedCheckpointPath; PlanApprovalText = ('RESUME PLAN ' + $identityPlan.planHash.value) }
    $originalAutomation = (Get-Command Invoke-AdminAutomation).ScriptBlock
    $Script:IdentityTargetCalls = 0
    function Invoke-AdminAutomation {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Synthetic mock records dispatch, including WhatIf, without performing target changes.')]
        [CmdletBinding(SupportsShouldProcess = $true)]
        param($Parameters, $ResolvedOutputPath)
        $null = $Parameters, $ResolvedOutputPath, $PSBoundParameters['Confirm'], $PSBoundParameters['WhatIf']
        $Script:IdentityTargetCalls++
        return [pscustomobject]@{ outcome = 'CompleteSuccess'; status = 'Succeeded'; exitCode = 0; targets = @([pscustomobject]@{ status = 'Success'; errorCategory = $null; errorMessage = $null }); errors = @() }
    }
    try {
        $identityLease = [WindowsAdminToolkit.Security.CheckpointLease]::Open((Get-AdminSha256Hex -Text ('ID:' + $identityCheckpoint.checkpointId)))
        try {
            Test-ToolkitThrow -Action { Invoke-AdminPlanExecution -Operation Resume -Parameters $resumeParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'A copied pending checkpoint cannot bypass an active ID lease'
        }
        finally { $identityLease.Dispose() }
        Test-ToolkitThrow -Action { Invoke-AdminPlanExecution -Operation Resume -Parameters $resumeParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'A sequential checkpoint copy cannot create a new execution authority'
        $hardlinkCheckpointPath = Join-Path $finalFixture 'alias.watcheckpoint.json'
        [void](New-Item -ItemType HardLink -Path $hardlinkCheckpointPath -Target $identityCheckpointPath)
        $resumeParameters.CheckpointPath = $hardlinkCheckpointPath
        Test-ToolkitThrow -Action { Invoke-AdminPlanExecution -Operation Resume -Parameters $resumeParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'A hard-link checkpoint alias cannot create a new execution authority'
        $resumeParameters.CheckpointPath = $identityCheckpointPath
        Test-ToolkitThrow -Action { Invoke-AdminPlanExecution -Operation Resume -Parameters $resumeParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'The original checkpoint also refuses an outstanding hard-link alias'
        [IO.File]::Delete($hardlinkCheckpointPath)
        $completedIdentity = Invoke-AdminPlanExecution -Operation Resume -Parameters $resumeParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
        Test-ToolkitAssertion -Condition ($completedIdentity.outcome -ceq 'CompleteSuccess' -and $Script:IdentityTargetCalls -eq 1) -Name 'The original checkpoint identity executes exactly one synthetic target'
        [IO.File]::WriteAllBytes($identityCheckpointPath, $pendingBytes)
        Test-ToolkitThrow -Action { Invoke-AdminPlanExecution -Operation Resume -Parameters $resumeParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'Replaying an earlier valid snapshot at the original path is refused by the durable revision'
        Test-ToolkitAssertion -Condition ($Script:IdentityTargetCalls -eq 1) -Name 'Copies, aliases, and stale replay invoke no additional synthetic target'
    }
    finally { Set-Item -Path Function:Invoke-AdminAutomation -Value $originalAutomation }

    $builderAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $projectRoot 'tools/New-ReleaseArtifacts.ps1'), [ref]$testEntryTokens, [ref]$testEntryErrors)
    $bindingFunction = $builderAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-ReleaseSignedSourceBinding' }, $true)
    . ([scriptblock]::Create($bindingFunction.Extent.Text))
    $unsigned = [Text.Encoding]::UTF8.GetBytes("Write-Output 'approved'`r`n")
    $validSyntheticTrailer = [Text.Encoding]::UTF8.GetBytes("# SIG # Begin signature block`r`n# U3ludGhldGlj`r`n# SIG # End signature block`r`n")
    Test-ReleaseSignedSourceBinding -UnsignedBytes $unsigned -SignedBytes ($unsigned + $validSyntheticTrailer)
    Test-ToolkitAssertion -Condition $true -Name 'Source binding permits an appended synthetic signature block without signing or private keys'
    $substituted = [Text.Encoding]::UTF8.GetBytes("Write-Output 'attacker'`r`n") + $validSyntheticTrailer
    Test-ToolkitThrow -Action { Test-ReleaseSignedSourceBinding -UnsignedBytes $unsigned -SignedBytes $substituted } -Name 'A successfully signed substitute cannot match the approved executable source'
    Test-ToolkitThrow -Action { Test-ReleaseSignedSourceBinding -UnsignedBytes $unsigned -SignedBytes ($unsigned + $validSyntheticTrailer + [Text.Encoding]::UTF8.GetBytes('Write-Output attacker')) } -Name 'Executable bytes after an appended signature block are refused'
}
finally {
    $finalPrefix = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\wat-final-'
    if ([IO.Path]::GetFullPath($finalFixture).StartsWith($finalPrefix, [StringComparison]::OrdinalIgnoreCase)) { [IO.Directory]::Delete($finalFixture, $true) }
}
