# Owned local fixtures and protected namespace controls only. No remote endpoint.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules/Microsoft.PowerShell.Utility/Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$fiveStandalone = -not (Get-Command Test-ToolkitAssertion -ErrorAction SilentlyContinue)
if ($fiveStandalone) {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'WindowsAdminToolkit.ps1')
    . (Join-Path $PSScriptRoot 'Offline-Transport.Guards.ps1')
    $Script:TestCount = 0; $Script:Failures = New-Object 'System.Collections.Generic.List[string]'
    function Test-ToolkitAssertion { param([bool]$Condition, [string]$Name) $Script:TestCount++; if (-not $Condition) { $Script:Failures.Add($Name) | Out-Null; Write-Host "FAIL $Name" } }
    function Test-ToolkitThrow { param([scriptblock]$Action, [string]$Name) $threw = $false; try { & $Action } catch { $threw = $true }; Test-ToolkitAssertion -Condition $threw -Name $Name }
}
Initialize-AdminSafeFileType
$fiveRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) ('wat-five-' + [guid]::NewGuid().ToString('N'))
[WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($fiveRoot)
try {
    foreach ($reserved in @('_PlanValidation', '_ValidatedPolicyProfile', '_PlanComputers', '_AnyFutureInternalKey', 'UnknownExternalKey')) {
        $publicMap = @{ Action = 'ScheduleReboot'; Local = $true }
        $publicMap[$reserved] = $true
        $resolution = Resolve-AdminAutomationRequest -Parameters $publicMap
        Test-ToolkitAssertion -Condition (-not $resolution.Success -and $resolution.Category -ceq 'Validation' -and $resolution.Message -match 'reserved key') -Name "Public resolver rejects $reserved before authorization or dispatch"
        Test-ToolkitThrow -Action { Invoke-AdminAutomation -Parameters $publicMap -ResolvedOutputPath '-' | Out-Null } -Name "Public automation rejects $reserved"
        Test-ToolkitThrow -Action { Invoke-AdminPlanCreate -Parameters $publicMap -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name "Public plan creation rejects $reserved"
    }
    $noConfirmation = Resolve-AdminAutomationRequest -Parameters @{ Action = 'ScheduleReboot'; Local = $true }
    Test-ToolkitAssertion -Condition (-not $noConfirmation.Success -and $noConfirmation.Category -ceq 'Authorization') -Name 'Public state change still requires exact authorization'
    $deniedPath = Join-Path $fiveRoot 'denied.json'
    [IO.File]::WriteAllText($deniedPath, '{"schemaVersion":"1.0","profileName":"Denied","actions":{"allow":["SystemInfo"],"deny":["ScheduleReboot"]},"transports":{"allow":["Local"]},"targetModes":{"allow":["Local"]},"targets":{"allow":[]}}')
    $fakePolicyMap = @{ Action = 'ScheduleReboot'; Local = $true; ConfirmationText = 'SCHEDULE REBOOT'; PolicyPath = $deniedPath; _ValidatedPolicyProfile = [pscustomobject]@{ ActionsAllow = @('ScheduleReboot') }; _PlanValidation = $true }
    $fakePolicyResult = Resolve-AdminAutomationRequest -Parameters $fakePolicyMap
    Test-ToolkitAssertion -Condition (-not $fakePolicyResult.Success -and $fakePolicyResult.Category -ceq 'Validation') -Name 'Caller policy object cannot replace file policy or skip confirmation'
    Test-ToolkitAssertion -Condition (-not (Get-Command Invoke-AdminInternalPlanRequest -ErrorAction SilentlyContinue)) -Name 'No generic caller-supplied internal context or Execute registrar remains'
    foreach ($common in @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction')) {
        $commonMap = @{ Action = 'SystemInfo'; Local = $true }
        $commonMap[$common] = if ($common -in @('Verbose', 'Debug')) { $true } else { 'Stop' }
        Test-ToolkitAssertion -Condition (Resolve-AdminAutomationRequest -Parameters $commonMap).Success -Name "Public canonical metadata accepts common parameter $common"
    }
    $caseMap = [Collections.Specialized.OrderedDictionary]::new([StringComparer]::Ordinal)
    $caseMap['Action'] = 'ScheduleReboot'; $caseMap['Local'] = $true; $caseMap['ConfirmationText'] = 'SCHEDULE REBOOT'; $caseMap['policypath'] = $deniedPath
    $caseResolution = Resolve-AdminAutomationRequest -Parameters $caseMap
    Test-ToolkitAssertion -Condition (-not $caseResolution.Success -and $caseResolution.Category -ceq 'Authorization' -and $caseResolution.PolicyDecision.applied) -Name 'Case-sensitive lower-case policy key is canonicalized and enforced'
    $caseMap['PolicyPath'] = $deniedPath
    Test-ToolkitAssertion -Condition ((Resolve-AdminAutomationRequest -Parameters $caseMap).Category -ceq 'Validation') -Name 'Semantic duplicate policy keys are refused'
    $genericMap = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
    $genericMap.Add('action', 'SystemInfo'); $genericMap.Add('local', $true)
    Test-ToolkitAssertion -Condition (Resolve-AdminAutomationRequest -Parameters $genericMap).Success -Name 'Generic IDictionary is snapshotted without explicit-interface Contains overload ambiguity'
    $mutableInput = @{ Action = 'SystemInfo'; Local = $true; WhatIf = $true }
    $ownedMap = ConvertTo-AdminOwnedParameterMap -Parameters $mutableInput
    $mutableInput.Action = 'ScheduleReboot'; $mutableInput.WhatIf = $false
    Test-ToolkitAssertion -Condition ($ownedMap['Action'] -ceq 'SystemInfo' -and [bool]$ownedMap['WhatIf']) -Name 'Owned canonical scalar snapshot is independent of later caller dictionary mutation'
    Test-ToolkitThrow -Action { $ownedMap['WhatIf'] = $false } -Name 'Owned request dictionary is immutable'
    $callerKbs = [string[]]@('KB123456')
    $arraySnapshot = ConvertTo-AdminOwnedParameterMap -Parameters @{ IncludeKB = $callerKbs }
    $callerKbs[0] = 'KB999999'
    Test-ToolkitAssertion -Condition ($arraySnapshot['IncludeKB'][0] -ceq 'KB123456') -Name 'Array snapshot does not retain the caller-owned mutable array'
    Test-ToolkitThrow -Action { $arraySnapshot['IncludeKB'][0] = 'KB999999' } -Name 'Array snapshot items are read-only'
    Test-ToolkitThrow -Action { ConvertTo-AdminOwnedParameterMap -Parameters @{ Credential = [pscustomobject]@{ UserName = 'synthetic-user' } } | Out-Null } -Name 'Canonical Credential rejects mutable or prompt-producing substitutes'

    if (-not ('WindowsFiveChangingMap' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections;
public sealed class WindowsFiveChangingMap : Hashtable {
    public int WhatIfIndexerReads;
    public override object this[object key] {
        get { if (String.Equals(key as string,"WhatIf",StringComparison.OrdinalIgnoreCase)) return ++WhatIfIndexerReads==1; return base[key]; }
        set { base[key]=value; }
    }
}
'@ -ErrorAction Stop
    }
    $changing = New-Object WindowsFiveChangingMap
    $changing['Action'] = 'ScheduleReboot'; $changing['Local'] = $true; $changing['WhatIf'] = $true; $changing['LogFile'] = Join-Path $fiveRoot 'changing-preview.log'
    $recordedDispatcher = (Get-Command Invoke-AdminTargetDetailed).ScriptBlock
    $Script:FiveRecordedDispatches = 0
    Set-Item Function:\Invoke-AdminTargetDetailed -Value { $Script:FiveRecordedDispatches++; throw 'Synthetic state-changing dispatcher must not run.' }
    try {
        foreach ($entryPoint in @('Wrapper', 'Core')) {
            foreach ($previewCase in @('Explicit', 'ExplicitFalseMap', 'MapOnly', 'Ambient', 'StateChanging')) {
                $previewInput = @{ Action = 'SystemInfo'; Local = $true; LogFile = Join-Path $fiveRoot ($entryPoint + '-' + $previewCase + '.log') }
                if ($previewCase -ceq 'ExplicitFalseMap') { $previewInput.WhatIf = $false }
                if ($previewCase -ceq 'MapOnly') { $previewInput.WhatIf = $true }
                if ($previewCase -ceq 'StateChanging') { $previewInput.Action = 'ScheduleReboot' }
                $previewInvoke = @{ Parameters = $previewInput; ResolvedOutputPath = '-'; Confirm = $false }
                if ($previewCase -ceq 'MapOnly') { $previewInvoke.WhatIf = $false }
                elseif ($previewCase -cne 'Ambient') { $previewInvoke.WhatIf = $true }
                $previousPreview = $WhatIfPreference
                try {
                    if ($previewCase -ceq 'Ambient') { $WhatIfPreference = $true }
                    if ($entryPoint -ceq 'Wrapper') { $previewResult = Invoke-AdminAutomation @previewInvoke }
                    else { $previewResult = Invoke-AdminAutomationCore @previewInvoke -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) }
                    Test-ToolkitAssertion -Condition ($previewResult.status -ceq 'WhatIf' -and $Script:FiveRecordedDispatches -eq 0) -Name "$entryPoint $previewCase WhatIf preserves preview with zero recorded dispatches"
                }
                finally { $WhatIfPreference = $previousPreview; Close-AdminRunSink }
            }
        }
        $executionMap = ConvertTo-AdminOwnedParameterMap -Parameters @{ Action = 'SystemInfo'; Local = $true; WhatIf = $false }
        # White-box guard: no public helper registers or changes this private context.
        $Script:InternalPlanContexts.Add($executionMap, [pscustomobject]@{ Purpose = 'ApprovedExecution'; ValidationOnly = $false })
        try {
            Test-ToolkitThrow -Action { Invoke-AdminAutomation -Parameters $executionMap -ResolvedOutputPath '-' -WhatIf | Out-Null } -Name 'Wrapper cannot change approved execution safety through WhatIf'
            Test-ToolkitThrow -Action { Invoke-AdminAutomationCore -Parameters $executionMap -ResolvedOutputPath '-' -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -WhatIf | Out-Null } -Name 'Core cannot change approved execution safety through WhatIf'
            Test-ToolkitAssertion -Condition (-not [bool]$executionMap['WhatIf'] -and $Script:FiveRecordedDispatches -eq 0) -Name 'Approved execution preview mismatch preserves original map and never dispatches'
        }
        finally { [void]$Script:InternalPlanContexts.Remove($executionMap) }
        $changingResult = Invoke-AdminAutomation -Parameters $changing -ResolvedOutputPath '-' -Confirm:$false
        Test-ToolkitAssertion -Condition ($changingResult.status -ceq 'WhatIf' -and $changing.WhatIfIndexerReads -eq 0 -and $Script:FiveRecordedDispatches -eq 0) -Name 'Changing WhatIf external indexer is never reread and cannot turn a validated preview into dispatch'
        $previewMap = ConvertTo-AdminOwnedParameterMap -Parameters @{ Action = 'ScheduleReboot'; Local = $true }
        # White-box defensive control only. Production registers this solely inside Plan Create.
        $Script:InternalPlanContexts.Add($previewMap, [pscustomobject]@{ Purpose = 'PlanPreview'; ValidationOnly = $true; Computers = $null; PolicyProfile = $null })
        try {
            Test-ToolkitAssertion -Condition (Resolve-AdminAutomationRequest -Parameters $previewMap).Success -Name 'Private plan preview context validates without executable authorization'
            Test-ToolkitThrow -Action { Invoke-AdminAutomation -Parameters $previewMap -ResolvedOutputPath '-' -Confirm:$false | Out-Null } -Name 'Automation refuses any preview context before side effects or dispatch'
            Test-ToolkitThrow -Action { Invoke-AdminAutomationCore -Parameters $previewMap -ResolvedOutputPath '-' -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -Confirm:$false | Out-Null } -Name 'Core independently refuses preview context execution'
            Test-ToolkitThrow -Action { ConvertTo-AdminExecutionParameterMap -Parameters $previewMap -Preview $true | Out-Null } -Name 'Preview composer cannot erase a private validation context'
        }
        finally { [void]$Script:InternalPlanContexts.Remove($previewMap) }
        Test-ToolkitAssertion -Condition ((Resolve-AdminAutomationRequest -Parameters $previewMap).Category -ceq 'Authorization') -Name 'Private preview context is removed before immutable map reuse'
        Test-ToolkitAssertion -Condition ($Script:FiveRecordedDispatches -eq 0) -Name 'All context and changing-map controls performed zero target operations'
        $originalFiveRegistryRoot = (Get-Command Get-AdminCheckpointRegistryRoot).ScriptBlock
        $Script:FiveOwnedRegistryRoot = Join-Path $fiveRoot 'owned-plan-ledger'
        [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($Script:FiveOwnedRegistryRoot)
        Set-Item Function:\Get-AdminCheckpointRegistryRoot -Value { return $Script:FiveOwnedRegistryRoot }
        try {
            $commonPending = Join-Path $fiveRoot 'common-pending.watplan.json'
            $commonApproved = Join-Path $fiveRoot 'common-approved.watplan.json'
            $commonCheckpoint = Join-Path $fiveRoot 'common.watcheckpoint.json'
            $commonLog = Join-Path $fiveRoot 'common-plan.log'
            $commonCreate = Invoke-AdminPlanOperation -Parameters @{ PlanOperation = 'Create'; PlanPath = $commonPending; Action = 'SystemInfo'; Local = $true; WhatIf = $true; Verbose = $true } -ResolvedOutputPath '-'
            Test-ToolkitAssertion -Condition ($commonCreate.status -ceq 'Planned') -Name 'Public map Create accepts common metadata with an owned preview'
            $commonHash = [string]$commonCreate.planHash
            $commonApproveMap = @{ PlanOperation = 'Approve'; PlanPath = $commonPending; ApprovedPlanPath = $commonApproved; ApprovedBy = 'Synthetic Reviewer'; ApprovalReference = 'OWNED-COMMON'; PlanApprovalText = 'APPROVE PLAN ' + $commonHash; Verbose = $true; ErrorAction = 'Stop'; WarningAction = 'Continue' }
            $commonApproval = Invoke-AdminPlanOperation -Parameters $commonApproveMap -ResolvedOutputPath '-'
            Test-ToolkitAssertion -Condition ($commonApproval.status -ceq 'Approved') -Name 'Public map Approve accepts non-authorizing common parameters'
            $commonExecuteMap = @{ PlanOperation = 'Execute'; PlanPath = $commonApproved; CheckpointPath = $commonCheckpoint; PlanApprovalText = 'EXECUTE PLAN ' + $commonHash; Debug = $true; ErrorAction = 'Stop'; InformationAction = 'Continue'; LogFile = $commonLog }
            $commonExecution = Invoke-AdminPlanOperation -Parameters $commonExecuteMap -ResolvedOutputPath '-'
            Test-ToolkitAssertion -Condition ($commonExecution.exitCode -eq 0 -and $Script:FiveRecordedDispatches -eq 0) -Name 'Public map Execute accepts common parameters without dispatching the approved WhatIf request'
            $commonExecuteMap.PlanOperation = 'Resume'; $commonExecuteMap.PlanApprovalText = 'RESUME PLAN ' + $commonHash
            $commonResume = Invoke-AdminPlanOperation -Parameters $commonExecuteMap -ResolvedOutputPath '-'
            Test-ToolkitAssertion -Condition ($commonResume.exitCode -eq 0 -and $Script:FiveRecordedDispatches -eq 0) -Name 'Public map Resume accepts common parameters and preserves zero target operations'
            foreach ($safetyCommon in @('WhatIf', 'Confirm')) {
                $approveOverride = $commonApproveMap.Clone(); $approveOverride[$safetyCommon] = $false
                Test-ToolkitAssertion -Condition ((Invoke-AdminPlanOperation -Parameters $approveOverride -ResolvedOutputPath '-').outcome -ceq 'ValidationFailure') -Name "Approve still rejects explicit $safetyCommon outside its reviewed semantics"
                $executeOverride = $commonExecuteMap.Clone(); $executeOverride[$safetyCommon] = $false
                Test-ToolkitAssertion -Condition ((Invoke-AdminPlanOperation -Parameters $executeOverride -ResolvedOutputPath '-').outcome -ceq 'ValidationFailure') -Name "Resume still rejects explicit $safetyCommon outside its reviewed semantics"
            }
        }
        finally { Set-Item Function:\Get-AdminCheckpointRegistryRoot -Value $originalFiveRegistryRoot }

    }
    finally { Set-Item Function:\Invoke-AdminTargetDetailed -Value $recordedDispatcher; Close-AdminRunSink }

    Test-ToolkitAssertion -Condition (-not (Test-AdminJsonHasDuplicateProperty -JsonText (('[' * 64) + '0' + (']' * 64)))) -Name 'JSON nesting at the documented depth limit remains supported'
    if (-not ('WindowsFiveJsonMemorySampler' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Threading;
public sealed class WindowsFiveJsonMemorySampler : IDisposable {
    Thread thread; volatile bool running; public long Peak; public long Samples;
    public WindowsFiveJsonMemorySampler() { Peak=GC.GetTotalMemory(false); running=true; thread=new Thread(Run); thread.IsBackground=true; thread.Start(); }
    void Run() { while(running) { long value=GC.GetTotalMemory(false); if(value>Peak)Peak=value; Samples++; Thread.Sleep(1); } }
    public void Dispose() { running=false; thread.Join(); }
}
'@ -ErrorAction Stop
    }
    $allocationMethod = [GC].GetMethod('GetAllocatedBytesForCurrentThread')
    foreach ($badJson in @((('[' * 65) + '0' + (']' * 65)), ('[' * 1048576), (('{"x":' * 65) + '0' + ('}' * 65)), ('[' + (('[],' * 8192) + '[]]')), ('{' + ((1..8193 | ForEach-Object { '"k' + $_ + '":0' }) -join ',') + '}'), ('{' + ((1..8193 | ForEach-Object { '"\u006b' + $_ + '":0' }) -join ',') + '}'), ('[' + ('0,' * 32769) + '0]'))) {
        $beforeMemory = [GC]::GetTotalMemory($true)
        $allocationBefore = if ($allocationMethod) { [long]$allocationMethod.Invoke($null, @()) } else { $null }
        $memorySampler = [WindowsFiveJsonMemorySampler]::new()
        $timer = [Diagnostics.Stopwatch]::StartNew(); $budgetFailure = $false
        try { Test-AdminJsonHasDuplicateProperty -JsonText $badJson | Out-Null } catch { $budgetFailure = $_.Exception.Message -match 'budget' }
        finally { $timer.Stop(); $memorySampler.Dispose() }
        $uncollectedGrowth = [GC]::GetTotalMemory($false) - $beforeMemory
        $growth = [GC]::GetTotalMemory($true) - $beforeMemory
        $observedPeak = $memorySampler.Peak - $beforeMemory
        $allocatedBytes = if ($allocationMethod) { [long]$allocationMethod.Invoke($null, @()) - $allocationBefore } else { $null }
        Write-Host "JSON fixture metrics: retained=$growth uncollected=$uncollectedGrowth sampledPeak=$observedPeak samples=$($memorySampler.Samples) threadAllocated=$allocatedBytes seconds=$($timer.Elapsed.TotalSeconds)"
        Test-ToolkitAssertion -Condition $budgetFailure -Name 'JSON hostile depth/container/property/token input fails at a preallocation budget'
        Test-ToolkitAssertion -Condition ($growth -lt 67108864 -and $timer.Elapsed.TotalSeconds -lt 20) -Name 'JSON hostile pre-scan retains bounded memory and work'
        Test-ToolkitAssertion -Condition ($observedPeak -lt 67108864) -Name 'Observed one-millisecond sampled JSON managed-heap growth remains below 64 MiB'
        if ($allocationMethod) { Test-ToolkitAssertion -Condition ($allocatedBytes -lt 134217728) -Name 'JSON hostile fixture transient thread allocations remain below 128 MiB' }
    }
    Test-ToolkitAssertion -Condition (Test-AdminJsonHasDuplicateProperty -JsonText '{"scope":1,"SCOPE":2}') -Name 'Bounded JSON scanner retains case-insensitive duplicate detection'
    Test-ToolkitAssertion -Condition (Test-AdminJsonHasDuplicateProperty -JsonText '{"scope":1,"\u0073cope":2}') -Name 'Bounded JSON scanner retains escaped duplicate detection'
    foreach ($duplicateJson in @('{"a/b":1,"a\/b":2}', '{"a\\b":1,"\u0061\\b":2}', '{"a\"b":1,"\u0061\"b":2}', '{"\ud83d\ude00":1,"\uD83D\uDE00":2}', '{"":1,"":2}', '{"a\nb":1,"\u0061\nb":2}')) {
        Test-ToolkitAssertion -Condition (Test-AdminJsonHasDuplicateProperty -JsonText $duplicateJson) -Name 'Allocation-bounded key decoding preserves escaped slash, backslash, quote, Unicode, empty and control aliases'
    }
    Test-ToolkitAssertion -Condition (-not (Test-AdminJsonHasDuplicateProperty -JsonText '{"\\u0061":1,"a":2}')) -Name 'Literal backslash-u key is distinct from decoded Unicode key'
    foreach ($controlCode in @(0, 1, 7, 8, 9, 10, 11, 12, 13, 31)) {
        $rawControlKey = '{"a' + [char]$controlCode + 'b":1,"a' + [char]$controlCode + 'b":2}'
        $rawControlValue = '{"a":"b' + [char]$controlCode + 'c"}'
        Test-ToolkitThrow -Action { Test-AdminJsonHasDuplicateProperty -JsonText $rawControlKey | Out-Null } -Name 'Pre-scan rejects unescaped C0 duplicate keys before any general decoder'
        Test-ToolkitThrow -Action { Test-AdminJsonHasDuplicateProperty -JsonText $rawControlValue | Out-Null } -Name 'Pre-scan rejects unescaped C0 string values before any general decoder'
    }
    foreach ($invalidKey in @('a\q', '\U0061', '\u061', '\u00x1')) {
        Test-ToolkitThrow -Action { Test-AdminJsonHasDuplicateProperty -JsonText ('{"' + $invalidKey + '":1}') | Out-Null } -Name 'Invalid property escape decoding fails closed instead of silently skipping duplicate scan'
    }
    foreach ($validUnicode in @('{"\u006a":1,"\u006A":2}', '{"\ud800":1,"\uD800":2}', '{"\udc00":1,"\uDC00":2}')) {
        Test-ToolkitAssertion -Condition (Test-AdminJsonHasDuplicateProperty -JsonText $validUnicode) -Name 'Unicode hex case and surrogate code-unit aliases preserve baseline duplicate detection'
    }
    $rawControlPath = Join-Path $fiveRoot 'raw-control.json'
    [IO.File]::WriteAllText($rawControlPath, ('{"a' + [char]10 + 'b":1,"a' + [char]10 + 'b":2}'))
    Test-ToolkitThrow -Action { Read-AdminStrictOrchestrationJson -LiteralPath $rawControlPath -MaximumBytes 4194304 -ArtifactName 'Synthetic raw control' | Out-Null } -Name 'Actual bounded JSON file reader rejects raw-control duplicates before lenient general decoding'
    Test-ToolkitThrow -Action { Import-AdminPolicyProfile -LiteralPath $rawControlPath | Out-Null } -Name 'Actual policy import refuses raw-control keys before schema or authorization decisions'
    foreach ($reader in @('Policy', 'Plan', 'Checkpoint', 'Request')) {
        $deepPath = Join-Path $fiveRoot ($reader + '.json'); [IO.File]::WriteAllText($deepPath, '[' * 1048576)
        if ($reader -ceq 'Policy') { Test-ToolkitThrow -Action { Import-AdminPolicyProfile -LiteralPath $deepPath | Out-Null } -Name 'Policy import uses bounded duplicate pre-scan' }
        else { Test-ToolkitThrow -Action { Read-AdminStrictOrchestrationJson -LiteralPath $deepPath -MaximumBytes 4194304 -ArtifactName $reader | Out-Null } -Name "$reader reader uses bounded duplicate pre-scan" }
    }


    # Standard grammar is checked before the permissive general decoder. Quoted
    # apostrophes/slashes and every ordinary JSON value remain supported.
    foreach ($validJson in @('{}', '[]', 'null', 'true', 'false', '0', '-0', '1', '-123', '0.25', '-2.5E+3', '1e-9',
        '{"a":[null,true,false,0,-1,2.5,1e2,{"b":"ok"}]}', '{"apostrophe":"it''s fine","slash":"a/b","commentText":"/* text */ // text"}',
        '{"a\/b":1}', '{"key":"\"\\\/\b\f\n\r\t\u0061\ud83d\ude00"}', (' ' + [char]9 + [char]10 + '{"x":1}' + [char]13),
        '{"empty":"","nested":{},"array":[]}')) {
        Test-ToolkitAssertion -Condition (-not (Test-AdminJsonHasDuplicateProperty -JsonText $validJson)) -Name 'Compiled pre-scan preserves complete standard JSON values, quoted punctuation and nesting'
    }
    foreach ($invalidJson in @('', ' ', '{a:1}', "{'a':1}", "{'a':1,'a':2}", '{a:1,a:2}', '{/* comment */"a":1}', '{"a":1// comment' + [char]10 + '}',
        '/*comment*/{}', '{}//comment', '# comment', '{"a":}', '{"a" 1}', '{:1}', '{,"a":1}', '{"a":1,}', '[1,]', '[,1]', '[1 2]',
        '{"a":1 "b":2}', '{]', '[}', '{"a":[1}', 'true false', '{}[]', '{"a":1}x', '"unterminated', '{"a":"\q"}',
        '{"a":"\u061"}', '{"a":"\U0061"}', '{"a":"\u00x1"}', '{"a":undefined}', '{"a":NaN}', '{"a":Infinity}', '+1', '01', '-01', '.5', '1.', '1e', '1e+', '--1',
        'TRUE', 'Null', 'nul', 'falsex', '{"a":1; "b":2}', '{["a"]:1}', ('{' + [char]0 + '"a":1}'), ('{' + [char]0xA0 + '"a":1}'))) {
        Test-ToolkitThrow -Action { Test-AdminJsonHasDuplicateProperty -JsonText $invalidJson | Out-Null } -Name 'Lexical grammar rejects nonstandard keys/comments, malformed values/numbers/delimiters and trailing data'
    }
    foreach ($malformedReader in @("{'a':1,'a':2}", '{a:1,a:2}', '{/* comment */"a":1}', '{"a":1,}')) {
        $malformedPath = Join-Path $fiveRoot 'nonstandard.json'
        [IO.File]::WriteAllText($malformedPath, $malformedReader, [Text.UTF8Encoding]::new($false))
        Test-ToolkitThrow -Action { Read-AdminStrictOrchestrationJson -LiteralPath $malformedPath -MaximumBytes 4194304 -ArtifactName 'Synthetic nonstandard grammar' | Out-Null } -Name 'Actual bounded JSON reader refuses lenient-decoder key/comment forms before materialization'
        Test-ToolkitThrow -Action { Import-AdminPolicyProfile -LiteralPath $malformedPath | Out-Null } -Name 'Actual policy import refuses nonstandard grammar before schema decisions'
    }
    foreach ($maximumBytes in @(1048576, 4194304)) {
        foreach ($keyShape in @('SparseEscape', 'DenseEscape')) {
            if ($keyShape -ceq 'SparseEscape') { $largeEncodedKey = ('a' * ($maximumBytes - 32)) + '\u0061'; $decodedLength = $maximumBytes - 31 }
            else { $escapeCount = [int][Math]::Floor(($maximumBytes - 20) / 6); $largeEncodedKey = '\u0061' * $escapeCount; $decodedLength = $escapeCount }
            $largeKeyJson = '{"' + $largeEncodedKey + '":0}'
            $beforeMemory = [GC]::GetTotalMemory($true)
            $allocationBefore = if ($allocationMethod) { [long]$allocationMethod.Invoke($null, @()) } else { $null }
            $memorySampler = [WindowsFiveJsonMemorySampler]::new(); $timer = [Diagnostics.Stopwatch]::StartNew()
            try { $largeDuplicate = Test-AdminJsonHasDuplicateProperty -JsonText $largeKeyJson }
            finally { $timer.Stop(); $memorySampler.Dispose() }
            $observedPeak = $memorySampler.Peak - $beforeMemory
            $allocatedBytes = if ($allocationMethod) { [long]$allocationMethod.Invoke($null, @()) - $allocationBefore } else { $null }
            $growth = [GC]::GetTotalMemory($true) - $beforeMemory
            Write-Host "JSON near-limit $maximumBytes $keyShape metrics: retained=$growth sampledPeak=$observedPeak samples=$($memorySampler.Samples) threadAllocated=$allocatedBytes seconds=$($timer.Elapsed.TotalSeconds)"
            Test-ToolkitAssertion -Condition (-not $largeDuplicate -and $largeKeyJson.Length -le $maximumBytes) -Name 'Near-limit sparse/dense escaped key has valid grammar without silent truncation'
            Test-ToolkitAssertion -Condition ($growth -lt 67108864 -and $observedPeak -lt 67108864 -and $timer.Elapsed.TotalSeconds -lt 20) -Name 'Near-limit compiled key scanning meets retained/sampled-heap/time bounds'
            if ($allocationMethod) { Test-ToolkitAssertion -Condition ($allocatedBytes -lt 134217728) -Name 'Near-limit escaped key has bounded compiled transient allocations' }
            $largeKeyPath = Join-Path $fiveRoot ("large-key-$maximumBytes-$keyShape.json")
            [IO.File]::WriteAllText($largeKeyPath, $largeKeyJson, [Text.UTF8Encoding]::new($false))
            $timer.Restart()
            $largeObject = Read-AdminStrictOrchestrationJson -LiteralPath $largeKeyPath -MaximumBytes $maximumBytes -ArtifactName 'Synthetic near-limit escaped key'
            $timer.Stop(); $actualLargeKey = @($largeObject.PSObject.Properties.Name)
            Test-ToolkitAssertion -Condition ($actualLargeKey.Count -eq 1 -and $actualLargeKey[0].Length -eq $decodedLength -and $timer.Elapsed.TotalSeconds -lt 20) -Name 'Actual 1 MiB/4 MiB retained-file reader decodes near-limit sparse/dense keys correctly'
            if ($maximumBytes -eq 1048576) {
                Test-ToolkitThrow -Action { Import-AdminPolicyProfile -LiteralPath $largeKeyPath | Out-Null } -Name 'Actual policy reader promptly rejects a near-limit unknown field after bounded standard grammar'
            }
            $largeEncodedKey = $null; $largeKeyJson = $null; $largeObject = $null; $actualLargeKey = $null
        }
    }

    $key = Get-AdminSha256Hex -Text ('synthetic-squatting-' + [guid]::NewGuid().ToString('N'))
    $oldGlobal = New-Object Threading.Mutex($true, ('Global\WindowsAdminToolkit-Checkpoint-' + $key))
    $newLease = $null
    try { $newLease = [WindowsAdminToolkit.Security.CheckpointLease]::Open($key); Test-ToolkitAssertion -Condition ($null -ne $newLease) -Name 'Owned squatted legacy global mutex cannot block the protected private namespace' }
    finally { if ($newLease) { $newLease.Dispose() }; $oldGlobal.ReleaseMutex(); $oldGlobal.Dispose() }
    $ownerSid = [WindowsAdminToolkit.Security.StorageSecurity]::CurrentSid
    $otherSid = 'S-1-5-21-111111111-222222222-333333333-1009'
    foreach ($sddl in @("O:$otherSid`G:$ownerSid`D:P(A;;GA;;;$ownerSid)", "O:$ownerSid`G:$ownerSid`D:P(A;;GA;;;$ownerSid)(A;;0x00100001;;;$otherSid)", "O:$ownerSid`G:$ownerSid`D:(A;;GA;;;$ownerSid)")) {
        $raw = New-Object Security.AccessControl.RawSecurityDescriptor($sddl); $bytes = New-Object byte[] $raw.BinaryLength; $raw.GetBinaryForm($bytes, 0)
        Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.CheckpointLease]::ValidateMutexDescriptor($bytes, $ownerSid) } -Name 'Mutex descriptor rejects foreign owner, synchronization rights or inherited DACL'
    }

    # Compile the builder-owned literal helper, never the application payload.
    $releaseText = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/New-ReleaseArtifacts.ps1'))
    $nativeMarker = '$releaseNativeSource = @' + "'"; $nativeStart = $releaseText.IndexOf($nativeMarker) + $nativeMarker.Length
    $nativeEnd = $releaseText.IndexOf("`n'@", $nativeStart)
    if (-not ('WindowsAdminToolkit.ReleaseSecurity.StorageSecurity' -as [type])) { Add-Type -TypeDefinition $releaseText.Substring($nativeStart, $nativeEnd - $nativeStart) -ErrorAction Stop }
    $raw = New-Object Security.AccessControl.RawSecurityDescriptor("O:$ownerSid`G:$ownerSid`D:P(A;;FA;;;$ownerSid)(A;;0x4;;;$otherSid)")
    $bytes = New-Object byte[] $raw.BinaryLength; $raw.GetBinaryForm($bytes, 0)
    Test-ToolkitThrow -Action { [WindowsAdminToolkit.ReleaseSecurity.StorageSecurity]::ValidateDescriptor($bytes, $false, $true, $false) } -Name 'Release ordinary source/parent directory rejects add-subdirectory-only grant'
    $weakDirectory = Join-Path $fiveRoot 'weak-directory'; [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($weakDirectory)
    if (-not ('WindowsFiveDaclFixture' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WindowsFiveDaclFixture {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfo(string name, int type, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateBoundaryDescriptor(string name, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AddSIDToBoundaryDescriptor(ref IntPtr boundary, IntPtr sid);
    [DllImport("kernel32.dll")] static extern void DeleteBoundaryDescriptor(IntPtr boundary);
    [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreatePrivateNamespace(ref SecurityAttributes attributes, IntPtr boundary, string alias);
    [DllImport("kernel32.dll", SetLastError=true)] [return: MarshalAs(UnmanagedType.U1)] static extern bool ClosePrivateNamespace(IntPtr handle, uint flags);
    public static int ForeignBoundaryResult(string sid, string ownerSid) {
        IntPtr boundary=IntPtr.Zero,sidPointer=IntPtr.Zero,descriptor=IntPtr.Zero,handle=IntPtr.Zero;
        try {
            string unique="WatForeignBoundaryFixture"+Guid.NewGuid().ToString("N");
            boundary=CreateBoundaryDescriptor(unique,0);if(boundary==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            var identity=new System.Security.Principal.SecurityIdentifier(sid);byte[] bytes=new byte[identity.BinaryLength];identity.GetBinaryForm(bytes,0);sidPointer=Marshal.AllocHGlobal(bytes.Length);Marshal.Copy(bytes,0,sidPointer,bytes.Length);
            if(!AddSIDToBoundaryDescriptor(ref boundary,sidPointer))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            uint size;if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:"+ownerSid+"D:P(A;;GA;;;"+ownerSid+")",1,out descriptor,out size))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            SecurityAttributes attributes=new SecurityAttributes();attributes.Length=Marshal.SizeOf(typeof(SecurityAttributes));attributes.Descriptor=descriptor;
            handle=CreatePrivateNamespace(ref attributes,boundary,unique);return handle==IntPtr.Zero?Marshal.GetLastWin32Error():0;
        }finally{if(handle!=IntPtr.Zero)ClosePrivateNamespace(handle,1);if(descriptor!=IntPtr.Zero)LocalFree(descriptor);if(sidPointer!=IntPtr.Zero)Marshal.FreeHGlobal(sidPointer);if(boundary!=IntPtr.Zero)DeleteBoundaryDescriptor(boundary);}
    }
    public static void SetDacl(string path, string fixtureRoot, string text) {
        string root=System.IO.Path.GetFullPath(fixtureRoot).TrimEnd('\\')+"\\";
        if(!System.IO.Path.GetFullPath(path).StartsWith(root,StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Only owned fixture descendants can receive a synthetic DACL.");
        IntPtr descriptor; uint size;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(text,1,out descriptor,out size)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try {bool present,defaulted;IntPtr dacl;if(!GetSecurityDescriptorDacl(descriptor,out present,out dacl,out defaulted)||!present||dacl==IntPtr.Zero)throw new InvalidOperationException("Missing fixture DACL.");uint error=SetNamedSecurityInfo(path,1,0x80000004u,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero);if(error!=0)throw new System.ComponentModel.Win32Exception((int)error);}
        finally{LocalFree(descriptor);}
    }
}
'@ -ErrorAction Stop
    }
    [WindowsFiveDaclFixture]::SetDacl($weakDirectory, $fiveRoot, "D:P(A;OICI;FA;;;$ownerSid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x4;;;$otherSid)")
    Test-ToolkitAssertion -Condition ([WindowsFiveDaclFixture]::ForeignBoundaryResult($otherSid, $ownerSid) -eq 5) -Name 'Native namespace creation cannot squat a boundary whose synthetic SID is absent from the caller token'
    Test-ToolkitThrow -Action { [WindowsAdminToolkit.ReleaseSecurity.PathLease]::OpenTrusted($weakDirectory, $true, $false, $false) | Out-Null } -Name 'Actual owned source directory with synthetic other-SID add-subdirectory grant is refused'
    $parent = Join-Path $fiveRoot 'native-parent'; [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($parent)
    $parentLease = [WindowsAdminToolkit.ReleaseSecurity.PathLease]::OpenTrusted($parent, $true, $false, $true)
    $childLease = $null
    try {
        $childLease = $parentLease.CreatePrivateChildDirectory('child')
        Test-ToolkitAssertion -Condition ($childLease.IsDirectory -and $childLease.Path -ceq (Join-Path $parent 'child')) -Name 'Release child directory is atomically created under the retained parent'
        Test-ToolkitThrow -Action { $parentLease.CreatePrivateChildDirectory('child') | Out-Null } -Name 'Relative native release creation preserves an existing directory collision'
        Test-ToolkitThrow -Action { $parentLease.CreatePrivateChildDirectory('..\outside') | Out-Null } -Name 'Relative native release creation refuses multi-component names'
        Test-ToolkitThrow -Action { $parentLease.CreatePrivateChildDirectory('NUL') | Out-Null } -Name 'Relative native release creation refuses DOS device names'
        Test-ToolkitThrow -Action { $parentLease.CreatePrivateChildDirectory('trailing.') | Out-Null } -Name 'Relative native release creation refuses noncanonical trailing dots'
        Test-ToolkitThrow -Action { [IO.Directory]::Move($parent, (Join-Path $fiveRoot 'moved-parent')) } -Name 'Release native parent and child handles prevent a directory swap'
    }
    finally { if ($childLease) { $childLease.Dispose() }; $parentLease.Dispose() }
    [IO.Directory]::Move($parent, (Join-Path $fiveRoot 'moved-parent'))
    Test-ToolkitAssertion -Condition ([IO.Directory]::Exists((Join-Path $fiveRoot 'moved-parent/child'))) -Name 'Released native directory handles permit the positive rename control'

    # Extract the literal builder function to exercise its actual bounded walk.
    $releaseTokens = $null; $releaseErrors = $null
    $releaseAst = [Management.Automation.Language.Parser]::ParseInput($releaseText, [ref]$releaseTokens, [ref]$releaseErrors)
    $walkFunction = $releaseAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-ReleaseDirectoryFile' }, $true)
    . ([scriptblock]::Create($walkFunction.Extent.Text))
    $walkWide = Join-Path $fiveRoot 'wide-source'; [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($walkWide)
    foreach ($fileIndex in 1..4097) { [IO.File]::WriteAllBytes((Join-Path $walkWide ('item' + $fileIndex)), [byte[]]@()) }
    $releaseLeases = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    try {
        $walkRefused = $false
        try { Get-ReleaseDirectoryFile -LiteralPath $walkWide | Out-Null } catch { $walkRefused = $_.Exception.Message -match '4096-item traversal budget' }
        Test-ToolkitAssertion -Condition $walkRefused -Name 'Actual incremental release walk rejects a 4097-item owned directory'
    }
    finally { foreach ($walkLease in $releaseLeases) { $walkLease.Dispose() } }
    $walkDeep = Join-Path $fiveRoot 'deep-source'; [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($walkDeep)
    $cursor = $walkDeep
    foreach ($depth in 1..33) { $cursor = Join-Path $cursor 'd'; [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($cursor) }
    $releaseLeases = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    try {
        $walkRefused = $false
        try { Get-ReleaseDirectoryFile -LiteralPath $walkDeep | Out-Null } catch { $walkRefused = $_.Exception.Message -match '32-level traversal budget' }
        Test-ToolkitAssertion -Condition $walkRefused -Name 'Actual release walk rejects a 33-level owned source tree'
    }
    finally { foreach ($walkLease in $releaseLeases) { $walkLease.Dispose() } }
}
finally { if ([IO.Directory]::Exists($fiveRoot)) { [IO.Directory]::Delete($fiveRoot, $true) } }
if ($fiveStandalone) { if ($Script:Failures.Count -ne 0) { throw ($Script:Failures -join '; ') }; Write-Host "All $Script:TestCount focused five-finding controls passed." }
