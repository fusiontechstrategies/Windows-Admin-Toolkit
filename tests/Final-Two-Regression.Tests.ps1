# Real native filesystem operations use only new private offline fixtures.
$ErrorActionPreference = 'Stop'
$twoStandalone = -not (Get-Command Test-ToolkitAssertion -ErrorAction SilentlyContinue)
if ($twoStandalone) {
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
$twoProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
$twoRoot = Join-Path $twoProfile ('wat-two-fixture-' + [guid]::NewGuid().ToString('N'))
[WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($twoRoot)
$twoAliases = New-Object 'System.Collections.Generic.List[string]'
try {
    $inside = Join-Path $twoRoot 'inside'
    $outside = Join-Path $twoRoot 'outside'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($inside)
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($outside)
    $tempName = '.admin-export-' + [guid]::NewGuid().ToString('N') + '.tmp'
    $publication = New-Object WindowsAdminToolkit.Security.NativePublication($inside, $tempName)
    try {
        $originalFile = $publication.FileIdentity
        $originalParent = $publication.ParentIdentity
        $publication.Write([Text.Encoding]::UTF8.GetBytes('synthetic native bytes'))
        Test-ToolkitThrow -Action { [IO.Directory]::Move($inside, (Join-Path $twoRoot 'moved')) } -Name 'Actual retained publication parent denies rename before publish'
        Test-ToolkitThrow -Action { New-Item -ItemType Junction -Path $inside -Target $outside -ErrorAction Stop | Out-Null } -Name 'Actual retained publication parent denies junction replacement'
        $publication.Publish('race.json')
        Test-ToolkitAssertion -Condition ($publication.FileIdentity -ceq $originalFile -and $publication.ParentIdentity -ceq $originalParent -and $publication.RenameStatus -ceq '00000000') -Name 'Native relative rename retains original file and parent IDs'
        Test-ToolkitThrow -Action { $publication.Publish('again.json') } -Name 'Published native capability refuses a second publication'
    }
    finally { $publication.Dispose() }
    Test-ToolkitAssertion -Condition ([IO.File]::ReadAllText((Join-Path $inside 'race.json')) -ceq 'synthetic native bytes') -Name 'Race attempt leaves exact bytes in original parent'
    Test-ToolkitAssertion -Condition (@([IO.Directory]::EnumerateFileSystemEntries($outside)).Count -eq 0) -Name 'Race attempt produces no outside file'
    $finalLease = [WindowsAdminToolkit.Security.PathLease]::OpenTrusted((Join-Path $inside 'race.json'), $false, $false, $true)
    try { Test-ToolkitAssertion -Condition ($finalLease.Identity -ceq $originalFile) -Name 'Independently opened published object has the original file ID and private DACL' }
    finally { $finalLease.Dispose() }

    $afterRelease = Join-Path $twoRoot 'after-release'
    [IO.Directory]::Move($inside, $afterRelease)
    Test-ToolkitAssertion -Condition ([IO.Directory]::Exists($afterRelease) -and -not [IO.Directory]::Exists($inside)) -Name 'Positive control can rename parent after native handles release'
    [IO.Directory]::Move($afterRelease, $inside)

    $collision = New-Object WindowsAdminToolkit.Security.NativePublication($inside, '.admin-export-collision.tmp')
    try {
        $collision.Write([Text.Encoding]::UTF8.GetBytes('must not replace'))
        Test-ToolkitThrow -Action { $collision.Publish('race.json') } -Name 'Native no-replace rename rejects an existing final file'
    }
    finally { $collision.Dispose() }
    Test-ToolkitAssertion -Condition ($collision.CleanupStatus -ceq '00000000' -and -not [IO.File]::Exists((Join-Path $inside '.admin-export-collision.tmp'))) -Name 'Final collision removes only the unpublished temp by object handle'
    Test-ToolkitAssertion -Condition ([IO.File]::ReadAllText((Join-Path $inside 'race.json')) -ceq 'synthetic native bytes') -Name 'Collision leaves existing final bytes unchanged'
    $occupiedTemp = Join-Path $inside '.admin-export-occupied.tmp'
    [IO.File]::WriteAllText($occupiedTemp, 'preexisting synthetic marker')
    Test-ToolkitThrow -Action { $unexpected = New-Object WindowsAdminToolkit.Security.NativePublication($inside, '.admin-export-occupied.tmp'); $unexpected.Dispose() } -Name 'Relative temporary creation rejects an occupied leaf'
    Test-ToolkitAssertion -Condition ([IO.File]::ReadAllText($occupiedTemp) -ceq 'preexisting synthetic marker') -Name 'Failed create does not clean up or overwrite a preexisting leaf'
    $aborted = New-Object WindowsAdminToolkit.Security.NativePublication($inside, '.admin-export-aborted.tmp')
    $aborted.Write([Text.Encoding]::UTF8.GetBytes('injected failure before publication'))
    $aborted.Dispose()
    Test-ToolkitAssertion -Condition ($aborted.CleanupStatus -ceq '00000000' -and -not [IO.File]::Exists((Join-Path $inside '.admin-export-aborted.tmp'))) -Name 'Prepublication failure deletes only its retained temp handle'
    foreach ($invalidLeaf in @('../escape.json', 'sub\escape.json', 'x:stream', 'CON.json', '..', 'trail.', 'trail ', 'bad?.json', 'bad*.json')) {
        $invalid = New-Object WindowsAdminToolkit.Security.NativePublication($inside, ('.admin-export-' + [guid]::NewGuid().ToString('N') + '.tmp'))
        try { Test-ToolkitThrow -Action { $invalid.Publish($invalidLeaf) } -Name "Native publication rejects strict leaf $invalidLeaf" }
        finally { $invalid.Dispose() }
        Test-ToolkitAssertion -Condition (-not [IO.File]::Exists((Join-Path $inside $invalid.TemporaryName))) -Name 'Invalid publish leaf still removes its own retained temp'
    }
    foreach ($emitBom in @($true, $false)) {
        $path = Join-Path $inside ('utf8-' + $emitBom + '.txt')
        [void](Write-AdminUtf8File -LiteralPath $path -Content ('hello ' + [char]0x03bb) -EmitBom $emitBom)
        $bytes = [IO.File]::ReadAllBytes($path)
        $expected = New-Object Text.UTF8Encoding($emitBom)
        $expectedBytes = @($expected.GetPreamble()) + @($expected.GetBytes('hello ' + [char]0x03bb))
        Test-ToolkitAssertion -Condition ([Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String([byte[]]$expectedBytes)) -Name "Shared output writer retains exact UTF8 and BOM=$emitBom"
    }
    $missing = Join-Path $twoRoot 'missing\output.json'
    Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath $missing -Content 'must not create parent' | Out-Null } -Name 'Generic output writer refuses a missing parent'
    Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath $missing | Out-Null } -Name 'Automation preflight refuses a missing parent'
    Test-ToolkitAssertion -Condition (-not [IO.Directory]::Exists((Join-Path $twoRoot 'missing'))) -Name 'Missing-parent rejection creates no directory side effect'
    $probe = Join-Path $inside 'preflight.json'
    [void](Resolve-AdminAutomationOutputPath -LiteralPath $probe)
    Test-ToolkitAssertion -Condition (-not [IO.File]::Exists($probe) -and @(Get-ChildItem -LiteralPath $inside -Filter '.admin-json-probe-*.tmp').Count -eq 0) -Name 'Native preflight disposes its probe by handle without publishing'

    $inheritedParent = Join-Path $twoRoot 'inherited-safe-parent'
    [void][IO.Directory]::CreateDirectory($inheritedParent)
    [void](Write-AdminUtf8File -LiteralPath (Join-Path $inheritedParent 'positive.json') -Content 'safe inherited parent' -EmitBom $false)
    Test-ToolkitAssertion -Condition ([IO.File]::ReadAllText((Join-Path $inheritedParent 'positive.json')) -ceq 'safe inherited parent') -Name 'Trusted inherited parent remains supported without ACL repairs'
    $unsafeParent = Join-Path $twoRoot 'unsafe-parent'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($unsafeParent)
    $fixtureAclTool = Join-Path ([WindowsAdminToolkit.Security.SystemPaths]::SystemDirectory()) 'icacls.exe'
    & $fixtureAclTool $unsafeParent '/grant' '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not establish the isolated mutable-DACL attack fixture.' }
    Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath (Join-Path $unsafeParent 'denied.json') -Content 'no unsafe write' | Out-Null } -Name 'Actual other-principal mutable output DACL is rejected before creation'
    Test-ToolkitAssertion -Condition (@([IO.Directory]::EnumerateFileSystemEntries($unsafeParent)).Count -eq 0) -Name 'Unsafe parent rejection creates no temporary or final file'

    # Only terminal publication parents reject creation grants. Ancestor policy remains separate.
    $currentSid = [WindowsAdminToolkit.Security.StorageSecurity]::CurrentSid
    foreach ($mask in @(2, 4)) {
        $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor("O:$($currentSid)G:$($currentSid)D:P(A;;FA;;;$currentSid)(A;;0x$($mask.ToString('x'));;;BU)")
        $descriptorBytes = New-Object byte[] $descriptor.BinaryLength
        $descriptor.GetBinaryForm($descriptorBytes, 0)
        [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($descriptorBytes, $false, $true, $true, $false)
        Test-ToolkitAssertion -Condition $true -Name "Ancestor volume-root relaxation still permits isolated creation mask $mask"
        Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($descriptorBytes, $false, $true, $true, $false, $true) } -Name "Terminal publication parent rejects creation mask $mask even at a volume root"
        if ($mask -eq 4) {
            [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($descriptorBytes, $false, $true, $false, $false)
            Test-ToolkitAssertion -Condition $true -Name 'Generic ancestor permits isolated add-subdirectory without changing publication policy'
            Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.StorageSecurity]::ValidateDescriptor($descriptorBytes, $false, $true, $false, $false, $true) } -Name 'Terminal publication parent rejects isolated add-subdirectory on a normal directory'
        }
    }
    $narrowParent = Join-Path $twoRoot 'narrow-add-subdirectory-parent'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($narrowParent)
    & $fixtureAclTool $narrowParent '/grant' '*S-1-5-32-545:(AD)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not establish isolated add-subdirectory fixture.' }
    $narrowAncestor = [WindowsAdminToolkit.Security.PathLease]::OpenTrusted($narrowParent, $true, $false, $false)
    try { $narrowAncestor.ValidateHeld() } finally { $narrowAncestor.Dispose() }
    Test-ToolkitAssertion -Condition $true -Name 'Actual narrow directory grant is accepted by ancestor-only policy as a control'
    Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath (Join-Path $narrowParent 'denied.json') -Content 'no planted final name' | Out-Null } -Name 'Actual narrow add-subdirectory publication parent is refused before creation'
    Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath (Join-Path $narrowParent 'denied.json') | Out-Null } -Name 'JSON preflight rejects actual narrow add-subdirectory publication grant'
    Test-ToolkitAssertion -Condition (@([IO.Directory]::EnumerateFileSystemEntries($narrowParent)).Count -eq 0) -Name 'Narrow DACL refusal leaves no temp or final object'

    [void][WindowsAdminToolkit.Security.SystemPaths]::RequireLocalPublicationPath($inside)
    Test-ToolkitAssertion -Condition $true -Name 'Actual direct local fixture mapping is supported'
    [WindowsAdminToolkit.Security.SystemPaths]::ValidatePublicationDeviceTarget('\Device\HarddiskVolume1')
    Test-ToolkitAssertion -Condition $true -Name 'Pure local volume mapping positive control is accepted'
    foreach ($mapping in @('\Device\Mup\synthetic.invalid\share', '\Device\LanmanRedirector\synthetic', '\??\C:\alias', '\Device\UnknownVolume', ('\Device\Mup' + [char]0 + '\Device\HarddiskVolume1'))) {
        Test-ToolkitThrow -Action { [WindowsAdminToolkit.Security.SystemPaths]::ValidatePublicationDeviceTarget($mapping) } -Name 'Pure unsupported mapping is refused without device or network access'
    }
    $Script:TwoProviderLookups = 0
    function global:Test-Path { param([string]$LiteralPath, $PathType) $Script:TwoProviderLookups++; throw "Unexpected provider lookup: $LiteralPath ($PathType)" }
    try {
        $uncJson = '\\synthetic.invalid\share\result.json'
        $uncPlan = '\\synthetic.invalid\share\result.watplan.json'
        Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath $uncJson -Content 'no UNC lookup' | Out-Null } -Name 'Shared writer refuses unsupported UNC before provider lookup'
        Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath $uncJson | Out-Null } -Name 'JSON preflight refuses unsupported UNC before provider lookup'
        Test-ToolkitThrow -Action { Resolve-AdminOrchestrationArtifactPath -LiteralPath $uncPlan -ArtifactType Plan | Out-Null } -Name 'Plan output preflight refuses unsupported UNC before provider lookup'
        Test-ToolkitThrow -Action { Resolve-AdminOrchestrationArtifactPath -LiteralPath $uncPlan -ArtifactType Plan -Existing | Out-Null } -Name 'Plan input preflight refuses unsupported UNC before provider lookup'
        Test-ToolkitAssertion -Condition ($Script:TwoProviderLookups -eq 0) -Name 'Unsupported UNC controls perform zero filesystem-provider lookups'
    }
    finally { Remove-Item Function:\Test-Path -ErrorAction SilentlyContinue; Remove-Variable TwoProviderLookups -Scope Script -ErrorAction SilentlyContinue }

    # Create only a local reparse object. Its deliberately unreachable target is never opened.
    if (-not ('WindowsPublicationFixtureLink' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Runtime.InteropServices;
public static class WindowsPublicationFixtureLink {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.I1)]
    public static extern bool CreateSymbolicLink(string link, string target, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool RemoveDirectory(string path);
}
"@
    }
    $remoteLink = Join-Path $twoRoot 'remote-target-symlink'
    $madeRemoteLink = [WindowsPublicationFixtureLink]::CreateSymbolicLink($remoteLink, '\\synthetic.invalid\not-an-endpoint', 3)
    if (-not $madeRemoteLink) { throw "Could not create isolated no-endpoint symbolic link fixture: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    try {
        Test-ToolkitAssertion -Condition $madeRemoteLink -Name 'Actual local directory symlink stores a UNC target without opening it'
        $Script:TwoProviderLookups = 0
        function global:Test-Path { param([string]$LiteralPath, $PathType) $Script:TwoProviderLookups++; throw "Unexpected remote fixture provider lookup: $LiteralPath ($PathType)" }
        function global:Get-Item { param([string]$LiteralPath, [switch]$Force) $Script:TwoProviderLookups++; throw "Unexpected remote fixture provider lookup: $LiteralPath ($Force)" }
        try {
            $remoteJson = Join-Path $remoteLink 'result.json'
            $remotePlan = Join-Path $remoteLink 'result.watplan.json'
            Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath $remoteJson -Content 'no endpoint' | Out-Null } -Name 'Shared writer rejects actual remote-capable local reparse ancestry'
            Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath $remoteJson | Out-Null } -Name 'JSON preflight rejects actual remote-capable ancestry before provider lookup'
            Test-ToolkitThrow -Action { Resolve-AdminOrchestrationArtifactPath -LiteralPath $remotePlan -ArtifactType Plan | Out-Null } -Name 'Plan output preflight rejects actual remote-capable ancestry before provider lookup'
            Test-ToolkitThrow -Action { Resolve-AdminOrchestrationArtifactPath -LiteralPath $remotePlan -ArtifactType Plan -Existing | Out-Null } -Name 'Plan input preflight rejects actual remote-capable ancestry before provider lookup'
            Test-ToolkitThrow -Action { Import-AdminPolicyProfile -LiteralPath $remoteJson | Out-Null } -Name 'Direct PolicyPath rejects remote-capable local ancestry before provider lookup'
            Test-ToolkitThrow -Action { Import-AdminComputerList -LiteralPath (Join-Path $remoteLink 'computers.txt') | Out-Null } -Name 'Computer-list import rejects remote-capable ancestry before provider lookup'
            Test-ToolkitThrow -Action { Get-AdminFileSha256Hex -LiteralPath $remoteJson | Out-Null } -Name 'File hashing rejects remote-capable ancestry before opening data'
            Test-ToolkitThrow -Action { Resolve-AdminPsExec -Path (Join-Path $remoteLink 'PsExec64.exe') | Out-Null } -Name 'Direct PsExec literal resolution rejects remote-capable ancestry'
            Test-ToolkitThrow -Action { Get-AdminAuthenticodeSignatureInfo -LiteralPath (Join-Path $remoteLink 'signature.exe') | Out-Null } -Name 'Direct signature inspection acquires no-follow input before Authenticode'
            Test-ToolkitThrow -Action { Invoke-AdminCapturedProcess -LiteralPath (Join-Path $remoteLink 'must-not-start.exe') -ArgumentText '-NoLogo' -TimeoutSeconds 1 -MaximumBytes 1024 | Out-Null } -Name 'Direct capture helper refuses remote-capable executable ancestry before dispatch'
            Test-ToolkitThrow -Action { Initialize-AdminLog -RequestedPath (Join-Path $remoteLink 'output.log') | Out-Null } -Name 'Supplied log path rejects remote-capable ancestry before stat'
            Test-ToolkitThrow -Action { Resolve-AdminAuditPath -LiteralPath (Join-Path $remoteLink 'audit.jsonl') | Out-Null } -Name 'Audit output preflight rejects remote-capable ancestry before stat'
            Test-ToolkitThrow -Action { Open-AdminMutableFile -LiteralPath (Join-Path $remoteLink 'nested\output.log') -Create | Out-Null } -Name 'Mutable parent discovery rejects remote-capable ancestry without provider traversal'
            $Script:TwoScriptAnswers = New-Object 'System.Collections.Generic.Queue[string]'
            $Script:TwoScriptAnswers.Enqueue('F'); $Script:TwoScriptAnswers.Enqueue((Join-Path $remoteLink 'custom.ps1'))
            function global:Read-Host { param([string]$Prompt) if ($Script:TwoScriptAnswers.Count -eq 0) { throw "Unexpected script prompt: $Prompt" }; return $Script:TwoScriptAnswers.Dequeue() }
            try { Test-ToolkitThrow -Action { Get-AdminActionRequest -Choice 20 | Out-Null } -Name 'Interactive local script loading rejects remote-capable ancestry before stat/read' }
            finally { Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue; Remove-Variable TwoScriptAnswers -Scope Script -ErrorAction SilentlyContinue }
            Test-ToolkitAssertion -Condition ($Script:TwoProviderLookups -eq 0) -Name 'Actual remote-capable local reparse controls perform zero provider lookups'
        }
        finally { Remove-Item Function:\Test-Path, Function:\Get-Item -ErrorAction SilentlyContinue; Remove-Variable TwoProviderLookups -Scope Script -ErrorAction SilentlyContinue }
    }
    finally { if (-not [WindowsPublicationFixtureLink]::RemoveDirectory($remoteLink)) { throw 'Could not remove owned symbolic-link object.' } }
    # Capture legitimate references first; only then replace their ancestry with a remote link.
    $referenceRoot = Join-Path $twoRoot 'reference-root'
    $referenceMoved = Join-Path $twoRoot 'reference-root-original'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($referenceRoot)
    $referencePolicy = Join-Path $referenceRoot 'policy.json'
    $policyExample = Join-Path (Split-Path -Parent $PSScriptRoot) 'examples\policies\read-only-local.json'
    [void](Write-AdminUtf8File -LiteralPath $referencePolicy -Content ([IO.File]::ReadAllText($policyExample)) -EmitBom $false)
    $policyPendingPath = Join-Path $inside 'policy-reference-pending.watplan.json'
    [void](Invoke-AdminPlanCreate -Parameters @{ PlanPath = $policyPendingPath; Action = 'SystemInfo'; Local = $true; PolicyPath = $referencePolicy } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-')
    $policyPending = Import-AdminOrchestrationPlan -LiteralPath $policyPendingPath
    Test-ToolkitAssertion -Condition ($policyPending.request.policy.applied -and $policyPending.request.policy.path -ceq $referencePolicy) -Name 'Valid pending plan captures actual bounded policy bytes before the ancestry attack'
    $fakePsExecPath = Join-Path $referenceRoot 'PsExec64.exe'
    [void](Write-AdminUtf8File -LiteralPath $fakePsExecPath -Content 'synthetic non-executable reference, never launched' -EmitBom $false)
    $savedResolver = (Get-Item Function:\Resolve-AdminPsExec).ScriptBlock
    $savedReferenceState = [ordered]@{}
    foreach ($key in $Script:State.Keys) { $savedReferenceState[$key] = $Script:State[$key] }
    try {
        Set-Item Function:\Resolve-AdminPsExec -Value { param([string]$Path) return [IO.Path]::GetFullPath($Path) }
        $Script:State.Transport = 'PsExec'; $Script:State.PsExecPath = $fakePsExecPath; $Script:State.PsExecFullPath = $fakePsExecPath
        $psExecPendingPath = Join-Path $inside 'psexec-reference-pending.watplan.json'
        $psExecCreated = Invoke-AdminPlanCreate -Parameters @{ PlanPath = $psExecPendingPath; Action = 'SystemInfo'; ComputerName = @('synthetic-psexec-host'); Transport = 'PsExec'; PsExecPath = $fakePsExecPath } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
        if ($psExecCreated.exitCode -ne 0) { throw ('Synthetic PsExec plan creation failed: ' + ($psExecCreated | ConvertTo-Json -Depth 10 -Compress)) }
        $psExecPending = Import-AdminOrchestrationPlan -LiteralPath $psExecPendingPath
        Test-ToolkitAssertion -Condition ($psExecPending.request.transport.name -ceq 'PsExec' -and $psExecPending.request.transport.psExecPath -ceq $fakePsExecPath) -Name 'Valid pending PsExec plan captures synthetic reference bytes without executing or signing them'
    }
    finally { Set-Item Function:\Resolve-AdminPsExec -Value $savedResolver; $Script:State = $savedReferenceState }
    [IO.Directory]::Move($referenceRoot, $referenceMoved)
    if (-not [WindowsPublicationFixtureLink]::CreateSymbolicLink($referenceRoot, '\\synthetic.invalid\not-an-endpoint', 3)) { throw 'Could not establish embedded-reference ancestry attack.' }
    try {
        $Script:TwoProviderLookups = 0
        function global:Test-Path { param([string]$LiteralPath, $PathType) $Script:TwoProviderLookups++; throw "Unexpected embedded reference lookup: $LiteralPath ($PathType)" }
        function global:Get-Item { param([string]$LiteralPath, [switch]$Force) $Script:TwoProviderLookups++; throw "Unexpected embedded reference lookup: $LiteralPath ($Force)" }
        try {
            foreach ($referenceCase in @(@($policyPendingPath, $policyPending, 'policy-reference-approved.watplan.json'), @($psExecPendingPath, $psExecPending, 'psexec-reference-approved.watplan.json'))) {
                $referenceApprovedPath = Join-Path $inside $referenceCase[2]
                $referenceParameters = @{ PlanPath = $referenceCase[0]; ApprovedPlanPath = $referenceApprovedPath; ApprovedBy = 'Synthetic Reviewer'; ApprovalReference = 'OFFLINE-REFERENCE'; PlanApprovalText = ('APPROVE PLAN ' + $referenceCase[1].planHash.value) }
                Test-ToolkitThrow -Action { Invoke-AdminPlanApprove -Parameters $referenceParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'Actual Plan Approve rejects a remote-target ancestry swap in an embedded policy/PsExec reference'
                Test-ToolkitAssertion -Condition (-not [IO.File]::Exists($referenceApprovedPath)) -Name 'Reference ancestry refusal publishes no approved plan'
            }
            Test-ToolkitAssertion -Condition ($Script:TwoProviderLookups -eq 0) -Name 'Embedded-reference approval controls perform zero provider lookups'
        }
        finally { Remove-Item Function:\Test-Path, Function:\Get-Item -ErrorAction SilentlyContinue; Remove-Variable TwoProviderLookups -Scope Script -ErrorAction SilentlyContinue }
    }
    finally { if (-not [WindowsPublicationFixtureLink]::RemoveDirectory($referenceRoot)) { throw 'Could not remove owned embedded-reference symbolic link.' } }

    # Exercise actual unsigned release construction from an isolated complete source copy.
    $releaseSource = Join-Path $twoRoot 'release-source'
    [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($releaseSource)
    foreach ($sourceEntry in @(Get-ChildItem -LiteralPath (Split-Path -Parent $PSScriptRoot) -Force | Where-Object { $_.Name -ne '.git' })) {
        Copy-Item -LiteralPath $sourceEntry.FullName -Destination $releaseSource -Recurse -Force
    }
    $releaseTool = Join-Path $releaseSource 'tools\New-ReleaseArtifacts.ps1'
    $releasePositive = Join-Path $twoRoot 'unsigned-release'
    $releaseResult = & $releaseTool -OutputDirectory $releasePositive
    Test-ToolkitAssertion -Condition ($releaseResult.ToolkitVersion -ceq $Script:ToolkitVersion -and [IO.File]::Exists((Join-Path $releasePositive 'SHA256SUMS.txt'))) -Name 'Actual unsigned release construction still verifies a complete retained source payload'
    $releaseRemoteParent = Join-Path $twoRoot 'release-remote-parent'
    if (-not [WindowsPublicationFixtureLink]::CreateSymbolicLink($releaseRemoteParent, '\\synthetic.invalid\not-an-endpoint', 3)) { throw 'Could not establish isolated release-output ancestry control.' }
    try {
        $releaseRefused = $false
        try { & $releaseTool -OutputDirectory (Join-Path $releaseRemoteParent 'must-not-create') | Out-Null }
        catch { $releaseRefused = $_.Exception.ToString() -match 'Reparse points are forbidden' }
        Test-ToolkitAssertion -Condition $releaseRefused -Name 'Actual release builder rejects remote-target output ancestry through the native guard'
    }
    finally { if (-not [WindowsPublicationFixtureLink]::RemoveDirectory($releaseRemoteParent)) { throw 'Could not remove owned release-output symbolic link.' } }

    # Swap two valid policies with identical metadata after actual request evaluation.
    $swapPolicyPath = Join-Path $inside 'swap-policy.json'
    $policyA = '{"schemaVersion":"1.0","profileName":"Swap policy","actions":{"allow":["SystemInfo"]},"transports":{"allow":["Local"]},"targetModes":{"allow":["Local"]},"targets":{"allow":[]}}'
    $policyB = $policyA.Replace('"SystemInfo"', '"DiskSpace"')
    [IO.File]::WriteAllText($swapPolicyPath, $policyA)
    $policyAHash = Get-AdminFileSha256Hex -LiteralPath $swapPolicyPath
    $Script:TwoOriginalRequestResolver = (Get-Item Function:\Resolve-AdminAutomationRequest).ScriptBlock
    $Script:TwoSwapPolicyPath = $swapPolicyPath
    $Script:TwoSwapPolicyB = $policyB
    function Resolve-AdminAutomationRequest {
        param([System.Collections.IDictionary]$Parameters)
        $result = & $Script:TwoOriginalRequestResolver -Parameters $Parameters
        if ($result.Success) { [IO.File]::WriteAllText($Script:TwoSwapPolicyPath, $Script:TwoSwapPolicyB) }
        return $result
    }
    $swapPending = Join-Path $inside 'swap-pending.watplan.json'
    try {
        $swapCreated = Invoke-AdminPlanCreate -Parameters @{ PlanPath = $swapPending; Action = 'SystemInfo'; Local = $true; PolicyPath = $swapPolicyPath } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
        if ($swapCreated.exitCode -ne 0) { throw ('Policy-swap Create fixture failed: ' + ($swapCreated | ConvertTo-Json -Depth 12 -Compress)) }
        Test-ToolkitAssertion -Condition ($swapCreated.exitCode -eq 0) -Name 'Actual Create completes against its evaluated policy snapshot despite a later namespace replacement'
    }
    finally {
        Set-Item Function:\Resolve-AdminAutomationRequest -Value $Script:TwoOriginalRequestResolver
        Remove-Variable TwoOriginalRequestResolver, TwoSwapPolicyPath, TwoSwapPolicyB -Scope Script -ErrorAction SilentlyContinue
    }
    $swapPlan = Import-AdminOrchestrationPlan -LiteralPath $swapPending
    Test-ToolkitAssertion -Condition ($swapPlan.request.policy.fileSha256 -ceq $policyAHash -and $swapPlan.request.policy.decision -ceq 'Allowed') -Name 'Pending decision and digest both describe Policy A rather than mixed Policy A/B evidence'
    $swapProfileB = Import-AdminPolicyProfile -LiteralPath $swapPolicyPath
    Test-ToolkitAssertion -Condition ($swapProfileB.ProfileName -ceq $swapPlan.request.policy.profileName -and $swapProfileB.SchemaVersion -ceq $swapPlan.request.policy.schemaVersion -and $swapProfileB.SourceSha256 -cne $policyAHash) -Name 'Swap attack uses equal policy metadata with genuinely different rule bytes'
    $swapApproval = @{ PlanPath = $swapPending; ApprovedPlanPath = (Join-Path $inside 'swap-approved.watplan.json'); ApprovedBy = 'Synthetic Reviewer'; ApprovalReference = 'OFFLINE-SWAP'; PlanApprovalText = ('APPROVE PLAN ' + $swapPlan.planHash.value) }
    Test-ToolkitThrow -Action { Invoke-AdminPlanApprove -Parameters $swapApproval -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'Actual Approve rejects Policy B even though its name and schema equal Policy A'
    Test-ToolkitAssertion -Condition (-not [IO.File]::Exists($swapApproval.ApprovedPlanPath)) -Name 'Policy swap cannot publish mixed approval evidence'
    [IO.File]::WriteAllText($swapPolicyPath, $policyA)
    $restoredApproval = Invoke-AdminPlanApprove -Parameters $swapApproval -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
    Test-ToolkitAssertion -Condition ($restoredApproval.exitCode -eq 0) -Name 'Restoring the exact evaluated policy bytes allows normal approval'
    $bomPolicyPath = Join-Path $inside 'bom-policy.json'
    [IO.File]::WriteAllText($bomPolicyPath, $policyA, (New-Object Text.UTF8Encoding($true)))
    $bomProfile = Import-AdminPolicyProfile -LiteralPath $bomPolicyPath
    Test-ToolkitAssertion -Condition ($bomProfile.SourceSha256 -ceq (Get-AdminFileSha256Hex -LiteralPath $bomPolicyPath)) -Name 'Policy snapshot digest includes accepted UTF-8 BOM bytes without text reconstruction'

    $collisionScript = Join-Path $inside 'input-and-log.ps1'
    [IO.File]::WriteAllText($collisionScript, 'Get-Date')
    $collisionBefore = Get-AdminFileSha256Hex -LiteralPath $collisionScript
    $collisionResult = Invoke-AdminAutomation -Parameters @{ Action = 'CustomPowerShell'; Local = $true; PowerShellFile = $collisionScript; LogFile = $collisionScript; AppendTrustedLog = $true; WhatIf = $true; JsonOutputPath = '-' } -ResolvedOutputPath '-'
    Test-ToolkitAssertion -Condition ($collisionResult.exitCode -eq 2 -and $collisionResult.outcome -ceq 'ValidationFailure') -Name 'Actual WhatIf automation refuses PowerShellFile and append-trusted log collision'
    Test-ToolkitAssertion -Condition ((Get-AdminFileSha256Hex -LiteralPath $collisionScript) -ceq $collisionBefore) -Name 'Rejected script/log collision preserves exact source bytes before sink initialization'

    foreach ($existingLeaf in @('occupied.json', 'occupied-dir.json')) {
        $existingPath = Join-Path $inside $existingLeaf
        if ($existingLeaf -ceq 'occupied.json') { [IO.File]::WriteAllText($existingPath, 'preserved collision') }
        else { [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($existingPath) }
        Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath $existingPath | Out-Null } -Name 'Native relative preflight refuses both existing file and directory destinations'
    }
    Test-ToolkitAssertion -Condition ([IO.File]::ReadAllText((Join-Path $inside 'occupied.json')) -ceq 'preserved collision') -Name 'Relative preflight preserves existing final collision bytes'
    Test-ToolkitAssertion -Condition (@(Get-ChildItem -LiteralPath $inside -Filter '.admin-json-probe-*.tmp').Count -eq 0) -Name 'Failed relative collision preflight cleans only its owned probe handle'

    # A real junction is a positive control for the no-follow rejection.
    $junction = Join-Path $twoRoot 'junction'
    [void](New-Item -ItemType Junction -Path $junction -Target $outside -ErrorAction Stop)
    $twoAliases.Add($junction) | Out-Null
    Test-ToolkitAssertion -Condition (([IO.File]::GetAttributes($junction) -band [IO.FileAttributes]::ReparsePoint) -ne 0) -Name 'Synthetic NTFS junction exists as a positive attack control'
    foreach ($relative in @('result.json', 'nested\result.json')) {
        if ($relative.StartsWith('nested')) { [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory((Join-Path $outside 'nested')) }
        $redirected = Join-Path $junction $relative
        Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath $redirected -Content 'must not leak' | Out-Null } -Name 'Shared writer rejects junction at every tested ancestry depth'
        Test-ToolkitThrow -Action { Resolve-AdminAutomationOutputPath -LiteralPath $redirected | Out-Null } -Name 'JSON preflight rejects junction at every tested ancestry depth'
    }
    $pendingPath = Join-Path $inside 'pending.watplan.json'
    $created = Invoke-AdminPlanCreate -Parameters @{ PlanPath = $pendingPath; Action = 'SystemInfo'; Local = $true } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
    Test-ToolkitAssertion -Condition ($created.exitCode -eq 0 -and [IO.File]::Exists($pendingPath)) -Name 'Plan Create publishes through the protected shared writer'
    $pending = Import-AdminOrchestrationPlan -LiteralPath $pendingPath
    Test-ToolkitThrow -Action { Invoke-AdminPlanCreate -Parameters @{ PlanPath = (Join-Path $junction 'redirected.watplan.json'); Action = 'SystemInfo'; Local = $true } -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'Actual Plan Create rejects a junction destination'
    $approvalParameters = @{ PlanPath = $pendingPath; ApprovedPlanPath = (Join-Path $junction 'approved.watplan.json'); ApprovedBy = 'Synthetic Reviewer'; ApprovalReference = 'OFFLINE-TEST'; PlanApprovalText = ('APPROVE PLAN ' + $pending.planHash.value) }
    Test-ToolkitThrow -Action { Invoke-AdminPlanApprove -Parameters $approvalParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-' | Out-Null } -Name 'Actual Plan Approve rejects a junction destination'
    $approvalParameters.ApprovedPlanPath = Join-Path $inside 'approved.watplan.json'
    $approved = Invoke-AdminPlanApprove -Parameters $approvalParameters -RunId ([guid]::NewGuid()) -StartedAtUtc ([datetime]::UtcNow) -ResolvedOutputPath '-'
    Test-ToolkitAssertion -Condition ($approved.exitCode -eq 0 -and [IO.File]::Exists($approvalParameters.ApprovedPlanPath)) -Name 'Plan Approve positive control publishes a distinct protected artifact'

    # Feed only scripted answers to the actual interactive export function.
    [void](Initialize-AdminLog -RequestedPath (Join-Path $inside 'exports.log'))
    $Script:TwoExportAnswers = New-Object 'System.Collections.Generic.Queue[string]'
    function global:Read-Host { param([string]$Prompt) if ($Script:TwoExportAnswers.Count -eq 0) { throw "Unexpected export prompt: $Prompt" }; return $Script:TwoExportAnswers.Dequeue() }
    try {
        foreach ($format in @(@('1', 'csv'), @('2', 'json'), @('3', 'html'))) {
            $exportPath = Join-Path $junction ('export.' + $format[1])
            $Script:TwoExportAnswers.Enqueue('SAVE RESULTS'); $Script:TwoExportAnswers.Enqueue($format[0]); $Script:TwoExportAnswers.Enqueue($exportPath)
            Test-ToolkitThrow -Action { Export-AdminResult -Results @([pscustomobject]@{ Target = 'synthetic'; Value = 'fixture' }) -Prefix fixture | Out-Null } -Name "Actual interactive $($format[1]) export rejects a junction destination"
            $exportPath = Join-Path $inside ('export.' + $format[1])
            $Script:TwoExportAnswers.Enqueue('SAVE RESULTS'); $Script:TwoExportAnswers.Enqueue($format[0]); $Script:TwoExportAnswers.Enqueue($exportPath)
            [void](Export-AdminResult -Results @([pscustomobject]@{ Target = 'synthetic'; Value = 'fixture' }) -Prefix fixture)
            Test-ToolkitAssertion -Condition ([IO.File]::Exists($exportPath)) -Name "Actual interactive $($format[1]) export positive control succeeds"
        }
    }
    finally { Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue; Remove-Variable TwoExportAnswers -Scope Script -ErrorAction SilentlyContinue }
    Test-ToolkitAssertion -Condition (@(Get-ChildItem -LiteralPath $outside -File -Recurse).Count -eq 0) -Name 'All JSON export and plan junction routes leave outside fixtures empty'

    $workflow = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) '.github/workflows/security.yml'))
    $defaults = [regex]::Match($workflow, '(?ms)^permissions:\r?\n(?<body>(?:^  [^\r\n]+\r?\n)+)').Groups['body'].Value
    Test-ToolkitAssertion -Condition ($defaults -match 'contents: read' -and $defaults -notmatch ': write') -Name 'Security workflow default token has no write authority'
    $writeJobs = @([regex]::Matches($workflow, '(?ms)^  (?<job>[a-z][a-z0-9_-]*):\r?\n(?<body>.*?)(?=^  [a-z][a-z0-9_-]*:|\z)') | Where-Object { $_.Groups['body'].Value -match 'security-events: write' })
    Test-ToolkitAssertion -Condition ($writeJobs.Count -eq 1 -and $writeJobs[0].Groups['job'].Value -ceq 'semgrep') -Name 'Only the actual SARIF uploader job receives security-events write'
    $gitleaks = [regex]::Match($workflow, '(?ms)^  gitleaks:\r?\n(?<body>.*?)(?=^  [a-z][a-z0-9_-]*:|\z)').Groups['body'].Value
    Test-ToolkitAssertion -Condition ($gitleaks -match '(?m)^    permissions:\r?$' -and $gitleaks -match 'contents: read' -and $gitleaks -match 'pull-requests: read' -and $gitleaks -notmatch ': write') -Name 'Scheduled Gitleaks explicitly receives read-only authority'
}
finally {
    Close-AdminRunSink
    foreach ($alias in $twoAliases) { if ([IO.Directory]::Exists($alias)) { [IO.Directory]::Delete($alias) } }
    $prefix = [IO.Path]::GetFullPath($twoProfile).TrimEnd('\') + '\wat-two-fixture-'
    if ([IO.Path]::GetFullPath($twoRoot).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and [IO.Directory]::Exists($twoRoot)) { [IO.Directory]::Delete($twoRoot, $true) }
}
if ($twoStandalone) {
    if ($Script:Failures.Count -gt 0) { throw ($Script:Failures -join "`n") }
    Write-Host "Final two fixtures: all $Script:TestCount assertions passed under $($PSVersionTable.PSVersion)."
}
