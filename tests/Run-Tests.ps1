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

Test-ToolkitAssertion -Condition ($Script:ToolkitVersion -eq '2.0.0') -Name 'Version is 2.0.0'
Test-ToolkitAssertion -Condition ($Script:ActionCatalog.Count -eq 20) -Name 'Action catalog contains 20 actions'
Test-ToolkitAssertion -Condition ($Script:ActionScripts.Count -eq 20) -Name 'Action script registry contains 20 scripts'

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
Test-ToolkitAssertion -Condition (-not (Test-AdminRegistryPath -RegistryPath "HKLM:\SOFTWARE$([char]10)Bad")) -Name 'Rejects a registry path containing a newline'
Test-ToolkitAssertion -Condition (Test-AdminRegistryValueName -ValueName 'Display Name') -Name 'Accepts a registry value containing spaces'
Test-ToolkitAssertion -Condition (-not (Test-AdminRegistryValueName -ValueName "Bad$([char]0)Name")) -Name 'Rejects a registry value containing a null character'

Test-ToolkitAssertion -Condition (Test-AdminEventLogName -LogName 'Microsoft-Windows-PowerShell/Operational') -Name 'Accepts a valid event log channel'
Test-ToolkitAssertion -Condition (-not (Test-AdminEventLogName -LogName 'System;whoami')) -Name 'Rejects event log metacharacters'
Test-ToolkitAssertion -Condition (Test-AdminTaskPath -TaskPath '\Microsoft\Windows\') -Name 'Accepts a valid scheduled-task path'
Test-ToolkitAssertion -Condition (-not (Test-AdminTaskPath -TaskPath '\Microsoft\..\')) -Name 'Rejects scheduled-task traversal notation'
Test-ToolkitAssertion -Condition (Test-AdminKbNumber -KbNumber 'KB5034441') -Name 'Accepts a valid KB number'
Test-ToolkitAssertion -Condition (-not (Test-AdminKbNumber -KbNumber 'KB1;whoami')) -Name 'Rejects an unsafe KB number'

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
Test-ToolkitAssertion -Condition $payloadMatch.Success -Name 'Encoded payload returns a result envelope'
if ($payloadMatch.Success) {
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $payloadJson = $utf8.GetString([Convert]::FromBase64String($payloadMatch.Groups['Data'].Value))
    $payloadEnvelope = ConvertFrom-Json -InputObject $payloadJson
    Test-ToolkitAssertion -Condition ([bool]$payloadEnvelope.Success) -Name 'Encoded payload reports success'
    Test-ToolkitAssertion -Condition ($payloadEnvelope.Data[0].Value -ceq $dangerousValue) -Name 'Encoded payload preserves argument data without execution'
}

$localSystemInfo = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName SystemInfo)
Test-ToolkitAssertion -Condition ($localSystemInfo.Count -eq 1 -and $localSystemInfo[0].Status -eq 'Success') -Name 'Local system-information action succeeds'
$localProcesses = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName RunningProcesses -ArgumentList @(1))
Test-ToolkitAssertion -Condition ($localProcesses.Count -eq 1 -and $localProcesses[0].Status -eq 'Success') -Name 'Local process action honors its limit'
$localService = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName ServiceManagement -ArgumentList @('wuauserv', 'Query'))
Test-ToolkitAssertion -Condition ($localService.Count -eq 1 -and $localService[0].Status -eq 'Success') -Name 'Local service query succeeds without changing state'
$localFailure = @(Invoke-AdminTarget -TargetMode Local -Computers @($env:COMPUTERNAME) -ActionName CustomPowerShell -ArgumentList @("throw 'expected test failure'"))
Test-ToolkitAssertion -Condition ($localFailure.Count -eq 1 -and $localFailure[0].Status -eq 'Failed') -Name 'Local action failures are normalized'
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
    $computerFile = Join-Path $resolvedTemporaryRoot 'computers.txt'
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($computerFile, @('# synthetic targets', 'server01.example.com', 'SERVER01.EXAMPLE.COM', '192.0.2.10', 'bad&host'), $encoding)
    $importResult = Import-AdminComputerList -LiteralPath $computerFile
    Test-ToolkitAssertion -Condition ($importResult.Computers.Count -eq 2) -Name 'Computer import deduplicates targets case-insensitively'
    Test-ToolkitAssertion -Condition ($importResult.InvalidLines.Count -eq 1) -Name 'Computer import reports invalid line numbers'
    Test-ToolkitThrow -Action { Import-AdminComputerList -LiteralPath $computerFile -MaximumTargets 1 | Out-Null } -Name 'Computer import enforces its target limit'

    $exportPath = Join-Path $resolvedTemporaryRoot 'result.txt'
    $writtenPath = Write-AdminUtf8File -LiteralPath $exportPath -Content 'test content'
    Test-ToolkitAssertion -Condition ($writtenPath -eq $exportPath -and (Test-Path -LiteralPath $exportPath -PathType Leaf)) -Name 'Atomic UTF-8 writer creates a new file'
    $bytes = [System.IO.File]::ReadAllBytes($exportPath)
    Test-ToolkitAssertion -Condition ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) -Name 'Export writer emits an explicit UTF-8 BOM'
    Test-ToolkitThrow -Action { Write-AdminUtf8File -LiteralPath $exportPath -Content 'replacement' | Out-Null } -Name 'Export writer refuses to overwrite an existing file'

    Test-ToolkitThrow -Action { Resolve-AdminPsExec -Path $toolkitPath | Out-Null } -Name 'PsExec validation rejects a non-PsExec executable'
    $localPsExec = Join-Path $projectRoot 'PsExec64.exe'
    if (Test-Path -LiteralPath $localPsExec -PathType Leaf) {
        $resolvedPsExec = Resolve-AdminPsExec -Path $localPsExec
        Test-ToolkitAssertion -Condition ($resolvedPsExec -eq $localPsExec) -Name 'PsExec validation accepts the signed local Microsoft binary'
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
