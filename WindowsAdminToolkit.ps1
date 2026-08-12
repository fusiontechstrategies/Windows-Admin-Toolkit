<#
.SYNOPSIS
    Provides an interactive toolkit for authorized Windows administration.

.DESCRIPTION
    Windows Admin Toolkit 2.0 supports local administration and
    bounded remote execution through PowerShell Remoting or PsExec. PowerShell
    Remoting is the default because it does not place passwords on process
    command lines. The optional PsExec transport uses only the current Windows
    identity and requires a valid Microsoft signature on the executable.

    The script is compatible with Windows PowerShell 5.1 and PowerShell 7.x on
    Windows. It does not change WinRM, firewall, TrustedHosts, or execution-policy
    settings automatically.

.PARAMETER Transport
    Remote transport. WinRM is the secure default. PsExec is an explicit fallback.

.PARAMETER PsExecPath
    Path or command name for a Microsoft-signed PsExec 2.43 or newer executable.

.PARAMETER Credential
    Optional credential for WinRM. PsExec deliberately uses only the current
    Windows identity to prevent command-line password exposure.

.PARAMETER MaxConcurrentJobs
    Maximum number of remote targets processed at one time.

.PARAMETER RetryCount
    Retry count for read-only remote actions. State-changing actions are never
    retried automatically.

.PARAMETER RetryDelaySeconds
    Delay between retries of read-only remote actions.

.PARAMETER OperationTimeoutMinutes
    Per-batch remote-operation timeout.

.PARAMETER ConnectivityTimeoutSeconds
    Timeout for preflight connection checks.

.PARAMETER LogFile
    Optional log path. The default is under the current user's local application
    data folder.

.PARAMETER UseSsl
    Uses WinRM over HTTPS.

.PARAMETER Authentication
    WinRM authentication mechanism. Basic, CredSSP, and unencrypted modes are not
    supported by this tool.

.PARAMETER Quiet
    Suppresses routine log messages. Interactive menus and safety prompts remain.

.PARAMETER SkipConnectivityCheck
    Skips the remote preflight check. The actual operation still enforces its
    timeout and reports connection failures.

.EXAMPLE
    .\WindowsAdminToolkit.ps1

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Transport WinRM -UseSsl

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Transport PsExec -PsExecPath C:\Tools\PsExec64.exe

.NOTES
    Version: 2.0.0
    License: MIT
    Use only on systems you own or are explicitly authorized to administer.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateSet('WinRM', 'PsExec')]
    [string]$Transport = 'WinRM',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PsExecPath = 'PsExec64.exe',

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateRange(1, 32)]
    [int]$MaxConcurrentJobs = 8,

    [Parameter()]
    [ValidateRange(0, 3)]
    [int]$RetryCount = 1,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$RetryDelaySeconds = 3,

    [Parameter()]
    [ValidateRange(1, 180)]
    [int]$OperationTimeoutMinutes = 30,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$ConnectivityTimeoutSeconds = 5,

    [Parameter()]
    [string]$LogFile,

    [Parameter()]
    [switch]$UseSsl,

    [Parameter()]
    [ValidateSet('Default', 'Kerberos', 'Negotiate')]
    [string]$Authentication = 'Default',

    [Parameter()]
    [switch]$Quiet,

    [Parameter()]
    [switch]$SkipConnectivityCheck
)

$Script:ToolkitVersion = '2.0.0'
$Script:WasDotSourced = $MyInvocation.InvocationName -eq '.'
$Script:ToolkitPath = $PSCommandPath
$Script:State = [ordered]@{
    LogFile                    = $null
    Quiet                      = [bool]$Quiet
    Transport                  = $Transport
    PsExecPath                 = $PsExecPath
    PsExecFullPath             = $null
    Credential                 = $Credential
    MaxConcurrentJobs          = $MaxConcurrentJobs
    RetryCount                 = $RetryCount
    RetryDelaySeconds          = $RetryDelaySeconds
    OperationTimeoutMinutes    = $OperationTimeoutMinutes
    ConnectivityTimeoutSeconds = $ConnectivityTimeoutSeconds
    UseSsl                     = [bool]$UseSsl
    Authentication             = $Authentication
    SkipConnectivityCheck      = [bool]$SkipConnectivityCheck
}

function Test-WindowsPlatform {
    [CmdletBinding()]
    param()

    return $env:OS -eq 'Windows_NT'
}

function Initialize-AdminLog {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$RequestedPath
    )

    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        $basePath = $env:LOCALAPPDATA
        if ([string]::IsNullOrWhiteSpace($basePath)) {
            $basePath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        }

        $logDirectory = Join-Path $basePath 'WindowsAdminToolkit\Logs'
        $RequestedPath = Join-Path $logDirectory ("WindowsAdminToolkit_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    }

    $fullPath = [System.IO.Path]::GetFullPath($RequestedPath)
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw 'The log path must include a valid parent directory.'
    }

    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }

    if (Test-Path -LiteralPath $fullPath -PathType Container) {
        throw "The log path points to a directory: $fullPath"
    }

    $Script:State.LogFile = $fullPath
    return $fullPath
}

function Write-AdminLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',

        [Parameter()]
        [switch]$NoConsole
    )

    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    if (-not [string]::IsNullOrWhiteSpace([string]$Script:State.LogFile)) {
        try {
            $encoding = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::AppendAllText($Script:State.LogFile, $entry + [Environment]::NewLine, $encoding)
        }
        catch {
            if (-not $NoConsole -and -not $Script:State.Quiet) {
                Write-Warning "Unable to write to the log file: $($_.Exception.Message)"
            }
        }
    }

    if (-not $NoConsole -and -not $Script:State.Quiet) {
        $color = switch ($Level) {
            'ERROR' { 'Red' }
            'WARN' { 'Yellow' }
            'SUCCESS' { 'Green' }
            'DEBUG' { 'DarkGray' }
            default { 'Gray' }
        }
        Write-Host $entry -ForegroundColor $color
    }
}

function Write-AdminBanner {
    [CmdletBinding()]
    param()

    Write-Host ''
    Write-Host '=====================================================================' -ForegroundColor Cyan
    Write-Host "  WINDOWS ADMIN TOOLKIT v$Script:ToolkitVersion" -ForegroundColor Cyan
    Write-Host '  Authorized Windows administration with guarded remote execution' -ForegroundColor White
    Write-Host '=====================================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Test-Administrator {
    [CmdletBinding()]
    param()

    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-AdminHostname {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ComputerName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        return $false
    }

    $value = $ComputerName.Trim()
    if ($value.Length -gt 253) {
        return $false
    }

    $ip = $null
    if ([System.Net.IPAddress]::TryParse($value, [ref]$ip)) {
        return $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $ip.ToString() -ceq $value
    }

    if ($value.EndsWith('.')) {
        $value = $value.Substring(0, $value.Length - 1)
    }

    if ([string]::IsNullOrWhiteSpace($value)) {
        return $false
    }

    foreach ($label in $value.Split('.')) {
        if ($label.Length -lt 1 -or $label.Length -gt 63) {
            return $false
        }
        if ($label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$') {
            return $false
        }
    }

    return $true
}

function Import-AdminComputerList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$MaximumTargets = 500
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "Computer list not found: $LiteralPath"
    }

    $rawLines = @(Get-Content -LiteralPath $LiteralPath -ErrorAction Stop)
    $valid = New-Object 'System.Collections.Generic.List[string]'
    $invalidLines = New-Object 'System.Collections.Generic.List[int]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    for ($index = 0; $index -lt $rawLines.Count; $index++) {
        $value = [string]$rawLines[$index]
        if ([string]::IsNullOrWhiteSpace($value) -or $value.TrimStart().StartsWith('#')) {
            continue
        }

        $value = $value.Trim()
        if (-not (Test-AdminHostname -ComputerName $value)) {
            $invalidLines.Add($index + 1) | Out-Null
            continue
        }

        if ($seen.Add($value)) {
            $valid.Add($value) | Out-Null
        }

        if ($valid.Count -gt $MaximumTargets) {
            throw "The list exceeds the maximum of $MaximumTargets unique targets."
        }
    }

    return [pscustomobject]@{
        Computers   = $valid.ToArray()
        InvalidLines = $invalidLines.ToArray()
    }
}

function Test-AdminServiceName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ServiceName
    )

    if ([string]::IsNullOrWhiteSpace($ServiceName) -or $ServiceName.Length -gt 256) {
        return $false
    }

    return $ServiceName -match '^[A-Za-z0-9_.-]+$'
}

function Test-AdminProcessName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ProcessName
    )

    if ([string]::IsNullOrWhiteSpace($ProcessName) -or $ProcessName.Length -gt 128) {
        return $false
    }

    return $ProcessName -match '^[A-Za-z0-9_.-]+$'
}

function Test-AdminRegistryPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$RegistryPath
    )

    if ([string]::IsNullOrWhiteSpace($RegistryPath) -or $RegistryPath.Length -gt 2048) {
        return $false
    }

    $value = $RegistryPath.Trim()
    if ($value.IndexOf([char]0) -ge 0 -or $value -match '[\r\n]') {
        return $false
    }

    return $value -match '^(?i)(?:(?:HKLM|HKCU|HKCR|HKU|HKCC):(?:\\[^\r\n]*)?|(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(?:\\[^\r\n]*)?)$'
}

function Test-AdminRegistryValueName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ValueName
    )

    return $ValueName.Length -le 16383 -and $ValueName.IndexOf([char]0) -lt 0 -and $ValueName -notmatch '[\r\n]'
}

function Test-AdminEventLogName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$LogName
    )

    if ([string]::IsNullOrWhiteSpace($LogName) -or $LogName.Length -gt 256) {
        return $false
    }

    return $LogName -match '^[A-Za-z0-9][A-Za-z0-9 ._\-/]*$' -and $LogName -notmatch '\.\.'
}

function Test-AdminTaskPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$TaskPath
    )

    if ([string]::IsNullOrWhiteSpace($TaskPath) -or $TaskPath.Length -gt 512) {
        return $false
    }

    return $TaskPath -match '^\\(?:[A-Za-z0-9 ._-]+\\)*$' -and $TaskPath -notmatch '\.\.'
}

function Test-AdminKbNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$KbNumber
    )

    return $KbNumber.Trim().ToUpperInvariant() -match '^KB\d{4,8}$'
}

function Test-AdminPowerShellText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ScriptText
    )

    if ([string]::IsNullOrWhiteSpace($ScriptText) -or $ScriptText.Length -gt 1048576) {
        return [pscustomobject]@{
            IsValid = $false
            Errors  = @('The script is empty or exceeds the 1 MiB limit.')
        }
    }

    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($ScriptText, [ref]$tokens, [ref]$errors)

    return [pscustomobject]@{
        IsValid = @($errors).Count -eq 0
        Errors  = @($errors | ForEach-Object { $_.Message })
    }
}

function ConvertTo-AdminCsvSafeValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [array]) {
        $text = $Value -join '; '
    }
    elseif ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $text = $Value | ConvertTo-Json -Compress -Depth 8
    }
    else {
        $text = [string]$Value
    }

    if ($text -match '^[\s\t\r\n]*[=+\-@]') {
        return "'$text"
    }

    return $text
}

function ConvertTo-AdminFlatObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $InputObject
    )

    $flat = [ordered]@{}
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            $flat[[string]$key] = ConvertTo-AdminCsvSafeValue -Value $InputObject[$key]
        }
    }
    else {
        foreach ($property in $InputObject.PSObject.Properties) {
            if ($property.Name -in @('PSComputerName', 'RunspaceId', 'PSShowComputerName')) {
                continue
            }
            $flat[$property.Name] = ConvertTo-AdminCsvSafeValue -Value $property.Value
        }
    }

    return [pscustomobject]$flat
}

function ConvertTo-AdminHtmlEncoded {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ''
    }

    if ($Value -is [array]) {
        $Value = $Value -join ', '
    }
    elseif ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $Value = $Value | ConvertTo-Json -Compress -Depth 8
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Write-AdminUtf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    if (Test-Path -LiteralPath $fullPath) {
        throw "Refusing to overwrite an existing file: $fullPath"
    }

    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null
    }

    $temporaryPath = Join-Path $parent ('.admin-export-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    try {
        $encoding = New-Object System.Text.UTF8Encoding($true)
        [System.IO.File]::WriteAllText($temporaryPath, $Content, $encoding)
        Move-Item -LiteralPath $temporaryPath -Destination $fullPath -ErrorAction Stop
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }

    return $fullPath
}

function Export-AdminResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Prefix
    )

    if (@($Results).Count -eq 0) {
        Write-Host 'No results are available to export.' -ForegroundColor Yellow
        return $null
    }

    $save = Read-Host 'Save these results? Type SAVE RESULTS to continue'
    if ($save -cne 'SAVE RESULTS') {
        return $null
    }

    Write-Host '  1. CSV'
    Write-Host '  2. JSON'
    Write-Host '  3. HTML'
    $formatChoice = Read-Host 'Select format [1]'
    $extension = switch ($formatChoice) {
        '2' { '.json' }
        '3' { '.html' }
        default { '.csv' }
    }

    $safePrefix = $Prefix -replace '[^A-Za-z0-9_-]', '_'
    $defaultName = '{0}_{1}{2}' -f $safePrefix, (Get-Date -Format 'yyyyMMdd_HHmmss'), $extension
    $requested = Read-Host "Output path [$defaultName]"
    if ([string]::IsNullOrWhiteSpace($requested)) {
        $requested = Join-Path (Get-Location).Path $defaultName
    }
    elseif (-not [System.IO.Path]::IsPathRooted($requested)) {
        $requested = Join-Path (Get-Location).Path $requested
    }

    if (-not $requested.EndsWith($extension, [System.StringComparison]::OrdinalIgnoreCase)) {
        $requested += $extension
    }

    $content = switch ($extension) {
        '.csv' {
            $flat = @($Results | ForEach-Object { ConvertTo-AdminFlatObject -InputObject $_ })
            ($flat | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
        }
        '.json' {
            ConvertTo-Json -InputObject @($Results) -Depth 12
        }
        '.html' {
            $properties = @($Results | ForEach-Object {
                    $_.PSObject.Properties.Name | Where-Object { $_ -notin @('PSComputerName', 'RunspaceId', 'PSShowComputerName') }
                } | Sort-Object -Unique)

            $builder = New-Object System.Text.StringBuilder
            [void]$builder.AppendLine('<!doctype html>')
            [void]$builder.AppendLine('<html lang="en"><head><meta charset="utf-8">')
            [void]$builder.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
            [void]$builder.AppendLine('<title>Windows Admin Toolkit Results</title>')
            [void]$builder.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1f2937}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d1d5db;padding:.45rem;text-align:left;vertical-align:top}th{background:#0f4c81;color:white}tr:nth-child(even){background:#f8fafc}.meta{color:#4b5563}</style></head><body>')
            [void]$builder.AppendLine('<h1>Windows Admin Toolkit Results</h1>')
            [void]$builder.AppendLine(('<p class="meta">Generated {0}. Treat this report as sensitive administrative data.</p>' -f (ConvertTo-AdminHtmlEncoded -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))))
            [void]$builder.AppendLine('<table><thead><tr>')
            foreach ($property in $properties) {
                [void]$builder.Append('<th>')
                [void]$builder.Append((ConvertTo-AdminHtmlEncoded -Value $property))
                [void]$builder.AppendLine('</th>')
            }
            [void]$builder.AppendLine('</tr></thead><tbody>')
            foreach ($result in $Results) {
                [void]$builder.AppendLine('<tr>')
                foreach ($property in $properties) {
                    [void]$builder.Append('<td>')
                    [void]$builder.Append((ConvertTo-AdminHtmlEncoded -Value $result.$property))
                    [void]$builder.AppendLine('</td>')
                }
                [void]$builder.AppendLine('</tr>')
            }
            [void]$builder.AppendLine('</tbody></table></body></html>')
            $builder.ToString()
        }
    }

    $savedPath = Write-AdminUtf8File -LiteralPath $requested -Content $content
    Write-AdminLog -Message "Results saved to: $savedPath" -Level SUCCESS
    return $savedPath
}

$Script:ActionScripts = [ordered]@{}

$Script:ActionScripts.SystemInfo = {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $uptime = (Get-Date) - $os.LastBootUpTime

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        OSName         = $os.Caption
        OSVersion      = $os.Version
        BuildNumber    = $os.BuildNumber
        Architecture   = $os.OSArchitecture
        LastBootTime   = $os.LastBootUpTime
        Uptime         = '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        Manufacturer   = $computer.Manufacturer
        Model          = $computer.Model
        Domain         = $computer.Domain
        Status         = 'Success'
    }
}

$Script:ActionScripts.DiskSpace = {
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
    foreach ($disk in $disks) {
        $size = [double]$disk.Size
        $free = [double]$disk.FreeSpace
        $usedPercent = if ($size -gt 0) { [math]::Round((($size - $free) / $size) * 100, 2) } else { 0 }

        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Drive         = $disk.DeviceID
            VolumeName    = $disk.VolumeName
            FileSystem    = $disk.FileSystem
            SizeGB        = [math]::Round($size / 1GB, 2)
            FreeGB        = [math]::Round($free / 1GB, 2)
            UsedPercent   = $usedPercent
            Status        = 'Success'
        }
    }
}

$Script:ActionScripts.HardwareInfo = {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $memory = @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop)
    $totalMemory = ($memory | Measure-Object -Property Capacity -Sum).Sum

    [pscustomobject]@{
        ComputerName     = $env:COMPUTERNAME
        Manufacturer     = $computer.Manufacturer
        Model            = $computer.Model
        SystemType       = $computer.SystemType
        Processor        = $cpu.Name
        PhysicalCores    = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        TotalMemoryGB    = [math]::Round([double]$totalMemory / 1GB, 2)
        MemoryModules    = $memory.Count
        BIOSVersion      = $bios.SMBIOSBIOSVersion
        SerialNumber     = $bios.SerialNumber
        Status           = 'Success'
    }
}

$Script:ActionScripts.NetworkConfig = {
    $adapters = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -ErrorAction Stop)
    foreach ($adapter in $adapters) {
        [pscustomobject]@{
            ComputerName  = $env:COMPUTERNAME
            Description   = $adapter.Description
            MACAddress    = $adapter.MACAddress
            IPAddress     = @($adapter.IPAddress) -join ', '
            SubnetMask    = @($adapter.IPSubnet) -join ', '
            Gateway       = @($adapter.DefaultIPGateway) -join ', '
            DNSServers    = @($adapter.DNSServerSearchOrder) -join ', '
            DHCPEnabled   = $adapter.DHCPEnabled
            DHCPServer    = $adapter.DHCPServer
            Status        = 'Success'
        }
    }
}

$Script:ActionScripts.LoggedOnUsers = {
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $sessions = @(Get-CimInstance -ClassName Win32_LogonSession -Filter 'LogonType=2 OR LogonType=10 OR LogonType=11' -ErrorAction Stop | Select-Object -First 200)

    foreach ($session in $sessions) {
        $accounts = @(Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -ResultClassName Win32_Account -ErrorAction SilentlyContinue)
        foreach ($account in $accounts) {
            $identity = '{0}\{1}' -f $account.Domain, $account.Name
            if ($seen.Add($identity)) {
                $rows.Add([pscustomobject]@{
                        ComputerName = $env:COMPUTERNAME
                        UserName     = $account.Name
                        Domain       = $account.Domain
                        LogonType    = $session.LogonType
                        LogonId      = $session.LogonId
                        StartTime    = $session.StartTime
                        Status       = 'Success'
                    }) | Out-Null
            }
        }
    }

    if ($rows.Count -eq 0) {
        $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $rows.Add([pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                UserName     = $computer.UserName
                Domain       = $computer.Domain
                LogonType    = $null
                LogonId      = $null
                StartTime    = $null
                Status       = 'Success'
            }) | Out-Null
    }

    $rows.ToArray()
}

$Script:ActionScripts.RunningProcesses = {
    param(
        [ValidateRange(1, 100)]
        [int]$TopCount = 20
    )

    Get-Process -ErrorAction Stop |
        Sort-Object -Property WorkingSet64 -Descending |
        Select-Object -First $TopCount |
        ForEach-Object {
            $cpuSeconds = try { [math]::Round([double]$_.CPU, 2) } catch { $null }
            $startTime = try { $_.StartTime } catch { $null }
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                ProcessName  = $_.ProcessName
                ProcessId    = $_.Id
                CPUSeconds   = $cpuSeconds
                MemoryMB     = [math]::Round([double]$_.WorkingSet64 / 1MB, 2)
                Handles      = $_.HandleCount
                Threads      = $_.Threads.Count
                StartTime    = $startTime
                Status       = 'Success'
            }
        }
}

$Script:ActionScripts.SoftwareInventory = {
    $basePaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    $items = New-Object 'System.Collections.Generic.List[object]'
    foreach ($basePath in $basePaths) {
        if (-not (Test-Path -LiteralPath $basePath)) {
            continue
        }

        foreach ($key in @(Get-ChildItem -LiteralPath $basePath -ErrorAction SilentlyContinue | Select-Object -First 5000)) {
            $software = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $software -or [string]::IsNullOrWhiteSpace([string]$software.DisplayName)) {
                continue
            }

            $items.Add([pscustomobject]@{
                    ComputerName = $env:COMPUTERNAME
                    Name         = $software.DisplayName
                    Version      = $software.DisplayVersion
                    Publisher    = $software.Publisher
                    InstallDate  = $software.InstallDate
                    Architecture = if ($basePath -match 'WOW6432Node') { '32-bit' } else { '64-bit' }
                    Status       = 'Success'
                }) | Out-Null
        }
    }

    $items.ToArray() | Sort-Object -Property Name, Version -Unique
}

$Script:ActionScripts.LicenseStatus = {
    $license = Get-CimInstance -ClassName SoftwareLicensingProduct -Filter 'PartialProductKey IS NOT NULL' -ErrorAction Stop |
        Where-Object { $_.Name -match 'Windows' } |
        Select-Object -First 1
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

    $statusText = switch ([int]$license.LicenseStatus) {
        0 { 'Unlicensed' }
        1 { 'Licensed' }
        2 { 'OOBGrace' }
        3 { 'OOTGrace' }
        4 { 'NonGenuineGrace' }
        5 { 'Notification' }
        6 { 'ExtendedGrace' }
        default { 'Unknown' }
    }

    [pscustomobject]@{
        ComputerName    = $env:COMPUTERNAME
        ProductName     = $os.Caption
        LicenseStatus   = $statusText
        LicenseCode     = $license.LicenseStatus
        Description     = $license.Description
        GracePeriodDays = if ($license.GracePeriodRemaining) { [math]::Round([double]$license.GracePeriodRemaining / 1440, 1) } else { $null }
        Status          = 'Success'
    }
}

$Script:ActionScripts.WindowsUpdate = {
    param(
        [string[]]$IncludeKBs = @()
    )

    $normalizedKBs = @($IncludeKBs | ForEach-Object { $_.Trim().ToUpperInvariant() })
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $selected = New-Object -ComObject Microsoft.Update.UpdateColl

    foreach ($update in $searchResult.Updates) {
        $include = $normalizedKBs.Count -eq 0
        if (-not $include) {
            foreach ($kb in @($update.KBArticleIDs)) {
                if (('KB{0}' -f $kb).ToUpperInvariant() -in $normalizedKBs) {
                    $include = $true
                    break
                }
            }
        }

        if ($include) {
            if (-not $update.EulaAccepted) {
                $update.AcceptEula()
            }
            [void]$selected.Add($update)
        }
    }

    if ($selected.Count -eq 0) {
        [pscustomobject]@{
            ComputerName     = $env:COMPUTERNAME
            UpdatesAvailable = $searchResult.Updates.Count
            UpdatesSelected  = 0
            UpdatesInstalled = 0
            RebootRequired   = $false
            Message          = 'No matching applicable updates were found.'
            Status           = 'Success'
        }
        return
    }

    $download = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $selected) {
        if (-not $update.IsDownloaded) {
            [void]$download.Add($update)
        }
    }

    if ($download.Count -gt 0) {
        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $download
        $downloadResult = $downloader.Download()
        if ($downloadResult.ResultCode -notin @(2, 3)) {
            throw "Windows Update download failed with result code $($downloadResult.ResultCode)."
        }
    }

    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $selected
    $installResult = $installer.Install()
    $installed = New-Object 'System.Collections.Generic.List[string]'
    $failed = New-Object 'System.Collections.Generic.List[string]'

    for ($index = 0; $index -lt $selected.Count; $index++) {
        $itemResult = $installResult.GetUpdateResult($index)
        if ($itemResult.ResultCode -eq 2) {
            $installed.Add([string]$selected.Item($index).Title) | Out-Null
        }
        else {
            $failed.Add([string]$selected.Item($index).Title) | Out-Null
        }
    }

    [pscustomobject]@{
        ComputerName     = $env:COMPUTERNAME
        UpdatesAvailable = $searchResult.Updates.Count
        UpdatesSelected  = $selected.Count
        UpdatesInstalled = $installed.Count
        FailedUpdates    = $failed.ToArray()
        RebootRequired   = [bool]$installResult.RebootRequired
        Message          = "Installed $($installed.Count) of $($selected.Count) selected updates."
        Status           = if ($failed.Count -eq 0) { 'Success' } else { 'Partial' }
    }
}

$Script:ActionScripts.ScheduleReboot = {
    param(
        [ValidateRange(30, 3600)]
        [int]$DelaySeconds = 60
    )

    $shutdownPath = Join-Path $env:SystemRoot 'System32\shutdown.exe'
    $message = 'Administrative reboot scheduled by Windows Admin Toolkit'
    $output = & $shutdownPath '/r' '/t' ([string]$DelaySeconds) '/d' 'p:4:1' '/c' $message 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "shutdown.exe failed with exit code $exitCode. $($output -join ' ')"
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        DelaySeconds = $DelaySeconds
        Message       = "Reboot scheduled in $DelaySeconds seconds. Use shutdown /a locally to cancel."
        Status        = 'Success'
    }
}

$Script:ActionScripts.PendingReboot = {
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $checkErrors = New-Object 'System.Collections.Generic.List[string]'

    try {
        $rename = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $rename -and $rename.PendingFileRenameOperations) {
            $reasons.Add('Pending file rename operations') | Out-Null
        }
    }
    catch {
        $checkErrors.Add("Pending file rename check failed: $($_.Exception.Message)") | Out-Null
    }

    foreach ($path in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending',
            'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData'
        )) {
        try {
            if (Test-Path -LiteralPath $path) {
                $reasons.Add($path) | Out-Null
            }
        }
        catch {
            $checkErrors.Add("Registry check failed: $($_.Exception.Message)") | Out-Null
        }
    }

    try {
        $activeName = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name ComputerName -ErrorAction Stop
        $pendingName = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -ErrorAction Stop
        if ($activeName.ComputerName -ne $pendingName.ComputerName) {
            $reasons.Add('Computer rename pending') | Out-Null
        }
    }
    catch {
        $checkErrors.Add("Computer-name check failed: $($_.Exception.Message)") | Out-Null
    }

    try {
        $sccm = Invoke-CimMethod -Namespace 'ROOT\ccm\ClientSDK' -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($sccm.RebootPending -or $sccm.IsHardRebootPending) {
            $reasons.Add('SCCM client reboot pending') | Out-Null
        }
    }
    catch {
        if ($_.Exception.Message -notmatch 'Invalid namespace|not found') {
            $checkErrors.Add("SCCM check failed: $($_.Exception.Message)") | Out-Null
        }
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        RebootPending = $reasons.Count -gt 0
        Reasons       = $reasons.ToArray()
        CheckErrors   = $checkErrors.ToArray()
        Status        = if ($reasons.Count -gt 0) { 'Pending' } elseif ($checkErrors.Count -gt 0) { 'ChecksWithErrors' } else { 'NotPending' }
    }
}

$Script:ActionScripts.ServiceManagement = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Stop', 'Restart', 'Query')]
        [string]$Action
    )

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    switch ($Action) {
        'Start' {
            if ($service.Status -ne 'Running') {
                Start-Service -Name $ServiceName -ErrorAction Stop
                $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            }
        }
        'Stop' {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $ServiceName -Force -ErrorAction Stop
                $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            }
        }
        'Restart' {
            Restart-Service -Name $ServiceName -Force -ErrorAction Stop
            $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        }
    }

    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        ServiceName  = $service.Name
        DisplayName  = $service.DisplayName
        RequestedAction = $Action
        State        = $service.Status
        StartType    = $service.StartType
        Status       = 'Success'
    }
}

$Script:ActionScripts.TerminateProcess = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProcessName
    )

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ProcessName)
    $protectedProcesses = @('System', 'Registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'fontdrvhost', 'dwm', 'Idle')
    if ($baseName -in $protectedProcesses) {
        throw "The safety policy blocks termination of core Windows process '$baseName'."
    }
    $processes = @(Get-Process -Name $baseName -ErrorAction Stop)
    $ids = @($processes | ForEach-Object { $_.Id })
    $processes | Stop-Process -Force -ErrorAction Stop

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        ProcessName  = $baseName
        ProcessIds   = $ids
        Terminated   = $ids.Count
        Status       = 'Success'
    }
}

$Script:ActionScripts.ClearTempFiles = {
    param(
        [ValidateRange(1, 30)]
        [int]$MinimumAgeDays = 2,

        [ValidateRange(100, 100000)]
        [int]$MaximumFiles = 50000
    )

    $roots = @($env:TEMP, (Join-Path $env:SystemRoot 'Temp')) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$MinimumAgeDays)
    $deleted = 0
    $freedBytes = [int64]0
    $errorCount = 0
    $examined = 0
    $limitReached = $false

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        $enumerationErrors = @()
        $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable enumerationErrors)
        $errorCount += $enumerationErrors.Count

        foreach ($file in $files) {
            $examined++
            if ($examined -gt $MaximumFiles) {
                $limitReached = $true
                break
            }
            if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                continue
            }
            if ($file.LastWriteTimeUtc -ge $cutoff) {
                continue
            }

            try {
                $length = [int64]$file.Length
                Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
                $deleted++
                $freedBytes += $length
            }
            catch {
                $errorCount++
            }
        }

        if ($limitReached) {
            break
        }
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        FilesExamined = [math]::Min($examined, $MaximumFiles)
        FilesDeleted = $deleted
        SpaceFreedMB = [math]::Round([double]$freedBytes / 1MB, 2)
        ErrorCount   = $errorCount
        LimitReached = $limitReached
        Status       = if ($limitReached) { 'Partial' } else { 'Success' }
    }
}

$Script:ActionScripts.ScheduledTasks = {
    param(
        [string]$TaskPath = '\',

        [ValidateRange(1, 500)]
        [int]$MaximumTasks = 50
    )

    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            $_.TaskPath.StartsWith($TaskPath, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First $MaximumTasks)

    foreach ($task in $tasks) {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            TaskName     = $task.TaskName
            TaskPath     = $task.TaskPath
            State        = $task.State
            LastRunTime  = if ($info) { $info.LastRunTime } else { $null }
            LastResult   = if ($info) { $info.LastTaskResult } else { $null }
            NextRunTime  = if ($info) { $info.NextRunTime } else { $null }
            Author       = $task.Author
            Status       = 'Success'
        }
    }
}

$Script:ActionScripts.FirewallStatus = {
    foreach ($firewallProfile in @(Get-NetFirewallProfile -ErrorAction Stop)) {
        [pscustomobject]@{
            ComputerName     = $env:COMPUTERNAME
            ProfileName      = $firewallProfile.Name
            Enabled          = $firewallProfile.Enabled
            DefaultInbound   = $firewallProfile.DefaultInboundAction
            DefaultOutbound  = $firewallProfile.DefaultOutboundAction
            LogAllowed       = $firewallProfile.LogAllowed
            LogBlocked       = $firewallProfile.LogBlocked
            LogFileName      = $firewallProfile.LogFileName
            Status           = 'Success'
        }
    }
}

$Script:ActionScripts.EventLogQuery = {
    param(
        [string]$LogName = 'System',

        [ValidateRange(1, 1000)]
        [int]$EntryCount = 20,

        [string[]]$Levels = @('Error', 'Warning')
    )

    $levelMap = @{
        Critical    = 1
        Error       = 2
        Warning     = 3
        Information = 4
        Verbose     = 5
    }
    $levelIds = @($Levels | ForEach-Object { $levelMap[$_] } | Where-Object { $null -ne $_ } | Sort-Object -Unique)
    if ($levelIds.Count -eq 0) {
        $levelIds = @(2, 3)
    }

    $filter = @{
        LogName = $LogName
        Level   = $levelIds
    }

    Get-WinEvent -FilterHashtable $filter -MaxEvents $EntryCount -ErrorAction Stop |
        ForEach-Object {
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                LogName      = $LogName
                TimeCreated  = $_.TimeCreated
                Level        = $_.LevelDisplayName
                ProviderName = $_.ProviderName
                EventId      = $_.Id
                Message      = if ($_.Message) { ($_.Message -split '[\r\n]+')[0] } else { '' }
                Status       = 'Success'
            }
        }
}

$Script:ActionScripts.RegistryRead = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$KeyPath,

        [AllowEmptyString()]
        [string]$ValueName = ''
    )

    $translations = [ordered]@{
        '^HKEY_LOCAL_MACHINE\\'  = 'HKLM:\'
        '^HKEY_CURRENT_USER\\'   = 'HKCU:\'
        '^HKEY_CLASSES_ROOT\\'   = 'HKCR:\'
        '^HKEY_USERS\\'          = 'HKU:\'
        '^HKEY_CURRENT_CONFIG\\' = 'HKCC:\'
    }
    $translatedPath = $KeyPath
    foreach ($pattern in $translations.Keys) {
        if ($translatedPath -match $pattern) {
            $translatedPath = $translatedPath -replace $pattern, $translations[$pattern]
            break
        }
    }

    if (-not (Test-Path -LiteralPath $translatedPath)) {
        throw "Registry key not found: $translatedPath"
    }

    $item = Get-ItemProperty -LiteralPath $translatedPath -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($ValueName)) {
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                continue
            }
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                KeyPath      = $translatedPath
                ValueName    = $property.Name
                ValueData    = $property.Value
                ValueType    = if ($null -eq $property.Value) { $null } else { $property.Value.GetType().Name }
                Status       = 'Success'
            }
        }
    }
    else {
        $property = $item.PSObject.Properties[$ValueName]
        if ($null -eq $property) {
            throw "Registry value not found: $ValueName"
        }
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            KeyPath      = $translatedPath
            ValueName    = $property.Name
            ValueData    = $property.Value
            ValueType    = if ($null -eq $property.Value) { $null } else { $property.Value.GetType().Name }
            Status       = 'Success'
        }
    }
}

$Script:ActionScripts.CustomCommand = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = [Convert]::ToBase64String($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($Command)))
    }
    finally {
        $sha256.Dispose()
    }

    $commandShell = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $output = & $commandShell '/d' '/s' '/c' $Command 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output -join [Environment]::NewLine
    $truncated = $false
    if ($text.Length -gt 1048576) {
        $text = $text.Substring(0, 1048576)
        $truncated = $true
    }

    [pscustomobject]@{
        ComputerName  = $env:COMPUTERNAME
        CommandSha256 = $hash
        ExitCode      = $exitCode
        Output        = $text
        OutputTruncated = $truncated
        Status        = if ($exitCode -eq 0) { 'Success' } else { 'Failed' }
    }
}

$Script:ActionScripts.CustomPowerShell = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptText
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = [Convert]::ToBase64String($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($ScriptText)))
    }
    finally {
        $sha256.Dispose()
    }

    $customBlock = [scriptblock]::Create($ScriptText)
    $output = & $customBlock *>&1 | Out-String -Width 4096
    $truncated = $false
    if ($output.Length -gt 1048576) {
        $output = $output.Substring(0, 1048576)
        $truncated = $true
    }

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        ScriptSha256   = $hash
        Output         = $output.TrimEnd()
        OutputTruncated = $truncated
        Status         = 'Success'
    }
}

$Script:ActionCatalog = [ordered]@{
    1  = [pscustomobject]@{ Name = 'OS Version and Uptime'; Script = 'SystemInfo'; ReadOnly = $true }
    2  = [pscustomobject]@{ Name = 'Disk Space'; Script = 'DiskSpace'; ReadOnly = $true }
    3  = [pscustomobject]@{ Name = 'Hardware Information'; Script = 'HardwareInfo'; ReadOnly = $true }
    4  = [pscustomobject]@{ Name = 'Network Configuration'; Script = 'NetworkConfig'; ReadOnly = $true }
    5  = [pscustomobject]@{ Name = 'Logged-On Users'; Script = 'LoggedOnUsers'; ReadOnly = $true }
    6  = [pscustomobject]@{ Name = 'Running Processes'; Script = 'RunningProcesses'; ReadOnly = $true }
    7  = [pscustomobject]@{ Name = 'Installed Software'; Script = 'SoftwareInventory'; ReadOnly = $true }
    8  = [pscustomobject]@{ Name = 'Windows License Status'; Script = 'LicenseStatus'; ReadOnly = $true }
    9  = [pscustomobject]@{ Name = 'Install Windows Updates'; Script = 'WindowsUpdate'; ReadOnly = $false }
    10 = [pscustomobject]@{ Name = 'Schedule Reboot'; Script = 'ScheduleReboot'; ReadOnly = $false }
    11 = [pscustomobject]@{ Name = 'Pending Reboot Status'; Script = 'PendingReboot'; ReadOnly = $true }
    12 = [pscustomobject]@{ Name = 'Manage Service'; Script = 'ServiceManagement'; ReadOnly = $false }
    13 = [pscustomobject]@{ Name = 'Terminate Process'; Script = 'TerminateProcess'; ReadOnly = $false }
    14 = [pscustomobject]@{ Name = 'Clear Temporary Files'; Script = 'ClearTempFiles'; ReadOnly = $false }
    15 = [pscustomobject]@{ Name = 'Scheduled Tasks'; Script = 'ScheduledTasks'; ReadOnly = $true }
    16 = [pscustomobject]@{ Name = 'Firewall Status'; Script = 'FirewallStatus'; ReadOnly = $true }
    17 = [pscustomobject]@{ Name = 'Event Log Query'; Script = 'EventLogQuery'; ReadOnly = $true }
    18 = [pscustomobject]@{ Name = 'Registry Read'; Script = 'RegistryRead'; ReadOnly = $true }
    19 = [pscustomobject]@{ Name = 'Custom CMD Command'; Script = 'CustomCommand'; ReadOnly = $false }
    20 = [pscustomobject]@{ Name = 'Custom PowerShell'; Script = 'CustomPowerShell'; ReadOnly = $false }
}

function Test-AdminTcpPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 5
    )

    if (-not (Test-AdminHostname -ComputerName $ComputerName)) {
        return $false
    }

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $asyncResult = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000, $false)) {
            return $false
        }
        $client.EndConnect($asyncResult)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Get-AdminAuthenticodeSignatureInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath
    )

    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction Stop
        return [pscustomobject]@{
            Status        = [string]$signature.Status
            StatusMessage = [string]$signature.StatusMessage
            SignerSubject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
        }
    }

    $windowsPowerShellPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $windowsPowerShellPath -PathType Leaf)) {
        throw 'Windows PowerShell is required to validate the PsExec Authenticode signature in this PowerShell edition.'
    }

    $signatureAction = @'
param(
    [Parameter(Mandatory = $true)]
    [string]$LiteralPath
)

$signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction Stop
[pscustomobject]@{
    Status = [string]$signature.Status
    StatusMessage = [string]$signature.StatusMessage
    SignerSubject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { $null }
}
'@

    $encodedPayload = ConvertTo-AdminEncodedPayload -ActionText $signatureAction -ArgumentList @($LiteralPath)
    $helperOutput = @(& $windowsPowerShellPath -NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedPayload 2>&1)
    $outputText = ($helperOutput | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    $resultMatches = [regex]::Matches($outputText, '(?m)^ADMINRESULT:(?<Data>[A-Za-z0-9+/=]+)\s*$')
    if ($resultMatches.Count -eq 0) {
        if ($outputText.Length -gt 2048) {
            $outputText = $outputText.Substring(0, 2048)
        }
        throw "Windows PowerShell did not return a valid signature result. $($outputText.Trim())"
    }

    $encodedResult = $resultMatches[$resultMatches.Count - 1].Groups['Data'].Value
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $resultJson = $utf8.GetString([Convert]::FromBase64String($encodedResult))
    $envelope = ConvertFrom-Json -InputObject $resultJson -ErrorAction Stop
    if (-not [bool]$envelope.Success) {
        throw "Windows PowerShell could not inspect the signature: $($envelope.ErrorMessage)"
    }

    $signatureData = @($envelope.Data)
    if ($signatureData.Count -ne 1) {
        throw 'Windows PowerShell returned an unexpected signature result.'
    }

    return $signatureData[0]
}

function Resolve-AdminPsExec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $resolvedPath = $null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    }
    else {
        $command = Get-Command -Name $Path -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($command) {
            $resolvedPath = $command.Path
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        throw "PsExec was not found: $Path"
    }

    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    $signature = Get-AdminAuthenticodeSignatureInfo -LiteralPath $resolvedPath
    if ($signature.Status -ne 'Valid') {
        throw "PsExec does not have a valid Authenticode signature: $resolvedPath"
    }
    if ([string]::IsNullOrWhiteSpace([string]$signature.SignerSubject) -or $signature.SignerSubject -notmatch 'O=Microsoft Corporation') {
        throw "PsExec is not signed by Microsoft Corporation: $resolvedPath"
    }
    if ($item.VersionInfo.ProductName -notmatch 'Sysinternals PsExec') {
        throw "The selected executable is not Sysinternals PsExec: $resolvedPath"
    }

    $version = $null
    if (-not [version]::TryParse([string]$item.VersionInfo.FileVersion, [ref]$version) -or $version -lt [version]'2.43') {
        throw "PsExec 2.43 or newer is required. Found: $($item.VersionInfo.FileVersion)"
    }

    return $resolvedPath
}

function ConvertTo-AdminEncodedPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ActionText,

        [Parameter()]
        [object[]]$ArgumentList = @()
    )

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $actionBase64 = [Convert]::ToBase64String($utf8.GetBytes($ActionText))
    $argumentJson = ConvertTo-Json -InputObject @($ArgumentList) -Compress -Depth 10
    $argumentBase64 = [Convert]::ToBase64String($utf8.GetBytes($argumentJson))

    $payload = @"
`$ErrorActionPreference = 'Stop'
`$utf8 = New-Object System.Text.UTF8Encoding(`$false)
`$actionText = `$utf8.GetString([Convert]::FromBase64String('$actionBase64'))
`$argumentJson = `$utf8.GetString([Convert]::FromBase64String('$argumentBase64'))
`$parsedArguments = ConvertFrom-Json -InputObject `$argumentJson
if (`$null -eq `$parsedArguments) {
    `$arguments = @()
}
else {
    `$arguments = @(`$parsedArguments)
}
try {
    `$action = [scriptblock]::Create(`$actionText)
    `$data = @(& `$action @arguments)
    `$envelope = [pscustomobject]@{
        Success = `$true
        Data = @(`$data)
        ErrorMessage = `$null
    }
    `$exitCode = 0
}
catch {
    `$envelope = [pscustomobject]@{
        Success = `$false
        Data = @()
        ErrorMessage = `$_.Exception.Message
    }
    `$exitCode = 1
}
`$json = ConvertTo-Json -InputObject `$envelope -Compress -Depth 12
`$encodedResult = [Convert]::ToBase64String(`$utf8.GetBytes(`$json))
[Console]::Out.WriteLine('ADMINRESULT:' + `$encodedResult)
exit `$exitCode
"@

    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
}

function ConvertTo-AdminFailureEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [int]$Attempts = 1
    )

    return [pscustomobject]@{
        ComputerName = $ComputerName
        Transport    = $Transport
        Attempts     = $Attempts
        Success      = $false
        Data         = @()
        ErrorMessage = $Message
    }
}

function Invoke-AdminPsExecTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$PsExecFullPath,

        [Parameter(Mandatory = $true)]
        [string]$ActionText,

        [Parameter()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [ValidateRange(1, 10800)]
        [int]$TimeoutSeconds = 1800,

        [Parameter()]
        [ValidateRange(1048576, 16777216)]
        [int]$MaximumOutputBytes = 8388608
    )

    if (-not (Test-AdminHostname -ComputerName $ComputerName)) {
        return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message 'The target computer name is invalid.'
    }

    $encodedPayload = ConvertTo-AdminEncodedPayload -ActionText $ActionText -ArgumentList $ArgumentList
    $connectionTimeout = [math]::Max(1, [math]::Min(60, $Script:State.ConnectivityTimeoutSeconds))
    $processArguments = @(
        "\\$ComputerName",
        '-accepteula',
        '-nobanner',
        '-h',
        '-n',
        [string]$connectionTimeout,
        'powershell.exe',
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        $encodedPayload
    )
    $argumentString = $processArguments -join ' '
    $identifier = [guid]::NewGuid().ToString('N')
    $outputPath = Join-Path ([System.IO.Path]::GetTempPath()) "admin-psexec-$identifier.out"
    $errorPath = Join-Path ([System.IO.Path]::GetTempPath()) "admin-psexec-$identifier.err"
    $process = $null
    $timedOut = $false
    $outputExceeded = $false

    try {
        $process = Start-Process -FilePath $PsExecFullPath -ArgumentList $argumentString -WindowStyle Hidden -PassThru -RedirectStandardOutput $outputPath -RedirectStandardError $errorPath -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

        while (-not $process.HasExited) {
            if ((Get-Date) -ge $deadline) {
                $timedOut = $true
                break
            }

            foreach ($path in @($outputPath, $errorPath)) {
                if (Test-Path -LiteralPath $path) {
                    $length = (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).Length
                    if ($length -gt $MaximumOutputBytes) {
                        $outputExceeded = $true
                        break
                    }
                }
            }

            if ($outputExceeded) {
                break
            }

            Start-Sleep -Milliseconds 250
            $process.Refresh()
        }

        if ($timedOut -or $outputExceeded) {
            try {
                $taskKill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
                & $taskKill '/PID' ([string]$process.Id) '/T' '/F' 2>&1 | Out-Null
            }
            catch {
                try { $process.Kill() } catch { Write-Verbose $_.Exception.Message }
            }
        }
        else {
            $process.WaitForExit()
        }

        if ($timedOut) {
            return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message "Operation timed out after $TimeoutSeconds seconds."
        }
        if ($outputExceeded) {
            return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message "Operation output exceeded the $MaximumOutputBytes byte limit."
        }

        $output = if (Test-Path -LiteralPath $outputPath) { [System.IO.File]::ReadAllText($outputPath) } else { '' }
        $resultMatches = [regex]::Matches($output, '(?m)^ADMINRESULT:(?<Data>[A-Za-z0-9+/=]+)\s*$')
        if ($resultMatches.Count -eq 0) {
            $errorText = if (Test-Path -LiteralPath $errorPath) { [System.IO.File]::ReadAllText($errorPath) } else { '' }
            if ($errorText.Length -gt 2048) {
                $errorText = $errorText.Substring(0, 2048)
            }
            if ([string]::IsNullOrWhiteSpace($errorText)) {
                $errorText = "PsExec exited with code $($process.ExitCode) without a valid result envelope."
            }
            return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message $errorText.Trim()
        }

        $encodedResult = $resultMatches[$resultMatches.Count - 1].Groups['Data'].Value
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $json = $utf8.GetString([Convert]::FromBase64String($encodedResult))
        $remoteEnvelope = ConvertFrom-Json -InputObject $json -ErrorAction Stop

        return [pscustomobject]@{
            ComputerName = $ComputerName
            Transport    = 'PsExec'
            Attempts     = 1
            Success      = [bool]$remoteEnvelope.Success
            Data         = @($remoteEnvelope.Data)
            ErrorMessage = $remoteEnvelope.ErrorMessage
        }
    }
    catch {
        return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message $_.Exception.Message
    }
    finally {
        foreach ($path in @($outputPath, $errorPath)) {
            if (Test-Path -LiteralPath $path) {
                Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            }
        }
        if ($process) {
            $process.Dispose()
        }
    }
}

function Invoke-AdminWinRmTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$ActionText,

        [Parameter()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [bool]$UseSsl = $false,

        [Parameter()]
        [ValidateSet('Default', 'Kerberos', 'Negotiate')]
        [string]$Authentication = 'Default',

        [Parameter()]
        [ValidateRange(1, 10800)]
        [int]$TimeoutSeconds = 1800
    )

    if (-not (Test-AdminHostname -ComputerName $ComputerName)) {
        return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'WinRM' -Message 'The target computer name is invalid.'
    }

    try {
        $action = [scriptblock]::Create($ActionText)
        $sessionOption = New-PSSessionOption -OpenTimeout ([math]::Min(60000, $TimeoutSeconds * 1000)) -OperationTimeout ($TimeoutSeconds * 1000) -CancelTimeout 5000
        $invokeParameters = @{
            ComputerName  = $ComputerName
            ScriptBlock   = $action
            ArgumentList  = @($ArgumentList)
            Authentication = $Authentication
            SessionOption = $sessionOption
            ErrorAction   = 'Stop'
        }
        if ($Credential) {
            $invokeParameters.Credential = $Credential
        }
        if ($UseSsl) {
            $invokeParameters.UseSSL = $true
        }

        $data = @(Invoke-Command @invokeParameters)
        return [pscustomobject]@{
            ComputerName = $ComputerName
            Transport    = 'WinRM'
            Attempts     = 1
            Success      = $true
            Data         = @($data)
            ErrorMessage = $null
        }
    }
    catch {
        return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'WinRM' -Message $_.Exception.Message
    }
}

function Invoke-AdminTargetWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('WinRM', 'PsExec')]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [string]$ActionText,

        [Parameter()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [string]$PsExecFullPath,

        [Parameter()]
        [bool]$UseSsl = $false,

        [Parameter()]
        [ValidateSet('Default', 'Kerberos', 'Negotiate')]
        [string]$Authentication = 'Default',

        [Parameter()]
        [ValidateRange(0, 3)]
        [int]$RetryCount = 0,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySeconds = 3,

        [Parameter()]
        [ValidateRange(1, 10800)]
        [int]$TimeoutSeconds = 1800
    )

    $lastResult = $null
    for ($attempt = 1; $attempt -le ($RetryCount + 1); $attempt++) {
        if ($Transport -eq 'WinRM') {
            $lastResult = Invoke-AdminWinRmTarget -ComputerName $ComputerName -Credential $Credential -ActionText $ActionText -ArgumentList $ArgumentList -UseSsl $UseSsl -Authentication $Authentication -TimeoutSeconds $TimeoutSeconds
        }
        else {
            $lastResult = Invoke-AdminPsExecTarget -ComputerName $ComputerName -PsExecFullPath $PsExecFullPath -ActionText $ActionText -ArgumentList $ArgumentList -TimeoutSeconds $TimeoutSeconds
        }

        $lastResult.Attempts = $attempt
        if ($lastResult.Success) {
            return $lastResult
        }
        if ($attempt -le $RetryCount) {
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }

    return $lastResult
}

function Add-AdminNormalizedData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter()]
        [AllowNull()]
        $Data
    )

    foreach ($item in @($Data)) {
        if ($null -eq $item) {
            continue
        }

        if ($item -is [string] -or $item.GetType().IsPrimitive) {
            $Destination.Add([pscustomobject]@{
                    ComputerName = $ComputerName
                    Output       = [string]$item
                    Status       = 'Success'
                }) | Out-Null
            continue
        }

        if ($null -eq $item.PSObject.Properties['ComputerName']) {
            $item | Add-Member -NotePropertyName ComputerName -NotePropertyValue $ComputerName -Force
        }
        $Destination.Add($item) | Out-Null
    }
}

function Add-AdminFailureResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Destination,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [int]$Attempts = 1
    )

    $Destination.Add([pscustomobject]@{
            ComputerName = $ComputerName
            Transport    = $Transport
            Attempts     = $Attempts
            Status       = 'Failed'
            ErrorMessage = $Message
        }) | Out-Null
}

function Invoke-AdminTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'Remote')]
        [string]$TargetMode,

        [Parameter(Mandatory = $true)]
        [string[]]$Computers,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ActionName,

        [Parameter()]
        [object[]]$ArgumentList = @(),

        [Parameter()]
        [bool]$ReadOnly = $true
    )

    if (-not $Script:ActionScripts.Contains($ActionName)) {
        throw "Unknown action script: $ActionName"
    }

    foreach ($computer in $Computers) {
        if ($TargetMode -eq 'Remote' -and -not (Test-AdminHostname -ComputerName $computer)) {
            throw "Invalid remote target: $computer"
        }
    }

    $actionBlock = $Script:ActionScripts[$ActionName]
    $results = New-Object 'System.Collections.Generic.List[object]'

    if ($TargetMode -eq 'Local') {
        try {
            $data = @(& $actionBlock @ArgumentList)
            Add-AdminNormalizedData -Destination $results -ComputerName $env:COMPUTERNAME -Data $data
            if ($results.Count -eq 0) {
                $results.Add([pscustomobject]@{
                        ComputerName = $env:COMPUTERNAME
                        Status       = 'Success'
                        Message      = 'The action completed without output.'
                    }) | Out-Null
            }
        }
        catch {
            Add-AdminFailureResult -Destination $results -ComputerName $env:COMPUTERNAME -Transport 'Local' -Message $_.Exception.Message
        }
        return $results.ToArray()
    }

    $actionText = $actionBlock.ToString()
    $argumentJson = ConvertTo-Json -InputObject @($ArgumentList) -Compress -Depth 10
    $effectiveRetryCount = if ($ReadOnly) { $Script:State.RetryCount } else { 0 }
    $timeoutSeconds = $Script:State.OperationTimeoutMinutes * 60
    $targetIndex = 0

    while ($targetIndex -lt $Computers.Count) {
        $lastIndex = [math]::Min($targetIndex + $Script:State.MaxConcurrentJobs - 1, $Computers.Count - 1)
        $batch = @($Computers[$targetIndex..$lastIndex])
        $records = New-Object System.Collections.ArrayList

        foreach ($computer in $batch) {
            try {
                $job = Start-Job -Name ('AdminJob_{0}' -f [guid]::NewGuid().ToString('N')) -ScriptBlock {
                    param(
                        $ToolkitPath,
                        $SelectedTransport,
                        $TargetComputer,
                        [System.Management.Automation.PSCredential]$RemoteCredential,
                        $RemoteActionText,
                        $RemoteArgumentJson,
                        $RemotePsExecPath,
                        $RemoteUseSsl,
                        $RemoteAuthentication,
                        $RemoteRetryCount,
                        $RemoteRetryDelay,
                        $RemoteTimeoutSeconds
                    )

                    . $ToolkitPath
                    $parsed = ConvertFrom-Json -InputObject $RemoteArgumentJson
                    $remoteArguments = if ($null -eq $parsed) { @() } else { @($parsed) }
                    Invoke-AdminTargetWithRetry -Transport $SelectedTransport -ComputerName $TargetComputer -Credential $RemoteCredential -ActionText $RemoteActionText -ArgumentList $remoteArguments -PsExecFullPath $RemotePsExecPath -UseSsl ([bool]$RemoteUseSsl) -Authentication $RemoteAuthentication -RetryCount $RemoteRetryCount -RetryDelaySeconds $RemoteRetryDelay -TimeoutSeconds $RemoteTimeoutSeconds
                } -ArgumentList @(
                    $Script:ToolkitPath,
                    $Script:State.Transport,
                    $computer,
                    $Script:State.Credential,
                    $actionText,
                    $argumentJson,
                    $Script:State.PsExecFullPath,
                    $Script:State.UseSsl,
                    $Script:State.Authentication,
                    $effectiveRetryCount,
                    $Script:State.RetryDelaySeconds,
                    $timeoutSeconds
                ) -ErrorAction Stop

                [void]$records.Add([pscustomobject]@{
                        Job          = $job
                        ComputerName = $computer
                        Started      = Get-Date
                    })
            }
            catch {
                Add-AdminFailureResult -Destination $results -ComputerName $computer -Transport $Script:State.Transport -Message "Unable to start background job: $($_.Exception.Message)"
            }
        }

        $batchDeadline = (Get-Date).AddSeconds($timeoutSeconds + 30)
        while ($records.Count -gt 0) {
            foreach ($record in @($records.ToArray())) {
                $job = $record.Job
                if ($job.State -in @('Completed', 'Failed', 'Stopped')) {
                    $receiveErrors = @()
                    $envelopes = @(Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable receiveErrors)
                    $envelope = $envelopes | Select-Object -Last 1

                    if ($null -eq $envelope) {
                        $message = if ($receiveErrors.Count -gt 0) { ($receiveErrors | ForEach-Object { $_.Exception.Message }) -join '; ' } else { "Job ended in state $($job.State) without a result." }
                        Add-AdminFailureResult -Destination $results -ComputerName $record.ComputerName -Transport $Script:State.Transport -Message $message
                    }
                    elseif ($envelope.Success) {
                        Add-AdminNormalizedData -Destination $results -ComputerName $record.ComputerName -Data $envelope.Data
                        if (@($envelope.Data).Count -eq 0) {
                            $results.Add([pscustomobject]@{
                                    ComputerName = $record.ComputerName
                                    Status       = 'Success'
                                    Message      = 'The action completed without output.'
                                }) | Out-Null
                        }
                    }
                    else {
                        Add-AdminFailureResult -Destination $results -ComputerName $record.ComputerName -Transport $Script:State.Transport -Message ([string]$envelope.ErrorMessage) -Attempts ([int]$envelope.Attempts)
                    }

                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                    [void]$records.Remove($record)
                }
            }

            if ($records.Count -eq 0) {
                break
            }

            if ((Get-Date) -ge $batchDeadline) {
                foreach ($record in @($records.ToArray())) {
                    Stop-Job -Job $record.Job -ErrorAction SilentlyContinue
                    Remove-Job -Job $record.Job -Force -ErrorAction SilentlyContinue
                    Add-AdminFailureResult -Destination $results -ComputerName $record.ComputerName -Transport $Script:State.Transport -Message "Batch timeout exceeded after $($Script:State.OperationTimeoutMinutes) minutes."
                    [void]$records.Remove($record)
                }
                break
            }

            Start-Sleep -Milliseconds 250
        }

        $targetIndex = $lastIndex + 1
    }

    return $results.ToArray()
}

function Test-AdminTargetConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Computers,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 5,

        [Parameter()]
        [ValidateRange(1, 32)]
        [int]$BatchSize = 8
    )

    $reachable = New-Object 'System.Collections.Generic.List[string]'
    $unreachable = New-Object 'System.Collections.Generic.List[string]'
    $offset = 0

    while ($offset -lt $Computers.Count) {
        $lastIndex = [math]::Min($offset + $BatchSize - 1, $Computers.Count - 1)
        $batch = @($Computers[$offset..$lastIndex])
        $connections = New-Object System.Collections.ArrayList
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

        foreach ($computer in $batch) {
            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $asyncResult = $client.BeginConnect($computer, $Port, $null, $null)
                [void]$connections.Add([pscustomobject]@{
                        Computer   = $computer
                        Client     = $client
                        AsyncResult = $asyncResult
                    })
            }
            catch {
                $client.Close()
                $unreachable.Add($computer) | Out-Null
            }
        }

        foreach ($connection in @($connections.ToArray())) {
            try {
                $remaining = [math]::Max(0, [int](($deadline - (Get-Date)).TotalMilliseconds))
                if ($remaining -gt 0 -and $connection.AsyncResult.AsyncWaitHandle.WaitOne($remaining, $false)) {
                    $connection.Client.EndConnect($connection.AsyncResult)
                    if ($connection.Client.Connected) {
                        $reachable.Add($connection.Computer) | Out-Null
                    }
                    else {
                        $unreachable.Add($connection.Computer) | Out-Null
                    }
                }
                else {
                    $unreachable.Add($connection.Computer) | Out-Null
                }
            }
            catch {
                $unreachable.Add($connection.Computer) | Out-Null
            }
            finally {
                $connection.Client.Close()
            }
        }

        $offset = $lastIndex + 1
    }

    return [pscustomobject]@{
        Reachable   = $reachable.ToArray()
        Unreachable = $unreachable.ToArray()
        Port        = $Port
    }
}

function Show-AdminMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'Remote')]
        [string]$TargetMode
    )

    Write-Host ''
    Write-Host '=====================================================================' -ForegroundColor Cyan
    Write-Host "  WINDOWS ADMIN TOOLKIT  |  $TargetMode MODE" -ForegroundColor Cyan
    Write-Host '=====================================================================' -ForegroundColor Cyan
    Write-Host '  SYSTEM INFORMATION                  SYSTEM MANAGEMENT'
    Write-Host '   1. OS version and uptime            9. Install Windows updates'
    Write-Host '   2. Disk space                      10. Schedule reboot'
    Write-Host '   3. Hardware information            11. Pending reboot status'
    Write-Host '   4. Network configuration           12. Manage service'
    Write-Host '   5. Logged-on users                 13. Terminate process'
    Write-Host '   6. Running processes               14. Clear temporary files'
    Write-Host '   7. Installed software              15. Scheduled tasks'
    Write-Host '   8. Windows license status'
    Write-Host ''
    Write-Host '  SECURITY AND CONFIGURATION          CUSTOM EXECUTION'
    Write-Host '  16. Firewall status                 19. Custom CMD command'
    Write-Host '  17. Event log query                 20. Custom PowerShell'
    Write-Host '  18. Registry read'
    Write-Host ''
    Write-Host '   H. Help                             Q. Quit' -ForegroundColor Yellow
    Write-Host '=====================================================================' -ForegroundColor Cyan
}

function Show-AdminHelp {
    [CmdletBinding()]
    param()

    $helpText = @'

WINDOWS ADMIN TOOLKIT HELP

Remote transports
  WinRM  Secure default. Supports the current identity or PSCredential.
  PsExec Explicit fallback. Uses only the current Windows identity. The tool
         refuses unsigned, non-Microsoft, or obsolete PsExec executables.

Safety controls
  State-changing actions require PowerShell ShouldProcess approval and an exact
  confirmation phrase. -WhatIf blocks those actions. Read-only actions may be
  retried. State-changing actions are never retried automatically.

Connectivity
  The preflight checks only the transport port. It does not modify firewall,
  WinRM, TrustedHosts, authentication, or execution-policy settings.

Custom execution
  Custom CMD and PowerShell features intentionally execute operator-supplied
  code with the selected administrative context. They are not sandboxed.

Reports
  Exports can contain hostnames, users, network details, serial numbers, event
  data, and other sensitive information. Existing files are never overwritten.

Compatibility
  Built-in actions and tests support Windows PowerShell 5.1 and PowerShell 7.x
  on Windows. Custom scripts must also use syntax supported by their target.
'@

    Write-Host $helpText -ForegroundColor Gray
    Read-Host 'Press Enter to continue' | Out-Null
}

function Read-AdminInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $true)]
        [int]$Default,

        [Parameter(Mandatory = $true)]
        [int]$Minimum,

        [Parameter(Mandatory = $true)]
        [int]$Maximum
    )

    $inputValue = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($inputValue)) {
        return $Default
    }

    $parsed = 0
    if (-not [int]::TryParse($inputValue, [ref]$parsed) -or $parsed -lt $Minimum -or $parsed -gt $Maximum) {
        Write-Host "Invalid value. Using $Default." -ForegroundColor Yellow
        return $Default
    }

    return $parsed
}

function Confirm-AdminToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    Write-Host ''
    Write-Host $Message -ForegroundColor Yellow
    $response = Read-Host "Type $Token to continue"
    return $response -ceq $Token
}

function Select-AdminTargetContext {
    [CmdletBinding()]
    param()

    $targetMode = $null
    while ($targetMode -notin @('Local', 'Remote')) {
        Write-Host '  [L] Local computer'
        Write-Host '  [R] Remote computer or computer list'
        $choice = (Read-Host 'Select target mode').Trim()
        if ($choice -match '^(?i)L(?:ocal)?$') {
            $targetMode = 'Local'
        }
        elseif ($choice -match '^(?i)R(?:emote)?$') {
            $targetMode = 'Remote'
        }
        else {
            Write-Host 'Enter L or R.' -ForegroundColor Yellow
        }
    }

    if ($targetMode -eq 'Local') {
        return [pscustomobject]@{
            Mode      = 'Local'
            Computers = @($env:COMPUTERNAME)
        }
    }

    $computers = @()
    while ($computers.Count -eq 0) {
        Write-Host ''
        Write-Host '  [S] Single computer'
        Write-Host '  [F] Computer list file'
        $inputMode = (Read-Host 'Select remote input mode').Trim()

        if ($inputMode -match '^(?i)S(?:ingle)?$') {
            $computer = (Read-Host 'Computer name or IPv4 address').Trim()
            if (Test-AdminHostname -ComputerName $computer) {
                $computers = @($computer)
            }
            else {
                Write-Host 'Invalid computer name or IPv4 address.' -ForegroundColor Yellow
            }
        }
        elseif ($inputMode -match '^(?i)F(?:ile)?$') {
            $path = Read-Host 'Computer list path'
            try {
                $import = Import-AdminComputerList -LiteralPath $path
                $computers = @($import.Computers)
                if ($import.InvalidLines.Count -gt 0) {
                    Write-Host ("Skipped invalid entries on line(s): {0}" -f (($import.InvalidLines | Select-Object -First 20) -join ', ')) -ForegroundColor Yellow
                }
                if ($computers.Count -eq 0) {
                    Write-Host 'The file contains no valid targets.' -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        }
        else {
            Write-Host 'Enter S or F.' -ForegroundColor Yellow
        }
    }

    if ($computers.Count -gt 25) {
        if (-not (Confirm-AdminToken -Message "The selected list contains $($computers.Count) targets." -Token 'USE TARGET LIST')) {
            throw 'Remote target selection was cancelled.'
        }
    }

    if ($Script:State.Transport -eq 'PsExec') {
        if ($Script:State.Credential) {
            throw 'PsExec does not accept alternate credentials in this tool. Use WinRM or launch the toolkit under the required Windows identity.'
        }
        if (-not (Confirm-AdminToken -Message 'PsExec is an optional fallback that installs a temporary remote service, uses SMB, runs under your current Windows identity, and accepts the Microsoft Sysinternals EULA.' -Token 'USE PSEXEC')) {
            throw 'PsExec transport selection was cancelled.'
        }
        $Script:State.PsExecFullPath = Resolve-AdminPsExec -Path $Script:State.PsExecPath
        Write-AdminLog -Message "Validated Microsoft-signed PsExec: $($Script:State.PsExecFullPath)" -Level SUCCESS
    }
    elseif (-not $Script:State.Credential) {
        $alternate = Read-Host 'Use alternate WinRM credentials? (Y/N) [N]'
        if ($alternate -match '^(?i)Y(?:es)?$') {
            $Script:State.Credential = Get-Credential -Message 'Enter credentials for authorized WinRM access'
            if (-not $Script:State.Credential) {
                throw 'Credential entry was cancelled.'
            }
        }
    }

    if (-not $Script:State.SkipConnectivityCheck) {
        $port = if ($Script:State.Transport -eq 'PsExec') { 445 } elseif ($Script:State.UseSsl) { 5986 } else { 5985 }
        Write-Host "Checking TCP port $port on $($computers.Count) target(s)..." -ForegroundColor Cyan
        $preflight = Test-AdminTargetConnectivity -Computers $computers -Port $port -TimeoutSeconds $Script:State.ConnectivityTimeoutSeconds -BatchSize $Script:State.MaxConcurrentJobs
        if ($preflight.Unreachable.Count -gt 0) {
            Write-Host "$($preflight.Unreachable.Count) target(s) did not answer on port $port." -ForegroundColor Yellow
            foreach ($item in @($preflight.Unreachable | Select-Object -First 10)) {
                Write-Host "  $item" -ForegroundColor Yellow
            }
            $keep = Read-Host 'Keep those targets for the actual operation? (Y/N) [N]'
            if ($keep -notmatch '^(?i)Y(?:es)?$') {
                $computers = @($preflight.Reachable)
            }
        }
    }

    if ($computers.Count -eq 0) {
        throw 'No remote targets remain after preflight.'
    }

    return [pscustomobject]@{
        Mode      = 'Remote'
        Computers = @($computers)
    }
}

function Get-AdminActionRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 20)]
        [int]$Choice
    )

    $catalogItem = $Script:ActionCatalog[$Choice]
    $arguments = @()
    $readOnly = [bool]$catalogItem.ReadOnly
    $token = $null
    $warning = $null
    $cancelled = $false

    switch ($Choice) {
        6 {
            $arguments = @(Read-AdminInteger -Prompt 'Number of processes' -Default 20 -Minimum 1 -Maximum 100)
        }
        9 {
            Write-Host '  [A] Install all applicable software updates'
            Write-Host '  [S] Install specific KBs'
            $mode = Read-Host 'Select update mode [A]'
            $kbList = @()
            if ($mode -match '^(?i)S') {
                $raw = Read-Host 'Comma-separated KB numbers'
                foreach ($entry in @($raw -split ',')) {
                    $kb = $entry.Trim().ToUpperInvariant()
                    if ($kb -and -not $kb.StartsWith('KB')) {
                        $kb = "KB$kb"
                    }
                    if (-not (Test-AdminKbNumber -KbNumber $kb)) {
                        Write-Host "Invalid KB number: $entry" -ForegroundColor Red
                        $cancelled = $true
                        break
                    }
                    $kbList += $kb
                }
            }
            $arguments = @(, $kbList)
            $token = 'INSTALL UPDATES'
            $warning = 'This will download and install Windows updates. It will not reboot automatically.'
        }
        10 {
            $delay = Read-AdminInteger -Prompt 'Reboot delay in seconds' -Default 60 -Minimum 30 -Maximum 3600
            $arguments = @($delay)
            $token = 'SCHEDULE REBOOT'
            $warning = "This will schedule a reboot in $delay seconds on every selected target."
        }
        12 {
            $serviceName = (Read-Host 'Service name').Trim()
            if (-not (Test-AdminServiceName -ServiceName $serviceName)) {
                Write-Host 'Invalid service name.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            Write-Host '  1. Query'
            Write-Host '  2. Start'
            Write-Host '  3. Stop'
            Write-Host '  4. Restart'
            $serviceChoice = Read-Host 'Select service action [1]'
            $serviceAction = switch ($serviceChoice) {
                '2' { 'Start' }
                '3' { 'Stop' }
                '4' { 'Restart' }
                default { 'Query' }
            }
            $arguments = @($serviceName, $serviceAction)
            if ($serviceAction -eq 'Query') {
                $readOnly = $true
            }
            else {
                $readOnly = $false
                $token = 'CHANGE SERVICE'
                $warning = "This will $($serviceAction.ToLowerInvariant()) service '$serviceName' on every selected target."
            }
        }
        13 {
            $processName = (Read-Host 'Exact process name').Trim()
            if (-not (Test-AdminProcessName -ProcessName $processName)) {
                Write-Host 'Invalid process name.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($processName)
            $protected = @('System', 'Registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'fontdrvhost', 'dwm', 'Idle')
            if ($baseName -in $protected) {
                Write-Host 'That core Windows process is blocked by the safety policy.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $arguments = @($processName)
            $token = 'TERMINATE PROCESS'
            $warning = "This will forcefully terminate every '$processName' instance on the selected targets."
        }
        14 {
            $age = Read-AdminInteger -Prompt 'Minimum file age in days' -Default 2 -Minimum 1 -Maximum 30
            $maximum = Read-AdminInteger -Prompt 'Maximum files examined per target' -Default 50000 -Minimum 100 -Maximum 100000
            $arguments = @($age, $maximum)
            $token = 'DELETE TEMP FILES'
            $warning = 'This deletes old files only from the user and Windows temp folders. Prefetch is never touched.'
        }
        15 {
            $taskPath = (Read-Host "Task path prefix [\]").Trim()
            if ([string]::IsNullOrWhiteSpace($taskPath)) {
                $taskPath = '\'
            }
            if (-not $taskPath.EndsWith('\')) {
                $taskPath += '\'
            }
            if (-not (Test-AdminTaskPath -TaskPath $taskPath)) {
                Write-Host 'Invalid task path.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $maximum = Read-AdminInteger -Prompt 'Maximum tasks' -Default 50 -Minimum 1 -Maximum 500
            $arguments = @($taskPath, $maximum)
        }
        17 {
            $logName = (Read-Host 'Event log name [System]').Trim()
            if ([string]::IsNullOrWhiteSpace($logName)) {
                $logName = 'System'
            }
            if (-not (Test-AdminEventLogName -LogName $logName)) {
                Write-Host 'Invalid event log name.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $count = Read-AdminInteger -Prompt 'Maximum events' -Default 20 -Minimum 1 -Maximum 1000
            $rawLevels = Read-Host 'Levels [Error,Warning]'
            if ([string]::IsNullOrWhiteSpace($rawLevels)) {
                $rawLevels = 'Error,Warning'
            }
            $allowedLevels = @('Critical', 'Error', 'Warning', 'Information', 'Verbose')
            $levels = @($rawLevels -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -in $allowedLevels } | Sort-Object -Unique)
            if ($levels.Count -eq 0) {
                Write-Host 'No valid event levels were supplied.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $arguments = @($logName, $count, (, $levels))
        }
        18 {
            $keyPath = (Read-Host 'Registry key path').Trim()
            if (-not (Test-AdminRegistryPath -RegistryPath $keyPath)) {
                Write-Host 'Invalid registry path.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $valueName = Read-Host 'Value name [blank lists all values]'
            if (-not (Test-AdminRegistryValueName -ValueName $valueName)) {
                Write-Host 'Invalid registry value name.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            $arguments = @($keyPath, $valueName)
        }
        19 {
            $command = Read-Host 'CMD command'
            if ([string]::IsNullOrWhiteSpace($command) -or $command.Length -gt 32767) {
                Write-Host 'The command is empty or too long.' -ForegroundColor Red
                $cancelled = $true
                break
            }
            Write-Host "Command: $command" -ForegroundColor Cyan
            $arguments = @($command)
            $token = 'RUN COMMAND'
            $warning = 'This command will run as supplied with full privileges. It is not sandboxed.'
        }
        20 {
            Write-Host '  [T] Enter one line of PowerShell'
            Write-Host '  [F] Load a local .ps1 file'
            $sourceMode = Read-Host 'Select script source [T]'
            if ($sourceMode -match '^(?i)F') {
                $scriptPath = Read-Host 'Path to .ps1 file'
                if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf) -or [System.IO.Path]::GetExtension($scriptPath) -ine '.ps1') {
                    Write-Host 'A valid .ps1 file is required.' -ForegroundColor Red
                    $cancelled = $true
                    break
                }
                $item = Get-Item -LiteralPath $scriptPath
                if ($item.Length -gt 1048576) {
                    Write-Host 'The script exceeds the 1 MiB limit.' -ForegroundColor Red
                    $cancelled = $true
                    break
                }
                $scriptText = Get-Content -LiteralPath $scriptPath -Raw -ErrorAction Stop
            }
            else {
                $scriptText = Read-Host 'PowerShell code'
            }

            $validation = Test-AdminPowerShellText -ScriptText $scriptText
            if (-not $validation.IsValid) {
                Write-Host ("Invalid PowerShell syntax: {0}" -f ($validation.Errors -join '; ')) -ForegroundColor Red
                $cancelled = $true
                break
            }
            $arguments = @($scriptText)
            $token = 'RUN SCRIPT'
            $warning = 'This PowerShell code will run with full privileges. It is not sandboxed.'
        }
    }

    return [pscustomobject]@{
        Cancelled         = $cancelled
        Name              = $catalogItem.Name
        Script            = $catalogItem.Script
        Arguments         = @($arguments)
        ReadOnly          = $readOnly
        ConfirmationToken = $token
        Warning           = $warning
    }
}

function Show-AdminResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results
    )

    Write-Host ''
    Write-Host 'RESULTS' -ForegroundColor Cyan
    Write-Host '---------------------------------------------------------------------' -ForegroundColor DarkGray

    $displayCount = [math]::Min(100, @($Results).Count)
    foreach ($result in @($Results | Select-Object -First $displayCount)) {
        $display = [ordered]@{}
        foreach ($property in $result.PSObject.Properties) {
            if ($property.Name -in @('PSComputerName', 'RunspaceId', 'PSShowComputerName')) {
                continue
            }
            $value = $property.Value
            if ($property.Name -eq 'Output' -and $null -ne $value -and ([string]$value).Length -gt 4000) {
                $value = ([string]$value).Substring(0, 4000) + [Environment]::NewLine + '[console output truncated]'
            }
            $display[$property.Name] = $value
        }
        [pscustomobject]$display | Format-List | Out-String -Width 180 | Write-Host
    }

    if (@($Results).Count -gt $displayCount) {
        Write-Host "Console display limited to $displayCount of $(@($Results).Count) records. Export to retain all records." -ForegroundColor Yellow
    }

    $failed = @($Results | Where-Object { $_.Status -in @('Failed', 'Error') }).Count
    Write-Host ("Records: {0}  Failed: {1}" -f @($Results).Count, $failed) -ForegroundColor $(if ($failed -gt 0) { 'Yellow' } else { 'Green' })
}

function Invoke-WindowsAdminToolkit {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    if (-not (Test-WindowsPlatform)) {
        throw 'Windows Admin Toolkit runs only on Windows.'
    }

    [void](Initialize-AdminLog -RequestedPath $LogFile)
    Write-AdminBanner
    Write-AdminLog -Message "Windows Admin Toolkit $Script:ToolkitVersion started under PowerShell $($PSVersionTable.PSVersion)." -NoConsole

    if (-not (Test-Administrator)) {
        Write-Host 'Warning: The current PowerShell session is not elevated. Some actions will fail.' -ForegroundColor Yellow
    }

    Write-Host "Remote transport: $($Script:State.Transport)" -ForegroundColor Gray
    if ($Script:State.Transport -eq 'WinRM') {
        Write-Host ("WinRM security: Authentication={0}, SSL={1}" -f $Script:State.Authentication, $Script:State.UseSsl) -ForegroundColor Gray
    }

    $context = Select-AdminTargetContext
    Write-AdminLog -Message ("Selected {0} mode with {1} target(s)." -f $context.Mode, $context.Computers.Count) -NoConsole

    while ($true) {
        Show-AdminMenu -TargetMode $context.Mode
        $choiceText = (Read-Host 'Select action').Trim()
        if ($choiceText -match '^(?i)Q$') {
            break
        }
        if ($choiceText -match '^(?i)H$') {
            Show-AdminHelp
            continue
        }

        $choice = 0
        if (-not [int]::TryParse($choiceText, [ref]$choice) -or $choice -lt 1 -or $choice -gt 20) {
            Write-Host 'Enter a number from 1 through 20, H, or Q.' -ForegroundColor Yellow
            continue
        }

        try {
            $request = Get-AdminActionRequest -Choice $choice
        }
        catch {
            Write-Host "Unable to prepare the action: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        if ($request.Cancelled) {
            continue
        }

        if (-not $request.ReadOnly) {
            $targetDescription = if ($context.Mode -eq 'Local') { "local computer $env:COMPUTERNAME" } else { "$($context.Computers.Count) remote target(s)" }
            if (-not $PSCmdlet.ShouldProcess($targetDescription, $request.Name)) {
                continue
            }
            if (-not (Confirm-AdminToken -Message $request.Warning -Token $request.ConfirmationToken)) {
                Write-Host 'Action cancelled.' -ForegroundColor Cyan
                continue
            }
        }

        Write-AdminLog -Message ("Starting action '{0}' on {1} target(s)." -f $request.Name, $context.Computers.Count) -Level INFO
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @(Invoke-AdminTarget -TargetMode $context.Mode -Computers $context.Computers -ActionName $request.Script -ArgumentList $request.Arguments -ReadOnly $request.ReadOnly)
        $stopwatch.Stop()

        Show-AdminResult -Results $results
        Write-AdminLog -Message ("Action '{0}' completed in {1:n1} seconds with {2} result record(s)." -f $request.Name, $stopwatch.Elapsed.TotalSeconds, $results.Count) -Level SUCCESS

        try {
            [void](Export-AdminResult -Results $results -Prefix $request.Name)
        }
        catch {
            Write-AdminLog -Message "Export failed: $($_.Exception.Message)" -Level ERROR
        }

        Read-Host 'Press Enter to continue' | Out-Null
    }

    Write-AdminLog -Message 'Windows Admin Toolkit finished.' -Level INFO
    Write-Host "Log: $($Script:State.LogFile)" -ForegroundColor Gray
}

if (-not $Script:WasDotSourced) {
    $invokeParameters = @{}
    if ($WhatIfPreference) {
        $invokeParameters.WhatIf = $true
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) {
        $invokeParameters.Confirm = $PSBoundParameters['Confirm']
    }

    try {
        Invoke-WindowsAdminToolkit @invokeParameters
    }
    catch {
        Write-Error $_.Exception.Message
        exit 1
    }
}
