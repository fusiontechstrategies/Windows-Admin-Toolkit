<#
.SYNOPSIS
    Provides interactive and noninteractive tools for authorized Windows administration.

.DESCRIPTION
    Windows Admin Toolkit 2.3.0 supports local administration and
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

.PARAMETER WinRmIdentity
    Optional in-memory PSCredential object for WinRM. Automation mode rejects
    username strings so native parameter binding cannot open credential UI.
    Credential remains a backward-compatible parameter alias.
    PsExec deliberately uses only the current Windows identity to prevent
    command-line password exposure.

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

.PARAMETER Automation
    Runs one named action without menus or prompts and returns a versioned JSON
    result envelope.

.PARAMETER PolicyPath
    Optional literal path to a versioned JSON policy profile. A supplied policy
    can only narrow the toolkit's built-in permissions and safety limits.

.PARAMETER AuditPath
    Optional literal path for a new per-run JSON Lines audit file. Existing
    files are never appended to or overwritten.

.PARAMETER AuditEventLog
    Also writes bounded audit records to the Windows Event Log. This integration
    is off by default and requires an already-registered event source.

.PARAMETER AuditEventSource
    Existing Windows Event Log source used with AuditEventLog. The toolkit never
    creates or modifies event-source registration.

.PARAMETER Action
    Stable action identifier used by automation mode.

.PARAMETER ListActions
    Returns the stable action catalog and input requirements without executing
    an action.

.PARAMETER Preflight
    Validates the complete automation request and discovers target capabilities
    without executing the requested action.

.PARAMETER Local
    Selects the local computer for automation mode.

.PARAMETER ComputerName
    Selects one validated remote computer for automation mode.

.PARAMETER ComputerListPath
    Selects a validated remote computer-list file for automation mode.

.PARAMETER JsonOutputPath
    JSON result destination for automation mode. Use a single hyphen or STDOUT
    for stdout. STDOUT is recommended with powershell.exe -File.

.PARAMETER ConfirmationText
    Exact action-specific authorization text for an actual state-changing run.

.PARAMETER TargetListConfirmationText
    Exact USE TARGET LIST authorization text required for more than 25 targets.

.PARAMETER PsExecConfirmationText
    Exact USE PSEXEC authorization text required for the optional PsExec transport.

.PARAMETER TopCount
    Maximum processes returned by the RunningProcesses automation action.

.PARAMETER IncludeKB
    Optional KB identifiers for the WindowsUpdate automation action. An empty
    array selects all applicable software updates.

.PARAMETER RebootDelaySeconds
    Delay before the ScheduleReboot automation action requests a reboot.

.PARAMETER ServiceName
    Validated service name for the ServiceManagement automation action.

.PARAMETER ServiceAction
    Query, Start, Stop, or Restart for the ServiceManagement automation action.

.PARAMETER ProcessName
    Exact process name for the TerminateProcess automation action.

.PARAMETER MinimumAgeDays
    Minimum age of files eligible for the ClearTempFiles automation action.

.PARAMETER MaximumFiles
    Maximum files examined by ClearTempFiles on each target.

.PARAMETER TaskPath
    Validated scheduled-task path prefix for the ScheduledTasks automation action.

.PARAMETER MaximumTasks
    Maximum scheduled tasks returned per target.

.PARAMETER EventLogName
    Validated event-log channel for the EventLogQuery automation action.

.PARAMETER EntryCount
    Maximum event-log entries returned per target.

.PARAMETER EventLevel
    One or more event levels for the EventLogQuery automation action.

.PARAMETER RegistryPath
    Validated registry provider or hive path for the RegistryRead automation action.

.PARAMETER RegistryValueName
    Optional registry value name. An empty value lists all values.

.PARAMETER CommandText
    Unsandboxed command text for the CustomCommand automation action.

.PARAMETER PowerShellText
    Unsandboxed source text for the CustomPowerShell automation action.

.PARAMETER PowerShellFile
    Literal local .ps1 path for the CustomPowerShell automation action.

.EXAMPLE
    .\WindowsAdminToolkit.ps1

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Transport WinRM -UseSsl

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Transport PsExec -PsExecPath C:\Tools\PsExec64.exe

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Automation -Action SystemInfo -Local -JsonOutputPath -

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Automation -ListActions -JsonOutputPath -

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Automation -Action SystemInfo -Local -PolicyPath .\read-only-local.json -Preflight -JsonOutputPath -

.EXAMPLE
    .\WindowsAdminToolkit.ps1 -Automation -Action SystemInfo -Local -AuditPath C:\Audit\system-info.jsonl -JsonOutputPath C:\Results\system-info.json

.NOTES
    Version: 2.3.0
    License: MIT
    Use only on systems you own or are explicitly authorized to administer.
#>

#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [string]$Transport = 'WinRM',

    [Parameter()]
    [string]$PsExecPath = 'PsExec64.exe',

    [Parameter()]
    [AllowNull()]
    [Alias('Credential')]
    [object]$WinRmIdentity,

    [Parameter()]
    [int]$MaxConcurrentJobs = 8,

    [Parameter()]
    [int]$RetryCount = 1,

    [Parameter()]
    [int]$RetryDelaySeconds = 3,

    [Parameter()]
    [int]$OperationTimeoutMinutes = 30,

    [Parameter()]
    [int]$ConnectivityTimeoutSeconds = 5,

    [Parameter()]
    [string]$LogFile,

    [Parameter()]
    [switch]$UseSsl,

    [Parameter()]
    [string]$Authentication = 'Default',

    [Parameter()]
    [switch]$Quiet,

    [Parameter()]
    [switch]$SkipConnectivityCheck,

    [Parameter()]
    [switch]$Automation,

    [Parameter()]
    [AllowEmptyString()]
    [string]$PolicyPath = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$AuditPath = '',

    [Parameter()]
    [switch]$AuditEventLog,

    [Parameter()]
    [AllowEmptyString()]
    [string]$AuditEventSource = 'WindowsAdminToolkit',

    [Parameter()]
    [AllowEmptyString()]
    [string]$Action = '',

    [Parameter()]
    [switch]$ListActions,

    [Parameter()]
    [switch]$Preflight,

    [Parameter()]
    [switch]$Local,

    [Parameter()]
    [AllowEmptyString()]
    [string]$ComputerName = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$ComputerListPath = '',

    [Parameter()]
    [string]$JsonOutputPath = '-',

    [Parameter()]
    [AllowEmptyString()]
    [string]$ConfirmationText = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$TargetListConfirmationText = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$PsExecConfirmationText = '',

    [Parameter()]
    [int]$TopCount = 20,

    [Parameter()]
    [string[]]$IncludeKB = @(),

    [Parameter()]
    [int]$RebootDelaySeconds = 60,

    [Parameter()]
    [AllowEmptyString()]
    [string]$ServiceName = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$ServiceAction = 'Query',

    [Parameter()]
    [AllowEmptyString()]
    [string]$ProcessName = '',

    [Parameter()]
    [int]$MinimumAgeDays = 2,

    [Parameter()]
    [int]$MaximumFiles = 50000,

    [Parameter()]
    [AllowEmptyString()]
    [string]$TaskPath = '\',

    [Parameter()]
    [int]$MaximumTasks = 50,

    [Parameter()]
    [AllowEmptyString()]
    [string]$EventLogName = 'System',

    [Parameter()]
    [int]$EntryCount = 20,

    [Parameter()]
    [string[]]$EventLevel = @('Error', 'Warning'),

    [Parameter()]
    [AllowEmptyString()]
    [string]$RegistryPath = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$RegistryValueName = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$CommandText = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$PowerShellText = '',

    [Parameter()]
    [AllowEmptyString()]
    [string]$PowerShellFile = ''
)

$Script:ToolkitVersion = '2.3.0'
$Script:WasDotSourced = $MyInvocation.InvocationName -eq '.'
$Script:ToolkitPath = $PSCommandPath
$Script:InvocationParameters = @{}
foreach ($boundName in $PSBoundParameters.Keys) {
    $canonicalBoundName = if ($boundName -eq 'WinRmIdentity') { 'Credential' } else { $boundName }
    $Script:InvocationParameters[$canonicalBoundName] = $PSBoundParameters[$boundName]
}
$normalizedTransport = if ($Transport -ieq 'WinRM') { 'WinRM' } elseif ($Transport -ieq 'PsExec') { 'PsExec' } else { $Transport }
$normalizedAuthentication = if ($Authentication -ieq 'Default') { 'Default' } elseif ($Authentication -ieq 'Kerberos') { 'Kerberos' } elseif ($Authentication -ieq 'Negotiate') { 'Negotiate' } else { $Authentication }
$Script:State = [ordered]@{
    LogFile                    = $null
    Quiet                      = [bool]$Quiet
    Transport                  = $normalizedTransport
    PsExecPath                 = $PsExecPath
    PsExecFullPath             = $null
    Credential                 = $WinRmIdentity
    MaxConcurrentJobs          = $MaxConcurrentJobs
    RetryCount                 = $RetryCount
    RetryDelaySeconds          = $RetryDelaySeconds
    OperationTimeoutMinutes    = $OperationTimeoutMinutes
    ConnectivityTimeoutSeconds = $ConnectivityTimeoutSeconds
    UseSsl                     = [bool]$UseSsl
    Authentication             = $normalizedAuthentication
    SkipConnectivityCheck      = [bool]$SkipConnectivityCheck
    PolicyProfile              = $null
    AuditContext               = $null
}

function Test-WindowsPlatform {
    [CmdletBinding()]
    param()

    return $env:OS -eq 'Windows_NT'
}

function Test-AdminLiteralFilePathText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$LiteralPath
    )

    if ([string]::IsNullOrWhiteSpace($LiteralPath) -or
        $LiteralPath -match '[\x00-\x1F\x7F]' -or
        $LiteralPath -match '(?i)^\\\\[.?]\\' -or
        $LiteralPath -match '(?i)^\\\\[^\\]+\\(?:pipe|mailslot)(?:\\|$)' -or
        [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($LiteralPath)) {
        return $false
    }

    $pathWithoutDrive = if ($LiteralPath -match '^[A-Za-z]:') { $LiteralPath.Substring(2) } else { $LiteralPath }
    if ($pathWithoutDrive.Contains(':')) {
        return $false
    }

    foreach ($segment in @($LiteralPath -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.' -or $segment -match '^[A-Za-z]:$') {
            continue
        }
        if ($segment -eq '..' -or $segment.Length -gt 255 -or $segment.TrimEnd(' ', '.') -cne $segment) {
            return $false
        }
        if ($segment.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            return $false
        }
        $deviceName = @($segment -split '\.', 2)[0].TrimEnd(' ', '.')
        if ($deviceName -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            return $false
        }
    }

    return $true
}

function Read-AdminBoundedUtf8File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter()]
        [ValidateRange(1, 16777216)]
        [int]$MaximumBytes = 1048576
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "Input file not found: $LiteralPath"
    }

    $stream = $null
    try {
        $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $fileLength = $stream.Length
        if ($fileLength -gt $MaximumBytes) {
            throw "The input file exceeds the $MaximumBytes byte limit."
        }

        $bytes = New-Object 'byte[]' ([int]$fileLength)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $readCount = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($readCount -le 0) {
                throw 'The input file ended before it could be read completely.'
            }
            $offset += $readCount
        }
    }
    finally {
        if ($stream) {
            $stream.Dispose()
        }
    }

    $textOffset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $textOffset = 3
    }
    try {
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        return $strictUtf8.GetString($bytes, $textOffset, $bytes.Length - $textOffset)
    }
    catch [System.Text.DecoderFallbackException] {
        throw 'The input file must contain valid UTF-8 text.'
    }
}

function Get-AdminRuntimeConfigurationError {
    [CmdletBinding()]
    param()

    if ($Script:State.Transport -notin @('WinRM', 'PsExec')) {
        return "Unsupported transport: $($Script:State.Transport)"
    }
    if ($Script:State.Authentication -notin @('Default', 'Kerberos', 'Negotiate')) {
        return "Unsupported WinRM authentication value: $($Script:State.Authentication)"
    }
    if ($Script:State.Transport -eq 'PsExec') {
        foreach ($winRmOnlyParameter in @('Authentication', 'UseSsl')) {
            if (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name $winRmOnlyParameter) {
                return "Parameter -$winRmOnlyParameter is valid only with the WinRM transport."
            }
        }
    }
    elseif (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name 'PsExecPath') {
        return 'Parameter -PsExecPath is valid only with the PsExec transport.'
    }
    if ($null -ne $Script:State.Credential -and $Script:State.Credential -isnot [System.Management.Automation.PSCredential]) {
        return 'Credential must be supplied as an in-memory PSCredential object. Username strings are rejected in automation mode to prevent credential prompts.'
    }
    if ($Script:State.MaxConcurrentJobs -lt 1 -or $Script:State.MaxConcurrentJobs -gt 32) {
        return 'MaxConcurrentJobs must be from 1 through 32.'
    }
    if ($Script:State.RetryCount -lt 0 -or $Script:State.RetryCount -gt 3) {
        return 'RetryCount must be from 0 through 3.'
    }
    if ($Script:State.RetryDelaySeconds -lt 1 -or $Script:State.RetryDelaySeconds -gt 60) {
        return 'RetryDelaySeconds must be from 1 through 60.'
    }
    if ($Script:State.OperationTimeoutMinutes -lt 1 -or $Script:State.OperationTimeoutMinutes -gt 180) {
        return 'OperationTimeoutMinutes must be from 1 through 180.'
    }
    if ($Script:State.ConnectivityTimeoutSeconds -lt 1 -or $Script:State.ConnectivityTimeoutSeconds -gt 60) {
        return 'ConnectivityTimeoutSeconds must be from 1 through 60.'
    }
    if ($Script:State.Transport -eq 'PsExec' -and $Script:State.Credential) {
        return 'PsExec does not accept alternate credentials in this toolkit.'
    }

    return $null
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
        $RequestedPath = Join-Path $logDirectory ("WindowsAdminToolkit_{0}_{1}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss_fff'), [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    if (-not (Test-AdminLiteralFilePathText -LiteralPath $RequestedPath)) {
        throw 'The log path contains an unsafe or unsupported component.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($RequestedPath)
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw 'The log path must include a valid parent directory.'
    }

    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }

    if (Test-Path -LiteralPath $fullPath -PathType Container) {
        throw "The log path points to a directory: $fullPath"
    }

    $logProbe = $null
    try {
        $logProbe = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    }
    finally {
        if ($logProbe) {
            $logProbe.Dispose()
        }
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

    $rawText = Read-AdminBoundedUtf8File -LiteralPath $LiteralPath -MaximumBytes 1048576
    $rawLines = @($rawText -split '\r\n|\n|\r')
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

    return $value -match '^(?i)(?:(?:HKLM|HKCU|HKCR|HKU|HKCC):(?:\\[^\r\n]*)?|(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)(?:\\[^\r\n]*)?)$' -and
        $value -notmatch '(?:^|\\)\.\.(?:\\|$)'
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
        [string]$Content,

        [Parameter()]
        [bool]$EmitBom = $true
    )

    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    if (Test-Path -LiteralPath $fullPath) {
        throw "Refusing to overwrite an existing file: $fullPath"
    }

    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }

    $temporaryPath = Join-Path $parent ('.admin-export-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    try {
        $encoding = New-Object System.Text.UTF8Encoding($EmitBom)
        [System.IO.File]::WriteAllText($temporaryPath, $Content, $encoding)
        [System.IO.File]::Move($temporaryPath, $fullPath)
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            [System.IO.File]::Delete($temporaryPath)
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
    $output = & {
        param([scriptblock]$Block)
        $ErrorActionPreference = 'Stop'
        & $Block
    } $customBlock *>&1 | Out-String -Width 4096
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

$Script:CapabilityDiscoveryScript = {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequestedActionId,

        [Parameter()]
        [string[]]$RequiredCommands = @(),

        [Parameter()]
        [string[]]$RequiredExecutables = @(),

        [Parameter()]
        [string[]]$RequiredComObjects = @(),

        [Parameter()]
        [bool]$RequiresAdministrator = $false
    )

    $availableCommands = New-Object 'System.Collections.Generic.List[string]'
    $missingCommands = New-Object 'System.Collections.Generic.List[string]'
    foreach ($commandName in $RequiredCommands) {
        if (Get-Command -Name $commandName -ErrorAction SilentlyContinue) {
            $availableCommands.Add($commandName) | Out-Null
        }
        else {
            $missingCommands.Add($commandName) | Out-Null
        }
    }

    $availableExecutables = New-Object 'System.Collections.Generic.List[string]'
    $missingExecutables = New-Object 'System.Collections.Generic.List[string]'
    foreach ($executableName in $RequiredExecutables) {
        if (Get-Command -Name $executableName -CommandType Application -ErrorAction SilentlyContinue) {
            $availableExecutables.Add($executableName) | Out-Null
        }
        else {
            $missingExecutables.Add($executableName) | Out-Null
        }
    }

    $availableComObjects = New-Object 'System.Collections.Generic.List[string]'
    $missingComObjects = New-Object 'System.Collections.Generic.List[string]'
    foreach ($comObjectName in $RequiredComObjects) {
        $comObject = $null
        try {
            $comObject = New-Object -ComObject $comObjectName -ErrorAction Stop
            $availableComObjects.Add($comObjectName) | Out-Null
        }
        catch {
            $missingComObjects.Add($comObjectName) | Out-Null
        }
        finally {
            if ($null -ne $comObject -and [System.Runtime.InteropServices.Marshal]::IsComObject($comObject)) {
                [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($comObject)
            }
        }
    }

    $isAdministrator = $false
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isAdministrator = $false
    }

    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if ($missingCommands.Count -gt 0) {
        $reasons.Add('One or more required PowerShell commands are unavailable in this session.') | Out-Null
    }
    if ($missingExecutables.Count -gt 0) {
        $reasons.Add('One or more required Windows executables are unavailable.') | Out-Null
    }
    if ($missingComObjects.Count -gt 0) {
        $reasons.Add('One or more required Windows COM components are unavailable.') | Out-Null
    }
    if ($RequiresAdministrator -and -not $isAdministrator) {
        $reasons.Add('The requested action requires an administrator or an equivalently delegated endpoint identity.') | Out-Null
    }
    $canRun = $reasons.Count -eq 0

    [pscustomobject]@{
        ComputerName          = $env:COMPUTERNAME
        RequestedActionId     = $RequestedActionId
        CanRun                = $canRun
        PowerShellVersion     = [string]$PSVersionTable.PSVersion
        PowerShellEdition     = if ($PSVersionTable.PSEdition) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
        LanguageMode          = [string]$ExecutionContext.SessionState.LanguageMode
        IsAdministrator       = $isAdministrator
        RequiresAdministrator = $RequiresAdministrator
        RequiredCommands      = @($RequiredCommands)
        AvailableCommands     = @($availableCommands.ToArray())
        MissingCommands       = @($missingCommands.ToArray())
        RequiredExecutables   = @($RequiredExecutables)
        AvailableExecutables  = @($availableExecutables.ToArray())
        MissingExecutables    = @($missingExecutables.ToArray())
        RequiredComObjects    = @($RequiredComObjects)
        AvailableComObjects   = @($availableComObjects.ToArray())
        MissingComObjects     = @($missingComObjects.ToArray())
        Reasons               = @($reasons.ToArray())
        Status                = if ($canRun) { 'Success' } else { 'Failed' }
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

$Script:AutomationSchemaVersion = '1.2'
$Script:PolicySchemaVersion = '1.0'
$Script:AuditSchemaVersion = '1.0'
$Script:AuditCanonicalization = 'WAT-AUDIT-SUMMARY-1'
$Script:AuditMaximumBytes = 16777216
$Script:AutomationExitCodes = [ordered]@{
    CompleteSuccess      = 0
    PartialSuccess       = 1
    ValidationFailure    = 2
    AuthorizationFailure = 3
    ExecutionFailure     = 4
    Timeout              = 5
    InternalFailure      = 10
}
$Script:AutomationInputNames = @(
    'TopCount',
    'IncludeKB',
    'RebootDelaySeconds',
    'ServiceName',
    'ServiceAction',
    'ProcessName',
    'MinimumAgeDays',
    'MaximumFiles',
    'TaskPath',
    'MaximumTasks',
    'EventLogName',
    'EntryCount',
    'EventLevel',
    'RegistryPath',
    'RegistryValueName',
    'CommandText',
    'PowerShellText',
    'PowerShellFile'
)
$Script:AutomationActionInputs = [ordered]@{
    SystemInfo        = @()
    DiskSpace         = @()
    HardwareInfo      = @()
    NetworkConfig     = @()
    LoggedOnUsers     = @()
    RunningProcesses  = @('TopCount')
    SoftwareInventory = @()
    LicenseStatus     = @()
    WindowsUpdate     = @('IncludeKB')
    ScheduleReboot    = @('RebootDelaySeconds')
    PendingReboot     = @()
    ServiceManagement = @('ServiceName', 'ServiceAction')
    TerminateProcess  = @('ProcessName')
    ClearTempFiles    = @('MinimumAgeDays', 'MaximumFiles')
    ScheduledTasks    = @('TaskPath', 'MaximumTasks')
    FirewallStatus    = @()
    EventLogQuery     = @('EventLogName', 'EntryCount', 'EventLevel')
    RegistryRead      = @('RegistryPath', 'RegistryValueName')
    CustomCommand     = @('CommandText')
    CustomPowerShell  = @('PowerShellText', 'PowerShellFile')
}
$Script:AutomationConfirmations = [ordered]@{
    WindowsUpdate     = 'INSTALL UPDATES'
    ScheduleReboot    = 'SCHEDULE REBOOT'
    ServiceManagement = 'CHANGE SERVICE'
    TerminateProcess  = 'TERMINATE PROCESS'
    ClearTempFiles    = 'DELETE TEMP FILES'
    CustomCommand     = 'RUN COMMAND'
    CustomPowerShell  = 'RUN SCRIPT'
}
$Script:PolicyInputDefinitions = [ordered]@{
    RunningProcesses = [ordered]@{
        TopCount = [pscustomobject]@{ Kind = 'Integer'; Minimum = 1; Maximum = 100; MaximumLength = $null; MaximumItems = $null; AllowedValues = $false }
    }
    WindowsUpdate = [ordered]@{
        IncludeKB = [pscustomobject]@{ Kind = 'StringArray'; Minimum = $null; Maximum = $null; MaximumLength = 10; MaximumItems = 100; AllowedValues = $true }
    }
    ScheduleReboot = [ordered]@{
        RebootDelaySeconds = [pscustomobject]@{ Kind = 'Integer'; Minimum = 30; Maximum = 3600; MaximumLength = $null; MaximumItems = $null; AllowedValues = $false }
    }
    ServiceManagement = [ordered]@{
        ServiceName   = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 256; MaximumItems = $null; AllowedValues = $true }
        ServiceAction = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 7; MaximumItems = $null; AllowedValues = $true }
    }
    TerminateProcess = [ordered]@{
        ProcessName = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 128; MaximumItems = $null; AllowedValues = $true }
    }
    ClearTempFiles = [ordered]@{
        MinimumAgeDays = [pscustomobject]@{ Kind = 'Integer'; Minimum = 1; Maximum = 30; MaximumLength = $null; MaximumItems = $null; AllowedValues = $false }
        MaximumFiles   = [pscustomobject]@{ Kind = 'Integer'; Minimum = 100; Maximum = 100000; MaximumLength = $null; MaximumItems = $null; AllowedValues = $false }
    }
    ScheduledTasks = [ordered]@{
        TaskPath     = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 512; MaximumItems = $null; AllowedValues = $true }
        MaximumTasks = [pscustomobject]@{ Kind = 'Integer'; Minimum = 1; Maximum = 500; MaximumLength = $null; MaximumItems = $null; AllowedValues = $false }
    }
    EventLogQuery = [ordered]@{
        EventLogName = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 256; MaximumItems = $null; AllowedValues = $true }
        EntryCount   = [pscustomobject]@{ Kind = 'Integer'; Minimum = 1; Maximum = 1000; MaximumLength = $null; MaximumItems = $null; AllowedValues = $false }
        EventLevel   = [pscustomobject]@{ Kind = 'StringArray'; Minimum = $null; Maximum = $null; MaximumLength = 11; MaximumItems = 20; AllowedValues = $true }
    }
    RegistryRead = [ordered]@{
        RegistryPath      = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 2048; MaximumItems = $null; AllowedValues = $true }
        RegistryValueName = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 16383; MaximumItems = $null; AllowedValues = $true }
    }
    CustomCommand = [ordered]@{
        CommandText = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 32767; MaximumItems = $null; AllowedValues = $false }
    }
    CustomPowerShell = [ordered]@{
        PowerShellText = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 1048576; MaximumItems = $null; AllowedValues = $false }
        PowerShellFile = [pscustomobject]@{ Kind = 'String'; Minimum = $null; Maximum = $null; MaximumLength = 32767; MaximumItems = $null; AllowedValues = $false }
    }
}
$Script:ActionCapabilityRequirements = [ordered]@{
    SystemInfo        = [pscustomobject]@{ Commands = @('Get-CimInstance'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    DiskSpace         = [pscustomobject]@{ Commands = @('Get-CimInstance'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    HardwareInfo      = [pscustomobject]@{ Commands = @('Get-CimInstance'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    NetworkConfig     = [pscustomobject]@{ Commands = @('Get-CimInstance'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    LoggedOnUsers     = [pscustomobject]@{ Commands = @('Get-CimInstance', 'Get-CimAssociatedInstance'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    RunningProcesses  = [pscustomobject]@{ Commands = @('Get-Process'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    SoftwareInventory = [pscustomobject]@{ Commands = @('Get-ChildItem', 'Get-ItemProperty'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    LicenseStatus     = [pscustomobject]@{ Commands = @('Get-CimInstance'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    WindowsUpdate     = [pscustomobject]@{ Commands = @(); Executables = @(); ComObjects = @('Microsoft.Update.Session'); RequiresAdministrator = $true }
    ScheduleReboot    = [pscustomobject]@{ Commands = @(); Executables = @('shutdown.exe'); ComObjects = @(); RequiresAdministrator = $true }
    PendingReboot     = [pscustomobject]@{ Commands = @('Get-ItemProperty', 'Test-Path'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    ServiceManagement = [pscustomobject]@{ Commands = @('Get-Service'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    TerminateProcess  = [pscustomobject]@{ Commands = @('Get-Process', 'Stop-Process'); Executables = @(); ComObjects = @(); RequiresAdministrator = $true }
    ClearTempFiles    = [pscustomobject]@{ Commands = @('Get-ChildItem', 'Remove-Item'); Executables = @(); ComObjects = @(); RequiresAdministrator = $true }
    ScheduledTasks    = [pscustomobject]@{ Commands = @('Get-ScheduledTask', 'Get-ScheduledTaskInfo'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    FirewallStatus    = [pscustomobject]@{ Commands = @('Get-NetFirewallProfile'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    EventLogQuery     = [pscustomobject]@{ Commands = @('Get-WinEvent'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    RegistryRead      = [pscustomobject]@{ Commands = @('Get-ItemProperty', 'Test-Path'); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
    CustomCommand     = [pscustomobject]@{ Commands = @(); Executables = @('cmd.exe'); ComObjects = @(); RequiresAdministrator = $false }
    CustomPowerShell  = [pscustomobject]@{ Commands = @(); Executables = @(); ComObjects = @(); RequiresAdministrator = $false }
}

function Get-AdminActionCapabilityRequirement {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ActionId,

        [Parameter()]
        [System.Collections.IDictionary]$Inputs = @{}
    )

    if (-not $Script:ActionCapabilityRequirements.Contains($ActionId)) {
        throw "Unknown action capability identifier: $ActionId"
    }

    $baseRequirement = $Script:ActionCapabilityRequirements[$ActionId]
    $commands = New-Object 'System.Collections.Generic.List[string]'
    foreach ($commandName in @($baseRequirement.Commands)) {
        $commands.Add([string]$commandName) | Out-Null
    }
    $requiresAdministrator = [bool]$baseRequirement.RequiresAdministrator

    if ($ActionId -ceq 'ServiceManagement') {
        if (-not $Inputs.Contains('ServiceAction')) {
            throw 'ServiceManagement capability discovery requires a resolved ServiceAction input.'
        }
        switch ([string]$Inputs['ServiceAction']) {
            'Query' { }
            'Start' {
                $commands.Add('Start-Service') | Out-Null
                $requiresAdministrator = $true
            }
            'Stop' {
                $commands.Add('Stop-Service') | Out-Null
                $requiresAdministrator = $true
            }
            'Restart' {
                $commands.Add('Restart-Service') | Out-Null
                $requiresAdministrator = $true
            }
            default { throw 'ServiceManagement capability discovery received an unsupported ServiceAction input.' }
        }
    }

    return [pscustomobject][ordered]@{
        Commands              = @($commands.ToArray())
        Executables           = @($baseRequirement.Executables)
        ComObjects            = @($baseRequirement.ComObjects)
        RequiresAdministrator = $requiresAdministrator
    }
}

foreach ($catalogEntry in $Script:ActionCatalog.GetEnumerator()) {
    $classification = if ($catalogEntry.Value.Script -eq 'ServiceManagement') {
        'Conditional'
    }
    elseif ($catalogEntry.Value.ReadOnly) {
        'ReadOnly'
    }
    else {
        'StateChanging'
    }
    $confirmation = if ($Script:AutomationConfirmations.Contains($catalogEntry.Value.Script)) {
        $Script:AutomationConfirmations[$catalogEntry.Value.Script]
    }
    else {
        $null
    }

    $catalogEntry.Value | Add-Member -NotePropertyName Id -NotePropertyValue $catalogEntry.Value.Script -Force
    $catalogEntry.Value | Add-Member -NotePropertyName Classification -NotePropertyValue $classification -Force
    $catalogEntry.Value | Add-Member -NotePropertyName ConfirmationText -NotePropertyValue $confirmation -Force
}

function Get-AdminActionCatalogItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ActionId
    )

    foreach ($catalogEntry in $Script:ActionCatalog.GetEnumerator()) {
        if ($catalogEntry.Value.Id -ieq $ActionId) {
            return $catalogEntry.Value
        }
    }

    return $null
}

function Get-AdminSafeActionId {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ActionId
    )

    $value = if ($null -eq $ActionId) { '' } else { $ActionId.Trim() }
    if ($value -notmatch '^[A-Za-z][A-Za-z0-9]{0,63}$') {
        return $null
    }
    return $value
}

function Get-AdminActionCatalogItemByMenuNumber {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 20)]
        [int]$MenuNumber
    )

    foreach ($catalogEntry in $Script:ActionCatalog.GetEnumerator()) {
        if ([int]$catalogEntry.Key -eq $MenuNumber) {
            return $catalogEntry.Value
        }
    }

    return $null
}

function ConvertTo-AdminAutomationInputDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Type,

        [Parameter()]
        [bool]$Required = $false,

        [Parameter()]
        [AllowNull()]
        $DefaultValue = $null,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$AllowedValues = @(),

        [Parameter()]
        [AllowNull()]
        $Minimum = $null,

        [Parameter()]
        [AllowNull()]
        $Maximum = $null,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    return [pscustomobject][ordered]@{
        name          = $Name
        type          = $Type
        required      = $Required
        default       = $DefaultValue
        allowedValues = @($AllowedValues)
        minimum       = $Minimum
        maximum       = $Maximum
        description   = $Description
    }
}

function Get-AdminAutomationActionDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$CatalogItem,

        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile
    )

    $inputs = @()
    switch ($CatalogItem.Id) {
        'RunningProcesses' {
            $inputs = @(ConvertTo-AdminAutomationInputDescriptor -Name 'TopCount' -Type 'integer' -DefaultValue 20 -Minimum 1 -Maximum 100 -Description 'Maximum processes returned by working-set size.')
        }
        'WindowsUpdate' {
            $inputs = @(ConvertTo-AdminAutomationInputDescriptor -Name 'IncludeKB' -Type 'string[]' -DefaultValue @() -Description 'Up to 100 optional KB identifiers. An empty array selects all applicable software updates.')
        }
        'ScheduleReboot' {
            $inputs = @(ConvertTo-AdminAutomationInputDescriptor -Name 'RebootDelaySeconds' -Type 'integer' -DefaultValue 60 -Minimum 30 -Maximum 3600 -Description 'Delay before the requested reboot.')
        }
        'ServiceManagement' {
            $inputs = @(
                ConvertTo-AdminAutomationInputDescriptor -Name 'ServiceName' -Type 'string' -Required $true -Description 'Validated Windows service name.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'ServiceAction' -Type 'string' -DefaultValue 'Query' -AllowedValues @('Query', 'Start', 'Stop', 'Restart') -Description 'Query is read-only. Other values are state-changing.'
            )
        }
        'TerminateProcess' {
            $inputs = @(ConvertTo-AdminAutomationInputDescriptor -Name 'ProcessName' -Type 'string' -Required $true -Description 'Exact process name. Protected Windows processes remain blocked.')
        }
        'ClearTempFiles' {
            $inputs = @(
                ConvertTo-AdminAutomationInputDescriptor -Name 'MinimumAgeDays' -Type 'integer' -DefaultValue 2 -Minimum 1 -Maximum 30 -Description 'Minimum age of files eligible for deletion.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'MaximumFiles' -Type 'integer' -DefaultValue 50000 -Minimum 100 -Maximum 100000 -Description 'Maximum files examined per target.'
            )
        }
        'ScheduledTasks' {
            $inputs = @(
                ConvertTo-AdminAutomationInputDescriptor -Name 'TaskPath' -Type 'string' -DefaultValue '\' -Description 'Validated scheduled-task path prefix.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'MaximumTasks' -Type 'integer' -DefaultValue 50 -Minimum 1 -Maximum 500 -Description 'Maximum tasks returned per target.'
            )
        }
        'EventLogQuery' {
            $inputs = @(
                ConvertTo-AdminAutomationInputDescriptor -Name 'EventLogName' -Type 'string' -DefaultValue 'System' -Description 'Validated Windows event-log channel.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'EntryCount' -Type 'integer' -DefaultValue 20 -Minimum 1 -Maximum 1000 -Description 'Maximum events returned per target.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'EventLevel' -Type 'string[]' -DefaultValue @('Error', 'Warning') -AllowedValues @('Critical', 'Error', 'Warning', 'Information', 'Verbose') -Description 'One or more event severity levels.'
            )
        }
        'RegistryRead' {
            $inputs = @(
                ConvertTo-AdminAutomationInputDescriptor -Name 'RegistryPath' -Type 'string' -Required $true -Description 'Validated registry provider or hive path.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'RegistryValueName' -Type 'string' -DefaultValue '' -Description 'Optional value name. Empty returns all values.'
            )
        }
        'CustomCommand' {
            $inputs = @(ConvertTo-AdminAutomationInputDescriptor -Name 'CommandText' -Type 'string' -Required $true -Description 'Unsandboxed CMD command text, limited to 32767 characters.')
        }
        'CustomPowerShell' {
            $inputs = @(
                ConvertTo-AdminAutomationInputDescriptor -Name 'PowerShellText' -Type 'string' -Description 'Unsandboxed PowerShell source. Mutually exclusive with PowerShellFile.'
                ConvertTo-AdminAutomationInputDescriptor -Name 'PowerShellFile' -Type 'path' -Description 'Literal local .ps1 path, limited to 1 MiB. Mutually exclusive with PowerShellText.'
            )
        }
    }

    $policyDecision = 'NotApplied'
    $policyReasonCode = 'NoPolicy'
    if ($null -ne $PolicyProfile) {
        if ($CatalogItem.Id -cin $PolicyProfile.ActionsDeny) {
            $policyDecision = 'Denied'
            $policyReasonCode = 'ActionDenied'
        }
        elseif ($CatalogItem.Id -cnotin $PolicyProfile.ActionsAllow) {
            $policyDecision = 'Denied'
            $policyReasonCode = 'ActionNotAllowed'
        }
        else {
            $policyDecision = 'Allowed'
            $policyReasonCode = 'PolicyAllowed'
        }
    }

    return [pscustomobject][ordered]@{
        id               = $CatalogItem.Id
        displayName      = $CatalogItem.Name
        classification   = $CatalogItem.Classification
        confirmationText = $CatalogItem.ConfirmationText
        inputs           = @($inputs)
        policyDecision   = $policyDecision
        policyReasonCode = $policyReasonCode
    }
}

function Get-AdminAutomationActionCatalog {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile
    )

    $descriptors = New-Object 'System.Collections.Generic.List[object]'
    foreach ($catalogEntry in $Script:ActionCatalog.GetEnumerator()) {
        $descriptors.Add((Get-AdminAutomationActionDescriptor -CatalogItem $catalogEntry.Value -PolicyProfile $PolicyProfile)) | Out-Null
    }
    return $descriptors.ToArray()
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

    if (-not (Test-AdminLiteralFilePathText -LiteralPath $Path)) {
        throw 'The PsExec path contains an unsafe or unsupported component.'
    }

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
    $argumentBase64 = ConvertTo-AdminArgumentEnvelope -ArgumentList $ArgumentList

    $payload = @"
`$ErrorActionPreference = 'Stop'
`$utf8 = New-Object System.Text.UTF8Encoding(`$false)
`$actionText = `$utf8.GetString([Convert]::FromBase64String('$actionBase64'))
`$argumentXml = `$utf8.GetString([Convert]::FromBase64String('$argumentBase64'))
`$parsedArguments = [System.Management.Automation.PSSerializer]::Deserialize(`$argumentXml)
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

function ConvertTo-AdminArgumentEnvelope {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object[]]$ArgumentList = @()
    )

    $argumentXml = [System.Management.Automation.PSSerializer]::Serialize([object[]]$ArgumentList, 10)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    return [Convert]::ToBase64String($utf8.GetBytes($argumentXml))
}

function ConvertFrom-AdminArgumentEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$EncodedEnvelope
    )

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $argumentXml = $utf8.GetString([Convert]::FromBase64String($EncodedEnvelope))
    $parsedArguments = [System.Management.Automation.PSSerializer]::Deserialize($argumentXml)
    if ($null -eq $parsedArguments) {
        return @()
    }
    return @($parsedArguments)
}

function ConvertTo-AdminSafeErrorMessage {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Message,

        [Parameter()]
        [ValidateRange(128, 4096)]
        [int]$MaximumLength = 1024
    )

    if ($null -eq $Message) {
        return 'The operation failed without an error message.'
    }

    $safeMessage = ([string]$Message -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ' ' -replace '[\r\n\t]+', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($safeMessage)) {
        $safeMessage = 'The operation failed without an error message.'
    }
    if ($safeMessage.Length -gt $MaximumLength) {
        $safeMessage = $safeMessage.Substring(0, $MaximumLength) + ' [truncated]'
    }

    return $safeMessage
}

function Get-AdminErrorCategory {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Message
    )

    $text = [string]$Message
    if ($text -match '(?i)timed?\s*out|timeout') {
        return 'Timeout'
    }
    if ($text -match '(?i)access is denied|access denied|unauthorized|authentication|logon failure|credentials') {
        return 'Authentication'
    }
    if ($text -match '(?i)cannot connect|connection|unreachable|name resolution|network path|WinRM cannot|RPC server') {
        return 'Connectivity'
    }
    if ($text -match '(?i)output exceeded|output limit') {
        return 'OutputLimit'
    }
    if ($text -match '(?i)invalid|not supported|not found|required|must be') {
        return 'Validation'
    }

    return 'Execution'
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
        [int]$Attempts = 1,

        [Parameter()]
        [ValidateSet('Validation', 'Authorization', 'Authentication', 'Connectivity', 'Timeout', 'OutputLimit', 'Execution', 'Internal')]
        [string]$ErrorCategory
    )

    $safeMessage = ConvertTo-AdminSafeErrorMessage -Message $Message
    if ([string]::IsNullOrWhiteSpace($ErrorCategory)) {
        $ErrorCategory = Get-AdminErrorCategory -Message $safeMessage
    }

    return [pscustomobject]@{
        ComputerName = $ComputerName
        Transport    = $Transport
        Attempts     = $Attempts
        Success      = $false
        Data         = @()
        ErrorCategory = $ErrorCategory
        ErrorMessage = $safeMessage
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
        return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message 'The target computer name is invalid.' -ErrorCategory Validation
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
            return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message "Operation timed out after $TimeoutSeconds seconds." -ErrorCategory Timeout
        }
        if ($outputExceeded) {
            return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'PsExec' -Message "Operation output exceeded the $MaximumOutputBytes byte limit." -ErrorCategory OutputLimit
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
            ErrorCategory = if ([bool]$remoteEnvelope.Success) { $null } else { Get-AdminErrorCategory -Message $remoteEnvelope.ErrorMessage }
            ErrorMessage = if ([bool]$remoteEnvelope.Success) { $null } else { ConvertTo-AdminSafeErrorMessage -Message $remoteEnvelope.ErrorMessage }
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
        return ConvertTo-AdminFailureEnvelope -ComputerName $ComputerName -Transport 'WinRM' -Message 'The target computer name is invalid.' -ErrorCategory Validation
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
            ErrorCategory = $null
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

function Get-AdminEffectiveRetryCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ReadOnly
    )

    if ($ReadOnly) {
        return [int]$Script:State.RetryCount
    }
    return 0
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
        [int]$Attempts = 1,

        [Parameter()]
        [string]$ErrorCategory
    )

    $safeMessage = ConvertTo-AdminSafeErrorMessage -Message $Message
    if ([string]::IsNullOrWhiteSpace($ErrorCategory)) {
        $ErrorCategory = Get-AdminErrorCategory -Message $safeMessage
    }

    $Destination.Add([pscustomobject]@{
            ComputerName = $ComputerName
            Transport    = $Transport
            Attempts     = $Attempts
            Status       = 'Failed'
            ErrorCategory = $ErrorCategory
            ErrorMessage = $safeMessage
        }) | Out-Null
}

function Get-AdminTargetStatusFromData {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Data = @()
    )

    $statuses = @($Data | ForEach-Object {
            if ($null -ne $_ -and $null -ne $_.PSObject.Properties['Status']) {
                [string]$_.Status
            }
        })
    if (@($statuses | Where-Object { $_ -in @('Failed', 'Error') }).Count -gt 0) {
        return 'Failed'
    }
    if (@($statuses | Where-Object { $_ -in @('Partial', 'ChecksWithErrors') }).Count -gt 0) {
        return 'Partial'
    }

    return 'Success'
}

function ConvertTo-AdminDetailedTargetResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Index,

        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [datetime]$StartedAtUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$FinishedAtUtc,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Success', 'Partial', 'Failed', 'TimedOut', 'WhatIf', 'Skipped')]
        [string]$Status,

        [Parameter()]
        [int]$Attempts = 0,

        [Parameter()]
        [AllowNull()]
        [string]$ErrorCategory,

        [Parameter()]
        [AllowNull()]
        [string]$ErrorMessage,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Data = @()
    )

    $durationMilliseconds = [math]::Max(0, [math]::Round(($FinishedAtUtc - $StartedAtUtc).TotalMilliseconds))
    return [pscustomobject][ordered]@{
        Index          = $Index
        ComputerName   = $ComputerName
        Transport      = $Transport
        StartedAtUtc   = $StartedAtUtc.ToUniversalTime()
        FinishedAtUtc  = $FinishedAtUtc.ToUniversalTime()
        DurationMs     = [int64]$durationMilliseconds
        Status         = $Status
        Attempts       = $Attempts
        ErrorCategory  = $ErrorCategory
        ErrorMessage   = if ($ErrorMessage) { ConvertTo-AdminSafeErrorMessage -Message $ErrorMessage } else { $null }
        Data           = @($Data)
    }
}

function Invoke-AdminTargetDetailed {
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
        [bool]$ReadOnly = $true,

        [Parameter()]
        [ValidateRange(1, 32)]
        [int]$MaxConcurrentJobs = $Script:State.MaxConcurrentJobs,

        [Parameter()]
        [ValidateRange(0, 3)]
        [int]$RetryCount = $Script:State.RetryCount,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$RetryDelaySeconds = $Script:State.RetryDelaySeconds,

        [Parameter()]
        [ValidateRange(1, 180)]
        [int]$OperationTimeoutMinutes = $Script:State.OperationTimeoutMinutes
    )

    if (-not $Script:ActionScripts.Contains($ActionName) -and $ActionName -cne 'CapabilityPreflight') {
        throw "Unknown action script: $ActionName"
    }

    foreach ($computer in $Computers) {
        if ($TargetMode -eq 'Remote' -and -not (Test-AdminHostname -ComputerName $computer)) {
            throw "Invalid remote target: $computer"
        }
    }

    $actionBlock = if ($ActionName -ceq 'CapabilityPreflight') { $Script:CapabilityDiscoveryScript } else { $Script:ActionScripts[$ActionName] }
    $targetResults = New-Object 'System.Collections.Generic.List[object]'

    if ($TargetMode -eq 'Local') {
        $startedAtUtc = [datetime]::UtcNow
        $dataItems = New-Object 'System.Collections.Generic.List[object]'
        try {
            $data = @(& $actionBlock @ArgumentList)
            Add-AdminNormalizedData -Destination $dataItems -ComputerName $env:COMPUTERNAME -Data $data
            if ($dataItems.Count -eq 0) {
                $dataItems.Add([pscustomobject]@{
                        ComputerName = $env:COMPUTERNAME
                        Status       = 'Success'
                        Message      = 'The action completed without output.'
                    }) | Out-Null
            }
            $finishedAtUtc = [datetime]::UtcNow
            $targetStatus = Get-AdminTargetStatusFromData -Data $dataItems.ToArray()
            $targetErrorCategory = if ($targetStatus -eq 'Failed') { 'Execution' } else { $null }
            $targetErrorMessage = if ($targetStatus -eq 'Failed') { 'The action returned one or more failed result records.' } else { $null }
            $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index 0 -ComputerName $env:COMPUTERNAME -Transport 'Local' -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -Status $targetStatus -Attempts 1 -ErrorCategory $targetErrorCategory -ErrorMessage $targetErrorMessage -Data $dataItems.ToArray())) | Out-Null
        }
        catch {
            $finishedAtUtc = [datetime]::UtcNow
            $errorCategory = Get-AdminErrorCategory -Message $_.Exception.Message
            $safeMessage = if ($ActionName -in @('CustomCommand', 'CustomPowerShell')) {
                'The custom action failed. Operator-supplied error text was omitted.'
            }
            else {
                ConvertTo-AdminSafeErrorMessage -Message $_.Exception.Message
            }
            $failureStatus = if ($errorCategory -eq 'Timeout') { 'TimedOut' } else { 'Failed' }
            $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index 0 -ComputerName $env:COMPUTERNAME -Transport 'Local' -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -Status $failureStatus -Attempts 1 -ErrorCategory $errorCategory -ErrorMessage $safeMessage)) | Out-Null
        }
        return $targetResults.ToArray()
    }

    $actionText = $actionBlock.ToString()
    $argumentEnvelope = ConvertTo-AdminArgumentEnvelope -ArgumentList $ArgumentList
    $effectiveRetryCount = if ($ReadOnly) { $RetryCount } else { 0 }
    $timeoutSeconds = $OperationTimeoutMinutes * 60
    $targetIndex = 0
    $startedJobs = New-Object 'System.Collections.Generic.List[object]'

    try {
        while ($targetIndex -lt $Computers.Count) {
            $lastIndex = [math]::Min($targetIndex + $MaxConcurrentJobs - 1, $Computers.Count - 1)
            $batch = @($Computers[$targetIndex..$lastIndex])
            $records = New-Object System.Collections.ArrayList

        for ($batchIndex = 0; $batchIndex -lt $batch.Count; $batchIndex++) {
            $computer = $batch[$batchIndex]
            $absoluteIndex = $targetIndex + $batchIndex
            $startedAtUtc = [datetime]::UtcNow
            try {
                $job = Start-Job -Name ('AdminJob_{0}' -f [guid]::NewGuid().ToString('N')) -ScriptBlock {
                    param(
                        $ToolkitPath,
                        $SelectedTransport,
                        $TargetComputer,
                        [System.Management.Automation.PSCredential]$RemoteCredential,
                        $RemoteActionText,
                        $RemoteArgumentEnvelope,
                        $RemotePsExecPath,
                        $RemoteUseSsl,
                        $RemoteAuthentication,
                        $RemoteRetryCount,
                        $RemoteRetryDelay,
                        $RemoteTimeoutSeconds
                    )

                    . $ToolkitPath
                    $remoteArguments = @(ConvertFrom-AdminArgumentEnvelope -EncodedEnvelope $RemoteArgumentEnvelope)
                    Invoke-AdminTargetWithRetry -Transport $SelectedTransport -ComputerName $TargetComputer -Credential $RemoteCredential -ActionText $RemoteActionText -ArgumentList $remoteArguments -PsExecFullPath $RemotePsExecPath -UseSsl ([bool]$RemoteUseSsl) -Authentication $RemoteAuthentication -RetryCount $RemoteRetryCount -RetryDelaySeconds $RemoteRetryDelay -TimeoutSeconds $RemoteTimeoutSeconds
                } -ArgumentList @(
                    $Script:ToolkitPath,
                    $Script:State.Transport,
                    $computer,
                    $Script:State.Credential,
                    $actionText,
                    $argumentEnvelope,
                    $Script:State.PsExecFullPath,
                    $Script:State.UseSsl,
                    $Script:State.Authentication,
                    $effectiveRetryCount,
                    $RetryDelaySeconds,
                    $timeoutSeconds
                ) -ErrorAction Stop

                $startedJobs.Add($job) | Out-Null
                [void]$records.Add([pscustomobject]@{
                        Job          = $job
                        Index        = $absoluteIndex
                        ComputerName = $computer
                        StartedAtUtc = $startedAtUtc
                    })
            }
            catch {
                $finishedAtUtc = [datetime]::UtcNow
                $message = ConvertTo-AdminSafeErrorMessage -Message "Unable to start background job: $($_.Exception.Message)"
                $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index $absoluteIndex -ComputerName $computer -Transport $Script:State.Transport -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -Status Failed -ErrorCategory Internal -ErrorMessage $message)) | Out-Null
            }
        }

        $batchDeadline = (Get-Date).AddSeconds($timeoutSeconds + 30)
        while ($records.Count -gt 0) {
            foreach ($record in @($records.ToArray())) {
                $job = $record.Job
                if ($job.State -in @('Completed', 'Failed', 'Stopped')) {
                    $finishedAtUtc = [datetime]::UtcNow
                    $receiveErrors = @()
                    $envelopes = @(Receive-Job -Job $job -ErrorAction SilentlyContinue -ErrorVariable receiveErrors)
                    $envelope = $envelopes | Select-Object -Last 1

                    if ($null -eq $envelope) {
                        $message = if ($receiveErrors.Count -gt 0) { ($receiveErrors | ForEach-Object { $_.Exception.Message }) -join '; ' } else { "Job ended in state $($job.State) without a result." }
                        $safeMessage = if ($ActionName -in @('CustomCommand', 'CustomPowerShell')) { 'The custom action job failed without a safe result.' } else { ConvertTo-AdminSafeErrorMessage -Message $message }
                        $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index $record.Index -ComputerName $record.ComputerName -Transport $Script:State.Transport -StartedAtUtc $record.StartedAtUtc -FinishedAtUtc $finishedAtUtc -Status Failed -ErrorCategory Internal -ErrorMessage $safeMessage)) | Out-Null
                    }
                    elseif ($envelope.Success) {
                        $dataItems = New-Object 'System.Collections.Generic.List[object]'
                        Add-AdminNormalizedData -Destination $dataItems -ComputerName $record.ComputerName -Data $envelope.Data
                        if ($dataItems.Count -eq 0) {
                            $dataItems.Add([pscustomobject]@{
                                    ComputerName = $record.ComputerName
                                    Status       = 'Success'
                                    Message      = 'The action completed without output.'
                                }) | Out-Null
                        }
                        $targetStatus = Get-AdminTargetStatusFromData -Data $dataItems.ToArray()
                        $targetErrorCategory = if ($targetStatus -eq 'Failed') { 'Execution' } else { $null }
                        $targetErrorMessage = if ($targetStatus -eq 'Failed') { 'The action returned one or more failed result records.' } else { $null }
                        $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index $record.Index -ComputerName $record.ComputerName -Transport $Script:State.Transport -StartedAtUtc $record.StartedAtUtc -FinishedAtUtc $finishedAtUtc -Status $targetStatus -Attempts ([int]$envelope.Attempts) -ErrorCategory $targetErrorCategory -ErrorMessage $targetErrorMessage -Data $dataItems.ToArray())) | Out-Null
                    }
                    else {
                        $category = if ($envelope.ErrorCategory) { [string]$envelope.ErrorCategory } else { Get-AdminErrorCategory -Message $envelope.ErrorMessage }
                        $status = if ($category -eq 'Timeout') { 'TimedOut' } else { 'Failed' }
                        $targetErrorMessage = if ($ActionName -in @('CustomCommand', 'CustomPowerShell')) { 'The custom action failed. Operator-supplied error text was omitted.' } else { [string]$envelope.ErrorMessage }
                        $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index $record.Index -ComputerName $record.ComputerName -Transport $Script:State.Transport -StartedAtUtc $record.StartedAtUtc -FinishedAtUtc $finishedAtUtc -Status $status -Attempts ([int]$envelope.Attempts) -ErrorCategory $category -ErrorMessage $targetErrorMessage)) | Out-Null
                    }

                    Remove-Job -Job $job -Force -WhatIf:$false -Confirm:$false -ErrorAction SilentlyContinue
                    [void]$records.Remove($record)
                }
            }

            if ($records.Count -eq 0) {
                break
            }

            if ((Get-Date) -ge $batchDeadline) {
                foreach ($record in @($records.ToArray())) {
                    Stop-Job -Job $record.Job -WhatIf:$false -Confirm:$false -ErrorAction SilentlyContinue
                    Remove-Job -Job $record.Job -Force -WhatIf:$false -Confirm:$false -ErrorAction SilentlyContinue
                    $finishedAtUtc = [datetime]::UtcNow
                    $message = "Batch timeout exceeded after $OperationTimeoutMinutes minutes."
                    $targetResults.Add((ConvertTo-AdminDetailedTargetResult -Index $record.Index -ComputerName $record.ComputerName -Transport $Script:State.Transport -StartedAtUtc $record.StartedAtUtc -FinishedAtUtc $finishedAtUtc -Status TimedOut -ErrorCategory Timeout -ErrorMessage $message)) | Out-Null
                    [void]$records.Remove($record)
                }
                break
            }

            Start-Sleep -Milliseconds 250
        }

            $targetIndex = $lastIndex + 1
        }
    }
    finally {
        foreach ($startedJob in @($startedJobs.ToArray())) {
            if ($startedJob.State -notin @('Completed', 'Failed', 'Stopped')) {
                Stop-Job -Job $startedJob -WhatIf:$false -Confirm:$false -ErrorAction SilentlyContinue
            }
            Remove-Job -Job $startedJob -Force -WhatIf:$false -Confirm:$false -ErrorAction SilentlyContinue
        }
    }

    return @($targetResults.ToArray() | Sort-Object -Property Index)
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

    $results = New-Object 'System.Collections.Generic.List[object]'
    $targetResults = @(Invoke-AdminTargetDetailed -TargetMode $TargetMode -Computers $Computers -ActionName $ActionName -ArgumentList $ArgumentList -ReadOnly $ReadOnly)
    foreach ($targetResult in $targetResults) {
        if (@($targetResult.Data).Count -gt 0) {
            foreach ($item in @($targetResult.Data)) {
                $results.Add($item) | Out-Null
            }
        }
        elseif ($targetResult.Status -in @('Failed', 'TimedOut')) {
            Add-AdminFailureResult -Destination $results -ComputerName $targetResult.ComputerName -Transport $targetResult.Transport -Message $targetResult.ErrorMessage -Attempts $targetResult.Attempts -ErrorCategory $targetResult.ErrorCategory
        }
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
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile
    )

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

    $contextTransport = if ($targetMode -eq 'Local') { 'Local' } else { $Script:State.Transport }
    $earlyPolicyDecision = Get-AdminPolicyExecutionContextDecision -PolicyProfile $PolicyProfile -TargetMode $targetMode -Transport $contextTransport
    if ($earlyPolicyDecision.decision -eq 'Denied') {
        Write-AdminLog -Message ("Policy denied the selected target mode or transport: {0}." -f $earlyPolicyDecision.reasonCode) -Level ERROR -NoConsole
        throw $earlyPolicyDecision.reason
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

    $targetPolicyResolution = Resolve-AdminPolicyContext -PolicyProfile $PolicyProfile -TargetMode Remote -Transport $Script:State.Transport -Computers $computers -Parameters $Script:InvocationParameters
    if (-not $targetPolicyResolution.Allowed) {
        Write-AdminLog -Message ("Policy denied the selected remote targets: {0}." -f $targetPolicyResolution.PolicyDecision.reasonCode) -Level ERROR -NoConsole
        throw $targetPolicyResolution.PolicyDecision.reason
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

    $catalogItem = Get-AdminActionCatalogItemByMenuNumber -MenuNumber $Choice
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
            $arguments = @($logName, $count, [string[]]$levels)
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

function Test-AdminParameterBound {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return $Parameters.Contains($Name)
}

function Get-AdminRequestedTargetSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters
    )

    $localSelected = (Test-AdminParameterBound -Parameters $Parameters -Name 'Local') -and [bool]$Parameters['Local']
    $computerNameSelected = (Test-AdminParameterBound -Parameters $Parameters -Name 'ComputerName') -and -not [string]::IsNullOrWhiteSpace([string]$Parameters['ComputerName'])
    $computerListSelected = (Test-AdminParameterBound -Parameters $Parameters -Name 'ComputerListPath') -and -not [string]::IsNullOrWhiteSpace([string]$Parameters['ComputerListPath'])
    $selectorCount = [int]$localSelected + [int]$computerNameSelected + [int]$computerListSelected
    if ($selectorCount -ne 1) {
        return [pscustomobject]@{
            TargetMode           = $null
            RequestedTargetCount = 0
            Transport            = $null
            Authentication       = $null
            UseSsl               = $false
        }
    }

    if ($localSelected) {
        return [pscustomobject]@{
            TargetMode           = 'Local'
            RequestedTargetCount = 1
            Transport            = 'Local'
            Authentication       = $null
            UseSsl               = $false
        }
    }

    $transportName = if ($Script:State.Transport -in @('WinRM', 'PsExec')) { $Script:State.Transport } else { $null }
    $authenticationName = if ($transportName -eq 'WinRM' -and $Script:State.Authentication -in @('Default', 'Kerberos', 'Negotiate')) { $Script:State.Authentication } else { $null }
    return [pscustomobject]@{
        TargetMode           = 'Remote'
        RequestedTargetCount = if ($computerNameSelected) { 1 } else { 0 }
        Transport            = $transportName
        Authentication       = $authenticationName
        UseSsl               = $transportName -eq 'WinRM' -and [bool]$Script:State.UseSsl
    }
}

function ConvertTo-AdminUtcTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Value
    )

    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-AdminNormalizedUtcTimestamp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    if ($Value -is [datetime]) {
        return ConvertTo-AdminUtcTimestamp -Value ([datetime]$Value)
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    $parsedValue = [datetime]::Parse(
        [string]$Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    )
    return ConvertTo-AdminUtcTimestamp -Value $parsedValue
}

function ConvertTo-AdminCanonicalJsonString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        $characterCode = [int]$character
        switch ($characterCode) {
            8 { [void]$builder.Append('\b'); continue }
            9 { [void]$builder.Append('\t'); continue }
            10 { [void]$builder.Append('\n'); continue }
            12 { [void]$builder.Append('\f'); continue }
            13 { [void]$builder.Append('\r'); continue }
            34 { [void]$builder.Append('\"'); continue }
            92 { [void]$builder.Append('\\'); continue }
        }
        if ($characterCode -lt 0x20 -or $characterCode -gt 0x7E) {
            [void]$builder.Append(('\u{0:x4}' -f $characterCode))
        }
        else {
            [void]$builder.Append($character)
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-AdminCanonicalJson {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter()]
        [ValidateRange(0, 30)]
        [int]$Depth = 0
    )

    if ($Depth -gt 20) {
        throw 'Canonical JSON exceeds the supported nesting depth.'
    }
    if ($null -eq $Value) {
        return 'null'
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid] -or
        $Value -is [version] -or $Value -is [uri] -or $Value.GetType().IsEnum) {
        return ConvertTo-AdminCanonicalJsonString -Value ([string]$Value)
    }
    if ($Value -is [datetime]) {
        return ConvertTo-AdminCanonicalJsonString -Value (ConvertTo-AdminUtcTimestamp -Value $Value)
    }
    if ($Value -is [datetimeoffset]) {
        return ConvertTo-AdminCanonicalJsonString -Value $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [bool]) {
        return $(if ($Value) { 'true' } else { 'false' })
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]) {
        return ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture))
    }
    if ($Value -is [decimal]) {
        return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [single] -or $Value -is [double]) {
        $floatingPointValue = [double]$Value
        if ([double]::IsNaN($floatingPointValue) -or [double]::IsInfinity($floatingPointValue)) {
            throw 'Canonical JSON does not permit non-finite numbers.'
        }
        return $floatingPointValue.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $propertyNames = New-Object 'System.Collections.Generic.List[string]'
        foreach ($key in $Value.Keys) {
            if ($null -eq $key) {
                throw 'Canonical JSON object keys cannot be null.'
            }
            $propertyNames.Add([string]$key) | Out-Null
        }
        $sortedPropertyNames = [string[]]$propertyNames.ToArray()
        [System.Array]::Sort($sortedPropertyNames, [System.StringComparer]::Ordinal)
        $members = New-Object 'System.Collections.Generic.List[string]'
        foreach ($propertyName in $sortedPropertyNames) {
            $members.Add(('{0}:{1}' -f (ConvertTo-AdminCanonicalJsonString -Value $propertyName), (ConvertTo-AdminCanonicalJson -Value $Value[$propertyName] -Depth ($Depth + 1)))) | Out-Null
        }
        return '{' + ($members.ToArray() -join ',') + '}'
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $Value) {
            $items.Add((ConvertTo-AdminCanonicalJson -Value $item -Depth ($Depth + 1))) | Out-Null
        }
        return '[' + ($items.ToArray() -join ',') + ']'
    }

    $objectPropertyNames = [string[]]@($Value.PSObject.Properties.Name)
    [System.Array]::Sort($objectPropertyNames, [System.StringComparer]::Ordinal)
    $objectMembers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($propertyName in $objectPropertyNames) {
        $objectMembers.Add(('{0}:{1}' -f (ConvertTo-AdminCanonicalJsonString -Value $propertyName), (ConvertTo-AdminCanonicalJson -Value $Value.$propertyName -Depth ($Depth + 1)))) | Out-Null
    }
    return '{' + ($objectMembers.ToArray() -join ',') + '}'
}

function Get-AdminSha256Hex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $hashBytes = $sha256.ComputeHash($encoding.GetBytes($Text))
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-AdminStableTargetId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
    )

    $identityText = 'WAT-TARGET-1|' + $ComputerName.ToUpperInvariant()
    return 't-' + (Get-AdminSha256Hex -Text $identityText).Substring(0, 24)
}

function Resolve-AdminAuditPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$LiteralPath,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$CollisionPaths = @()
    )

    $requestedPath = $LiteralPath.Trim()
    if ([string]::IsNullOrWhiteSpace($requestedPath)) {
        throw 'AuditPath cannot be empty when supplied.'
    }
    if ($requestedPath -ceq '-' -or $requestedPath -ieq 'STDOUT') {
        throw 'AuditPath must be a new .jsonl file and cannot use stdout.'
    }
    if (-not (Test-AdminLiteralFilePathText -LiteralPath $requestedPath)) {
        throw 'The audit path contains an unsafe or unsupported component.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($requestedPath)
    if (-not $fullPath.EndsWith('.jsonl', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'AuditPath must use the .jsonl extension.'
    }
    foreach ($collisionPath in @($CollisionPaths)) {
        if ([string]::IsNullOrWhiteSpace($collisionPath) -or $collisionPath -ceq '-') {
            continue
        }
        $fullCollisionPath = [System.IO.Path]::GetFullPath($collisionPath)
        if ($fullPath.Equals($fullCollisionPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'AuditPath must be different from every other configured output path.'
        }
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw "Refusing to append to or overwrite an existing audit file: $fullPath"
    }
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw 'AuditPath must include a valid parent directory.'
    }
    if ((Test-Path -LiteralPath $parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw 'The audit parent path is not a directory.'
    }
    return $fullPath
}

function Initialize-AdminAuditContext {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [string]$ResolvedAuditPath,

        [Parameter()]
        [bool]$EventLogEnabled = $false,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$EventSource = 'WindowsAdminToolkit'
    )

    $eventSourceName = $EventSource.Trim()
    if ($EventLogEnabled) {
        if ($eventSourceName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$') {
            throw 'AuditEventSource contains unsupported characters or exceeds 128 characters.'
        }
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventSourceName)) {
                throw "Windows Event Log source '$eventSourceName' is not registered. The toolkit will not create it automatically."
            }
        }
        catch {
            if ($_.Exception.Message -match 'not registered') {
                throw
            }
            throw "Unable to validate Windows Event Log source '$eventSourceName': $($_.Exception.Message)"
        }
    }

    $context = [pscustomobject][ordered]@{
        Enabled         = -not [string]::IsNullOrWhiteSpace([string]$ResolvedAuditPath) -or $EventLogEnabled
        Path            = if ([string]::IsNullOrWhiteSpace([string]$ResolvedAuditPath)) { $null } else { [string]$ResolvedAuditPath }
        EventLogEnabled = [bool]$EventLogEnabled
        EventSource     = if ($EventLogEnabled) { $eventSourceName } else { $null }
        RecordCount     = 0
        BytesWritten    = [int64]0
        SinkFailed      = $false
        Complete        = $false
        SummaryHash     = $null
        RequestRecorded = $false
        PolicyRecorded  = $false
        StartedTargetIds = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal))
    }

    if ($context.Path) {
        $parent = Split-Path -Parent $context.Path
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            [void][System.IO.Directory]::CreateDirectory($parent)
        }
        $stream = $null
        try {
            $stream = New-Object System.IO.FileStream($context.Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        }
        finally {
            if ($stream) {
                $stream.Dispose()
            }
        }
    }

    return $context
}

function ConvertTo-AdminAuditEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$RunId,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000000)]
        [int]$Sequence,

        [Parameter(Mandatory = $true)]
        [ValidateSet('run.started', 'request.resolved', 'policy.decision', 'target.started', 'target.completed', 'run.summary', 'audit.failure')]
        [string]$EventType,

        [Parameter(Mandatory = $true)]
        [datetime]$TimestampUtc,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Initialization', 'Request', 'Authorization', 'Connectivity', 'Execution', 'Summary', 'Audit')]
        [string]$Stage,

        [Parameter()]
        [AllowNull()]
        $ActionId,

        [Parameter()]
        [AllowNull()]
        $Target,

        [Parameter()]
        [AllowNull()]
        $Outcome,

        [Parameter()]
        [AllowNull()]
        $DurationMs,

        [Parameter()]
        [AllowNull()]
        $Policy,

        [Parameter()]
        [AllowNull()]
        $ErrorRecord,

        [Parameter()]
        [AllowNull()]
        $Summary
    )

    return [pscustomobject][ordered]@{
        schemaVersion  = $Script:AuditSchemaVersion
        eventId        = '{0}:{1:D6}' -f $RunId.ToString('D'), $Sequence
        sequence       = [int]$Sequence
        eventType      = $EventType
        timestampUtc   = ConvertTo-AdminUtcTimestamp -Value $TimestampUtc
        runId          = $RunId.ToString('D')
        toolkitVersion = $Script:ToolkitVersion
        stage          = $Stage
        actionId       = if ([string]::IsNullOrWhiteSpace([string]$ActionId)) { $null } else { [string]$ActionId }
        target         = $Target
        outcome        = if ([string]::IsNullOrWhiteSpace([string]$Outcome)) { $null } else { [string]$Outcome }
        durationMs     = if ($null -eq $DurationMs) { $null } else { [int64]$DurationMs }
        policy         = $Policy
        error          = $ErrorRecord
        summary        = $Summary
    }
}

function Write-AdminAuditRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Context,

        [Parameter(Mandatory = $true)]
        [psobject]$Event
    )

    if ([bool]$Context.SinkFailed) {
        throw 'The configured audit sink previously failed during this run and cannot be reused.'
    }

    try {
        $json = ConvertTo-Json -InputObject $Event -Compress -Depth 20
        $encoding = New-Object System.Text.UTF8Encoding($false, $true)
        $recordBytes = $encoding.GetBytes($json + "`n")
        if (($Context.BytesWritten + $recordBytes.Length) -gt $Script:AuditMaximumBytes) {
            throw "The per-run audit file exceeded the $Script:AuditMaximumBytes byte safety limit."
        }

        if ($Context.Path) {
            $stream = $null
            try {
                $stream = New-Object System.IO.FileStream($Context.Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
                if ($stream.Length -ne $Context.BytesWritten) {
                    throw 'The audit file changed unexpectedly during the run.'
                }
                [void]$stream.Seek(0, [System.IO.SeekOrigin]::End)
                $stream.Write($recordBytes, 0, $recordBytes.Length)
                $stream.Flush()
                $Context.BytesWritten = [int64]($Context.BytesWritten + $recordBytes.Length)
            }
            finally {
                if ($stream) {
                    $stream.Dispose()
                }
            }
        }

        if ($Context.EventLogEnabled) {
            if ($json.Length -gt 30000) {
                throw 'The audit record exceeds the safe Windows Event Log message limit.'
            }
            $eventIdMap = @{
                'run.started'      = 1000
                'request.resolved' = 1001
                'policy.decision'  = 1002
                'target.started'   = 1100
                'target.completed' = 1101
                'run.summary'      = 1200
                'audit.failure'    = 1900
            }
            try {
                [System.Diagnostics.EventLog]::WriteEntry($Context.EventSource, $json, [System.Diagnostics.EventLogEntryType]::Information, [int]$eventIdMap[$Event.eventType])
            }
            catch {
                throw "Unable to write the configured Windows Event Log audit sink: $($_.Exception.Message)"
            }
        }

        $Context.RecordCount = [int]$Context.RecordCount + 1
        return $Event
    }
    catch {
        $Context.SinkFailed = $true
        throw
    }
}

function Get-AdminAuditStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$Context
    )

    $enabled = $null -ne $Context -and [bool]$Context.Enabled
    return [pscustomobject][ordered]@{
        enabled          = $enabled
        schemaVersion    = if ($enabled) { $Script:AuditSchemaVersion } else { $null }
        path             = if ($enabled -and $Context.Path) { [string]$Context.Path } else { $null }
        eventLog         = $enabled -and [bool]$Context.EventLogEnabled
        eventSource      = if ($enabled -and $Context.EventLogEnabled) { [string]$Context.EventSource } else { $null }
        recordCount      = if ($enabled) { [int]$Context.RecordCount } else { 0 }
        complete         = $enabled -and -not [bool]$Context.SinkFailed -and [bool]$Context.Complete
        hashAlgorithm    = if ($enabled -and $Context.SummaryHash) { 'SHA-256' } else { $null }
        canonicalization = if ($enabled -and $Context.SummaryHash) { $Script:AuditCanonicalization } else { $null }
        summaryHash      = if ($enabled -and $Context.SummaryHash) { [string]$Context.SummaryHash } else { $null }
    }
}

function ConvertTo-AdminJsonSafeValue {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter()]
        [ValidateRange(0, 20)]
        [int]$Depth = 0,

        [Parameter()]
        [ValidateRange(1, 20)]
        [int]$MaximumDepth = 10
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Depth -ge $MaximumDepth) {
        return '[maximum depth exceeded]'
    }
    if ($Value -is [System.Management.Automation.PSCredential] -or
        $Value -is [System.Security.SecureString] -or
        $Value -is [scriptblock] -or
        $Value -is [System.Exception] -or
        $Value -is [System.Management.Automation.ErrorRecord]) {
        return $null
    }
    if ($Value -is [datetime]) {
        return ConvertTo-AdminUtcTimestamp -Value $Value
    }
    if ($Value -is [datetimeoffset]) {
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [timespan]) {
        return $Value.ToString('c', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    if ($Value -is [guid] -or $Value -is [version] -or $Value -is [uri] -or $Value.GetType().IsEnum) {
        return [string]$Value
    }
    if ($Value -is [single] -or $Value -is [double]) {
        $floatingPointValue = [double]$Value
        if ([double]::IsNaN($floatingPointValue)) {
            return 'NaN'
        }
        if ([double]::IsPositiveInfinity($floatingPointValue)) {
            return 'Infinity'
        }
        if ([double]::IsNegativeInfinity($floatingPointValue)) {
            return '-Infinity'
        }
        return $Value
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [bool] -or
        $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or $Value -is [decimal]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $safeDictionary = [ordered]@{}
        $dictionaryEntries = New-Object 'System.Collections.Generic.List[object]'
        $dictionaryIndex = 0
        foreach ($dictionaryEntry in $Value.GetEnumerator()) {
            $dictionaryKey = $dictionaryEntry.Key
            if ($null -eq $dictionaryKey) {
                $dictionaryKeyText = ''
                $dictionaryKeyType = ''
            }
            else {
                $dictionaryKeyType = $dictionaryKey.GetType().FullName
                if ($dictionaryKey -is [System.IFormattable]) {
                    $dictionaryKeyText = $dictionaryKey.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture)
                }
                else {
                    $dictionaryKeyText = [string]$dictionaryKey
                }
            }

            $dictionaryEntries.Add([pscustomobject]@{
                    KeyText = $dictionaryKeyText
                    SortKey = ('{0}{1}{2}{1}{3:D10}' -f $dictionaryKeyText, ([char]0), $dictionaryKeyType, $dictionaryIndex)
                    Value   = $dictionaryEntry.Value
                }) | Out-Null
            $dictionaryIndex++
        }

        [string[]]$dictionarySortKeys = @($dictionaryEntries | ForEach-Object { $_.SortKey })
        [object[]]$sortedDictionaryEntries = @($dictionaryEntries.ToArray())
        [System.Array]::Sort(
            [System.Array]$dictionarySortKeys,
            [System.Array]$sortedDictionaryEntries,
            [System.StringComparer]::Ordinal
        )

        foreach ($dictionaryEntry in $sortedDictionaryEntries) {
            $dictionaryKeyText = [string]$dictionaryEntry.KeyText
            if ($dictionaryKeyText -match '^(?i:Credential|Password|SecureString|ScriptBlock|InvocationInfo|Exception|RunspaceId|PSComputerName|PSShowComputerName)$') {
                continue
            }

            $outputKey = $dictionaryKeyText
            $outputKeySuffix = 2
            while ($safeDictionary.Contains($outputKey)) {
                $outputKey = '{0}#{1}' -f $dictionaryKeyText, $outputKeySuffix
                $outputKeySuffix++
            }
            $safeDictionary[$outputKey] = ConvertTo-AdminJsonSafeValue -Value $dictionaryEntry.Value -Depth ($Depth + 1) -MaximumDepth $MaximumDepth
        }
        return [pscustomobject]$safeDictionary
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $safeItems = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Value) {
            $safeItems.Add((ConvertTo-AdminJsonSafeValue -Value $item -Depth ($Depth + 1) -MaximumDepth $MaximumDepth)) | Out-Null
        }
        return , $safeItems.ToArray()
    }

    $safeObject = [ordered]@{}
    [string[]]$propertyNames = @($Value.PSObject.Properties.Name | Sort-Object -Unique)
    [array]::Sort($propertyNames, [System.StringComparer]::Ordinal)
    foreach ($propertyName in $propertyNames) {
        if ($propertyName -match '^(?i:Credential|Password|SecureString|ScriptBlock|InvocationInfo|Exception|RunspaceId|PSComputerName|PSShowComputerName)$') {
            continue
        }
        try {
            $safeObject[$propertyName] = ConvertTo-AdminJsonSafeValue -Value $Value.$propertyName -Depth ($Depth + 1) -MaximumDepth $MaximumDepth
        }
        catch {
            $safeObject[$propertyName] = $null
        }
    }

    if ($safeObject.Count -eq 0) {
        return [string]$Value
    }
    return [pscustomobject]$safeObject
}

function ConvertTo-AdminAutomationTargetEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$TargetResult
    )

    $safeData = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @($TargetResult.Data)) {
        $safeData.Add((ConvertTo-AdminJsonSafeValue -Value $item -MaximumDepth 10)) | Out-Null
    }

    return [pscustomobject][ordered]@{
        targetId       = Get-AdminStableTargetId -ComputerName ([string]$TargetResult.ComputerName)
        target         = [string]$TargetResult.ComputerName
        status         = [string]$TargetResult.Status
        startedAtUtc   = ConvertTo-AdminUtcTimestamp -Value $TargetResult.StartedAtUtc
        finishedAtUtc  = ConvertTo-AdminUtcTimestamp -Value $TargetResult.FinishedAtUtc
        durationMs     = [int64]$TargetResult.DurationMs
        attempts       = [int]$TargetResult.Attempts
        errorCategory  = if ($TargetResult.ErrorCategory) { [string]$TargetResult.ErrorCategory } else { $null }
        errorMessage   = if ($TargetResult.ErrorMessage) { ConvertTo-AdminSafeErrorMessage -Message $TargetResult.ErrorMessage } else { $null }
        data           = @($safeData.ToArray())
    }
}

function ConvertTo-AdminAutomationEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$RunId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartedAtUtc,

        [Parameter(Mandatory = $true)]
        [datetime]$FinishedAtUtc,

        [Parameter()]
        [AllowNull()]
        $ActionId,

        [Parameter()]
        [AllowNull()]
        $ActionName,

        [Parameter()]
        [AllowNull()]
        $ReadOnly,

        [Parameter()]
        [bool]$Preflight = $false,

        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyDecision,

        [Parameter()]
        [AllowNull()]
        $TargetMode,

        [Parameter()]
        [AllowNull()]
        $Transport,

        [Parameter()]
        [AllowNull()]
        $Authentication,

        [Parameter()]
        [bool]$UseSsl = $false,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Outcome,

        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [Parameter()]
        [ValidateRange(0, 1000)]
        [int]$RequestedTargetCount = 0,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$TargetResults = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$Warnings = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Errors = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$ReportPaths = @(),

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$Actions = @(),

        [Parameter()]
        [AllowNull()]
        [psobject]$Audit
    )

    $targets = New-Object 'System.Collections.Generic.List[object]'
    $recordCount = 0
    foreach ($targetResult in @($TargetResults | Sort-Object -Property Index)) {
        $targetEnvelope = ConvertTo-AdminAutomationTargetEnvelope -TargetResult $targetResult
        $targets.Add($targetEnvelope) | Out-Null
        $recordCount += @($targetEnvelope.data).Count
    }

    $durationMilliseconds = [math]::Max(0, [math]::Round(($FinishedAtUtc - $StartedAtUtc).TotalMilliseconds))
    $readOnlyValue = if ($null -eq $ReadOnly) { $null } else { [bool]$ReadOnly }
    $stateChangingValue = if ($null -eq $ReadOnly) { $null } else { -not [bool]$ReadOnly }
    $safeErrors = New-Object 'System.Collections.Generic.List[object]'
    foreach ($errorItem in @($Errors)) {
        $safeErrors.Add([pscustomobject][ordered]@{
                category = [string]$errorItem.Category
                message  = ConvertTo-AdminSafeErrorMessage -Message $errorItem.Message
            }) | Out-Null
    }
    $canonicalActionId = $null
    if (-not [string]::IsNullOrWhiteSpace([string]$ActionId)) {
        $safeActionId = Get-AdminSafeActionId -ActionId ([string]$ActionId)
        $canonicalActionItem = if ($safeActionId) { Get-AdminActionCatalogItem -ActionId $safeActionId } else { $null }
        if ($canonicalActionItem) {
            $canonicalActionId = $canonicalActionItem.Id
        }
    }
    if ($null -eq $PolicyDecision) {
        $PolicyDecision = ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
    }
    if ($null -eq $Audit) {
        $Audit = Get-AdminAuditStatus
    }
    $safePolicyDecision = [pscustomobject][ordered]@{
        applied       = [bool]$PolicyDecision.applied
        schemaVersion = if ([string]::IsNullOrWhiteSpace([string]$PolicyDecision.schemaVersion)) { $null } else { [string]$PolicyDecision.schemaVersion }
        profileName   = if ([string]::IsNullOrWhiteSpace([string]$PolicyDecision.profileName)) { $null } else { [string]$PolicyDecision.profileName }
        decision      = if ([string]$PolicyDecision.decision -in @('NotApplied', 'NotEvaluated', 'Allowed', 'Denied', 'Invalid')) { [string]$PolicyDecision.decision } else { 'Invalid' }
        reasonCode    = if ([string]$PolicyDecision.reasonCode -match '^[A-Za-z][A-Za-z0-9]{0,63}$') { [string]$PolicyDecision.reasonCode } else { 'PolicyInvalid' }
        reason        = ConvertTo-AdminSafeErrorMessage -Message $PolicyDecision.reason
    }

    return [pscustomobject][ordered]@{
        schemaVersion  = $Script:AutomationSchemaVersion
        toolkitVersion = $Script:ToolkitVersion
        runId          = $RunId.ToString('D')
        startedAtUtc   = ConvertTo-AdminUtcTimestamp -Value $StartedAtUtc
        finishedAtUtc  = ConvertTo-AdminUtcTimestamp -Value $FinishedAtUtc
        durationMs     = [int64]$durationMilliseconds
        actionId       = $canonicalActionId
        actionName     = if ([string]::IsNullOrWhiteSpace([string]$ActionName)) { $null } else { [string]$ActionName }
        readOnly       = $readOnlyValue
        stateChanging  = $stateChangingValue
        preflight      = [bool]$Preflight
        targetMode     = if ($TargetMode -in @('Local', 'Remote')) { [string]$TargetMode } else { $null }
        transport      = [pscustomobject][ordered]@{
            name           = if ($Transport -in @('Local', 'WinRM', 'PsExec')) { [string]$Transport } else { $null }
            authentication = if ($Authentication -in @('Default', 'Kerberos', 'Negotiate')) { [string]$Authentication } else { $null }
            useSsl         = [bool]$UseSsl
        }
        policy         = $safePolicyDecision
        audit          = $Audit
        status         = $Status
        outcome        = $Outcome
        exitCode       = [int]$ExitCode
        targetCount    = [int]$RequestedTargetCount
        recordCount    = [int]$recordCount
        targets        = @($targets.ToArray())
        warnings       = @($Warnings | ForEach-Object { [string]$_ })
        errors         = @($safeErrors.ToArray())
        reportPaths    = @($ReportPaths | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
        actions        = @($Actions)
    }
}

function ConvertTo-AdminAutomationJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Envelope
    )

    return ConvertTo-Json -InputObject $Envelope -Compress -Depth 20
}

function Get-AdminAuditRunSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [psobject]$Context
    )

    $targetSummaries = New-Object 'System.Collections.Generic.List[object]'
    $succeededCount = 0
    $partialCount = 0
    $failedCount = 0
    $timedOutCount = 0
    $skippedCount = 0
    $whatIfCount = 0
    $targetIndex = 0
    foreach ($target in @($Envelope.targets)) {
        switch ([string]$target.status) {
            'Success' { $succeededCount++ }
            'Partial' { $partialCount++ }
            'Failed' { $failedCount++ }
            'TimedOut' { $timedOutCount++ }
            'Skipped' { $skippedCount++ }
            'WhatIf' { $whatIfCount++ }
        }
        $targetSummaries.Add([pscustomobject][ordered]@{
                targetId      = [string]$target.targetId
                index         = [int]$targetIndex
                target        = [string]$target.target
                status        = [string]$target.status
                startedAtUtc  = ConvertTo-AdminNormalizedUtcTimestamp -Value $target.startedAtUtc
                finishedAtUtc = ConvertTo-AdminNormalizedUtcTimestamp -Value $target.finishedAtUtc
                durationMs    = [int64]$target.durationMs
                attempts      = [int]$target.attempts
                errorCategory = if ($target.errorCategory) { [string]$target.errorCategory } else { $null }
            }) | Out-Null
        $targetIndex++
    }

    $canonicalPayload = [pscustomobject][ordered]@{
        canonicalization = $Script:AuditCanonicalization
        auditSchemaVersion = $Script:AuditSchemaVersion
        toolkitVersion   = [string]$Envelope.toolkitVersion
        runId            = [string]$Envelope.runId
        startedAtUtc     = ConvertTo-AdminNormalizedUtcTimestamp -Value $Envelope.startedAtUtc
        finishedAtUtc    = ConvertTo-AdminNormalizedUtcTimestamp -Value $Envelope.finishedAtUtc
        durationMs       = [int64]$Envelope.durationMs
        actionId         = if ($Envelope.actionId) { [string]$Envelope.actionId } else { $null }
        targetMode       = if ($Envelope.targetMode) { [string]$Envelope.targetMode } else { $null }
        transport        = [pscustomobject][ordered]@{
            name           = if ($Envelope.transport.name) { [string]$Envelope.transport.name } else { $null }
            authentication = if ($Envelope.transport.authentication) { [string]$Envelope.transport.authentication } else { $null }
            useSsl         = [bool]$Envelope.transport.useSsl
        }
        policy           = [pscustomobject][ordered]@{
            applied       = [bool]$Envelope.policy.applied
            schemaVersion = if ($Envelope.policy.schemaVersion) { [string]$Envelope.policy.schemaVersion } else { $null }
            profileName   = if ($Envelope.policy.profileName) { [string]$Envelope.policy.profileName } else { $null }
            decision      = [string]$Envelope.policy.decision
            reasonCode    = [string]$Envelope.policy.reasonCode
        }
        status           = [string]$Envelope.status
        outcome          = [string]$Envelope.outcome
        exitCode         = [int]$Envelope.exitCode
        targetCount      = [int]$Envelope.targetCount
        recordCount      = [int]$Envelope.recordCount
        auditRecordCount = [int]$Context.RecordCount + 1
        targets          = @($targetSummaries.ToArray())
    }
    $canonicalJson = ConvertTo-AdminCanonicalJson -Value $canonicalPayload
    $summaryHash = Get-AdminSha256Hex -Text $canonicalJson
    $summary = [pscustomobject][ordered]@{
        status           = [string]$Envelope.status
        outcome          = [string]$Envelope.outcome
        exitCode         = [int]$Envelope.exitCode
        targetCount      = [int]$Envelope.targetCount
        recordCount      = [int]$Envelope.recordCount
        succeededCount   = [int]$succeededCount
        partialCount     = [int]$partialCount
        failedCount      = [int]$failedCount
        timedOutCount    = [int]$timedOutCount
        skippedCount     = [int]$skippedCount
        whatIfCount      = [int]$whatIfCount
        auditRecordCount = [int]$Context.RecordCount + 1
        hashAlgorithm    = 'SHA-256'
        canonicalization = $Script:AuditCanonicalization
        summaryHash      = $summaryHash
    }
    return [pscustomobject][ordered]@{
        CanonicalPayload = $canonicalPayload
        CanonicalJson    = $canonicalJson
        Summary          = $summary
        SummaryHash      = $summaryHash
    }
}

function Write-AdminAuditExecutionStarted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$RunId,

        [Parameter(Mandatory = $true)]
        [psobject]$Request,

        [Parameter(Mandatory = $true)]
        [psobject]$Context
    )

    $timestampUtc = [datetime]::UtcNow
    if (-not $Context.RequestRecorded) {
        $requestEvent = ConvertTo-AdminAuditEvent -RunId $RunId -Sequence ([int]$Context.RecordCount + 1) -EventType request.resolved -TimestampUtc $timestampUtc -Stage Request -ActionId $Request.ActionId -Outcome Resolved -DurationMs ([int64]0)
        [void](Write-AdminAuditRecord -Context $Context -Event $requestEvent)
        $Context.RequestRecorded = $true
    }
    if (-not $Context.PolicyRecorded) {
        $policy = [pscustomobject][ordered]@{
            applied       = [bool]$Request.PolicyDecision.applied
            schemaVersion = if ($Request.PolicyDecision.schemaVersion) { [string]$Request.PolicyDecision.schemaVersion } else { $null }
            profileName   = if ($Request.PolicyDecision.profileName) { [string]$Request.PolicyDecision.profileName } else { $null }
            decision      = [string]$Request.PolicyDecision.decision
            reasonCode    = [string]$Request.PolicyDecision.reasonCode
            reason        = ConvertTo-AdminSafeErrorMessage -Message ([string]$Request.PolicyDecision.reason)
        }
        $policyEvent = ConvertTo-AdminAuditEvent -RunId $RunId -Sequence ([int]$Context.RecordCount + 1) -EventType policy.decision -TimestampUtc $timestampUtc -Stage Authorization -ActionId $Request.ActionId -Outcome ([string]$Request.PolicyDecision.decision) -Policy $policy
        [void](Write-AdminAuditRecord -Context $Context -Event $policyEvent)
        $Context.PolicyRecorded = $true
    }

    $targetStage = if ($Request.TargetMode -eq 'Remote' -and -not $Script:State.SkipConnectivityCheck) { 'Connectivity' } else { 'Execution' }
    for ($targetIndex = 0; $targetIndex -lt $Request.Computers.Count; $targetIndex++) {
        $computerName = [string]$Request.Computers[$targetIndex]
        $targetId = Get-AdminStableTargetId -ComputerName $computerName
        if ($Context.StartedTargetIds.Contains($targetId)) {
            continue
        }
        $target = [pscustomobject][ordered]@{
            targetId = $targetId
            index    = [int]$targetIndex
            name     = $computerName
        }
        $startedEvent = ConvertTo-AdminAuditEvent -RunId $RunId -Sequence ([int]$Context.RecordCount + 1) -EventType target.started -TimestampUtc $timestampUtc -Stage $targetStage -ActionId $Request.ActionId -Target $target
        [void](Write-AdminAuditRecord -Context $Context -Event $startedEvent)
        [void]$Context.StartedTargetIds.Add($targetId)
    }
}

function Write-AdminAutomationAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [psobject]$Context
    )

    $runId = [guid]::Parse([string]$Envelope.runId)
    $startedAtUtc = [datetime]::Parse([string]$Envelope.startedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $finishedAtUtc = [datetime]::Parse([string]$Envelope.finishedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $actionId = if ($Envelope.actionId) { [string]$Envelope.actionId } else { $null }
    $requestError = $null
    if (@($Envelope.errors).Count -gt 0) {
        $requestError = [pscustomobject][ordered]@{
            category = [string]$Envelope.errors[0].category
            message  = ConvertTo-AdminSafeErrorMessage -Message ([string]$Envelope.errors[0].message)
        }
    }

    if (-not $Context.RequestRecorded) {
        $requestEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType request.resolved -TimestampUtc $startedAtUtc -Stage Request -ActionId $actionId -Outcome ([string]$Envelope.status) -DurationMs ([int64]0) -ErrorRecord $requestError
        [void](Write-AdminAuditRecord -Context $Context -Event $requestEvent)
        $Context.RequestRecorded = $true
    }

    $policy = [pscustomobject][ordered]@{
        applied       = [bool]$Envelope.policy.applied
        schemaVersion = if ($Envelope.policy.schemaVersion) { [string]$Envelope.policy.schemaVersion } else { $null }
        profileName   = if ($Envelope.policy.profileName) { [string]$Envelope.policy.profileName } else { $null }
        decision      = [string]$Envelope.policy.decision
        reasonCode    = [string]$Envelope.policy.reasonCode
        reason        = ConvertTo-AdminSafeErrorMessage -Message ([string]$Envelope.policy.reason)
    }
    if (-not $Context.PolicyRecorded) {
        $policyEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType policy.decision -TimestampUtc $startedAtUtc -Stage Authorization -ActionId $actionId -Outcome ([string]$Envelope.policy.decision) -Policy $policy
        [void](Write-AdminAuditRecord -Context $Context -Event $policyEvent)
        $Context.PolicyRecorded = $true
    }

    $targetIndex = 0
    foreach ($targetResult in @($Envelope.targets)) {
        $target = [pscustomobject][ordered]@{
            targetId = [string]$targetResult.targetId
            index    = [int]$targetIndex
            name     = [string]$targetResult.target
        }
        $targetStartedAtUtc = [datetime]::Parse([string]$targetResult.startedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $targetFinishedAtUtc = [datetime]::Parse([string]$targetResult.finishedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        $targetStage = if ([string]$targetResult.errorCategory -eq 'Connectivity') { 'Connectivity' } else { 'Execution' }
        if (-not $Context.StartedTargetIds.Contains([string]$targetResult.targetId)) {
            $startedEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType target.started -TimestampUtc $targetStartedAtUtc -Stage $targetStage -ActionId $actionId -Target $target
            [void](Write-AdminAuditRecord -Context $Context -Event $startedEvent)
            [void]$Context.StartedTargetIds.Add([string]$targetResult.targetId)
        }

        $targetError = $null
        if ($targetResult.errorCategory -or $targetResult.errorMessage) {
            $targetError = [pscustomobject][ordered]@{
                category = if ($targetResult.errorCategory) { [string]$targetResult.errorCategory } else { 'Execution' }
                message  = if ($targetResult.errorMessage) { ConvertTo-AdminSafeErrorMessage -Message ([string]$targetResult.errorMessage) } else { 'The target did not complete successfully.' }
            }
        }
        $completedEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType target.completed -TimestampUtc $targetFinishedAtUtc -Stage $targetStage -ActionId $actionId -Target $target -Outcome ([string]$targetResult.status) -DurationMs ([int64]$targetResult.durationMs) -ErrorRecord $targetError
        [void](Write-AdminAuditRecord -Context $Context -Event $completedEvent)
        $targetIndex++
    }

    $runSummary = Get-AdminAuditRunSummary -Envelope $Envelope -Context $Context
    $summaryEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType run.summary -TimestampUtc $finishedAtUtc -Stage Summary -ActionId $actionId -Outcome ([string]$Envelope.outcome) -DurationMs ([int64]$Envelope.durationMs) -Policy $policy -Summary $runSummary.Summary
    [void](Write-AdminAuditRecord -Context $Context -Event $summaryEvent)
    $Context.SummaryHash = [string]$runSummary.SummaryHash
    $Context.Complete = $true
    $Envelope.audit = Get-AdminAuditStatus -Context $Context
    return $Envelope
}

function ConvertTo-AdminAuditSinkFailureEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$OriginalEnvelope,

        [Parameter(Mandatory = $true)]
        [psobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $originalOutcome = [string]$OriginalEnvelope.outcome
    $finishedAtUtc = [datetime]::UtcNow
    $startedAtUtc = [datetime]::Parse([string]$OriginalEnvelope.startedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $OriginalEnvelope.finishedAtUtc = ConvertTo-AdminUtcTimestamp -Value $finishedAtUtc
    $OriginalEnvelope.durationMs = [int64][math]::Max(0, [math]::Round(($finishedAtUtc - $startedAtUtc).TotalMilliseconds))
    $OriginalEnvelope.status = 'InternalFailure'
    $OriginalEnvelope.outcome = 'InternalFailure'
    $OriginalEnvelope.exitCode = [int]$Script:AutomationExitCodes.InternalFailure
    $OriginalEnvelope.warnings = @($OriginalEnvelope.warnings) + @("The run outcome before the audit sink failure was $originalOutcome. Review preserved target evidence before retrying any state-changing action.")
    $OriginalEnvelope.errors = @($OriginalEnvelope.errors) + @([pscustomobject][ordered]@{
            category = 'Audit'
            message  = ConvertTo-AdminSafeErrorMessage -Message $Message
        })
    $Context.Complete = $false
    $Context.SummaryHash = $null
    $OriginalEnvelope.audit = Get-AdminAuditStatus -Context $Context
    return $OriginalEnvelope
}

function Write-AdminAuditFailureRevision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Envelope,

        [Parameter(Mandatory = $true)]
        [psobject]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Context.Complete = $false
    $Context.SummaryHash = $null
    $runId = [guid]::Parse([string]$Envelope.runId)
    $finishedAtUtc = [datetime]::Parse([string]$Envelope.finishedAtUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    $actionId = if ($Envelope.actionId) { [string]$Envelope.actionId } else { $null }
    $auditError = [pscustomobject][ordered]@{
        category = 'Output'
        message  = ConvertTo-AdminSafeErrorMessage -Message $Message
    }
    $failureEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType audit.failure -TimestampUtc $finishedAtUtc -Stage Audit -ActionId $actionId -Outcome OutputSinkFailure -ErrorRecord $auditError
    [void](Write-AdminAuditRecord -Context $Context -Event $failureEvent)

    $policy = [pscustomobject][ordered]@{
        applied       = [bool]$Envelope.policy.applied
        schemaVersion = if ($Envelope.policy.schemaVersion) { [string]$Envelope.policy.schemaVersion } else { $null }
        profileName   = if ($Envelope.policy.profileName) { [string]$Envelope.policy.profileName } else { $null }
        decision      = [string]$Envelope.policy.decision
        reasonCode    = [string]$Envelope.policy.reasonCode
        reason        = ConvertTo-AdminSafeErrorMessage -Message ([string]$Envelope.policy.reason)
    }
    $runSummary = Get-AdminAuditRunSummary -Envelope $Envelope -Context $Context
    $summaryEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence ([int]$Context.RecordCount + 1) -EventType run.summary -TimestampUtc $finishedAtUtc -Stage Summary -ActionId $actionId -Outcome ([string]$Envelope.outcome) -DurationMs ([int64]$Envelope.durationMs) -Policy $policy -Summary $runSummary.Summary
    [void](Write-AdminAuditRecord -Context $Context -Event $summaryEvent)
    $Context.SummaryHash = [string]$runSummary.SummaryHash
    $Context.Complete = $true
    $Envelope.audit = Get-AdminAuditStatus -Context $Context
    return $Envelope
}

function ConvertTo-AdminOutputSinkFailureEnvelope {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$OriginalEnvelope,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $finishedAtUtc = [datetime]::UtcNow
    $startedAtUtc = [datetime]::Parse(
        [string]$OriginalEnvelope.startedAtUtc,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind
    ).ToUniversalTime()
    $durationMilliseconds = [math]::Max(0, [math]::Round(($finishedAtUtc - $startedAtUtc).TotalMilliseconds))
    $safeMessage = ConvertTo-AdminSafeErrorMessage -Message $Message

    $OriginalEnvelope.finishedAtUtc = ConvertTo-AdminUtcTimestamp -Value $finishedAtUtc
    $OriginalEnvelope.durationMs = [int64]$durationMilliseconds
    $OriginalEnvelope.status = 'InternalFailure'
    $OriginalEnvelope.outcome = 'InternalFailure'
    $OriginalEnvelope.exitCode = [int]$Script:AutomationExitCodes.InternalFailure
    $OriginalEnvelope.warnings = @($OriginalEnvelope.warnings) + @('Target execution finished before the requested JSON result could be delivered. Review the preserved target results before deciding whether to retry.')
    $OriginalEnvelope.errors = @($OriginalEnvelope.errors) + @([pscustomobject][ordered]@{ category = 'Internal'; message = $safeMessage })
    $OriginalEnvelope.reportPaths = @()
    return $OriginalEnvelope
}

function Resolve-AdminAutomationOutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath
    )

    if ($LiteralPath -ceq '-' -or $LiteralPath -ieq 'STDOUT') {
        return '-'
    }
    if (-not (Test-AdminLiteralFilePathText -LiteralPath $LiteralPath)) {
        throw 'The JSON output path contains an unsafe or unsupported component.'
    }

    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    if ([System.IO.Path]::GetExtension($fullPath) -ine '.json') {
        throw 'The JSON output path must use the .json extension.'
    }
    if (Test-Path -LiteralPath $fullPath) {
        throw "Refusing to overwrite an existing JSON output file: $fullPath"
    }
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw 'The JSON output path must include a valid parent directory.'
    }

    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][System.IO.Directory]::CreateDirectory($parent)
    }

    $leafName = Split-Path -Leaf $fullPath
    $deviceBaseName = @($leafName -split '\.', 2)[0]
    if ([string]::IsNullOrWhiteSpace($leafName) -or $leafName.Length -gt 255 -or $leafName.TrimEnd(' ', '.') -cne $leafName) {
        throw 'The JSON output file name is invalid.'
    }
    if ($leafName.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 -or $deviceBaseName -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        throw 'The JSON output file name is not supported on Windows.'
    }

    $outputProbe = $null
    $outputProbeCreated = $false
    $outputProbePath = Join-Path $parent ('.admin-json-probe-{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    try {
        $outputProbe = [System.IO.File]::Open($outputProbePath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $outputProbeCreated = $true
    }
    finally {
        if ($outputProbe) {
            $outputProbe.Dispose()
        }
        if ($outputProbeCreated -and (Test-Path -LiteralPath $outputProbePath -PathType Leaf)) {
            [System.IO.File]::Delete($outputProbePath)
        }
    }

    return $fullPath
}

function Get-AdminAutomationResolutionFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Validation', 'Authorization')]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyDecision
    )

    if ($null -eq $PolicyDecision) {
        $PolicyDecision = if ($null -ne $Script:State.PolicyProfile) {
            ConvertTo-AdminPolicyDecision -Applied $true -SchemaVersion $Script:State.PolicyProfile.SchemaVersion -ProfileName $Script:State.PolicyProfile.ProfileName -Decision NotEvaluated -ReasonCode RequestInvalid -Reason 'The request failed validation before policy evaluation completed.'
        }
        else {
            ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
        }
    }

    return [pscustomobject][ordered]@{
        Success       = $false
        Category      = $Category
        Message       = ConvertTo-AdminSafeErrorMessage -Message $Message
        PolicyDecision = $PolicyDecision
        Request       = $null
    }
}

function Resolve-AdminAutomationInputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath,

        [Parameter()]
        [AllowEmptyString()]
        [string]$RequiredExtension = ''
    )

    if (-not (Test-AdminLiteralFilePathText -LiteralPath $LiteralPath)) {
        throw 'The input path contains an unsafe or unsupported component.'
    }
    $fullPath = [System.IO.Path]::GetFullPath($LiteralPath)
    if (-not [string]::IsNullOrWhiteSpace($RequiredExtension) -and [System.IO.Path]::GetExtension($fullPath) -ine $RequiredExtension) {
        throw "The input file must use the $RequiredExtension extension."
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Input file not found: $fullPath"
    }

    return $fullPath
}

function ConvertTo-AdminPolicyDecision {
    [CmdletBinding()]
    param(
        [Parameter()]
        [bool]$Applied = $false,

        [Parameter()]
        [AllowNull()]
        [string]$SchemaVersion,

        [Parameter()]
        [AllowNull()]
        [string]$ProfileName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('NotApplied', 'NotEvaluated', 'Allowed', 'Denied', 'Invalid')]
        [string]$Decision,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z][A-Za-z0-9]{0,63}$')]
        [string]$ReasonCode,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason
    )

    return [pscustomobject][ordered]@{
        applied       = $Applied
        schemaVersion = if ([string]::IsNullOrWhiteSpace($SchemaVersion)) { $null } else { $SchemaVersion }
        profileName   = if ([string]::IsNullOrWhiteSpace($ProfileName)) { $null } else { $ProfileName }
        decision      = $Decision
        reasonCode    = $ReasonCode
        reason        = ConvertTo-AdminSafeErrorMessage -Message $Reason
    }
}

function Test-AdminJsonHasDuplicateProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$JsonText
    )

    $frames = New-Object 'System.Collections.Generic.List[object]'
    $index = 0
    while ($index -lt $JsonText.Length) {
        $character = $JsonText[$index]
        if ($character -eq '{') {
            $frames.Add([pscustomobject]@{
                    Type = 'Object'
                    Keys = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                }) | Out-Null
            $index++
            continue
        }
        if ($character -eq '[') {
            $frames.Add([pscustomobject]@{ Type = 'Array'; Keys = $null }) | Out-Null
            $index++
            continue
        }
        if ($character -eq '}' -or $character -eq ']') {
            if ($frames.Count -gt 0) {
                $frames.RemoveAt($frames.Count - 1)
            }
            $index++
            continue
        }
        if ($character -ne '"') {
            $index++
            continue
        }

        $stringStart = $index
        $index++
        $escaped = $false
        while ($index -lt $JsonText.Length) {
            $stringCharacter = $JsonText[$index]
            if ($escaped) {
                $escaped = $false
            }
            elseif ($stringCharacter -eq '\') {
                $escaped = $true
            }
            elseif ($stringCharacter -eq '"') {
                break
            }
            $index++
        }
        if ($index -ge $JsonText.Length) {
            return $false
        }

        $stringEnd = $index
        $nextIndex = $stringEnd + 1
        while ($nextIndex -lt $JsonText.Length -and [char]::IsWhiteSpace($JsonText[$nextIndex])) {
            $nextIndex++
        }
        if ($nextIndex -lt $JsonText.Length -and $JsonText[$nextIndex] -eq ':' -and $frames.Count -gt 0) {
            $frame = $frames[$frames.Count - 1]
            if ($frame.Type -eq 'Object') {
                try {
                    $jsonString = $JsonText.Substring($stringStart, $stringEnd - $stringStart + 1)
                    $propertyName = [string](ConvertFrom-Json -InputObject $jsonString -ErrorAction Stop)
                }
                catch {
                    return $false
                }
                if (-not $frame.Keys.Add($propertyName)) {
                    return $true
                }
            }
        }
        $index = $stringEnd + 1
    }

    return $false
}

function Get-AdminPolicyPropertyError {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$AllowedProperties,

        [Parameter()]
        [string[]]$RequiredProperties = @(),

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Context
    )

    if ($null -eq $InputObject -or $InputObject -isnot [pscustomobject]) {
        return "$Context must be a JSON object."
    }
    $propertyNames = @($InputObject.PSObject.Properties.Name)
    if (@($propertyNames | Where-Object { $_ -cnotin $AllowedProperties }).Count -gt 0) {
        return "$Context contains unsupported properties."
    }
    if (@($RequiredProperties | Where-Object { $_ -cnotin $propertyNames }).Count -gt 0) {
        return "$Context is missing one or more required properties."
    }
    return $null
}

function ConvertTo-AdminPolicyStringList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        $Value,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 1000)]
        [int]$MinimumCount,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 1000)]
        [int]$MaximumCount,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Context
    )

    if ($Value -isnot [System.Array]) {
        throw "$Context must be a JSON array."
    }
    $items = @($Value)
    if ($items.Count -lt $MinimumCount -or $items.Count -gt $MaximumCount) {
        throw "$Context contains an unsupported number of values."
    }
    $normalized = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $items) {
        if ($item -isnot [string]) {
            throw "$Context accepts string values only."
        }
        $text = ([string]$item).Trim()
        if ([string]::IsNullOrWhiteSpace($text) -or $text.Length -gt 2048 -or $text -match '[\x00-\x1F\x7F]') {
            throw "$Context contains an invalid string value."
        }
        if (-not $seen.Add($text)) {
            throw "$Context contains duplicate values."
        }
        $normalized.Add($text) | Out-Null
    }
    return $normalized.ToArray()
}

function Test-AdminPolicyTargetPattern {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Pattern
    )

    if ($Pattern.EndsWith('.')) {
        return $false
    }
    if ($Pattern.StartsWith('*.')) {
        $suffix = $Pattern.Substring(2)
        if ($suffix -match '^\d+(?:\.\d+){3}$') {
            return $false
        }
        return Test-AdminHostname -ComputerName $suffix
    }
    return Test-AdminHostname -ComputerName $Pattern
}

function Test-AdminPolicyTargetMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    if ($Pattern.StartsWith('*.')) {
        $suffix = $Pattern.Substring(1)
        return $ComputerName.Length -gt $suffix.Length -and $ComputerName.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)
    }
    return $ComputerName.Equals($Pattern, [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-AdminPolicyInteger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value,

        [Parameter(Mandatory = $true)]
        [int]$Minimum,

        [Parameter(Mandatory = $true)]
        [int]$Maximum,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Context
    )

    $text = [Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)
    $number = 0
    if ($text -notmatch '^-?\d+$' -or -not [int]::TryParse($text, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
        throw "$Context must be an integer."
    }
    if ($number -lt $Minimum -or $number -gt $Maximum) {
        throw "$Context must be from $Minimum through $Maximum."
    }
    return $number
}

function Test-AdminPolicyAllowedInputValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActionId,

        [Parameter(Mandatory = $true)]
        [string]$InputName,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    switch ("$ActionId/$InputName") {
        'WindowsUpdate/IncludeKB' {
            return (Test-AdminKbNumber -KbNumber $Value) -and $Value -ceq $Value.Trim().ToUpperInvariant()
        }
        'ServiceManagement/ServiceName' { return Test-AdminServiceName -ServiceName $Value }
        'ServiceManagement/ServiceAction' { return $Value -cin @('Query', 'Start', 'Stop', 'Restart') }
        'TerminateProcess/ProcessName' { return Test-AdminProcessName -ProcessName $Value }
        'ScheduledTasks/TaskPath' { return Test-AdminTaskPath -TaskPath $Value }
        'EventLogQuery/EventLogName' { return Test-AdminEventLogName -LogName $Value }
        'EventLogQuery/EventLevel' { return $Value -cin @('Critical', 'Error', 'Warning', 'Information', 'Verbose') }
        'RegistryRead/RegistryPath' { return Test-AdminRegistryPath -RegistryPath $Value }
        'RegistryRead/RegistryValueName' { return Test-AdminRegistryValueName -ValueName $Value }
        default { return $false }
    }
}

function Import-AdminPolicyProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath
    )

    $resolvedPath = Resolve-AdminAutomationInputFile -LiteralPath $LiteralPath -RequiredExtension '.json'
    $jsonText = Read-AdminBoundedUtf8File -LiteralPath $resolvedPath -MaximumBytes 1048576
    if (Test-AdminJsonHasDuplicateProperty -JsonText $jsonText) {
        throw 'The policy profile contains duplicate or case-conflicting property names.'
    }
    try {
        $policyObject = ConvertFrom-Json -InputObject $jsonText -ErrorAction Stop
    }
    catch {
        throw 'The policy profile must contain valid JSON.'
    }

    $rootError = Get-AdminPolicyPropertyError -InputObject $policyObject -AllowedProperties @('schemaVersion', 'profileName', 'description', 'actions', 'transports', 'targetModes', 'targets', 'limits', 'actionInputs') -RequiredProperties @('schemaVersion', 'profileName', 'actions', 'transports', 'targetModes', 'targets') -Context 'The policy profile'
    if ($rootError) {
        throw $rootError
    }
    if ($policyObject.schemaVersion -isnot [string] -or [string]$policyObject.schemaVersion -cne $Script:PolicySchemaVersion) {
        throw "The policy profile schemaVersion must be $Script:PolicySchemaVersion."
    }
    if ($policyObject.profileName -isnot [string] -or [string]$policyObject.profileName -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') {
        throw 'The policy profileName is invalid.'
    }
    $description = ''
    if ($policyObject.PSObject.Properties.Name -ccontains 'description') {
        if ($policyObject.description -isnot [string] -or ([string]$policyObject.description).Length -gt 512 -or [string]$policyObject.description -match '[\x00-\x1F\x7F]') {
            throw 'The policy description is invalid.'
        }
        $description = [string]$policyObject.description
    }

    $actionError = Get-AdminPolicyPropertyError -InputObject $policyObject.actions -AllowedProperties @('allow', 'deny') -RequiredProperties @('allow') -Context 'The actions policy'
    if ($actionError) { throw $actionError }
    $actionAllow = @(ConvertTo-AdminPolicyStringList -Value $policyObject.actions.allow -MinimumCount 1 -MaximumCount 20 -Context 'The actions allow list')
    $actionDeny = @(
        if ($policyObject.actions.PSObject.Properties.Name -ccontains 'deny') {
            ConvertTo-AdminPolicyStringList -Value $policyObject.actions.deny -MinimumCount 0 -MaximumCount 20 -Context 'The actions deny list'
        }
    )
    foreach ($actionId in @($actionAllow + $actionDeny)) {
        $catalogItem = Get-AdminActionCatalogItem -ActionId $actionId
        if ($null -eq $catalogItem -or $catalogItem.Id -cne $actionId) {
            throw 'The policy contains an unsupported or incorrectly cased action identifier.'
        }
    }
    if (@($actionAllow | Where-Object { $_ -cin $actionDeny }).Count -gt 0) {
        throw 'The actions allow and deny lists conflict.'
    }

    $transportError = Get-AdminPolicyPropertyError -InputObject $policyObject.transports -AllowedProperties @('allow', 'deny') -RequiredProperties @('allow') -Context 'The transports policy'
    if ($transportError) { throw $transportError }
    $transportAllow = @(ConvertTo-AdminPolicyStringList -Value $policyObject.transports.allow -MinimumCount 1 -MaximumCount 3 -Context 'The transports allow list')
    $transportDeny = @(
        if ($policyObject.transports.PSObject.Properties.Name -ccontains 'deny') {
            ConvertTo-AdminPolicyStringList -Value $policyObject.transports.deny -MinimumCount 0 -MaximumCount 3 -Context 'The transports deny list'
        }
    )
    foreach ($transportValue in @($transportAllow + $transportDeny)) {
        if ($transportValue -cnotin @('Local', 'WinRM', 'PsExec')) {
            throw 'The policy contains an unsupported or incorrectly cased transport.'
        }
    }
    if (@($transportAllow | Where-Object { $_ -cin $transportDeny }).Count -gt 0) {
        throw 'The transports allow and deny lists conflict.'
    }

    $targetModeError = Get-AdminPolicyPropertyError -InputObject $policyObject.targetModes -AllowedProperties @('allow', 'deny') -RequiredProperties @('allow') -Context 'The targetModes policy'
    if ($targetModeError) { throw $targetModeError }
    $targetModeAllow = @(ConvertTo-AdminPolicyStringList -Value $policyObject.targetModes.allow -MinimumCount 1 -MaximumCount 2 -Context 'The targetModes allow list')
    $targetModeDeny = @(
        if ($policyObject.targetModes.PSObject.Properties.Name -ccontains 'deny') {
            ConvertTo-AdminPolicyStringList -Value $policyObject.targetModes.deny -MinimumCount 0 -MaximumCount 2 -Context 'The targetModes deny list'
        }
    )
    foreach ($targetModeValue in @($targetModeAllow + $targetModeDeny)) {
        if ($targetModeValue -cnotin @('Local', 'Remote')) {
            throw 'The policy contains an unsupported or incorrectly cased target mode.'
        }
    }
    if (@($targetModeAllow | Where-Object { $_ -cin $targetModeDeny }).Count -gt 0) {
        throw 'The targetModes allow and deny lists conflict.'
    }

    $targetError = Get-AdminPolicyPropertyError -InputObject $policyObject.targets -AllowedProperties @('allow', 'deny') -RequiredProperties @('allow') -Context 'The targets policy'
    if ($targetError) { throw $targetError }
    $targetAllow = @(ConvertTo-AdminPolicyStringList -Value $policyObject.targets.allow -MinimumCount 0 -MaximumCount 500 -Context 'The targets allow list')
    $targetDeny = @(
        if ($policyObject.targets.PSObject.Properties.Name -ccontains 'deny') {
            ConvertTo-AdminPolicyStringList -Value $policyObject.targets.deny -MinimumCount 0 -MaximumCount 500 -Context 'The targets deny list'
        }
    )
    foreach ($targetPattern in @($targetAllow + $targetDeny)) {
        if (-not (Test-AdminPolicyTargetPattern -Pattern $targetPattern)) {
            throw 'The policy contains an invalid target pattern. Use an exact validated target or one leading star-dot suffix pattern.'
        }
    }
    if (@($targetAllow | Where-Object { $_ -in $targetDeny }).Count -gt 0) {
        throw 'The targets allow and deny lists contain the same pattern.'
    }

    $effectiveTargetModes = @($targetModeAllow | Where-Object { $_ -cnotin $targetModeDeny })
    $effectiveTransports = @($transportAllow | Where-Object { $_ -cnotin $transportDeny })
    $localModeAllowed = 'Local' -cin $effectiveTargetModes
    $localTransportAllowed = 'Local' -cin $effectiveTransports
    $remoteModeAllowed = 'Remote' -cin $effectiveTargetModes
    $remoteTransportAllowed = @($effectiveTransports | Where-Object { $_ -cin @('WinRM', 'PsExec') }).Count -gt 0
    if ($localModeAllowed -ne $localTransportAllowed -or $remoteModeAllowed -ne $remoteTransportAllowed) {
        throw 'Each allowed target mode must have only its compatible transport class, and each allowed transport class must have its matching target mode.'
    }
    $localPossible = $localModeAllowed -and $localTransportAllowed
    $remotePossible = $remoteModeAllowed -and $remoteTransportAllowed
    if (-not $localPossible -and -not $remotePossible) {
        throw 'The policy targetModes and transports do not permit any execution path.'
    }
    if ($remotePossible -and $targetAllow.Count -eq 0) {
        throw 'A policy that permits remote execution requires at least one targets allow pattern.'
    }
    if (-not $remotePossible -and ($targetAllow.Count -gt 0 -or $targetDeny.Count -gt 0)) {
        throw 'A policy without remote execution cannot contain inert remote target rules.'
    }

    $limits = [ordered]@{
        MaxTargets                    = $null
        MaxConcurrentJobs             = $null
        MaxRetryCount                 = $null
        MaxRetryDelaySeconds          = $null
        MaxOperationTimeoutMinutes    = $null
        MaxConnectivityTimeoutSeconds = $null
    }
    if ($policyObject.PSObject.Properties.Name -ccontains 'limits') {
        $limitPropertyMap = [ordered]@{
            maxTargets                    = [pscustomobject]@{ Name = 'MaxTargets'; Minimum = 1; Maximum = 500 }
            maxConcurrentJobs             = [pscustomobject]@{ Name = 'MaxConcurrentJobs'; Minimum = 1; Maximum = 32 }
            maxRetryCount                 = [pscustomobject]@{ Name = 'MaxRetryCount'; Minimum = 0; Maximum = 3 }
            maxRetryDelaySeconds          = [pscustomobject]@{ Name = 'MaxRetryDelaySeconds'; Minimum = 1; Maximum = 60 }
            maxOperationTimeoutMinutes    = [pscustomobject]@{ Name = 'MaxOperationTimeoutMinutes'; Minimum = 1; Maximum = 180 }
            maxConnectivityTimeoutSeconds = [pscustomobject]@{ Name = 'MaxConnectivityTimeoutSeconds'; Minimum = 1; Maximum = 60 }
        }
        $limitError = Get-AdminPolicyPropertyError -InputObject $policyObject.limits -AllowedProperties @($limitPropertyMap.Keys) -Context 'The limits policy'
        if ($limitError) { throw $limitError }
        foreach ($limitProperty in @($policyObject.limits.PSObject.Properties)) {
            $limitDefinition = $limitPropertyMap[$limitProperty.Name]
            $limits[$limitDefinition.Name] = ConvertTo-AdminPolicyInteger -Value $limitProperty.Value -Minimum $limitDefinition.Minimum -Maximum $limitDefinition.Maximum -Context "The $($limitProperty.Name) policy limit"
        }
    }

    $actionInputs = [ordered]@{}
    if ($policyObject.PSObject.Properties.Name -ccontains 'actionInputs') {
        if ($null -eq $policyObject.actionInputs -or $policyObject.actionInputs -isnot [pscustomobject]) {
            throw 'The actionInputs policy must be a JSON object.'
        }
        foreach ($actionProperty in @($policyObject.actionInputs.PSObject.Properties)) {
            $actionId = $actionProperty.Name
            $catalogItem = Get-AdminActionCatalogItem -ActionId $actionId
            if ($null -eq $catalogItem -or $catalogItem.Id -cne $actionId -or -not $Script:PolicyInputDefinitions.Contains($actionId)) {
                throw 'The actionInputs policy contains an unsupported action identifier.'
            }
            if ($actionId -cnotin $actionAllow -or $actionId -cin $actionDeny) {
                throw 'The actionInputs policy can constrain only an action present in the effective actions allow list.'
            }
            $actionConstraintObject = $actionProperty.Value
            if ($null -eq $actionConstraintObject -or $actionConstraintObject -isnot [pscustomobject]) {
                throw 'Each actionInputs action value must be a JSON object.'
            }
            $inputDefinitions = $Script:PolicyInputDefinitions[$actionId]
            $actionConstraints = [ordered]@{}
            foreach ($inputProperty in @($actionConstraintObject.PSObject.Properties)) {
                $inputName = $inputProperty.Name
                if ($inputName -cnotin @($inputDefinitions.Keys)) {
                    throw 'The actionInputs policy contains an unsupported input name.'
                }
                $definition = $inputDefinitions[$inputName]
                $constraintObject = $inputProperty.Value
                $allowedConstraintProperties = switch ($definition.Kind) {
                    'Integer' { @('minimum', 'maximum') }
                    'StringArray' {
                        $values = @('maximumLength', 'maximumItems')
                        if ($definition.AllowedValues) { $values += 'allowedValues' }
                        $values
                    }
                    default {
                        $values = @('maximumLength')
                        if ($definition.AllowedValues) { $values += 'allowedValues' }
                        $values
                    }
                }
                $constraintError = Get-AdminPolicyPropertyError -InputObject $constraintObject -AllowedProperties $allowedConstraintProperties -Context 'An action input constraint'
                if ($constraintError) { throw $constraintError }
                $constraintPropertyNames = @($constraintObject.PSObject.Properties.Name)
                if ($constraintPropertyNames.Count -eq 0) {
                    throw 'An action input constraint must contain at least one supported property.'
                }

                $normalizedConstraint = [ordered]@{
                    Minimum       = $null
                    Maximum       = $null
                    MaximumLength = $null
                    MaximumItems  = $null
                    AllowedValues = @()
                }
                if ($constraintPropertyNames -ccontains 'minimum') {
                    $normalizedConstraint.Minimum = ConvertTo-AdminPolicyInteger -Value $constraintObject.minimum -Minimum $definition.Minimum -Maximum $definition.Maximum -Context 'An action input minimum'
                }
                if ($constraintPropertyNames -ccontains 'maximum') {
                    $normalizedConstraint.Maximum = ConvertTo-AdminPolicyInteger -Value $constraintObject.maximum -Minimum $definition.Minimum -Maximum $definition.Maximum -Context 'An action input maximum'
                }
                if ($null -ne $normalizedConstraint.Minimum -and $null -ne $normalizedConstraint.Maximum -and $normalizedConstraint.Minimum -gt $normalizedConstraint.Maximum) {
                    throw 'An action input minimum cannot exceed its maximum.'
                }
                if ($constraintPropertyNames -ccontains 'maximumLength') {
                    $normalizedConstraint.MaximumLength = ConvertTo-AdminPolicyInteger -Value $constraintObject.maximumLength -Minimum 1 -Maximum $definition.MaximumLength -Context 'An action input maximumLength'
                }
                if ($constraintPropertyNames -ccontains 'maximumItems') {
                    $normalizedConstraint.MaximumItems = ConvertTo-AdminPolicyInteger -Value $constraintObject.maximumItems -Minimum 1 -Maximum $definition.MaximumItems -Context 'An action input maximumItems'
                }
                if ($constraintPropertyNames -ccontains 'allowedValues') {
                    if ($constraintObject.allowedValues -isnot [System.Array]) {
                        throw 'An action input allowedValues value must be a JSON array.'
                    }
                    $allowedInputValues = @($constraintObject.allowedValues)
                    if ($allowedInputValues.Count -lt 1 -or $allowedInputValues.Count -gt 100) {
                        throw 'An action input allowedValues list must contain from 1 through 100 values.'
                    }
                    $normalizedAllowedValues = New-Object 'System.Collections.Generic.List[string]'
                    $seenAllowedValues = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                    foreach ($allowedInputValue in $allowedInputValues) {
                        if ($allowedInputValue -isnot [string]) {
                            throw 'An action input allowedValues list accepts strings only.'
                        }
                        $allowedInputText = [string]$allowedInputValue
                        if ($allowedInputText.Length -gt $definition.MaximumLength -or -not (Test-AdminPolicyAllowedInputValue -ActionId $actionId -InputName $inputName -Value $allowedInputText)) {
                            throw 'An action input allowedValues list contains an invalid value.'
                        }
                        if (-not $seenAllowedValues.Add($allowedInputText)) {
                            throw 'An action input allowedValues list contains duplicate values.'
                        }
                        $normalizedAllowedValues.Add($allowedInputText) | Out-Null
                    }
                    if ($null -ne $normalizedConstraint.MaximumLength -and @($normalizedAllowedValues.ToArray() | Where-Object { $_.Length -gt [int]$normalizedConstraint.MaximumLength }).Count -gt 0) {
                        throw 'An action input allowedValues list conflicts with its maximumLength constraint.'
                    }
                    $normalizedConstraint.AllowedValues = @($normalizedAllowedValues.ToArray())
                }
                $actionConstraints[$inputName] = [pscustomobject]$normalizedConstraint
            }
            if ($actionConstraints.Count -eq 0) {
                throw 'Each actionInputs action must contain at least one input constraint.'
            }
            $actionInputs[$actionId] = $actionConstraints
        }
    }

    return [pscustomobject][ordered]@{
        SchemaVersion  = $Script:PolicySchemaVersion
        ProfileName    = [string]$policyObject.profileName
        Description    = $description
        SourcePath     = $resolvedPath
        ActionsAllow   = @($actionAllow)
        ActionsDeny    = @($actionDeny)
        TransportsAllow = @($transportAllow)
        TransportsDeny = @($transportDeny)
        TargetModesAllow = @($targetModeAllow)
        TargetModesDeny = @($targetModeDeny)
        TargetsAllow   = @($targetAllow)
        TargetsDeny    = @($targetDeny)
        Limits         = [pscustomobject]$limits
        ActionInputs   = $actionInputs
    }
}

function Get-AdminRequestedExecutionSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters
    )

    return [pscustomobject][ordered]@{
        MaxConcurrentJobs          = if (Test-AdminParameterBound -Parameters $Parameters -Name 'MaxConcurrentJobs') { [int]$Parameters['MaxConcurrentJobs'] } else { [int]$Script:State.MaxConcurrentJobs }
        RetryCount                 = if (Test-AdminParameterBound -Parameters $Parameters -Name 'RetryCount') { [int]$Parameters['RetryCount'] } else { [int]$Script:State.RetryCount }
        RetryDelaySeconds          = if (Test-AdminParameterBound -Parameters $Parameters -Name 'RetryDelaySeconds') { [int]$Parameters['RetryDelaySeconds'] } else { [int]$Script:State.RetryDelaySeconds }
        OperationTimeoutMinutes    = if (Test-AdminParameterBound -Parameters $Parameters -Name 'OperationTimeoutMinutes') { [int]$Parameters['OperationTimeoutMinutes'] } else { [int]$Script:State.OperationTimeoutMinutes }
        ConnectivityTimeoutSeconds = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ConnectivityTimeoutSeconds') { [int]$Parameters['ConnectivityTimeoutSeconds'] } else { [int]$Script:State.ConnectivityTimeoutSeconds }
    }
}

function ConvertTo-AdminPolicyResolution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Allowed,

        [Parameter(Mandatory = $true)]
        [psobject]$PolicyDecision,

        [Parameter(Mandatory = $true)]
        [psobject]$ExecutionSettings
    )

    return [pscustomobject][ordered]@{
        Allowed           = $Allowed
        PolicyDecision    = $PolicyDecision
        ExecutionSettings = $ExecutionSettings
    }
}

function Get-AdminPolicyExecutionContextDecision {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'Remote')]
        [string]$TargetMode,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'WinRM', 'PsExec')]
        [string]$Transport
    )

    if ($null -eq $PolicyProfile) {
        return ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
    }
    $decisionParameters = @{
        Applied       = $true
        SchemaVersion = $PolicyProfile.SchemaVersion
        ProfileName   = $PolicyProfile.ProfileName
    }
    if ($TargetMode -cin $PolicyProfile.TargetModesDeny) {
        return ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetModeDenied -Reason 'The policy explicitly denies the requested target mode.'
    }
    if ($TargetMode -cnotin $PolicyProfile.TargetModesAllow) {
        return ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetModeNotAllowed -Reason 'The requested target mode is not present in the policy allow list.'
    }
    if ($Transport -cin $PolicyProfile.TransportsDeny) {
        return ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TransportDenied -Reason 'The policy explicitly denies the requested transport.'
    }
    if ($Transport -cnotin $PolicyProfile.TransportsAllow) {
        return ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TransportNotAllowed -Reason 'The requested transport is not present in the policy allow list.'
    }
    return ConvertTo-AdminPolicyDecision @decisionParameters -Decision Allowed -ReasonCode PolicyAllowed -Reason 'The requested target mode and transport satisfy the supplied policy profile.'
}

function Resolve-AdminPolicyRequest {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile,

        [Parameter(Mandatory = $true)]
        [string]$ActionId,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'Remote')]
        [string]$TargetMode,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'WinRM', 'PsExec')]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [string[]]$Computers,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Inputs,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters
    )

    $executionSettings = Get-AdminRequestedExecutionSetting -Parameters $Parameters
    if ($null -eq $PolicyProfile) {
        $decision = ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
        return ConvertTo-AdminPolicyResolution -Allowed $true -PolicyDecision $decision -ExecutionSettings $executionSettings
    }

    $decisionParameters = @{
        Applied       = $true
        SchemaVersion = $PolicyProfile.SchemaVersion
        ProfileName   = $PolicyProfile.ProfileName
    }
    if ($ActionId -cin $PolicyProfile.ActionsDeny) {
        $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionDenied -Reason 'The policy explicitly denies the requested action.'
        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
    }
    if ($ActionId -cnotin $PolicyProfile.ActionsAllow) {
        $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionNotAllowed -Reason 'The requested action is not present in the policy allow list.'
        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
    }
    $executionContextDecision = Get-AdminPolicyExecutionContextDecision -PolicyProfile $PolicyProfile -TargetMode $TargetMode -Transport $Transport
    if ($executionContextDecision.decision -eq 'Denied') {
        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $executionContextDecision -ExecutionSettings $executionSettings
    }

    if ($TargetMode -eq 'Remote') {
        foreach ($computer in $Computers) {
            if (@($PolicyProfile.TargetsDeny | Where-Object { Test-AdminPolicyTargetMatch -ComputerName $computer -Pattern $_ }).Count -gt 0) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetDenied -Reason 'The policy explicitly denies one or more requested targets.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            if (@($PolicyProfile.TargetsAllow | Where-Object { Test-AdminPolicyTargetMatch -ComputerName $computer -Pattern $_ }).Count -eq 0) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetNotAllowed -Reason 'One or more requested targets do not match the policy allow patterns.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
        }
    }
    if ($null -ne $PolicyProfile.Limits.MaxTargets -and $Computers.Count -gt [int]$PolicyProfile.Limits.MaxTargets) {
        $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetCountExceeded -Reason 'The request exceeds the policy target-count limit.'
        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
    }

    $runtimeLimits = @(
        [pscustomobject]@{ ParameterName = 'MaxConcurrentJobs'; SettingName = 'MaxConcurrentJobs'; LimitName = 'MaxConcurrentJobs' }
        [pscustomobject]@{ ParameterName = 'RetryCount'; SettingName = 'RetryCount'; LimitName = 'MaxRetryCount' }
        [pscustomobject]@{ ParameterName = 'RetryDelaySeconds'; SettingName = 'RetryDelaySeconds'; LimitName = 'MaxRetryDelaySeconds' }
        [pscustomobject]@{ ParameterName = 'OperationTimeoutMinutes'; SettingName = 'OperationTimeoutMinutes'; LimitName = 'MaxOperationTimeoutMinutes' }
        [pscustomobject]@{ ParameterName = 'ConnectivityTimeoutSeconds'; SettingName = 'ConnectivityTimeoutSeconds'; LimitName = 'MaxConnectivityTimeoutSeconds' }
    )
    foreach ($runtimeLimit in $runtimeLimits) {
        $limit = $PolicyProfile.Limits.($runtimeLimit.LimitName)
        if ($null -eq $limit) {
            continue
        }
        $requestedValue = [int]$executionSettings.($runtimeLimit.SettingName)
        if ((Test-AdminParameterBound -Parameters $Parameters -Name $runtimeLimit.ParameterName) -and $requestedValue -gt [int]$limit) {
            $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode RuntimeLimitExceeded -Reason 'An explicit runtime setting exceeds its policy limit.'
            return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
        }
        $executionSettings.($runtimeLimit.SettingName) = [math]::Min($requestedValue, [int]$limit)
    }

    if ($PolicyProfile.ActionInputs.Contains($ActionId)) {
        $actionConstraints = $PolicyProfile.ActionInputs[$ActionId]
        foreach ($inputName in @($actionConstraints.Keys)) {
            if (-not $Inputs.Contains($inputName)) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionInputDenied -Reason 'A policy-constrained action input was not resolved.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            $constraint = $actionConstraints[$inputName]
            $inputValue = $Inputs[$inputName]
            if ($null -ne $constraint.Minimum -and [int64]$inputValue -lt [int64]$constraint.Minimum) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionInputDenied -Reason 'An action input is below its policy minimum.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            if ($null -ne $constraint.Maximum -and [int64]$inputValue -gt [int64]$constraint.Maximum) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionInputDenied -Reason 'An action input exceeds its policy maximum.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            $inputItems = if ($inputValue -is [System.Array]) { @($inputValue) } else { @($inputValue) }
            if ($null -ne $constraint.MaximumItems -and $inputItems.Count -gt [int]$constraint.MaximumItems) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionInputDenied -Reason 'An action input contains more items than the policy permits.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            if ($null -ne $constraint.MaximumLength -and @($inputItems | Where-Object { ([string]$_).Length -gt [int]$constraint.MaximumLength }).Count -gt 0) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionInputDenied -Reason 'An action input exceeds its policy length limit.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            if (@($constraint.AllowedValues).Count -gt 0) {
                foreach ($inputItem in $inputItems) {
                    if ([string]$inputItem -notin @($constraint.AllowedValues)) {
                        $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode ActionInputDenied -Reason 'An action input is not present in its policy allow list.'
                        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
                    }
                }
            }
        }
    }

    $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Allowed -ReasonCode PolicyAllowed -Reason 'The request satisfies the supplied policy profile.'
    return ConvertTo-AdminPolicyResolution -Allowed $true -PolicyDecision $decision -ExecutionSettings $executionSettings
}

function Use-AdminPolicyRuntimeLimit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$PolicyProfile,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters
    )

    $runtimeLimits = @(
        [pscustomobject]@{ ParameterName = 'MaxConcurrentJobs'; SettingName = 'MaxConcurrentJobs'; LimitName = 'MaxConcurrentJobs' }
        [pscustomobject]@{ ParameterName = 'RetryCount'; SettingName = 'RetryCount'; LimitName = 'MaxRetryCount' }
        [pscustomobject]@{ ParameterName = 'RetryDelaySeconds'; SettingName = 'RetryDelaySeconds'; LimitName = 'MaxRetryDelaySeconds' }
        [pscustomobject]@{ ParameterName = 'OperationTimeoutMinutes'; SettingName = 'OperationTimeoutMinutes'; LimitName = 'MaxOperationTimeoutMinutes' }
        [pscustomobject]@{ ParameterName = 'ConnectivityTimeoutSeconds'; SettingName = 'ConnectivityTimeoutSeconds'; LimitName = 'MaxConnectivityTimeoutSeconds' }
    )
    foreach ($runtimeLimit in $runtimeLimits) {
        $limit = $PolicyProfile.Limits.($runtimeLimit.LimitName)
        if ($null -eq $limit) {
            continue
        }
        $requestedValue = [int]$Script:State.($runtimeLimit.SettingName)
        if ((Test-AdminParameterBound -Parameters $Parameters -Name $runtimeLimit.ParameterName) -and $requestedValue -gt [int]$limit) {
            throw 'An explicit runtime setting exceeds its policy limit.'
        }
        $Script:State.($runtimeLimit.SettingName) = [math]::Min($requestedValue, [int]$limit)
    }
}

function Resolve-AdminPolicyContext {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'Remote')]
        [string]$TargetMode,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Local', 'WinRM', 'PsExec')]
        [string]$Transport,

        [Parameter(Mandatory = $true)]
        [string[]]$Computers,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters
    )

    $executionSettings = Get-AdminRequestedExecutionSetting -Parameters $Parameters
    if ($null -eq $PolicyProfile) {
        $decision = ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
        return ConvertTo-AdminPolicyResolution -Allowed $true -PolicyDecision $decision -ExecutionSettings $executionSettings
    }
    $decisionParameters = @{
        Applied       = $true
        SchemaVersion = $PolicyProfile.SchemaVersion
        ProfileName   = $PolicyProfile.ProfileName
    }
    $executionContextDecision = Get-AdminPolicyExecutionContextDecision -PolicyProfile $PolicyProfile -TargetMode $TargetMode -Transport $Transport
    if ($executionContextDecision.decision -eq 'Denied') {
        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $executionContextDecision -ExecutionSettings $executionSettings
    }
    if ($TargetMode -eq 'Remote') {
        foreach ($computer in $Computers) {
            if (@($PolicyProfile.TargetsDeny | Where-Object { Test-AdminPolicyTargetMatch -ComputerName $computer -Pattern $_ }).Count -gt 0) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetDenied -Reason 'The policy explicitly denies one or more selected targets.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
            if (@($PolicyProfile.TargetsAllow | Where-Object { Test-AdminPolicyTargetMatch -ComputerName $computer -Pattern $_ }).Count -eq 0) {
                $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetNotAllowed -Reason 'One or more selected targets do not match the policy allow patterns.'
                return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
            }
        }
    }
    if ($null -ne $PolicyProfile.Limits.MaxTargets -and $Computers.Count -gt [int]$PolicyProfile.Limits.MaxTargets) {
        $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Denied -ReasonCode TargetCountExceeded -Reason 'The selected context exceeds the policy target-count limit.'
        return ConvertTo-AdminPolicyResolution -Allowed $false -PolicyDecision $decision -ExecutionSettings $executionSettings
    }
    $decision = ConvertTo-AdminPolicyDecision @decisionParameters -Decision Allowed -ReasonCode PolicyAllowed -Reason 'The selected target context satisfies the supplied policy profile.'
    return ConvertTo-AdminPolicyResolution -Allowed $true -PolicyDecision $decision -ExecutionSettings $executionSettings
}

function Get-AdminPolicyActionDecision {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [psobject]$PolicyProfile,

        [Parameter(Mandatory = $true)]
        [string]$ActionId
    )

    if ($null -eq $PolicyProfile) {
        return ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
    }
    if ($ActionId -cin $PolicyProfile.ActionsDeny) {
        return ConvertTo-AdminPolicyDecision -Applied $true -SchemaVersion $PolicyProfile.SchemaVersion -ProfileName $PolicyProfile.ProfileName -Decision Denied -ReasonCode ActionDenied -Reason 'The policy explicitly denies the selected action.'
    }
    if ($ActionId -cnotin $PolicyProfile.ActionsAllow) {
        return ConvertTo-AdminPolicyDecision -Applied $true -SchemaVersion $PolicyProfile.SchemaVersion -ProfileName $PolicyProfile.ProfileName -Decision Denied -ReasonCode ActionNotAllowed -Reason 'The selected action is not present in the policy allow list.'
    }
    return ConvertTo-AdminPolicyDecision -Applied $true -SchemaVersion $PolicyProfile.SchemaVersion -ProfileName $PolicyProfile.ProfileName -Decision Allowed -ReasonCode PolicyAllowed -Reason 'The selected action is present in the policy allow list.'
}

function ConvertTo-AdminActionInputMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ActionId,

        [Parameter()]
        [AllowEmptyCollection()]
        [object[]]$ArgumentList = @()
    )

    $inputs = [ordered]@{}
    switch ($ActionId) {
        'RunningProcesses' { $inputs.TopCount = [int]$ArgumentList[0] }
        'WindowsUpdate' { $inputs.IncludeKB = [string[]]@($ArgumentList[0]) }
        'ScheduleReboot' { $inputs.RebootDelaySeconds = [int]$ArgumentList[0] }
        'ServiceManagement' {
            $inputs.ServiceName = [string]$ArgumentList[0]
            $inputs.ServiceAction = [string]$ArgumentList[1]
        }
        'TerminateProcess' { $inputs.ProcessName = [string]$ArgumentList[0] }
        'ClearTempFiles' {
            $inputs.MinimumAgeDays = [int]$ArgumentList[0]
            $inputs.MaximumFiles = [int]$ArgumentList[1]
        }
        'ScheduledTasks' {
            $inputs.TaskPath = [string]$ArgumentList[0]
            $inputs.MaximumTasks = [int]$ArgumentList[1]
        }
        'EventLogQuery' {
            $inputs.EventLogName = [string]$ArgumentList[0]
            $inputs.EntryCount = [int]$ArgumentList[1]
            $inputs.EventLevel = [string[]]@($ArgumentList[2])
        }
        'RegistryRead' {
            $inputs.RegistryPath = [string]$ArgumentList[0]
            $inputs.RegistryValueName = [string]$ArgumentList[1]
        }
        'CustomCommand' { $inputs.CommandText = [string]$ArgumentList[0] }
        'CustomPowerShell' { $inputs.PowerShellText = [string]$ArgumentList[0] }
    }
    return $inputs
}

function Resolve-AdminAutomationRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters
    )

    $Script:State.PolicyProfile = $null
    if (Test-AdminParameterBound -Parameters $Parameters -Name 'PolicyPath') {
        $requestedPolicyPath = ([string]$Parameters['PolicyPath']).Trim()
        if ([string]::IsNullOrWhiteSpace($requestedPolicyPath)) {
            $invalidPolicyDecision = ConvertTo-AdminPolicyDecision -Applied $true -Decision Invalid -ReasonCode PolicyInvalid -Reason 'The supplied policy profile could not be loaded or validated.'
            return Get-AdminAutomationResolutionFailure -Category Validation -Message 'PolicyPath cannot be empty when supplied.' -PolicyDecision $invalidPolicyDecision
        }
        try {
            $Script:State.PolicyProfile = Import-AdminPolicyProfile -LiteralPath $requestedPolicyPath
        }
        catch {
            $invalidPolicyDecision = ConvertTo-AdminPolicyDecision -Applied $true -Decision Invalid -ReasonCode PolicyInvalid -Reason 'The supplied policy profile could not be loaded or validated.'
            return Get-AdminAutomationResolutionFailure -Category Validation -Message $_.Exception.Message -PolicyDecision $invalidPolicyDecision
        }
    }

    if ((Test-AdminParameterBound -Parameters $Parameters -Name 'Confirm') -and [bool]$Parameters['Confirm']) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message 'Automation mode does not permit an interactive -Confirm prompt. Omit -Confirm or use -Confirm:$false.'
    }
    $preflightRequested = (Test-AdminParameterBound -Parameters $Parameters -Name 'Preflight') -and [bool]$Parameters['Preflight']
    $whatIfRequested = (Test-AdminParameterBound -Parameters $Parameters -Name 'WhatIf') -and [bool]$Parameters['WhatIf']
    if ($preflightRequested -and $whatIfRequested) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message 'Preflight cannot be combined with WhatIf.'
    }
    $configurationError = Get-AdminRuntimeConfigurationError
    if (-not [string]::IsNullOrWhiteSpace($configurationError)) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message $configurationError
    }

    $rawActionId = if (Test-AdminParameterBound -Parameters $Parameters -Name 'Action') { ([string]$Parameters['Action']).Trim() } else { '' }
    if ([string]::IsNullOrWhiteSpace($rawActionId)) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message 'Automation mode requires -Action or -ListActions.'
    }
    $requestedActionId = Get-AdminSafeActionId -ActionId $rawActionId
    if ([string]::IsNullOrWhiteSpace($requestedActionId)) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message 'The action identifier format is invalid.'
    }
    $catalogItem = Get-AdminActionCatalogItem -ActionId $requestedActionId
    if ($null -eq $catalogItem) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message "Unknown action identifier: $requestedActionId"
    }

    # Deny a known action before resolving target lists or reading action input files.
    # This keeps policy-denied requests free of avoidable file-system side effects.
    $earlyActionDecision = Get-AdminPolicyActionDecision -PolicyProfile $Script:State.PolicyProfile -ActionId $catalogItem.Id
    if ($earlyActionDecision.decision -eq 'Denied') {
        return Get-AdminAutomationResolutionFailure -Category Authorization -Message $earlyActionDecision.reason -PolicyDecision $earlyActionDecision
    }

    $allowedInputs = @($Script:AutomationActionInputs[$catalogItem.Id])
    foreach ($inputName in $Script:AutomationInputNames) {
        if ((Test-AdminParameterBound -Parameters $Parameters -Name $inputName) -and $inputName -notin $allowedInputs) {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message "Parameter -$inputName is not valid for action $($catalogItem.Id)."
        }
    }

    $localSelected = (Test-AdminParameterBound -Parameters $Parameters -Name 'Local') -and [bool]$Parameters['Local']
    $singleTarget = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ComputerName') { ([string]$Parameters['ComputerName']).Trim() } else { '' }
    $listPath = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ComputerListPath') { ([string]$Parameters['ComputerListPath']).Trim() } else { '' }
    $selectorCount = 0
    if ($localSelected) { $selectorCount++ }
    if (-not [string]::IsNullOrWhiteSpace($singleTarget)) { $selectorCount++ }
    if (-not [string]::IsNullOrWhiteSpace($listPath)) { $selectorCount++ }
    if ($selectorCount -ne 1) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message 'Select exactly one target source: -Local, -ComputerName, or -ComputerListPath.'
    }

    $targetMode = if ($localSelected) { 'Local' } else { 'Remote' }
    $policyTransport = if ($targetMode -eq 'Local') { 'Local' } else { $Script:State.Transport }
    $earlyContextDecision = Get-AdminPolicyExecutionContextDecision -PolicyProfile $Script:State.PolicyProfile -TargetMode $targetMode -Transport $policyTransport
    if ($earlyContextDecision.decision -eq 'Denied') {
        return Get-AdminAutomationResolutionFailure -Category Authorization -Message $earlyContextDecision.reason -PolicyDecision $earlyContextDecision
    }
    $computers = @()
    if ($targetMode -eq 'Local') {
        $remoteOnlyParameters = @(
            'Transport',
            'PsExecPath',
            'Credential',
            'MaxConcurrentJobs',
            'RetryCount',
            'RetryDelaySeconds',
            'OperationTimeoutMinutes',
            'ConnectivityTimeoutSeconds',
            'UseSsl',
            'Authentication',
            'SkipConnectivityCheck',
            'ComputerName',
            'ComputerListPath',
            'PsExecConfirmationText'
        )
        foreach ($parameterName in $remoteOnlyParameters) {
            if (Test-AdminParameterBound -Parameters $Parameters -Name $parameterName) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message "Parameter -$parameterName is not valid with -Local."
            }
        }
        $computers = @($env:COMPUTERNAME)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($singleTarget)) {
        if (-not (Test-AdminHostname -ComputerName $singleTarget)) {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message "Invalid remote target: $singleTarget"
        }
        $computers = @($singleTarget)
    }
    else {
        try {
            $resolvedListPath = Resolve-AdminAutomationInputFile -LiteralPath $listPath
            $importResult = Import-AdminComputerList -LiteralPath $resolvedListPath -MaximumTargets 500
        }
        catch {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message $_.Exception.Message
        }
        if (@($importResult.InvalidLines).Count -gt 0) {
            $lineText = (@($importResult.InvalidLines | Select-Object -First 20) -join ', ')
            return Get-AdminAutomationResolutionFailure -Category Validation -Message "The computer list contains invalid targets on line(s): $lineText"
        }
        $computers = @($importResult.Computers)
        if ($computers.Count -eq 0) {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message 'The computer list contains no valid targets.'
        }
    }

    $earlyTargetPolicyResolution = Resolve-AdminPolicyContext -PolicyProfile $Script:State.PolicyProfile -TargetMode $targetMode -Transport $policyTransport -Computers $computers -Parameters $Parameters
    if (-not $earlyTargetPolicyResolution.Allowed) {
        return Get-AdminAutomationResolutionFailure -Category Authorization -Message $earlyTargetPolicyResolution.PolicyDecision.reason -PolicyDecision $earlyTargetPolicyResolution.PolicyDecision
    }

    if ($computers.Count -gt 25) {
        $targetAuthorization = if (Test-AdminParameterBound -Parameters $Parameters -Name 'TargetListConfirmationText') { [string]$Parameters['TargetListConfirmationText'] } else { '' }
        if ($targetAuthorization -cne 'USE TARGET LIST') {
            return Get-AdminAutomationResolutionFailure -Category Authorization -Message 'More than 25 targets require -TargetListConfirmationText with the exact value USE TARGET LIST.'
        }
    }
    elseif ((Test-AdminParameterBound -Parameters $Parameters -Name 'TargetListConfirmationText') -and -not [string]::IsNullOrWhiteSpace([string]$Parameters['TargetListConfirmationText'])) {
        return Get-AdminAutomationResolutionFailure -Category Validation -Message 'TargetListConfirmationText is accepted only when the request contains more than 25 targets.'
    }

    if ($targetMode -eq 'Remote' -and $Script:State.Transport -eq 'PsExec') {
        foreach ($winRmOnlyParameter in @('Authentication', 'UseSsl')) {
            if (Test-AdminParameterBound -Parameters $Parameters -Name $winRmOnlyParameter) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message "Parameter -$winRmOnlyParameter is valid only with the WinRM transport."
            }
        }
        if ($Script:State.Credential) {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message 'PsExec does not accept alternate credentials in this toolkit.'
        }
        $psExecAuthorization = if (Test-AdminParameterBound -Parameters $Parameters -Name 'PsExecConfirmationText') { [string]$Parameters['PsExecConfirmationText'] } else { '' }
        if ($psExecAuthorization -cne 'USE PSEXEC') {
            return Get-AdminAutomationResolutionFailure -Category Authorization -Message 'PsExec requires -PsExecConfirmationText with the exact value USE PSEXEC.'
        }
        try {
            $Script:State.PsExecFullPath = Resolve-AdminPsExec -Path $Script:State.PsExecPath
        }
        catch {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message $_.Exception.Message
        }
    }
    else {
        if (Test-AdminParameterBound -Parameters $Parameters -Name 'PsExecPath') {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message 'Parameter -PsExecPath is valid only with the PsExec transport.'
        }
        if ((Test-AdminParameterBound -Parameters $Parameters -Name 'PsExecConfirmationText') -and -not [string]::IsNullOrWhiteSpace([string]$Parameters['PsExecConfirmationText'])) {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message 'PsExecConfirmationText is accepted only for the PsExec transport.'
        }
    }

    $arguments = @()
    $normalizedInputs = [ordered]@{}
    $effectiveReadOnly = [bool]$catalogItem.ReadOnly
    switch ($catalogItem.Id) {
        'RunningProcesses' {
            $value = if (Test-AdminParameterBound -Parameters $Parameters -Name 'TopCount') { [int]$Parameters['TopCount'] } else { 20 }
            if ($value -lt 1 -or $value -gt 100) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'TopCount must be from 1 through 100.'
            }
            $arguments = @($value)
            $normalizedInputs.TopCount = $value
        }
        'WindowsUpdate' {
            $requestedKbs = @(if (Test-AdminParameterBound -Parameters $Parameters -Name 'IncludeKB') { $Parameters['IncludeKB'] })
            if ($requestedKbs.Count -gt 100) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'IncludeKB accepts at most 100 KB identifiers.'
            }
            $normalizedKbs = New-Object 'System.Collections.Generic.List[string]'
            $seenKbs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($requestedKb in $requestedKbs) {
                $kb = ([string]$requestedKb).Trim().ToUpperInvariant()
                if (-not [string]::IsNullOrWhiteSpace($kb) -and -not $kb.StartsWith('KB')) {
                    $kb = "KB$kb"
                }
                if (-not (Test-AdminKbNumber -KbNumber $kb)) {
                    return Get-AdminAutomationResolutionFailure -Category Validation -Message "Invalid KB identifier: $requestedKb"
                }
                if ($seenKbs.Add($kb)) {
                    $normalizedKbs.Add($kb) | Out-Null
                }
            }
            $arguments = @(, $normalizedKbs.ToArray())
            $normalizedInputs.IncludeKB = [string[]]$normalizedKbs.ToArray()
        }
        'ScheduleReboot' {
            $value = if (Test-AdminParameterBound -Parameters $Parameters -Name 'RebootDelaySeconds') { [int]$Parameters['RebootDelaySeconds'] } else { 60 }
            if ($value -lt 30 -or $value -gt 3600) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'RebootDelaySeconds must be from 30 through 3600.'
            }
            $arguments = @($value)
            $normalizedInputs.RebootDelaySeconds = $value
        }
        'ServiceManagement' {
            $requestedService = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ServiceName') { ([string]$Parameters['ServiceName']).Trim() } else { '' }
            if (-not (Test-AdminServiceName -ServiceName $requestedService)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'ServiceManagement requires a valid -ServiceName.'
            }
            $requestedServiceAction = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ServiceAction') { ([string]$Parameters['ServiceAction']).Trim() } else { 'Query' }
            $serviceActionMap = @{
                query   = 'Query'
                start   = 'Start'
                stop    = 'Stop'
                restart = 'Restart'
            }
            $serviceActionKey = $requestedServiceAction.ToLowerInvariant()
            if (-not $serviceActionMap.ContainsKey($serviceActionKey)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'ServiceAction must be Query, Start, Stop, or Restart.'
            }
            $canonicalServiceAction = $serviceActionMap[$serviceActionKey]
            $effectiveReadOnly = $canonicalServiceAction -eq 'Query'
            $arguments = @($requestedService, $canonicalServiceAction)
            $normalizedInputs.ServiceName = $requestedService
            $normalizedInputs.ServiceAction = $canonicalServiceAction
        }
        'TerminateProcess' {
            $requestedProcess = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ProcessName') { ([string]$Parameters['ProcessName']).Trim() } else { '' }
            if (-not (Test-AdminProcessName -ProcessName $requestedProcess)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'TerminateProcess requires a valid -ProcessName.'
            }
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($requestedProcess)
            $protectedProcesses = @('System', 'Registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'fontdrvhost', 'dwm', 'Idle')
            if ($baseName -in $protectedProcesses) {
                return Get-AdminAutomationResolutionFailure -Category Authorization -Message "The safety policy blocks termination of core Windows process '$baseName'."
            }
            $arguments = @($requestedProcess)
            $normalizedInputs.ProcessName = $requestedProcess
        }
        'ClearTempFiles' {
            $age = if (Test-AdminParameterBound -Parameters $Parameters -Name 'MinimumAgeDays') { [int]$Parameters['MinimumAgeDays'] } else { 2 }
            $maximum = if (Test-AdminParameterBound -Parameters $Parameters -Name 'MaximumFiles') { [int]$Parameters['MaximumFiles'] } else { 50000 }
            if ($age -lt 1 -or $age -gt 30) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'MinimumAgeDays must be from 1 through 30.'
            }
            if ($maximum -lt 100 -or $maximum -gt 100000) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'MaximumFiles must be from 100 through 100000.'
            }
            $arguments = @($age, $maximum)
            $normalizedInputs.MinimumAgeDays = $age
            $normalizedInputs.MaximumFiles = $maximum
        }
        'ScheduledTasks' {
            $requestedTaskPath = if (Test-AdminParameterBound -Parameters $Parameters -Name 'TaskPath') { ([string]$Parameters['TaskPath']).Trim() } else { '\' }
            if ([string]::IsNullOrWhiteSpace($requestedTaskPath)) {
                $requestedTaskPath = '\'
            }
            if (-not $requestedTaskPath.EndsWith('\')) {
                $requestedTaskPath += '\'
            }
            if (-not (Test-AdminTaskPath -TaskPath $requestedTaskPath)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'TaskPath is invalid.'
            }
            $maximum = if (Test-AdminParameterBound -Parameters $Parameters -Name 'MaximumTasks') { [int]$Parameters['MaximumTasks'] } else { 50 }
            if ($maximum -lt 1 -or $maximum -gt 500) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'MaximumTasks must be from 1 through 500.'
            }
            $arguments = @($requestedTaskPath, $maximum)
            $normalizedInputs.TaskPath = $requestedTaskPath
            $normalizedInputs.MaximumTasks = $maximum
        }
        'EventLogQuery' {
            $requestedLogName = if (Test-AdminParameterBound -Parameters $Parameters -Name 'EventLogName') { ([string]$Parameters['EventLogName']).Trim() } else { 'System' }
            if (-not (Test-AdminEventLogName -LogName $requestedLogName)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'EventLogName is invalid.'
            }
            $count = if (Test-AdminParameterBound -Parameters $Parameters -Name 'EntryCount') { [int]$Parameters['EntryCount'] } else { 20 }
            if ($count -lt 1 -or $count -gt 1000) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'EntryCount must be from 1 through 1000.'
            }
            $requestedLevels = @(if (Test-AdminParameterBound -Parameters $Parameters -Name 'EventLevel') { $Parameters['EventLevel'] } else { 'Error'; 'Warning' })
            $eventLevelCharacterCount = 0
            foreach ($requestedLevelValue in $requestedLevels) {
                $eventLevelCharacterCount += ([string]$requestedLevelValue).Length
            }
            if ($requestedLevels.Count -gt 20 -or $eventLevelCharacterCount -gt 1024) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'EventLevel input exceeds the supported size limit.'
            }
            $levelMap = @{
                critical    = 'Critical'
                error       = 'Error'
                warning     = 'Warning'
                information = 'Information'
                verbose     = 'Verbose'
            }
            $levels = New-Object 'System.Collections.Generic.List[string]'
            $seenLevels = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($requestedLevel in $requestedLevels) {
                foreach ($levelPart in @(([string]$requestedLevel) -split ',')) {
                    $levelKey = $levelPart.Trim().ToLowerInvariant()
                    if (-not $levelMap.ContainsKey($levelKey)) {
                        return Get-AdminAutomationResolutionFailure -Category Validation -Message "Invalid event level: $levelPart"
                    }
                    $canonicalLevel = $levelMap[$levelKey]
                    if ($seenLevels.Add($canonicalLevel)) {
                        $levels.Add($canonicalLevel) | Out-Null
                    }
                }
            }
            if ($levels.Count -eq 0) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'At least one EventLevel is required.'
            }
            $arguments = @($requestedLogName, $count, [string[]]$levels.ToArray())
            $normalizedInputs.EventLogName = $requestedLogName
            $normalizedInputs.EntryCount = $count
            $normalizedInputs.EventLevel = [string[]]$levels.ToArray()
        }
        'RegistryRead' {
            $requestedRegistryPath = if (Test-AdminParameterBound -Parameters $Parameters -Name 'RegistryPath') { ([string]$Parameters['RegistryPath']).Trim() } else { '' }
            if (-not (Test-AdminRegistryPath -RegistryPath $requestedRegistryPath)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'RegistryRead requires a valid -RegistryPath.'
            }
            $requestedValueName = if (Test-AdminParameterBound -Parameters $Parameters -Name 'RegistryValueName') { [string]$Parameters['RegistryValueName'] } else { '' }
            if (-not (Test-AdminRegistryValueName -ValueName $requestedValueName)) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'RegistryValueName is invalid.'
            }
            $arguments = @($requestedRegistryPath, $requestedValueName)
            $normalizedInputs.RegistryPath = $requestedRegistryPath
            $normalizedInputs.RegistryValueName = $requestedValueName
        }
        'CustomCommand' {
            $requestedCommand = if (Test-AdminParameterBound -Parameters $Parameters -Name 'CommandText') { [string]$Parameters['CommandText'] } else { '' }
            if ([string]::IsNullOrWhiteSpace($requestedCommand) -or $requestedCommand.Length -gt 32767) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'CustomCommand requires nonempty CommandText no longer than 32767 characters.'
            }
            $arguments = @($requestedCommand)
            $normalizedInputs.CommandText = $requestedCommand
        }
        'CustomPowerShell' {
            $requestedScriptText = if (Test-AdminParameterBound -Parameters $Parameters -Name 'PowerShellText') { [string]$Parameters['PowerShellText'] } else { '' }
            $requestedScriptFile = if (Test-AdminParameterBound -Parameters $Parameters -Name 'PowerShellFile') { ([string]$Parameters['PowerShellFile']).Trim() } else { '' }
            $hasText = -not [string]::IsNullOrWhiteSpace($requestedScriptText)
            $hasFile = -not [string]::IsNullOrWhiteSpace($requestedScriptFile)
            if ([int]$hasText + [int]$hasFile -ne 1) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'CustomPowerShell requires exactly one of -PowerShellText or -PowerShellFile.'
            }
            if ($hasFile) {
                try {
                    $resolvedScriptPath = Resolve-AdminAutomationInputFile -LiteralPath $requestedScriptFile -RequiredExtension '.ps1'
                    $requestedScriptText = Read-AdminBoundedUtf8File -LiteralPath $resolvedScriptPath -MaximumBytes 1048576
                    $normalizedInputs.PowerShellFile = $resolvedScriptPath
                }
                catch {
                    return Get-AdminAutomationResolutionFailure -Category Validation -Message $_.Exception.Message
                }
            }
            $scriptValidation = Test-AdminPowerShellText -ScriptText $requestedScriptText
            if (-not $scriptValidation.IsValid) {
                return Get-AdminAutomationResolutionFailure -Category Validation -Message 'PowerShell source is invalid and was not executed.'
            }
            $arguments = @($requestedScriptText)
            $normalizedInputs.PowerShellText = $requestedScriptText
        }
    }

    $policyResolution = Resolve-AdminPolicyRequest -PolicyProfile $Script:State.PolicyProfile -ActionId $catalogItem.Id -TargetMode $targetMode -Transport $policyTransport -Computers $computers -Inputs $normalizedInputs -Parameters $Parameters
    if (-not $policyResolution.Allowed) {
        return Get-AdminAutomationResolutionFailure -Category Authorization -Message $policyResolution.PolicyDecision.reason -PolicyDecision $policyResolution.PolicyDecision
    }

    $expectedConfirmation = if ($Script:AutomationConfirmations.Contains($catalogItem.Id)) { [string]$Script:AutomationConfirmations[$catalogItem.Id] } else { $null }
    $providedConfirmation = if (Test-AdminParameterBound -Parameters $Parameters -Name 'ConfirmationText') { [string]$Parameters['ConfirmationText'] } else { '' }
    if ($effectiveReadOnly) {
        if (-not [string]::IsNullOrWhiteSpace($providedConfirmation)) {
            return Get-AdminAutomationResolutionFailure -Category Validation -Message 'ConfirmationText is not accepted for a read-only request.' -PolicyDecision $policyResolution.PolicyDecision
        }
    }
    elseif ($whatIfRequested -or $preflightRequested) {
        if (-not [string]::IsNullOrWhiteSpace($providedConfirmation) -and $providedConfirmation -cne $expectedConfirmation) {
            return Get-AdminAutomationResolutionFailure -Category Authorization -Message "The supplied ConfirmationText does not match the exact value $expectedConfirmation." -PolicyDecision $policyResolution.PolicyDecision
        }
    }
    elseif ($providedConfirmation -cne $expectedConfirmation) {
        return Get-AdminAutomationResolutionFailure -Category Authorization -Message "This action requires -ConfirmationText with the exact value $expectedConfirmation." -PolicyDecision $policyResolution.PolicyDecision
    }

    $warnings = New-Object 'System.Collections.Generic.List[string]'
    if ($catalogItem.Id -in @('CustomCommand', 'CustomPowerShell')) {
        $warnings.Add('This expert action executes operator-supplied content without a sandbox.') | Out-Null
    }

    $request = [pscustomobject][ordered]@{
        CatalogItem         = $catalogItem
        ActionId            = $catalogItem.Id
        ActionName          = $catalogItem.Name
        Script              = $catalogItem.Script
        Arguments           = @($arguments)
        ReadOnly            = [bool]$effectiveReadOnly
        ExpectedConfirmation = $expectedConfirmation
        TargetMode          = $targetMode
        Computers           = @($computers)
        Inputs              = $normalizedInputs
        Preflight           = $preflightRequested
        PolicyProfile       = $Script:State.PolicyProfile
        PolicyDecision      = $policyResolution.PolicyDecision
        ExecutionSettings   = $policyResolution.ExecutionSettings
        Warnings            = @($warnings.ToArray())
    }
    return [pscustomobject][ordered]@{
        Success       = $true
        Category      = $null
        Message       = $null
        PolicyDecision = $policyResolution.PolicyDecision
        Request       = $request
    }
}

function Get-AdminAutomationOutcome {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$TargetResults
    )

    $successCount = @($TargetResults | Where-Object { $_.Status -eq 'Success' }).Count
    $partialCount = @($TargetResults | Where-Object { $_.Status -eq 'Partial' }).Count
    $failedCount = @($TargetResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $timeoutCount = @($TargetResults | Where-Object { $_.Status -eq 'TimedOut' }).Count

    if ($successCount -eq $TargetResults.Count -and $TargetResults.Count -gt 0) {
        $status = 'Succeeded'
        $outcome = 'CompleteSuccess'
        $exitCode = $Script:AutomationExitCodes.CompleteSuccess
    }
    elseif (($successCount + $partialCount) -gt 0) {
        $status = 'PartiallySucceeded'
        $outcome = 'PartialSuccess'
        $exitCode = $Script:AutomationExitCodes.PartialSuccess
    }
    elseif ($timeoutCount -eq $TargetResults.Count -and $TargetResults.Count -gt 0) {
        $status = 'TimedOut'
        $outcome = 'Timeout'
        $exitCode = $Script:AutomationExitCodes.Timeout
    }
    else {
        $status = 'Failed'
        $outcome = 'ExecutionFailure'
        $exitCode = $Script:AutomationExitCodes.ExecutionFailure
    }

    return [pscustomobject][ordered]@{
        Status       = $status
        Outcome      = $outcome
        ExitCode     = [int]$exitCode
        SuccessCount = $successCount
        PartialCount = $partialCount
        FailedCount  = $failedCount
        TimeoutCount = $timeoutCount
    }
}

function Invoke-AdminAutomationCore {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResolvedOutputPath,

        [Parameter(Mandatory = $true)]
        [guid]$RunId,

        [Parameter(Mandatory = $true)]
        [datetime]$StartedAtUtc
    )

    $requestedActionId = if (Test-AdminParameterBound -Parameters $Parameters -Name 'Action') { Get-AdminSafeActionId -ActionId ([string]$Parameters['Action']) } else { $null }
    $reportPaths = if ($ResolvedOutputPath -ceq '-') { @() } else { @($ResolvedOutputPath) }
    $requestedTargetSummary = Get-AdminRequestedTargetSummary -Parameters $Parameters
    $transportName = $requestedTargetSummary.Transport
    $transportAuthentication = $requestedTargetSummary.Authentication
    $transportUseSsl = $requestedTargetSummary.UseSsl
    $preflightRequested = (Test-AdminParameterBound -Parameters $Parameters -Name 'Preflight') -and [bool]$Parameters['Preflight']
    $requestedPolicyDecision = if (Test-AdminParameterBound -Parameters $Parameters -Name 'PolicyPath') {
        ConvertTo-AdminPolicyDecision -Applied $true -Decision NotEvaluated -ReasonCode NotEvaluated -Reason 'The policy profile has not been evaluated.'
    }
    else {
        ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
    }

    if ((Test-AdminParameterBound -Parameters $Parameters -Name 'ListActions') -and [bool]$Parameters['ListActions']) {
        if (Test-AdminParameterBound -Parameters $Parameters -Name 'Action') {
            $finishedAtUtc = [datetime]::UtcNow
            return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -PolicyDecision $requestedPolicyDecision -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -Errors @([pscustomobject]@{ Category = 'Validation'; Message = 'ListActions cannot be combined with Action.' }) -ReportPaths $reportPaths
        }
        $catalogOnlyParameters = @(
            'Transport',
            'PsExecPath',
            'Credential',
            'MaxConcurrentJobs',
            'RetryCount',
            'RetryDelaySeconds',
            'OperationTimeoutMinutes',
            'ConnectivityTimeoutSeconds',
            'LogFile',
            'UseSsl',
            'Authentication',
            'Quiet',
            'SkipConnectivityCheck',
            'Local',
            'ComputerName',
            'ComputerListPath',
            'ConfirmationText',
            'TargetListConfirmationText',
            'PsExecConfirmationText',
            'Preflight',
            'WhatIf',
            'Confirm'
        ) + $Script:AutomationInputNames
        foreach ($parameterName in $catalogOnlyParameters) {
            if (Test-AdminParameterBound -Parameters $Parameters -Name $parameterName) {
                $finishedAtUtc = [datetime]::UtcNow
                return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -PolicyDecision $requestedPolicyDecision -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -Errors @([pscustomobject]@{ Category = 'Validation'; Message = "Parameter -$parameterName cannot be combined with -ListActions." }) -ReportPaths $reportPaths
            }
        }

        $catalogPolicyProfile = $null
        $catalogPolicyDecision = $requestedPolicyDecision
        if (Test-AdminParameterBound -Parameters $Parameters -Name 'PolicyPath') {
            $requestedCatalogPolicyPath = ([string]$Parameters['PolicyPath']).Trim()
            try {
                if ([string]::IsNullOrWhiteSpace($requestedCatalogPolicyPath)) {
                    throw 'PolicyPath cannot be empty when supplied.'
                }
                $catalogPolicyProfile = Import-AdminPolicyProfile -LiteralPath $requestedCatalogPolicyPath
                $catalogPolicyDecision = ConvertTo-AdminPolicyDecision -Applied $true -SchemaVersion $catalogPolicyProfile.SchemaVersion -ProfileName $catalogPolicyProfile.ProfileName -Decision Allowed -ReasonCode PolicyLoaded -Reason 'The policy profile was validated and applied to the action catalog.'
            }
            catch {
                $invalidPolicyDecision = ConvertTo-AdminPolicyDecision -Applied $true -Decision Invalid -ReasonCode PolicyInvalid -Reason 'The supplied policy profile could not be loaded or validated.'
                $finishedAtUtc = [datetime]::UtcNow
                return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -PolicyDecision $invalidPolicyDecision -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -Errors @([pscustomobject]@{ Category = 'Validation'; Message = $_.Exception.Message }) -ReportPaths $reportPaths
            }
        }
        $actions = @(Get-AdminAutomationActionCatalog -PolicyProfile $catalogPolicyProfile)
        $finishedAtUtc = [datetime]::UtcNow
        return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -PolicyDecision $catalogPolicyDecision -Status Succeeded -Outcome CompleteSuccess -ExitCode $Script:AutomationExitCodes.CompleteSuccess -Actions $actions -ReportPaths $reportPaths
    }

    if (-not (Test-WindowsPlatform)) {
        $finishedAtUtc = [datetime]::UtcNow
        return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -PolicyDecision $requestedPolicyDecision -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -Errors @([pscustomobject]@{ Category = 'Validation'; Message = 'Windows Admin Toolkit runs only on Windows.' }) -ReportPaths $reportPaths
    }

    $resolution = Resolve-AdminAutomationRequest -Parameters $Parameters
    if (-not $resolution.Success) {
        $catalogItem = if ($requestedActionId) { Get-AdminActionCatalogItem -ActionId $requestedActionId } else { $null }
        $actionName = if ($catalogItem) { $catalogItem.Name } else { $null }
        $readOnly = if ($catalogItem -and $catalogItem.Classification -ne 'Conditional') { [bool]$catalogItem.ReadOnly } else { $null }
        $outcome = if ($resolution.Category -eq 'Authorization') { 'AuthorizationFailure' } else { 'ValidationFailure' }
        $status = if ($resolution.Category -eq 'Authorization') { 'AuthorizationFailed' } else { 'ValidationFailed' }
        $exitCode = if ($resolution.Category -eq 'Authorization') { $Script:AutomationExitCodes.AuthorizationFailure } else { $Script:AutomationExitCodes.ValidationFailure }
        $resolutionWarnings = New-Object 'System.Collections.Generic.List[string]'
        if ($resolution.PolicyDecision.applied) {
            try {
                $requestedFailureLogPath = if (Test-AdminParameterBound -Parameters $Parameters -Name 'LogFile') { [string]$Parameters['LogFile'] } else { $null }
                [void](Initialize-AdminLog -RequestedPath $requestedFailureLogPath)
                Write-AdminLog -Message ("Automation run {0} policy decision: {1} ({2})." -f $runId, $resolution.PolicyDecision.decision, $resolution.PolicyDecision.reasonCode) -NoConsole
            }
            catch {
                $resolutionWarnings.Add('The policy decision was returned in JSON, but the safe log could not be initialized.') | Out-Null
            }
        }
        $finishedAtUtc = [datetime]::UtcNow
        return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -ActionName $actionName -ReadOnly $readOnly -Preflight $preflightRequested -PolicyDecision $resolution.PolicyDecision -TargetMode $requestedTargetSummary.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status $status -Outcome $outcome -ExitCode $exitCode -RequestedTargetCount $requestedTargetSummary.RequestedTargetCount -Errors @([pscustomobject]@{ Category = $resolution.Category; Message = $resolution.Message }) -Warnings $resolutionWarnings.ToArray() -ReportPaths $reportPaths
    }

    $request = $resolution.Request
    $transportName = if ($request.TargetMode -eq 'Local') { 'Local' } else { $Script:State.Transport }
    $transportAuthentication = if ($request.TargetMode -eq 'Remote' -and $Script:State.Transport -eq 'WinRM') { $Script:State.Authentication } else { $null }
    $transportUseSsl = $request.TargetMode -eq 'Remote' -and $Script:State.Transport -eq 'WinRM' -and [bool]$Script:State.UseSsl
    try {
        $requestedLogPath = if (Test-AdminParameterBound -Parameters $Parameters -Name 'LogFile') { [string]$Parameters['LogFile'] } else { $null }
        [void](Initialize-AdminLog -RequestedPath $requestedLogPath)
        Write-AdminLog -Message ("Automation run {0} prepared action '{1}' for {2} target(s)." -f $runId, $request.ActionName, $request.Computers.Count) -NoConsole
        Write-AdminLog -Message ("Automation run {0} policy decision: {1} ({2})." -f $runId, $request.PolicyDecision.decision, $request.PolicyDecision.reasonCode) -NoConsole
    }
    catch {
        $finishedAtUtc = [datetime]::UtcNow
        return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $request.ActionId -ActionName $request.ActionName -ReadOnly $request.ReadOnly -Preflight $request.Preflight -PolicyDecision $request.PolicyDecision -TargetMode $request.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -RequestedTargetCount $request.Computers.Count -Errors @([pscustomobject]@{ Category = 'Validation'; Message = "Unable to initialize the log: $($_.Exception.Message)" }) -ReportPaths $reportPaths
    }

    if (-not $request.ReadOnly -and -not $request.Preflight) {
        $whatIfRequested = (Test-AdminParameterBound -Parameters $Parameters -Name 'WhatIf') -and [bool]$Parameters['WhatIf']
        if ($whatIfRequested) {
            $previewResults = New-Object 'System.Collections.Generic.List[object]'
            for ($index = 0; $index -lt $request.Computers.Count; $index++) {
                $previewTime = [datetime]::UtcNow
                $previewResults.Add((ConvertTo-AdminDetailedTargetResult -Index $index -ComputerName $request.Computers[$index] -Transport $transportName -StartedAtUtc $previewTime -FinishedAtUtc $previewTime -Status WhatIf -Data @())) | Out-Null
            }
            $warnings = @($request.Warnings) + @('WhatIf preview completed. No target operation was started.')
            $finishedAtUtc = [datetime]::UtcNow
            Write-AdminLog -Message ("Automation run {0} completed as a WhatIf preview." -f $runId) -NoConsole
            return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $request.ActionId -ActionName $request.ActionName -ReadOnly $request.ReadOnly -PolicyDecision $request.PolicyDecision -TargetMode $request.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status WhatIf -Outcome CompleteSuccess -ExitCode $Script:AutomationExitCodes.CompleteSuccess -RequestedTargetCount $request.Computers.Count -TargetResults $previewResults.ToArray() -Warnings $warnings -ReportPaths $reportPaths
        }

        $targetDescription = if ($request.TargetMode -eq 'Local') { "local computer $env:COMPUTERNAME" } else { "$($request.Computers.Count) remote target(s)" }
        $shouldProcess = $PSCmdlet.ShouldProcess($targetDescription, $request.ActionName)
        if (-not $shouldProcess) {
            $finishedAtUtc = [datetime]::UtcNow
            return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $request.ActionId -ActionName $request.ActionName -ReadOnly $request.ReadOnly -PolicyDecision $request.PolicyDecision -TargetMode $request.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status AuthorizationFailed -Outcome AuthorizationFailure -ExitCode $Script:AutomationExitCodes.AuthorizationFailure -RequestedTargetCount $request.Computers.Count -Errors @([pscustomobject]@{ Category = 'Authorization'; Message = 'PowerShell ShouldProcess did not authorize the operation.' }) -Warnings $request.Warnings -ReportPaths $reportPaths
        }
    }

    if ($Script:State.AuditContext -and $Script:State.AuditContext.Enabled) {
        Write-AdminAuditExecutionStarted -RunId $runId -Request $request -Context $Script:State.AuditContext
    }

    $preflightFailures = @{}
    $executionComputers = @($request.Computers)
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    foreach ($requestWarning in @($request.Warnings)) {
        $warnings.Add($requestWarning) | Out-Null
    }
    if ($request.TargetMode -eq 'Remote' -and -not $Script:State.SkipConnectivityCheck) {
        $port = if ($Script:State.Transport -eq 'PsExec') { 445 } elseif ($Script:State.UseSsl) { 5986 } else { 5985 }
        $preflightStartedAtUtc = [datetime]::UtcNow
        try {
            $preflight = Test-AdminTargetConnectivity -Computers $request.Computers -Port $port -TimeoutSeconds $request.ExecutionSettings.ConnectivityTimeoutSeconds -BatchSize $request.ExecutionSettings.MaxConcurrentJobs
            $executionComputers = @($preflight.Reachable)
            foreach ($unreachableComputer in @($preflight.Unreachable)) {
                $preflightFinishedAtUtc = [datetime]::UtcNow
                $preflightFailures[$unreachableComputer] = ConvertTo-AdminDetailedTargetResult -Index 0 -ComputerName $unreachableComputer -Transport $transportName -StartedAtUtc $preflightStartedAtUtc -FinishedAtUtc $preflightFinishedAtUtc -Status Failed -ErrorCategory Connectivity -ErrorMessage "The target did not answer on TCP port $port during preflight."
            }
            if (@($preflight.Unreachable).Count -gt 0) {
                $warnings.Add("$(@($preflight.Unreachable).Count) target(s) failed the TCP port $port preflight and were not executed.") | Out-Null
            }
        }
        catch {
            $preflightFinishedAtUtc = [datetime]::UtcNow
            $executionComputers = @()
            foreach ($computer in $request.Computers) {
                $preflightFailures[$computer] = ConvertTo-AdminDetailedTargetResult -Index 0 -ComputerName $computer -Transport $transportName -StartedAtUtc $preflightStartedAtUtc -FinishedAtUtc $preflightFinishedAtUtc -Status Failed -ErrorCategory Connectivity -ErrorMessage $_.Exception.Message
            }
            $warnings.Add('The connectivity preflight failed before target execution.') | Out-Null
        }
    }

    $executionActionName = $request.Script
    $executionArguments = @($request.Arguments)
    $executionReadOnly = $request.ReadOnly
    if ($request.Preflight) {
        $capabilityRequirements = Get-AdminActionCapabilityRequirement -ActionId $request.ActionId -Inputs $request.Inputs
        $executionActionName = 'CapabilityPreflight'
        $capabilityArguments = New-Object 'System.Collections.Generic.List[object]'
        $capabilityArguments.Add([string]$request.ActionId) | Out-Null
        $capabilityArguments.Add([string[]]@($capabilityRequirements.Commands)) | Out-Null
        $capabilityArguments.Add([string[]]@($capabilityRequirements.Executables)) | Out-Null
        $capabilityArguments.Add([string[]]@($capabilityRequirements.ComObjects)) | Out-Null
        $capabilityArguments.Add([bool]$capabilityRequirements.RequiresAdministrator) | Out-Null
        $executionArguments = $capabilityArguments.ToArray()
        $executionReadOnly = $true
        $warnings.Add('Capability preflight completed without executing the requested action.') | Out-Null
    }

    $executionResults = @()
    if ($executionComputers.Count -gt 0) {
        try {
            $executionResults = @(Invoke-AdminTargetDetailed -TargetMode $request.TargetMode -Computers $executionComputers -ActionName $executionActionName -ArgumentList $executionArguments -ReadOnly $executionReadOnly -MaxConcurrentJobs $request.ExecutionSettings.MaxConcurrentJobs -RetryCount $request.ExecutionSettings.RetryCount -RetryDelaySeconds $request.ExecutionSettings.RetryDelaySeconds -OperationTimeoutMinutes $request.ExecutionSettings.OperationTimeoutMinutes)
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            $finishedAtUtc = [datetime]::UtcNow
            Write-AdminLog -Message ("Automation run {0} was cancelled before completion." -f $runId) -Level WARN -NoConsole
            return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $request.ActionId -ActionName $request.ActionName -ReadOnly $request.ReadOnly -Preflight $request.Preflight -PolicyDecision $request.PolicyDecision -TargetMode $request.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status InternalFailure -Outcome InternalFailure -ExitCode $Script:AutomationExitCodes.InternalFailure -RequestedTargetCount $request.Computers.Count -Errors @([pscustomobject]@{ Category = 'Internal'; Message = 'The automation run was cancelled before completion.' }) -Warnings $warnings.ToArray() -ReportPaths $reportPaths
        }
        catch {
            $finishedAtUtc = [datetime]::UtcNow
            $internalErrorMessage = if ($request.Script -in @('CustomCommand', 'CustomPowerShell')) { 'The custom action failed internally. Operator-supplied error text was omitted.' } else { ConvertTo-AdminSafeErrorMessage -Message $_.Exception.Message }
            Write-AdminLog -Message ("Automation run {0} failed internally: {1}" -f $runId, $internalErrorMessage) -Level ERROR -NoConsole
            return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $request.ActionId -ActionName $request.ActionName -ReadOnly $request.ReadOnly -Preflight $request.Preflight -PolicyDecision $request.PolicyDecision -TargetMode $request.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status InternalFailure -Outcome InternalFailure -ExitCode $Script:AutomationExitCodes.InternalFailure -RequestedTargetCount $request.Computers.Count -Errors @([pscustomobject]@{ Category = 'Internal'; Message = $internalErrorMessage }) -Warnings $warnings.ToArray() -ReportPaths $reportPaths
        }
    }

    $executionMap = @{}
    foreach ($executionResult in $executionResults) {
        $executionMap[[string]$executionResult.ComputerName] = $executionResult
    }
    $orderedResults = New-Object 'System.Collections.Generic.List[object]'
    for ($index = 0; $index -lt $request.Computers.Count; $index++) {
        $computer = $request.Computers[$index]
        $result = if ($preflightFailures.ContainsKey($computer)) { $preflightFailures[$computer] } else { $executionMap[$computer] }
        if ($null -eq $result) {
            $missingTime = [datetime]::UtcNow
            $result = ConvertTo-AdminDetailedTargetResult -Index $index -ComputerName $computer -Transport $transportName -StartedAtUtc $missingTime -FinishedAtUtc $missingTime -Status Failed -ErrorCategory Internal -ErrorMessage 'The target completed without a deterministic result.'
        }
        $result.Index = $index
        $orderedResults.Add($result) | Out-Null
    }

    $aggregate = Get-AdminAutomationOutcome -TargetResults $orderedResults.ToArray()
    if ($aggregate.PartialCount -gt 0) {
        $warnings.Add("$($aggregate.PartialCount) target(s) returned a partial action result.") | Out-Null
    }
    if ($aggregate.FailedCount -gt 0) {
        $warnings.Add("$($aggregate.FailedCount) target(s) failed.") | Out-Null
    }
    if ($aggregate.TimeoutCount -gt 0) {
        $warnings.Add("$($aggregate.TimeoutCount) target(s) timed out.") | Out-Null
    }

    $finishedAtUtc = [datetime]::UtcNow
    Write-AdminLog -Message ("Automation run {0} finished with outcome {1}." -f $runId, $aggregate.Outcome) -NoConsole
    return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $request.ActionId -ActionName $request.ActionName -ReadOnly $request.ReadOnly -Preflight $request.Preflight -PolicyDecision $request.PolicyDecision -TargetMode $request.TargetMode -Transport $transportName -Authentication $transportAuthentication -UseSsl $transportUseSsl -Status $aggregate.Status -Outcome $aggregate.Outcome -ExitCode $aggregate.ExitCode -RequestedTargetCount $request.Computers.Count -TargetResults $orderedResults.ToArray() -Warnings $warnings.ToArray() -ReportPaths $reportPaths
}

function Invoke-AdminAutomation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Parameters,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ResolvedOutputPath
    )

    $startedAtUtc = [datetime]::UtcNow
    $runId = [guid]::NewGuid()
    $Script:State.AuditContext = $null
    $auditPathRequested = Test-AdminParameterBound -Parameters $Parameters -Name 'AuditPath'
    $eventLogRequested = (Test-AdminParameterBound -Parameters $Parameters -Name 'AuditEventLog') -and [bool]$Parameters['AuditEventLog']
    $eventSourceBound = Test-AdminParameterBound -Parameters $Parameters -Name 'AuditEventSource'
    $auditRequested = $auditPathRequested -or $eventLogRequested -or $eventSourceBound
    $auditContext = $null
    $requestedActionId = if (Test-AdminParameterBound -Parameters $Parameters -Name 'Action') { Get-AdminSafeActionId -ActionId ([string]$Parameters['Action']) } else { $null }
    $requestedCatalogItem = if ($requestedActionId) { Get-AdminActionCatalogItem -ActionId $requestedActionId } else { $null }
    $requestedTargetSummary = Get-AdminRequestedTargetSummary -Parameters $Parameters
    $requestedPolicyDecision = if (Test-AdminParameterBound -Parameters $Parameters -Name 'PolicyPath') {
        ConvertTo-AdminPolicyDecision -Applied $true -Decision NotEvaluated -ReasonCode NotEvaluated -Reason 'The policy profile has not been evaluated.'
    }
    else {
        ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.'
    }
    $reportPaths = if ($ResolvedOutputPath -ceq '-') { @() } else { @($ResolvedOutputPath) }

    if ($eventSourceBound -and -not $eventLogRequested) {
        $finishedAtUtc = [datetime]::UtcNow
        return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -ActionName $(if ($requestedCatalogItem) { $requestedCatalogItem.Name } else { $null }) -ReadOnly $(if ($requestedCatalogItem -and $requestedCatalogItem.Classification -ne 'Conditional') { [bool]$requestedCatalogItem.ReadOnly } else { $null }) -PolicyDecision $requestedPolicyDecision -TargetMode $requestedTargetSummary.TargetMode -Transport $requestedTargetSummary.Transport -Authentication $requestedTargetSummary.Authentication -UseSsl $requestedTargetSummary.UseSsl -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -RequestedTargetCount $requestedTargetSummary.RequestedTargetCount -Errors @([pscustomobject]@{ Category = 'Validation'; Message = 'AuditEventSource requires -AuditEventLog.' }) -ReportPaths $reportPaths
    }

    if ($auditRequested) {
        try {
            $collisionPaths = New-Object 'System.Collections.Generic.List[string]'
            if ($ResolvedOutputPath -cne '-') {
                $collisionPaths.Add($ResolvedOutputPath) | Out-Null
            }
            if ((Test-AdminParameterBound -Parameters $Parameters -Name 'LogFile') -and -not [string]::IsNullOrWhiteSpace([string]$Parameters['LogFile'])) {
                $collisionPaths.Add([string]$Parameters['LogFile']) | Out-Null
            }
            $resolvedAuditPath = $null
            if ($auditPathRequested) {
                $resolvedAuditPath = Resolve-AdminAuditPath -LiteralPath ([string]$Parameters['AuditPath']) -CollisionPaths $collisionPaths.ToArray()
            }
            $requestedEventSource = if ($eventSourceBound) { [string]$Parameters['AuditEventSource'] } else { 'WindowsAdminToolkit' }
            $auditContext = Initialize-AdminAuditContext -ResolvedAuditPath $resolvedAuditPath -EventLogEnabled $eventLogRequested -EventSource $requestedEventSource
            $Script:State.AuditContext = $auditContext
        }
        catch {
            $finishedAtUtc = [datetime]::UtcNow
            $failedAuditContext = if ($auditContext) {
                $auditContext
            }
            else {
                [pscustomobject][ordered]@{
                    Enabled         = $true
                    Path            = $null
                    EventLogEnabled = [bool]$eventLogRequested
                    EventSource     = if ($eventLogRequested) { if ($eventSourceBound) { [string]$Parameters['AuditEventSource'] } else { 'WindowsAdminToolkit' } } else { $null }
                    RecordCount     = 0
                    BytesWritten    = [int64]0
                    SinkFailed      = $false
                    Complete        = $false
                    SummaryHash     = $null
                }
            }
            return ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -ActionName $(if ($requestedCatalogItem) { $requestedCatalogItem.Name } else { $null }) -ReadOnly $(if ($requestedCatalogItem -and $requestedCatalogItem.Classification -ne 'Conditional') { [bool]$requestedCatalogItem.ReadOnly } else { $null }) -PolicyDecision $requestedPolicyDecision -TargetMode $requestedTargetSummary.TargetMode -Transport $requestedTargetSummary.Transport -Authentication $requestedTargetSummary.Authentication -UseSsl $requestedTargetSummary.UseSsl -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -RequestedTargetCount $requestedTargetSummary.RequestedTargetCount -Errors @([pscustomobject]@{ Category = 'Audit'; Message = $_.Exception.Message }) -ReportPaths $reportPaths -Audit (Get-AdminAuditStatus -Context $failedAuditContext)
        }

        try {
            $runStartedEvent = ConvertTo-AdminAuditEvent -RunId $runId -Sequence 1 -EventType run.started -TimestampUtc $startedAtUtc -Stage Initialization -ActionId $requestedActionId -Outcome Started
            [void](Write-AdminAuditRecord -Context $auditContext -Event $runStartedEvent)
        }
        catch {
            $finishedAtUtc = [datetime]::UtcNow
            $initialEnvelope = ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -ActionName $(if ($requestedCatalogItem) { $requestedCatalogItem.Name } else { $null }) -ReadOnly $(if ($requestedCatalogItem -and $requestedCatalogItem.Classification -ne 'Conditional') { [bool]$requestedCatalogItem.ReadOnly } else { $null }) -PolicyDecision $requestedPolicyDecision -TargetMode $requestedTargetSummary.TargetMode -Transport $requestedTargetSummary.Transport -Authentication $requestedTargetSummary.Authentication -UseSsl $requestedTargetSummary.UseSsl -Status InternalFailure -Outcome InternalFailure -ExitCode $Script:AutomationExitCodes.InternalFailure -RequestedTargetCount $requestedTargetSummary.RequestedTargetCount -Errors @([pscustomobject]@{ Category = 'Audit'; Message = 'The configured audit sink failed before target execution.' }) -ReportPaths $reportPaths -Audit (Get-AdminAuditStatus -Context $auditContext)
            return ConvertTo-AdminAuditSinkFailureEnvelope -OriginalEnvelope $initialEnvelope -Context $auditContext -Message $_.Exception.Message
        }
    }

    $coreInvokeParameters = @{
        Parameters         = $Parameters
        ResolvedOutputPath = $ResolvedOutputPath
        RunId              = $runId
        StartedAtUtc       = $startedAtUtc
        Confirm            = $false
    }
    if ($WhatIfPreference) {
        $coreInvokeParameters.WhatIf = $true
    }

    try {
        $envelope = Invoke-AdminAutomationCore @coreInvokeParameters
    }
    catch {
        $finishedAtUtc = [datetime]::UtcNow
        $internalMessage = if ($requestedActionId -in @('CustomCommand', 'CustomPowerShell')) { 'The custom action failed internally. Operator-supplied error text was omitted.' } else { ConvertTo-AdminSafeErrorMessage -Message $_.Exception.Message }
        $envelope = ConvertTo-AdminAutomationEnvelope -RunId $runId -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -ActionId $requestedActionId -ActionName $(if ($requestedCatalogItem) { $requestedCatalogItem.Name } else { $null }) -ReadOnly $(if ($requestedCatalogItem -and $requestedCatalogItem.Classification -ne 'Conditional') { [bool]$requestedCatalogItem.ReadOnly } else { $null }) -PolicyDecision $requestedPolicyDecision -TargetMode $requestedTargetSummary.TargetMode -Transport $requestedTargetSummary.Transport -Authentication $requestedTargetSummary.Authentication -UseSsl $requestedTargetSummary.UseSsl -Status InternalFailure -Outcome InternalFailure -ExitCode $Script:AutomationExitCodes.InternalFailure -RequestedTargetCount $requestedTargetSummary.RequestedTargetCount -Errors @([pscustomobject]@{ Category = 'Internal'; Message = $internalMessage }) -ReportPaths $reportPaths
    }

    if ($auditContext -and $auditContext.Enabled) {
        try {
            $envelope = Write-AdminAutomationAudit -Envelope $envelope -Context $auditContext
        }
        catch {
            $envelope = ConvertTo-AdminAuditSinkFailureEnvelope -OriginalEnvelope $envelope -Context $auditContext -Message ("The configured audit sink failed: {0}" -f $_.Exception.Message)
        }
    }
    return $envelope
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

    $interactivePolicyProfile = $null
    $Script:State.PolicyProfile = $null
    if (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name 'PolicyPath') {
        $requestedPolicyPath = ([string]$Script:InvocationParameters['PolicyPath']).Trim()
        if ([string]::IsNullOrWhiteSpace($requestedPolicyPath)) {
            throw 'PolicyPath cannot be empty when supplied.'
        }
        $interactivePolicyProfile = Import-AdminPolicyProfile -LiteralPath $requestedPolicyPath
        $Script:State.PolicyProfile = $interactivePolicyProfile
        Use-AdminPolicyRuntimeLimit -PolicyProfile $interactivePolicyProfile -Parameters $Script:InvocationParameters
    }

    if ($null -ne $Script:State.Credential -and $Script:State.Credential -isnot [System.Management.Automation.PSCredential]) {
        if ($Script:State.Transport -eq 'PsExec') {
            throw 'PsExec does not accept alternate credentials in this toolkit.'
        }
        if ($Script:State.Credential -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Script:State.Credential)) {
            throw 'Credential must be a PSCredential object or a nonempty username in interactive mode.'
        }

        $credentialUserName = ([string]$Script:State.Credential).Trim()
        $Script:State.Credential = Get-Credential -UserName $credentialUserName -Message 'Enter credentials for authorized WinRM access'
        if (-not $Script:State.Credential) {
            throw 'Credential entry was cancelled.'
        }
    }

    $configurationError = Get-AdminRuntimeConfigurationError
    if (-not [string]::IsNullOrWhiteSpace($configurationError)) {
        throw $configurationError
    }

    [void](Initialize-AdminLog -RequestedPath $LogFile)
    Write-AdminBanner
    Write-AdminLog -Message "Windows Admin Toolkit $Script:ToolkitVersion started under PowerShell $($PSVersionTable.PSVersion)." -NoConsole
    if ($interactivePolicyProfile) {
        Write-Host "Policy profile: $($interactivePolicyProfile.ProfileName)" -ForegroundColor Gray
        Write-AdminLog -Message ("Policy profile '{0}' loaded and validated." -f $interactivePolicyProfile.ProfileName) -NoConsole
    }

    if (-not (Test-Administrator)) {
        Write-Host 'Warning: The current PowerShell session is not elevated. Some actions will fail.' -ForegroundColor Yellow
    }

    Write-Host "Remote transport: $($Script:State.Transport)" -ForegroundColor Gray
    if ($Script:State.Transport -eq 'WinRM') {
        Write-Host ("WinRM security: Authentication={0}, SSL={1}" -f $Script:State.Authentication, $Script:State.UseSsl) -ForegroundColor Gray
    }

    $context = Select-AdminTargetContext -PolicyProfile $interactivePolicyProfile
    Write-AdminLog -Message ("Selected {0} mode with {1} target(s)." -f $context.Mode, $context.Computers.Count) -NoConsole
    $contextTransport = if ($context.Mode -eq 'Local') { 'Local' } else { $Script:State.Transport }
    $contextPolicyResolution = Resolve-AdminPolicyContext -PolicyProfile $interactivePolicyProfile -TargetMode $context.Mode -Transport $contextTransport -Computers $context.Computers -Parameters $Script:InvocationParameters
    if (-not $contextPolicyResolution.Allowed) {
        Write-AdminLog -Message ("Policy denied the selected target context: {0}." -f $contextPolicyResolution.PolicyDecision.reasonCode) -Level ERROR -NoConsole
        throw $contextPolicyResolution.PolicyDecision.reason
    }
    if ($interactivePolicyProfile) {
        Write-AdminLog -Message ("Policy allowed the selected target context: {0}." -f $contextPolicyResolution.PolicyDecision.reasonCode) -NoConsole
    }

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

        $selectedCatalogItem = Get-AdminActionCatalogItemByMenuNumber -MenuNumber $choice
        $actionPolicyDecision = Get-AdminPolicyActionDecision -PolicyProfile $interactivePolicyProfile -ActionId $selectedCatalogItem.Id
        if ($actionPolicyDecision.decision -eq 'Denied') {
            Write-Host ("Policy denied this action: {0}" -f $actionPolicyDecision.reason) -ForegroundColor Red
            Write-AdminLog -Message ("Policy denied action '{0}': {1}." -f $selectedCatalogItem.Id, $actionPolicyDecision.reasonCode) -Level WARN -NoConsole
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

        $interactiveInputs = ConvertTo-AdminActionInputMap -ActionId $request.Script -ArgumentList $request.Arguments
        $interactivePolicyResolution = Resolve-AdminPolicyRequest -PolicyProfile $interactivePolicyProfile -ActionId $request.Script -TargetMode $context.Mode -Transport $contextTransport -Computers $context.Computers -Inputs $interactiveInputs -Parameters $Script:InvocationParameters
        if (-not $interactivePolicyResolution.Allowed) {
            Write-Host ("Policy denied this request: {0}" -f $interactivePolicyResolution.PolicyDecision.reason) -ForegroundColor Red
            Write-AdminLog -Message ("Policy denied action '{0}': {1}." -f $request.Script, $interactivePolicyResolution.PolicyDecision.reasonCode) -Level WARN -NoConsole
            continue
        }
        if ($interactivePolicyProfile) {
            Write-AdminLog -Message ("Policy allowed action '{0}': {1}." -f $request.Script, $interactivePolicyResolution.PolicyDecision.reasonCode) -NoConsole
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

        if ($interactivePolicyProfile) {
            foreach ($result in $results) {
                $result | Add-Member -NotePropertyName PolicyProfile -NotePropertyValue $interactivePolicyProfile.ProfileName -Force
                $result | Add-Member -NotePropertyName PolicyDecision -NotePropertyValue $interactivePolicyResolution.PolicyDecision.decision -Force
                $result | Add-Member -NotePropertyName PolicyReasonCode -NotePropertyValue $interactivePolicyResolution.PolicyDecision.reasonCode -Force
            }
        }

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
    if ($Automation) {
        $ProgressPreference = 'SilentlyContinue'
        $VerbosePreference = 'SilentlyContinue'
        $DebugPreference = 'SilentlyContinue'
        $InformationPreference = 'SilentlyContinue'
        $WarningPreference = 'SilentlyContinue'

        try {
            $resolvedOutputPath = Resolve-AdminAutomationOutputPath -LiteralPath $JsonOutputPath
        }
        catch {
            $failureStartedAtUtc = [datetime]::UtcNow
            $failureRequestedActionId = Get-AdminSafeActionId -ActionId $Action
            $failureCatalogItem = if ($failureRequestedActionId) { Get-AdminActionCatalogItem -ActionId $failureRequestedActionId } else { $null }
            $failureActionId = if ($failureCatalogItem) { $failureCatalogItem.Id } else { $null }
            $failureActionName = if ($failureCatalogItem) { $failureCatalogItem.Name } else { $null }
            $failureReadOnly = if ($failureCatalogItem -and $failureCatalogItem.Classification -ne 'Conditional') { [bool]$failureCatalogItem.ReadOnly } else { $null }
            $failureTargetSummary = Get-AdminRequestedTargetSummary -Parameters $Script:InvocationParameters
            $failurePolicyDecision = if (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name 'PolicyPath') { ConvertTo-AdminPolicyDecision -Applied $true -Decision NotEvaluated -ReasonCode NotEvaluated -Reason 'The output request failed before the policy profile could be evaluated.' } else { ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.' }
            $failurePreflight = (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name 'Preflight') -and [bool]$Script:InvocationParameters['Preflight']
            $failureEnvelope = ConvertTo-AdminAutomationEnvelope -RunId ([guid]::NewGuid()) -StartedAtUtc $failureStartedAtUtc -FinishedAtUtc ([datetime]::UtcNow) -ActionId $failureActionId -ActionName $failureActionName -ReadOnly $failureReadOnly -Preflight $failurePreflight -PolicyDecision $failurePolicyDecision -TargetMode $failureTargetSummary.TargetMode -Transport $failureTargetSummary.Transport -Authentication $failureTargetSummary.Authentication -UseSsl $failureTargetSummary.UseSsl -Status ValidationFailed -Outcome ValidationFailure -ExitCode $Script:AutomationExitCodes.ValidationFailure -RequestedTargetCount $failureTargetSummary.RequestedTargetCount -Errors @([pscustomobject]@{ Category = 'Validation'; Message = $_.Exception.Message })
            [Console]::Error.WriteLine((ConvertTo-AdminAutomationJson -Envelope $failureEnvelope))
            exit $Script:AutomationExitCodes.ValidationFailure
        }

        $automationEnvelope = $null
        try {
            $automationInvokeParameters = @{
                Parameters         = $Script:InvocationParameters
                ResolvedOutputPath = $resolvedOutputPath
                Confirm            = $false
            }
            if ($WhatIfPreference) {
                $automationInvokeParameters.WhatIf = $true
            }
            $automationEnvelope = Invoke-AdminAutomation @automationInvokeParameters
            $automationJson = ConvertTo-AdminAutomationJson -Envelope $automationEnvelope
            if ($resolvedOutputPath -ceq '-') {
                [Console]::Out.WriteLine($automationJson)
            }
            else {
                [void](Write-AdminUtf8File -LiteralPath $resolvedOutputPath -Content $automationJson -EmitBom $false)
            }
            exit ([int]$automationEnvelope.exitCode)
        }
        catch {
            $failureStartedAtUtc = [datetime]::UtcNow
            try {
                $failureEnvelope = if ($null -ne $automationEnvelope) {
                    $outputFailureMessage = "The requested JSON output sink failed: {0}" -f $_.Exception.Message
                    $outputFailureEnvelope = ConvertTo-AdminOutputSinkFailureEnvelope -OriginalEnvelope $automationEnvelope -Message $outputFailureMessage
                    if ($Script:State.AuditContext -and $Script:State.AuditContext.Enabled) {
                        try {
                            $outputFailureEnvelope = Write-AdminAuditFailureRevision -Envelope $outputFailureEnvelope -Context $Script:State.AuditContext -Message $outputFailureMessage
                        }
                        catch {
                            $outputFailureEnvelope = ConvertTo-AdminAuditSinkFailureEnvelope -OriginalEnvelope $outputFailureEnvelope -Context $Script:State.AuditContext -Message ("The audit sink also failed while recording the JSON output failure: {0}" -f $_.Exception.Message)
                        }
                    }
                    $outputFailureEnvelope
                }
                else {
                    $failurePolicyDecision = if (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name 'PolicyPath') { ConvertTo-AdminPolicyDecision -Applied $true -Decision NotEvaluated -ReasonCode NotEvaluated -Reason 'The run failed before the policy profile could be evaluated.' } else { ConvertTo-AdminPolicyDecision -Decision NotApplied -ReasonCode NoPolicy -Reason 'No policy profile was supplied.' }
                    $failurePreflight = (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name 'Preflight') -and [bool]$Script:InvocationParameters['Preflight']
                    ConvertTo-AdminAutomationEnvelope -RunId ([guid]::NewGuid()) -StartedAtUtc $failureStartedAtUtc -FinishedAtUtc ([datetime]::UtcNow) -ActionId (Get-AdminSafeActionId -ActionId $Action) -Preflight $failurePreflight -PolicyDecision $failurePolicyDecision -Status InternalFailure -Outcome InternalFailure -ExitCode $Script:AutomationExitCodes.InternalFailure -Errors @([pscustomobject]@{ Category = 'Internal'; Message = $_.Exception.Message })
                }
                [Console]::Error.WriteLine((ConvertTo-AdminAutomationJson -Envelope $failureEnvelope))
            }
            catch {
                [Console]::Error.WriteLine('Windows Admin Toolkit encountered an internal automation failure.')
            }
            exit $Script:AutomationExitCodes.InternalFailure
        }
    }

    $automationOnlyParameters = @(
        'Action',
        'ListActions',
        'Preflight',
        'AuditPath',
        'AuditEventLog',
        'AuditEventSource',
        'Local',
        'ComputerName',
        'ComputerListPath',
        'JsonOutputPath',
        'ConfirmationText',
        'TargetListConfirmationText',
        'PsExecConfirmationText'
    ) + $Script:AutomationInputNames
    foreach ($parameterName in $automationOnlyParameters) {
        if (Test-AdminParameterBound -Parameters $Script:InvocationParameters -Name $parameterName) {
            Write-Error "Parameter -$parameterName requires -Automation."
            exit 1
        }
    }

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
