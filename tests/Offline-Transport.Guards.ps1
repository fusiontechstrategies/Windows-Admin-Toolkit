# Test-only fail-closed transport doubles, loaded after the application.
$Script:OfflineNetworkGuardCounts = @{ ConnectivityDouble = 0; RemoteDispatch = 0; RemoteCommand = 0; TcpAttempt = 0; NativeRemoteProcess = 0; NativeLocalFixture = 0 }
$Script:OfflineOriginalTargetDetailed = (Get-Item Function:\Invoke-AdminTargetDetailed).ScriptBlock
$Script:OfflineOriginalCapturedProcess = (Get-Item Function:\Invoke-AdminCapturedProcess).ScriptBlock
$Script:OfflineOriginalTcpPort = (Get-Item Function:\Test-AdminTcpPort).ScriptBlock

function Test-AdminTargetConnectivity {
    [CmdletBinding()]
    param([string[]]$Computers, [int]$Port, [int]$TimeoutSeconds, [int]$BatchSize)
    $null = $PSBoundParameters
    $Script:OfflineNetworkGuardCounts.ConnectivityDouble++
    return [pscustomobject]@{ Reachable = @(); Unreachable = @($Computers) }
}

function Test-AdminTcpPort {
    [CmdletBinding()]
    param([string]$ComputerName, [int]$Port, [int]$TimeoutSeconds)
    if (-not (Test-AdminHostname -ComputerName $ComputerName)) { return & $Script:OfflineOriginalTcpPort @PSBoundParameters }
    $Script:OfflineNetworkGuardCounts.TcpAttempt++
    throw 'Offline test attempted an unmocked TCP probe.'
}

Set-Item -Path Function:\Invoke-Command -Value {
    [CmdletBinding()]
    param([scriptblock]$ScriptBlock, [object[]]$ArgumentList, [object[]]$ComputerName, [object]$Session, [object]$Authentication, [object]$SessionOption, [Management.Automation.PSCredential]$Credential, [switch]$UseSSL)
    $null = $PSBoundParameters
    if ($PSBoundParameters.ContainsKey('ComputerName') -or $PSBoundParameters.ContainsKey('Session')) {
        $Script:OfflineNetworkGuardCounts.RemoteCommand++
        throw 'Offline test attempted an unmocked remote command.'
    }
    return Microsoft.PowerShell.Core\Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
}

function Invoke-AdminCapturedProcess {
    [CmdletBinding()]
    param([string]$LiteralPath, [string]$ArgumentText, [int]$TimeoutSeconds, [int]$MaximumBytes)
    $currentEngineExecutable = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ([string]::Equals($LiteralPath, $currentEngineExecutable, [StringComparison]::OrdinalIgnoreCase) -and $ArgumentText -match '^\s*-NoLogo -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+\s*$') {
        $Script:OfflineNetworkGuardCounts.NativeLocalFixture++
        return & $Script:OfflineOriginalCapturedProcess @PSBoundParameters
    }
    $Script:OfflineNetworkGuardCounts.NativeRemoteProcess++
    throw 'Offline test attempted an unmocked native transport process.'
}

function Invoke-AdminTargetDetailed {
    [CmdletBinding()]
    param([string]$TargetMode, [string[]]$Computers, [string]$ActionName,
        [object[]]$ArgumentList = @(), [bool]$ReadOnly = $true,
        [int]$MaxConcurrentJobs = $Script:State.MaxConcurrentJobs,
        [int]$RetryCount = $Script:State.RetryCount,
        [int]$RetryDelaySeconds = $Script:State.RetryDelaySeconds,
        [int]$OperationTimeoutMinutes = $Script:State.OperationTimeoutMinutes)
    if ($TargetMode -eq 'Remote' -and @($Computers | Where-Object { -not (Test-AdminHostname -ComputerName $_) }).Count -eq 0) {
        $Script:OfflineNetworkGuardCounts.RemoteDispatch++
        throw 'Offline test attempted unmocked remote worker dispatch.'
    }
    return & $Script:OfflineOriginalTargetDetailed @PSBoundParameters
}
