# Testing Windows Admin Toolkit

Windows Admin Toolkit uses a dependency-free test harness so the same checks run under Windows PowerShell 5.1 and PowerShell 7.x without a test-framework bootstrap.

## Verified release matrix

Release 2.0.0 was validated on August 12, 2026.

| Environment | PowerShell | Checks | Result |
| --- | --- | ---: | --- |
| Windows 11 Pro 25H2, build 26200.9168 | Windows PowerShell 5.1.26100.9168 | 124 | Passed |
| Windows 11 Pro 25H2, build 26200.9168 | PowerShell 7.6.4 | 124 | Passed |
| `mcr.microsoft.com/windows/servercore:ltsc2025` | Windows PowerShell 5.1.26100.33296 | 124 | Passed |
| `mcr.microsoft.com/powershell:7.5-windowsservercore-ltsc2022` | PowerShell 7.5.0 | 124 | Passed |

Total completed automated checks: 496.

The container runs used Hyper-V isolation and mounted the project folder read-only.

## Container image identities

| Image | Pulled digest |
| --- | --- |
| `mcr.microsoft.com/windows/servercore:ltsc2025` | `sha256:eeaa17aefe5d949f03b1db17182f5855cf40e757533468cf5b50e07c7c385ada` |
| `mcr.microsoft.com/powershell:7.5-windowsservercore-ltsc2022` | `sha256:a306e284beb0b3663d6133c85b4dcf6e26244fc953f6bacf71806e6ed279c67f` |

## Run the native tests

From the repository root:

```powershell
powershell.exe -NoLogo -NoProfile -File .\tests\Run-Tests.ps1
pwsh.exe -NoLogo -NoProfile -File .\tests\Run-Tests.ps1
```

## Run the container tests

Switch Docker Desktop to Windows containers first.

```powershell
$sourcePath = (Get-Location).Path

docker run --rm --isolation=hyperv `
  --mount "type=bind,source=$sourcePath,target=C:\workspace,readonly" `
  mcr.microsoft.com/windows/servercore:ltsc2025 `
  powershell.exe -NoLogo -NoProfile -File C:\workspace\tests\Run-Tests.ps1

docker run --rm --isolation=hyperv `
  --mount "type=bind,source=$sourcePath,target=C:\workspace,readonly" `
  mcr.microsoft.com/powershell:7.5-windowsservercore-ltsc2022 `
  pwsh.exe -NoLogo -NoProfile -File C:\workspace\tests\Run-Tests.ps1
```

## Static analysis

PSScriptAnalyzer 1.25.0 completes with zero findings under the committed settings.

```powershell
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0
$findings = Invoke-ScriptAnalyzer `
  -Path . `
  -Recurse `
  -Settings .\PSScriptAnalyzerSettings.psd1

if ($findings) {
    $findings | Format-Table -AutoSize
    throw 'PSScriptAnalyzer reported one or more findings.'
}
```

## Automated coverage

The test suite verifies:

- Application version, 20-action catalog, and action-script registration
- Parser compatibility and noninteractive action blocks
- Hostname, IPv4, service, process, registry, event-log, task-path, and KB validation
- Rejection of metacharacters, malformed paths, traversal notation, and ambiguous addresses
- CSV formula neutralization and HTML encoding
- Atomic UTF-8 exports with explicit BOM and no overwrites
- `ShouldProcess` support and absence of execution-policy bypasses
- Absence of `Invoke-Expression` and plaintext credential conversion
- Encoded payload integrity with adversarial argument text
- Local system, process, and service-query execution
- Normalized failure handling
- Remote target rejection before jobs or transports start
- Protected core-process enforcement
- PsExec product, version, Microsoft signer, and Authenticode verification
- Application ASCII compatibility and the repository rule prohibiting em dashes

The automated suite makes no destructive system changes.
