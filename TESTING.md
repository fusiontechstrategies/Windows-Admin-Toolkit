# Testing Windows Admin Toolkit

Windows Admin Toolkit uses a dependency-free test harness so the same checks run under Windows PowerShell 5.1 and PowerShell 7.x without a test-framework bootstrap.

## Current 3.0.0 native validation

The 3.0.0 controlled orchestration milestone was validated natively on August 22, 2026.

| Environment | PowerShell | Checks | Result |
| --- | --- | ---: | --- |
| Windows 11 Pro 25H2, build 26200.9168 native host | Windows PowerShell 5.1.26100.9168 | 643 | Passed |
| Windows 11 Pro 25H2, build 26200.9168 native host | PowerShell 7.6.4 | 643 | Passed |

Total completed 3.0.0 native checks: 1,286.

PSScriptAnalyzer 1.25.0 completed with zero findings under the committed settings. The 3.0.0 working tree was not rerun in Windows containers because Docker Desktop 4.87.0 was running its Linux engine rather than a Windows container runtime. The container results below remain the exact historical record for release 2.0.0 and are not presented as 3.0.0 validation.

## Historical 2.0.0 release matrix

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
- Stable action identifiers, order, classification, confirmation text, and action input metadata
- Parser compatibility and noninteractive action blocks
- Automation request resolution for every action without interactive input paths
- Local, remote, target-list, and incompatible-selector validation
- Exact state-change, large-target-list, and PsExec authorization values
- Read-only retry behavior and zero retries for state-changing actions
- `ShouldProcess` and clean no-connection `WhatIf` previews
- Stable JSON schema, fields, ordering, arrays, UTC dates, normalized casing, and safe serialization depth
- Result schema version 1.2 policy, audit, preflight, and stable target-ID fields, plus nine committed result examples
- Policy schema version 1.0, two committed profiles, stable action IDs, and absolute built-in ceilings
- Audit schema version 1.0 with complete event structure, lifecycle types, target identities, policy decisions, normalized errors, and terminal summaries
- Deterministic canonical JSON and cross-edition SHA-256 hash vectors
- Stable case-insensitive target IDs across runs and distinct IDs for different targets
- New-file-only JSON Lines output, UTF-8 without a byte-order mark, path collision rejection, 16 MiB bounds, and unexpected-mutation detection
- Native successful audit lifecycles, sequence continuity, result correlation, and summary-hash verification
- Visible audit-sink mutation failure with preserved target evidence and exit code 10
- Post-execution JSON result-sink failure events and authoritative replacement audit summaries
- Orchestration plan, checkpoint, and operation-result schema version 1.0 plus four committed correlated examples
- Strict plan and checkpoint UTF-8, size, suffix, duplicate-key, case-conflict, unknown-property, lifecycle, and canonical-hash validation
- Separate pending and approved plan files with full-hash authorization and approval-metadata hash verification
- Rejection of credentials, audit sinks, custom-code actions, and execution-time overrides in plan workflows
- Atomic checkpoint creation and replacement without temporary artifacts, overwrite, or terminal-target repetition
- Safe Resume behavior for completed targets and interrupted `InProgress` targets converted to `Unknown`
- Preservation of action-specific confirmation and zero retries for approved state-changing `WhatIf` plans
- Canonical path and raw SHA-256 binding for policy files referenced by approved plans
- Unsigned release-candidate generation under both PowerShell editions without changing source bytes
- SPDX 2.3 payload inventory, verified SHA-256 manifest coverage, and no-overwrite release destinations
- Strict policy UTF-8 and size bounds, duplicate and case-conflicting JSON keys, unknown fields, unsupported values, and inconsistent rules
- Policy action, transport, target-mode, exact-target, suffix-target, target-count, runtime, and action-input decisions
- Policy precedence, explicit-value denial, omitted-value clamping, and deny-before-connect behavior
- Policy-aware action catalog annotations and explicit allowed, denied, invalid, not-evaluated, and not-applied result states
- Capability preflight under native Windows PowerShell and PowerShell 7 child processes
- Proof that custom PowerShell capability preflight neither executes supplied content nor writes it to the safe log
- Clean stdout JSON, deterministic exit codes, and stderr separation for unusable output destinations
- Complete-success, partial-success, execution-failure, timeout, validation, and authorization aggregation
- Atomic automation JSON output and overwrite refusal
- Hostname, IPv4, service, process, registry, event-log, task-path, and KB validation
- Rejection of metacharacters, malformed paths, traversal notation, and ambiguous addresses
- Strict, bounded UTF-8 decoding for target lists and custom PowerShell files
- CSV formula neutralization and HTML encoding
- Atomic UTF-8 exports with explicit BOM and no overwrites
- `ShouldProcess` support and absence of execution-policy bypasses
- Absence of `Invoke-Expression`, plaintext credential conversion, and automatic security-setting changes
- Native automation rejection of username strings without opening credential UI
- Encoded payload integrity with adversarial argument text
- Typed nested-array preservation across background-job and encoded remote payload boundaries
- Local system, process, and service-query execution
- Normalized failure handling
- Remote target rejection before jobs or transports start
- Protected core-process enforcement
- PsExec product, version, Microsoft signer, and Authenticode verification
- Interactive menu-number regression coverage for all 20 actions
- Application ASCII compatibility and the repository rule prohibiting em dashes

The automated suite makes no destructive system changes.
