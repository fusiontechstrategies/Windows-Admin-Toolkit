# Testing Windows Admin Toolkit

Windows Admin Toolkit uses a dependency-free test harness so the same checks run under Windows PowerShell 5.1 and PowerShell 7.x without a test-framework bootstrap.

## Current source security regressions

The main harness also runs `tests/Latest-Ten-Regression.Tests.ps1`. Actual offline probes cover loaded-source replacement across background jobs, private relative file creation, preauthorized writer conflicts, retained leaf and ancestor replacement refusal, equal-length audit substitution, explicit trusted log append, target aliases and attribution, zero-success outcome precedence, terminal controls, poisoned environment paths, protected-source DACL controls, and release/source overlap. CI workspaces use an explicit test-only launch-trust stub for synthetic backends; production source protection is independently exercised with rejecting and valid descriptor controls. Cleanup tests replace the exact production root resolver with owned fixture paths and refuse to execute if that replacement fails. No host permission changes or live target mutations are performed.

The main harness also runs `tests/Security-Regression.Tests.ps1` on both editions. It uses unique synthetic filesystem fixtures, mocked WinRM producers, and test-created child processes. Coverage includes junction rejection, locked leaf and ancestor replacement, immutable orchestration policy consumption, bounded discovery and 128 MiB input rejection, read-only previews, explicit policy KB selection, incremental output limits, aggregate worker budgets, concurrent Resume with exactly one target invocation, and checkpoint lease recovery after a helper crash.

These tests do not connect to live administrative targets. The existing release builder checks still verify unsigned candidate payload hashes, manifest and SPDX coverage, source-byte preservation, and no-overwrite output; they do not publish or sign a release.

## Final 3.0.0 qualification

The final 3.0.0 controlled-orchestration repository tree was qualified on August 24, 2026. The final host and CI suite contains 649 checks. The clean virtual-machine runs completed the preceding 647-check suite before two release-certificate regression checks were added; the application script did not change between those runs and the final signing fix.

| Environment | PowerShell | Checks | Result |
| --- | --- | ---: | --- |
| Windows 11 Pro 25H2, build 26200.9168 native host | Windows PowerShell 5.1.26100.9168 | 649 | Passed |
| Windows 11 Pro 25H2, build 26200.9168 native host | PowerShell 7.6.4 | 649 | Passed |
| Windows 10 Pro, build 19045 clean virtual machine | Windows PowerShell 5.1 | 647 | Passed |
| Windows 11 Pro, build 26200 clean virtual machine | Windows PowerShell 5.1 | 647 | Passed |
| Windows Server 2022 Datacenter, build 20348 clean virtual machine | Windows PowerShell 5.1 | 647 | Passed |
| Windows Server 2025 Standard, build 26100 clean virtual machine | Windows PowerShell 5.1 | 647 | Passed |

Total completed host and baseline-VM checks: 3,886.

The pull request and public `main` branch also passed GitHub CI on Windows Server 2022 and Windows Server 2025 under both Windows PowerShell 5.1 and PowerShell 7. PSScriptAnalyzer 1.25.0 reported zero findings, and the repository secret scan passed.

Each virtual machine ran individually from a disposable baseline and was restored after qualification. Credentials, private machine names, generated evidence, and local test infrastructure are not included in the repository.

### Extended VM qualification

| Qualification | Result |
| --- | ---: |
| Adversarial validation and security stress | 244 of 244 assertions passed |
| Forced interruption and deterministic resume across 120 targets | 30 of 30 assertions passed |
| Live WinRM on Windows Server 2022 and Windows Server 2025 | 18 of 18 assertions passed |
| Windows 10 FIPS-policy suite | 647 of 647 checks passed |
| Disposable standard-user behavior | 7 of 7 assertions passed |
| Controlled disposable live state changes | 5 of 5 assertions passed |
| Microsoft Defender custom scan of the exact source tree | 0 new detections and 0 active threats |
| Release-candidate manifest, SPDX 2.3 SBOM, source-byte, parser, and path-safety checks | Passed |

The controlled live-change run affected only test-created or immediately reversible state: exact marker creation, a test-created Notepad process, the Windows Update service, and a scheduled reboot that was immediately aborted. Actual update installation and broad temporary-file deletion were not run live because they are not narrowly reversible. Successful WinRM used the real remoting stack on both supported server editions. A positive PsExec execution was not attempted because no trusted local PsExec binary was present; its fail-closed validation paths passed.

The VM qualification candidate was unsigned. After final repository checks, the official 3.0.0 release assets were Authenticode-signed by Fusion Technology Strategies, Inc. with a DigiCert-issued code-signing certificate and a verified DigiCert timestamp. Independent verification required a valid Authenticode status, trusted signer and timestamp chains, byte-for-byte preservation of the reviewed source before the appended signature block, complete SHA-256 manifest coverage, complete SPDX payload coverage, and archive-entry hash equivalence.

The 3.0.0 tree was not rerun in Windows containers because Docker Desktop was using a Linux rather than Windows container runtime. The clean virtual-machine matrix and GitHub Windows runners provide the 3.0.0 operating-system coverage. The container results below remain the exact historical record for release 2.0.0 and are not presented as 3.0.0 validation.

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
- Private checkpoint creation and retained in-place revisions without temporary artifacts, overwrite, or terminal-target repetition; incomplete or ledger-mismatched revisions refuse Resume
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
- Native retained-parent UTF-8 exports with exact BOM bytes, no-replace final collisions, private file identities, object-only failure cleanup, real junction controls, rename denial while held and a rename-after-release positive control
- Missing output-parent refusal with no directory side effect, trusted inherited-parent support, actual other-principal mutable DACL rejection, and real JSON/export/Plan Create/Approve publication paths
- Read-only scanner token defaults and SARIF-only code-scanning write authority
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

The final publication fixtures distinguish ancestor-only volume-root grants from strict terminal-parent grants. They exercise actual isolated add-subdirectory DACL refusal and synthetic mapping/UNC rejection before any provider lookup. No mapped network drive, SUBST alias, remote endpoint, alternate user token or host ACL is created or contacted.

A native-created local directory symlink with a synthetic UNC target exercises remote-capable ancestry refusal without opening the target. Provider-command counters remain zero; native cleanup removes only the owned symbolic-link object. Native relative preflight also tests existing-file and existing-directory collisions with preserved final bytes.

The final path-boundary fixtures exercise local symbolic links with an intentionally nonexistent UNC target without contacting it. Provider-call counters verify that direct policy, target-list, custom-source, hashing, PsExec, signature/capture, log/audit and embedded approval-reference routes reject the link before provider lookup. Separate real unsigned release construction and native rejection controls cover packaging. Fixtures create only owned private profile directories and link objects; they do not change existing host ACLs or launch PsExec.
