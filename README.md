# Windows Admin Toolkit

One script. Twenty guarded Windows administration workflows. Secure local and remote operations across Windows PowerShell 5.1 and PowerShell 7.x.

[![CI](https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/actions/workflows/ci.yml)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-2671be.svg)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Windows Admin Toolkit turns common Windows administration work into a focused interactive or noninteractive experience without becoming a framework, module collection, or installation project. The application remains a single PowerShell script that can inspect, report on, and administer authorized local or remote Windows systems.

## Why administrators use it

- One portable application file: `WindowsAdminToolkit.ps1`
- Compatible with Windows PowerShell 5.1 and PowerShell 7.x
- Secure WinRM transport by default
- Optional, tightly validated Microsoft Sysinternals PsExec fallback
- Bounded concurrency, timeouts, normalized failures, and read-only retries
- Exact confirmation phrases and `ShouldProcess` protection for changes
- Stable named actions, JSON envelopes, and exit codes for RMM, scheduled-task, and CI use
- Optional least-privilege policy profiles with explicit machine-readable decisions
- Capability preflight that checks action readiness without executing the requested action
- CSV, JSON, and self-contained HTML reporting
- No automatic firewall, WinRM, TrustedHosts, or execution-policy changes

## Twenty built-in workflows

| Area | Workflows |
| --- | --- |
| System visibility | System information, disk space, hardware, network configuration, logged-on users, running processes, installed software, Windows license status |
| Maintenance | Windows updates, scheduled reboot, pending reboot detection, service management, process termination, temporary-file cleanup, scheduled tasks |
| Security and diagnostics | Firewall status, event log queries, registry reads |
| Expert execution | Custom CMD commands and custom PowerShell code with explicit unsandboxed-execution warnings |

## Security by design

Windows Admin Toolkit treats remote administration as a privileged security boundary.

- WinRM is the default remote transport and supports `Default`, `Kerberos`, or `Negotiate` authentication.
- PsExec never receives an alternate password from this tool. It uses the current Windows identity, preventing plaintext password exposure in process arguments.
- PsExec must be Microsoft-signed, identify as Sysinternals PsExec, and be version 2.43 or newer.
- Remote actions and arguments use encoded, typed data envelopes instead of constructed command strings.
- State-changing actions are never retried automatically.
- Destructive and unsandboxed actions require an exact confirmation phrase in addition to PowerShell approval.
- Core Windows processes, including `lsass`, `services`, and `svchost`, are blocked from process termination.
- Temporary-file cleanup never touches Windows Prefetch, ignores reparse points, uses literal paths, and enforces a file-count ceiling.
- CSV exports neutralize spreadsheet formulas. HTML exports encode values. File exports are atomic and never overwrite an existing report.
- Logs record action summaries, not credentials, custom code, or custom-command output.
- Optional policies can only narrow actions, transports, target modes, targets, runtime limits, and supported action inputs.

Read [SECURITY.md](SECURITY.md) and [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) before operating the toolkit in a production environment.

## Requirements

- A supported Windows client or Windows Server operating system
- Windows PowerShell 5.1 or PowerShell 7.x
- Administrator rights for actions that require elevation
- WinRM connectivity for default remote administration
- Optional: Microsoft Sysinternals PsExec 2.43 or newer for the fallback transport

The toolkit does not enable remote-management services or weaken security settings on your behalf.

## Quick start

```powershell
git clone https://github.com/fusiontechstrategies/Windows-Admin-Toolkit.git
Set-Location .\Windows-Admin-Toolkit
.\WindowsAdminToolkit.ps1
```

If Windows marks a trusted downloaded copy as blocked, review the source and then remove only the downloaded-file marker:

```powershell
Unblock-File -LiteralPath .\WindowsAdminToolkit.ps1
```

The toolkit does not require or recommend an execution-policy bypass.

## Common launch options

```powershell
# Default secure WinRM transport
.\WindowsAdminToolkit.ps1

# WinRM over HTTPS
.\WindowsAdminToolkit.ps1 -Transport WinRM -UseSsl

# Kerberos authentication with four concurrent remote jobs
.\WindowsAdminToolkit.ps1 -Authentication Kerberos -MaxConcurrentJobs 4

# Optional PsExec fallback under the current Windows identity
.\WindowsAdminToolkit.ps1 -Transport PsExec -PsExecPath C:\Tools\PsExec64.exe

# Preview state-changing actions without applying them
.\WindowsAdminToolkit.ps1 -WhatIf

# Noninteractive local inventory with clean JSON on stdout
.\WindowsAdminToolkit.ps1 -Automation -Action SystemInfo -Local -JsonOutputPath -

# Validate policy and capability readiness without running the requested action
.\WindowsAdminToolkit.ps1 -Automation -Action SystemInfo -Local -PolicyPath .\examples\policies\read-only-local.json -Preflight -JsonOutputPath -
```

| Parameter | Default | Purpose |
| --- | --- | --- |
| `Transport` | `WinRM` | Selects `WinRM` or the optional `PsExec` fallback |
| `PsExecPath` | `PsExec64.exe` | Locates a Microsoft-signed PsExec executable |
| `WinRmIdentity` (`Credential` alias) | Current identity | Supplies an optional in-memory `PSCredential` for WinRM only |
| `MaxConcurrentJobs` | `8` | Limits simultaneous remote targets from 1 through 32 |
| `RetryCount` | `1` | Retries read-only remote actions only |
| `RetryDelaySeconds` | `3` | Sets the delay between read-only retries |
| `OperationTimeoutMinutes` | `30` | Limits each remote operation batch |
| `ConnectivityTimeoutSeconds` | `5` | Limits each preflight TCP check |
| `LogFile` | User-local log folder | Selects a specific log path |
| `UseSsl` | Off | Uses WinRM HTTPS on port 5986 |
| `Authentication` | `Default` | Selects `Default`, `Kerberos`, or `Negotiate` |
| `Quiet` | Off | Suppresses routine log messages |
| `SkipConnectivityCheck` | Off | Skips only the preflight port check |
| `PolicyPath` | None | Applies a strict versioned least-privilege profile in automation or interactive mode |
| `Preflight` | Off | In automation mode, checks requested-action capability without executing it |

Automation mode accepts `WinRmIdentity` (or its backward-compatible `Credential` alias) only as an in-memory `PSCredential` object from a calling PowerShell session. It rejects username strings instead of allowing native parameter binding to open credential UI. Scheduled tasks and RMM jobs should run under their authorized Windows identity or invoke the toolkit from a wrapper that already holds an approved `PSCredential`; never place passwords in command text.

## Automation, policy, and preflight

Version 2.2.0 builds on the fail-closed 2.1.0 automation interface with optional least-privilege policy profiles and capability preflight. Automation runs one stable named action without menus or prompts and uses the same action implementations as the interactive menu.

```powershell
# Enumerate all stable action IDs and input requirements
.\WindowsAdminToolkit.ps1 -Automation -ListActions -JsonOutputPath -

# Query one remote target over WinRM and create a new JSON result
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action DiskSpace `
  -ComputerName server01.example.com `
  -JsonOutputPath C:\Ops\Results\server01-disk.json

# Preview a state-changing action without contacting the target
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action ScheduleReboot `
  -ComputerName server01.example.com `
  -RebootDelaySeconds 300 `
  -WhatIf `
  -JsonOutputPath -

# Enumerate action decisions under a validated policy
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -ListActions `
  -PolicyPath .\examples\policies\read-only-local.json `
  -JsonOutputPath -

# Check a remote action's dependencies without executing that action
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action EventLogQuery `
  -ComputerName server01.example.com `
  -EventLogName System `
  -EntryCount 50 `
  -PolicyPath .\examples\policies\helpdesk-winrm.json `
  -Preflight `
  -JsonOutputPath -
```

Automation requires exactly one target source and rejects missing, conflicting, or action-incompatible inputs before target work. Actual state changes require the action's exact `-ConfirmationText`; `-WhatIf` returns a successful preview. Result schema version 1.1 and exit codes 0, 1, 2, 3, 4, 5, and 10 are documented in [AUTOMATION.md](AUTOMATION.md).

Policy schema version 1.0 uses explicit action, transport, target-mode, and target allow lists. Optional deny lists, runtime caps, and action-input constraints can only make built-in behavior narrower. Malformed profiles return validation exit code 2; valid policy denials return authorization exit code 3. The full precedence, target-pattern, decision, capability, and JEA contract is in [POLICY.md](POLICY.md). Copy-pasteable RMM, scheduled-task, WinRM, target-list, policy, preflight, and CI examples are in [examples/automation/README.md](examples/automation/README.md).

## Remote target lists

Copy [computers_example.txt](computers_example.txt) and replace its synthetic examples with systems you are authorized to administer. Use one hostname, fully qualified domain name, or canonical IPv4 address per line. Blank lines and lines beginning with `#` are ignored.

```text
server01.example.com
workstation01.example.com
192.0.2.10
```

The toolkit requires valid UTF-8 target lists, validates every target, reports invalid line numbers, removes duplicates case-insensitively, and caps imported lists at 1 MiB and 500 unique systems.

## Reports and logs

After an action, results can be exported to:

- CSV for spreadsheet analysis
- JSON for structured processing
- HTML for a self-contained browser report

Default logs are stored under:

```text
%LOCALAPPDATA%\WindowsAdminToolkit\Logs
```

Existing report files are never overwritten.

## Testing and validation

Release 2.0.0 completed 496 automated checks across four Windows and PowerShell environments on August 12, 2026. The 2.2.0 policy milestone currently contains 504 deterministic checks and has passed natively under both Windows PowerShell 5.1 and PowerShell 7.6.4, for 1,008 completed native checks.

| Environment | PowerShell | Result |
| --- | --- | --- |
| Native Windows 11 Pro, build 26200.9168 | Windows PowerShell 5.1.26100.9168 | 124 passed |
| Native Windows 11 Pro, build 26200.9168 | PowerShell 7.6.4 | 124 passed |
| Microsoft Windows Server Core 2025, Hyper-V-isolated container | Windows PowerShell 5.1.26100.33296 | 124 passed |
| Microsoft PowerShell Server Core 2022, Hyper-V-isolated container | PowerShell 7.5.0 | 124 passed |

The displayed container matrix is the historical 2.0.0 release record. Its tests mounted the repository read-only. The current native suite adds strict policy parsing, precedence and denial behavior, runtime and action-input caps, policy-aware catalogs, capability preflight, native exit behavior, and proof that preflight does not execute or log custom code. PSScriptAnalyzer 1.25.0 reports zero findings under the committed settings. The automated suite makes no destructive system changes.

The prior release's container tags, digests, commands, and the exact current native validation record are in [TESTING.md](TESTING.md). Continuous integration repeats the dependency-free suite on Windows Server 2022 and Windows Server 2025 with both Windows PowerShell and PowerShell 7.

## Enterprise roadmap

The 2.1.0 automation interface and 2.2.0 policy and least-privilege implementation are complete for release review. The next milestone is 2.3.0 enterprise auditability, followed by controlled change plans, resumable target batches, and signed release artifacts. See [ROADMAP.md](ROADMAP.md).

## Contributing

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and run both supported PowerShell editions before submitting code.

## License

Windows Admin Toolkit is available under the [MIT License](LICENSE).

Microsoft, Windows, PowerShell, Sysinternals, and PsExec are trademarks of their respective owners. PsExec is not included in this repository.
