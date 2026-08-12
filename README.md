# Windows Admin Toolkit

One script. Twenty guarded Windows administration workflows. Secure local and remote operations across Windows PowerShell 5.1 and PowerShell 7.x.

[![CI](https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/actions/workflows/ci.yml)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-2671be.svg)](https://learn.microsoft.com/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Windows Admin Toolkit turns common Windows administration work into a focused, menu-driven experience without becoming a framework, module collection, or installation project. The application remains a single PowerShell script that can inspect, report on, and administer authorized local or remote Windows systems.

## Why administrators use it

- One portable application file: `WindowsAdminToolkit.ps1`
- Compatible with Windows PowerShell 5.1 and PowerShell 7.x
- Secure WinRM transport by default
- Optional, tightly validated Microsoft Sysinternals PsExec fallback
- Bounded concurrency, timeouts, normalized failures, and read-only retries
- Exact confirmation phrases and `ShouldProcess` protection for changes
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
```

| Parameter | Default | Purpose |
| --- | --- | --- |
| `Transport` | `WinRM` | Selects `WinRM` or the optional `PsExec` fallback |
| `PsExecPath` | `PsExec64.exe` | Locates a Microsoft-signed PsExec executable |
| `Credential` | Current identity | Supplies an optional credential for WinRM only |
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

## Remote target lists

Copy [computers_example.txt](computers_example.txt) and replace its synthetic examples with systems you are authorized to administer. Use one hostname, fully qualified domain name, or canonical IPv4 address per line. Blank lines and lines beginning with `#` are ignored.

```text
server01.example.com
workstation01.example.com
192.0.2.10
```

The toolkit validates targets, reports invalid line numbers, removes duplicates case-insensitively, and caps imported lists at 500 unique systems.

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

Release 2.0.0 completed 496 automated checks across four Windows and PowerShell environments on August 12, 2026.

| Environment | PowerShell | Result |
| --- | --- | --- |
| Native Windows 11 Pro, build 26200.9168 | Windows PowerShell 5.1.26100.9168 | 124 passed |
| Native Windows 11 Pro, build 26200.9168 | PowerShell 7.6.4 | 124 passed |
| Microsoft Windows Server Core 2025, Hyper-V-isolated container | Windows PowerShell 5.1.26100.33296 | 124 passed |
| Microsoft PowerShell Server Core 2022, Hyper-V-isolated container | PowerShell 7.5.0 | 124 passed |

Container tests mounted the repository read-only. PSScriptAnalyzer 1.25.0 reported zero findings with the committed compatibility settings. Automated coverage includes all action registrations, parser compatibility, validators, injection resistance, report safety, failure normalization, local read-only execution, service queries, remote-target rejection, encoded argument integrity, and PsExec identity and signature verification. The automated suite makes no destructive system changes.

Exact container tags, digests, commands, and coverage details are recorded in [TESTING.md](TESTING.md). Continuous integration repeats the dependency-free suite on Windows Server 2022 and Windows Server 2025 with both Windows PowerShell and PowerShell 7.

## Enterprise roadmap

The next headline milestone is a noninteractive automation mode for RMM platforms, scheduled tasks, CI systems, and orchestration tools. Policy profiles, JEA-oriented operation, structured audit events, change plans, resumable target batches, and signed release artifacts follow in the planned enterprise direction. See [ROADMAP.md](ROADMAP.md).

## Contributing

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and run both supported PowerShell editions before submitting code.

## License

Windows Admin Toolkit is available under the [MIT License](LICENSE).

Microsoft, Windows, PowerShell, Sysinternals, and PsExec are trademarks of their respective owners. PsExec is not included in this repository.
