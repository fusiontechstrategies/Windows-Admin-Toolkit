# Changelog

All notable changes to Windows Admin Toolkit are documented here.

The format follows Keep a Changelog principles, and the project uses Semantic Versioning.

## [2.0.0] - 2026-08-12

### Added

- One-file Windows Admin Toolkit application with 20 guarded workflows
- Windows PowerShell 5.1 and PowerShell 7.x compatibility
- Secure WinRM default transport and optional PsExec fallback
- Bounded concurrency, operation timeouts, connectivity checks, and normalized failures
- CSV, JSON, and self-contained HTML reports
- Dependency-free automated test harness
- Native and Hyper-V-isolated Windows container validation
- Continuous integration, security guidance, contribution templates, and public-release documentation

### Security

- Removed plaintext PsExec credential handling
- Replaced constructed remote commands with encoded, typed data envelopes
- Added Microsoft Authenticode signer, Sysinternals product, and minimum-version checks for PsExec
- Added exact confirmation phrases and `ShouldProcess` protection for state changes
- Limited retries to read-only actions
- Added strict target and action input validation
- Added CSV formula neutralization, HTML encoding, atomic output, and overwrite refusal
- Blocked termination of core Windows processes
- Restricted cleanup to validated temp locations and excluded Windows Prefetch

### Changed

- Renamed the project and application to Windows Admin Toolkit
- Made WinRM the default remote-management transport
- Moved default logs to `%LOCALAPPDATA%\WindowsAdminToolkit\Logs`

[2.0.0]: https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/releases/tag/v2.0.0
