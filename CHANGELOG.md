# Changelog

All notable changes to Windows Admin Toolkit are documented here.

The format follows Keep a Changelog principles, and the project uses Semantic Versioning.

## [Unreleased]

### Added

- Noninteractive `-Automation` mode with 20 stable named action identifiers
- Explicit local, single-remote-target, and validated target-list selectors
- Action-specific noninteractive inputs with complete pre-execution validation
- JSON schema version 1.0 with deterministic root fields, target ordering, UTC timestamps, array stability, safe serialization, and outcome-to-exit-code constraints
- Stable exit codes for complete success, partial success, validation, authorization, execution, timeout, and internal failures
- Clean stdout JSON with `-` and native `STDOUT` selectors, atomic file output, overwrite refusal, and six committed result examples
- `-ListActions` catalog discovery for action metadata and input requirements
- RMM, scheduled-task, WinRM, target-list, CI, and `WhatIf` examples
- Automation regression coverage under Windows PowerShell 5.1 and PowerShell 7.x

### Changed

- Refactored interactive and automation modes to share one action catalog and one execution implementation
- Added deterministic per-target timing, attempts, normalized errors, and concurrency-order restoration
- Increased the dependency-free native suite to 379 deterministic checks

### Fixed

- Corrected interactive menu lookup so choices 1 through 20 invoke their matching actions, including choice 20
- Preserved KB filters and event-level arrays across local, background-job, WinRM, and encoded PsExec argument boundaries
- Normalized invalid configuration fields and nonfinite numbers so failure JSON remains schema-valid across PowerShell editions
- Mapped pending-reboot check errors to partial results instead of complete success
- Treated unhandled PowerShell error records from the custom expert action as execution failures
- Preserved completed target evidence in stderr fallback envelopes when a JSON output sink fails after execution
- Wrote automation JSON files as interoperable UTF-8 without a byte-order mark while preserving BOM behavior for interactive exports
- Removed the optional local PsExec binary from the deterministic test count while retaining its validation when available

### Security

- Required exact action-specific authorization for unattended state changes while retaining `ShouldProcess`
- Made `WhatIf` return a no-connection preview and prohibited interactive confirmation prompts in automation mode
- Kept automatic retries disabled for state-changing actions
- Added exact authorization for target lists over 25 systems and for PsExec use
- Excluded credentials, custom source, raw exceptions, and remoting metadata from automation output and logs
- Omitted operator-supplied exception text from expert-action error fields and logs while retaining normalized outcomes
- Added `WinRmIdentity` with the backward-compatible `Credential` alias, rejecting username strings in automation before PowerShell can open credential UI; alternate WinRM credentials must be supplied as in-memory `PSCredential` objects
- Added fail-closed validation for incompatible inputs, transports, paths, target lists, and protected process requests
- Rejected WinRM-only controls with PsExec and PsExec-only controls with WinRM
- Added strict, bounded UTF-8 decoding for target lists and custom PowerShell files across both PowerShell editions
- Added pre-execution JSON destination writeability checks, reserved-name rejection, unique log names, and cancellation cleanup for background jobs

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
[Unreleased]: https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/compare/v2.0.0...HEAD
