# Changelog

All notable changes to Windows Admin Toolkit are documented here.

The format follows Keep a Changelog principles, and the project uses Semantic Versioning.

## [Unreleased]

### Added

- Noninteractive `-Automation` mode with 20 stable named action identifiers
- Explicit local, single-remote-target, and validated target-list selectors
- Action-specific noninteractive inputs with complete pre-execution validation
- JSON result schema version 1.2 with deterministic root fields, stable target IDs, target ordering, UTC timestamps, array stability, safe serialization, policy decisions, audit metadata, preflight state, and outcome-to-exit-code constraints
- Stable exit codes for complete success, partial success, validation, authorization, execution, timeout, and internal failures
- Clean stdout JSON with `-` and native `STDOUT` selectors, atomic file output, overwrite refusal, and nine committed result examples
- `-ListActions` catalog discovery for action metadata, input requirements, and optional policy annotations
- Optional strict policy profiles for actions, transports, target modes, target patterns, runtime caps, and supported action-input constraints
- Policy schema version 1.0 and two synthetic least-privilege example profiles
- `-Preflight` capability discovery for commands, executables, COM components, administrator status, PowerShell environment, and language mode without requested-action execution
- RMM, scheduled-task, WinRM, target-list, CI, `WhatIf`, policy, preflight, and JEA-oriented examples and guidance
- Opt-in per-run JSON Lines auditing with unique run IDs, sequenced lifecycle events, stable cross-run target IDs, UTC timings, normalized outcomes, and explicit policy decisions
- Optional Windows Event Log audit forwarding that requires an existing source and never changes Event Log configuration
- Audit schema version 1.0, SIEM-oriented terminal summaries, and documented `WAT-AUDIT-SUMMARY-1` SHA-256 canonicalization
- A complete synthetic audited result and six-record JSON Lines lifecycle example
- Automation regression coverage under Windows PowerShell 5.1 and PowerShell 7.x
- Controlled orchestration with separate `Create`, `Approve`, `Execute`, and `Resume` operations
- Strict plan schema version 1.0 with canonical action, input, ordered-target, transport, policy, and safety snapshots
- Full SHA-256 plan hashes under `WAT-PLAN-1` and separately hashed approval metadata under `WAT-PLAN-APPROVAL-1`
- Atomic checkpoint schema version 1.0 with explicit per-target lifecycle states, one-attempt evidence, deterministic summaries, and `WAT-CHECKPOINT-1` hashes
- Orchestration result schema version 1.0 and four internally consistent synthetic plan, checkpoint, and result examples
- Release-candidate automation with optional SHA-256 Authenticode signing, verified `SHA256SUMS.txt`, and an SPDX 2.3 JSON SBOM
- Complete orchestration, recovery, release-integrity, security, and responsible-use guidance

### Changed

- Refactored interactive and automation modes to share one action catalog and one execution implementation
- Added deterministic per-target timing, attempts, normalized errors, and concurrency-order restoration
- Increased the dependency-free native suite to 647 deterministic checks per PowerShell edition
- Updated the toolkit version to 3.0.0 while retaining the direct automation result contract at schema version 1.2
- Made controlled orchestration sequential at one-target checkpoint granularity so interruption recovery has deterministic boundaries

### Fixed

- Corrected interactive menu lookup so choices 1 through 20 invoke their matching actions, including choice 20
- Preserved KB filters and event-level arrays across local, background-job, WinRM, and encoded PsExec argument boundaries
- Normalized invalid configuration fields and nonfinite numbers so failure JSON remains schema-valid across PowerShell editions
- Mapped pending-reboot check errors to partial results instead of complete success
- Treated unhandled PowerShell error records from the custom expert action as execution failures
- Preserved completed target evidence in stderr fallback envelopes when a JSON output sink fails after execution
- Appended an explicit audit failure and authoritative replacement summary when JSON result delivery fails after an audited execution
- Wrote automation JSON files as interoperable UTF-8 without a byte-order mark while preserving BOM behavior for interactive exports
- Removed the optional local PsExec binary from the deterministic test count while retaining its validation when available
- Applied one consistent local-computer identity rule when importing plans, including legacy Windows names that contain underscores
- Normalized remoted enum and scalar values before JSON serialization so case-colliding extended properties cannot produce JSON that Windows PowerShell rejects

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
- Made policy parsing a strict UTF-8, 1 MiB security boundary that rejects duplicate keys, case conflicts, unknown fields, unsupported values, inconsistent rules, and constraints that could silently do nothing
- Enforced built-in ceilings as absolute, denied explicitly supplied values above policy limits, and clamped omitted runtime values to tighter policy caps
- Evaluated target deny rules before allow patterns and stopped known denied actions before target-list or custom-source file reads
- Kept policy files credential-free and preserved every existing confirmation, `ShouldProcess`, target-count, transport, protected-process, and no-retry safeguard
- Proved through native child-process tests that capability preflight does not execute or log supplied custom PowerShell
- Made every audit destination a new literal `.jsonl` file with no append or overwrite behavior, a 16 MiB per-run ceiling, unexpected-mutation detection, and no automatic rotation or deletion
- Flushed target-start evidence before connectivity or requested-action execution and converted configured audit-sink failures into visible non-success results
- Excluded credentials, custom source, raw action data, and raw custom output from audit records
- Kept Windows Event Log integration off by default and prohibited automatic source registration or configuration changes
- Made plan and checkpoint parsing strict UTF-8 security boundaries with hard size limits, duplicate-key and case-conflict detection, unknown-property rejection, canonical identifiers and timestamps, and hash verification
- Required exact full-plan-hash phrases for approval, execution, and resume while preserving action-specific, large-target, PsExec, policy, `ShouldProcess`, `WhatIf`, protected-resource, and no-retry safeguards
- Rejected execution-time overrides of approved actions, inputs, targets, transports, policies, and safety settings and re-resolved the complete contract before target work
- Limited version 1 plans to the current Windows identity and excluded both unsandboxed custom-code actions
- Bound referenced policy and PsExec files by canonical path and SHA-256, with existing PsExec signer, product, and version checks repeated before execution
- Prevented Resume from automatically repeating completed, failed, timed-out, skipped, unknown, or interrupted in-progress targets
- Kept signing keys, certificate provisioning, trust configuration, tagging, upload, and publication outside automated release tooling

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
