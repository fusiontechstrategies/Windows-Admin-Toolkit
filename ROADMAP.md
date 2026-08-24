# Enterprise Roadmap

Windows Admin Toolkit will remain a one-file PowerShell application while gaining features suited to repeatable enterprise operations.

Roadmap items describe direction, not guaranteed delivery dates. Security, Windows PowerShell 5.1 compatibility, PowerShell 7.x compatibility, and the one-file application model remain release requirements.

## 2.1.0: Automation interface

Release status: included in 3.0.0 on August 24, 2026.

- Noninteractive named-action mode alongside the existing menu
- Validated command parameters for targets, inputs, transport, and output
- Stable process exit codes for orchestration systems
- Versioned machine-readable JSON result envelopes and committed schema
- Safe report-path and overwrite behavior for unattended runs
- Exact noninteractive authorization and `WhatIf` for state changes
- Documentation and examples for WinRM, target lists, RMM tools, scheduled tasks, and CI systems

## 2.2.0: Policy and least privilege

Release status: included in 3.0.0 on August 24, 2026.

- Versioned strict policy profiles for action, transport, target-mode, and target allow or deny decisions
- Literal exact-target and leading star-dot suffix controls without wildcard expansion
- Policy caps for target count, concurrency, retries, delays, connectivity, operation timeouts, and supported action inputs
- Built-in safety ceilings that policy cannot relax, with documented command-line precedence
- Capability preflight before requested-action execution
- Explicit policy decisions and reason codes in logs, results, and action catalogs
- JEA-oriented WinRM guidance without endpoint or security-setting changes

## 2.3.0: Enterprise auditability

Release status: included in 3.0.0 on August 24, 2026.

- New per-run JSON Lines audit logs with unique run IDs, stable cross-run target IDs, UTC timings, lifecycle stages, outcomes, and normalized errors
- Explicit policy-decision events and bounded target start or completion events without raw action data
- Optional Windows Event Log integration that is off by default and requires an existing source
- SHA-256 run-summary hashes under the documented `WAT-AUDIT-SUMMARY-1` canonicalization method
- Machine-readable terminal summaries for SIEM, RMM, and ticketing ingestion
- Bounded file behavior, unexpected-mutation detection, and visible audit-sink failure semantics

## 3.0.0: Controlled orchestration

Release status: released on August 24, 2026.

- Strict versioned pending and approved change-plan files with canonical SHA-256 request hashes and separately hashed approval metadata
- Exact full-hash approval, execution, and resume phrases without mutable action, input, target, transport, policy, or runtime overrides
- Atomic per-target checkpoints with explicit `Pending`, `InProgress`, `Completed`, `Failed`, `TimedOut`, `Skipped`, and `Unknown` lifecycle states
- Resume of only pending targets, with interrupted in-progress work converted to unknown and no automatic repetition of terminal state changes
- Current-Windows-identity plan boundary, custom-code exclusion, policy and PsExec file-hash binding, and preservation of every existing safety gate
- Orchestration plan, checkpoint, and result JSON Schemas plus deterministic synthetic examples
- Release-candidate tooling for optional SHA-256 Authenticode signing, verified SHA-256 manifests, and SPDX 2.3 software bills of materials

## Proposals

Open a feature request to discuss an enterprise workflow. Proposals should describe privileges, inputs, outputs, failure behavior, safety controls, and compatibility with both supported PowerShell editions.
