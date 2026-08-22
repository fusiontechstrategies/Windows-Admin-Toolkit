# Enterprise Roadmap

Windows Admin Toolkit will remain a one-file PowerShell application while gaining features suited to repeatable enterprise operations.

Roadmap items describe direction, not guaranteed delivery dates. Security, Windows PowerShell 5.1 compatibility, PowerShell 7.x compatibility, and the one-file application model remain release requirements.

## 2.1.0: Automation interface

Implementation status: complete for release review.

- Noninteractive named-action mode alongside the existing menu
- Validated command parameters for targets, inputs, transport, and output
- Stable process exit codes for orchestration systems
- Versioned machine-readable JSON result envelopes and committed schema
- Safe report-path and overwrite behavior for unattended runs
- Exact noninteractive authorization and `WhatIf` for state changes
- Documentation and examples for WinRM, target lists, RMM tools, scheduled tasks, and CI systems

## 2.2.0: Policy and least privilege

Implementation status: complete for release review.

- Versioned strict policy profiles for action, transport, target-mode, and target allow or deny decisions
- Literal exact-target and leading star-dot suffix controls without wildcard expansion
- Policy caps for target count, concurrency, retries, delays, connectivity, operation timeouts, and supported action inputs
- Built-in safety ceilings that policy cannot relax, with documented command-line precedence
- Capability preflight before requested-action execution
- Explicit policy decisions and reason codes in logs, results, and action catalogs
- JEA-oriented WinRM guidance without endpoint or security-setting changes

## 2.3.0: Enterprise auditability

- JSON Lines audit logs with run IDs, target IDs, timings, and outcomes
- Optional Windows Event Log integration
- Tamper-evident run-summary hashes
- Machine-readable summaries for SIEM, RMM, and ticketing ingestion

## 3.0.0: Controlled orchestration

- Reviewable change-plan files
- Execution of an approved plan without changing its target or action definition
- Checkpointed and resumable large-target runs
- Per-target lifecycle status and deterministic completion summaries
- Authenticode-signed releases, SHA-256 manifests, and software bill of materials

## Proposals

Open a feature request to discuss an enterprise workflow. Proposals should describe privileges, inputs, outputs, failure behavior, safety controls, and compatibility with both supported PowerShell editions.
