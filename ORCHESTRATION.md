# Controlled orchestration

Windows Admin Toolkit 3.0 adds a review-before-run workflow for repeatable administration. It separates request construction, human approval, execution, and interruption recovery into four explicit operations:

1. `Create` writes a new pending `.watplan.json` file.
2. `Approve` verifies the complete plan hash and writes a different approved plan file.
3. `Execute` verifies the approved contract and creates a new `.watcheckpoint.json` file before running targets.
4. `Resume` verifies the same plan and checkpoint and processes only targets still marked `Pending`.

Every operation uses `-Automation` and emits orchestration result schema `1.0` to stdout or `-JsonOutputPath`. The existing direct automation result schema remains `1.2`.

## Create a pending plan

Plan creation runs the same input, target, transport, policy, and built-in safety validation used by direct automation. It does not run connectivity checks or the requested action. The destination must be new, literal, and end in `.watplan.json`.

```powershell
./WindowsAdminToolkit.ps1 -Automation `
  -PlanOperation Create `
  -PlanPath 'C:\ChangePlans\inventory-pending.watplan.json' `
  -Action SystemInfo `
  -ComputerName 'server01.example.com' `
  -Transport WinRM `
  -Authentication Kerberos `
  -UseSsl `
  -JsonOutputPath '-'
```

Inspect the entire plan, including `request.targets`, `request.inputs`, `request.transport`, `request.policy`, `request.safety`, and `planHash.value`. Plan schema `1.0` is defined in `schemas/orchestration-plan-v1.schema.json`.

Plan creation deliberately rejects credentials, audit destinations, execution confirmation tokens, and the two custom-code actions. Version 1 plans run only under the current Windows identity. `CustomCommand` and `CustomPowerShell` remain available through direct automation but cannot be embedded in an approved plan.

## Approve the reviewed hash

Approval never edits the pending plan. It requires a different new `.watplan.json` destination, an approver identity, a change reference, and an exact full-hash phrase:

```powershell
$pending = Get-Content 'C:\ChangePlans\inventory-pending.watplan.json' -Raw | ConvertFrom-Json
$hash = $pending.planHash.value

./WindowsAdminToolkit.ps1 -Automation `
  -PlanOperation Approve `
  -PlanPath 'C:\ChangePlans\inventory-pending.watplan.json' `
  -ApprovedPlanPath 'C:\ChangePlans\inventory-approved.watplan.json' `
  -ApprovedBy 'Change Advisory Board' `
  -ApprovalReference 'CHG-2026-0822' `
  -PlanApprovalText "APPROVE PLAN $hash" `
  -JsonOutputPath '-'
```

The plan hash covers the action, inputs, ordered targets, transport, referenced policy metadata, and safety settings under canonicalization identifier `WAT-PLAN-1`. Approval metadata is separately bound by `approvalHash` under `WAT-PLAN-APPROVAL-1`. These SHA-256 hashes detect accidental or unauthorized changes when the attacker cannot also replace the trusted artifact; they are not digital signatures or access controls.

If a plan references a policy file or PsExec binary, approval and execution both require the same canonical path and SHA-256 file hash. Execute and Resume hold read handles that deny ordinary write or replacement access to those approved files for the complete operation. PsExec also undergoes the toolkit's existing Authenticode, product, and minimum-version checks.

## Execute an approved plan

Execution accepts the approved plan, a new checkpoint destination, and an exact operation phrase. It rejects command-line overrides of the approved action, inputs, targets, transport, policy, or runtime settings.

```powershell
$approved = Get-Content 'C:\ChangePlans\inventory-approved.watplan.json' -Raw | ConvertFrom-Json
$hash = $approved.planHash.value

./WindowsAdminToolkit.ps1 -Automation `
  -PlanOperation Execute `
  -PlanPath 'C:\ChangePlans\inventory-approved.watplan.json' `
  -CheckpointPath 'C:\ChangePlans\inventory.watcheckpoint.json' `
  -PlanApprovalText "EXECUTE PLAN $hash" `
  -JsonOutputPath 'C:\ChangePlans\inventory-execution.json'
```

State-changing plans still require their existing exact `-ConfirmationText` at both `Execute` and `Resume`. Plans over 25 targets still require `-TargetListConfirmationText 'USE TARGET LIST'`, and PsExec plans still require `-PsExecConfirmationText 'USE PSEXEC'`. `ShouldProcess`, `WhatIf`, protected-process rules, path safeguards, built-in limits, policy restrictions, and the no-retry rule for state changes all remain active.

Targets are checkpointed one at a time in deterministic plan order. Version 1 intentionally favors exact recovery semantics over concurrent execution: a checkpoint is atomically updated before a target starts and after its terminal result is known.

## Resume safely

Resume requires the same approved plan and an existing checkpoint:

```powershell
$approved = Get-Content 'C:\ChangePlans\inventory-approved.watplan.json' -Raw | ConvertFrom-Json
$hash = $approved.planHash.value

./WindowsAdminToolkit.ps1 -Automation `
  -PlanOperation Resume `
  -PlanPath 'C:\ChangePlans\inventory-approved.watplan.json' `
  -CheckpointPath 'C:\ChangePlans\inventory.watcheckpoint.json' `
  -PlanApprovalText "RESUME PLAN $hash" `
  -JsonOutputPath 'C:\ChangePlans\inventory-resume.json'
```

Resume runs only `Pending` targets. It never automatically repeats `Completed`, `Failed`, `TimedOut`, `Skipped`, or `Unknown` targets. A target left `InProgress` by an interrupted process becomes `Unknown` on resume and is not repeated, because the toolkit cannot prove whether its state change completed. Verify that target manually and create a newly reviewed plan if more work is required.

## Lifecycle states

| State | Meaning | Automatically run by Resume |
|---|---|---:|
| `Pending` | No execution attempt has started | Yes |
| `InProgress` | Checkpoint recorded a start but no terminal result yet | No; converted to `Unknown` |
| `Completed` | The target returned complete or accepted partial action success | No |
| `Failed` | The requested action failed | No |
| `TimedOut` | The target operation timed out | No |
| `Skipped` | Validation or authorization prevented execution | No |
| `Unknown` | Completion cannot be safely established | No |

Each target permits at most one orchestration attempt. The checkpoint summary is recomputed from target states and protected by `WAT-CHECKPOINT-1` SHA-256 canonicalization. Checkpoint schema `1.0` is defined in `schemas/orchestration-checkpoint-v1.schema.json`; result schema `1.0` is defined in `schemas/orchestration-result-v1.schema.json`.

Lifecycle completion and action outcome remain distinct. A target whose requested action finishes with `PartialSuccess` is terminal `Completed`, but the orchestration result remains `CompletedWithExceptions` with partial-success exit code 1. An all-skipped validation retains exit code 2, while an all-skipped authorization denial retains exit code 3.

## Strict artifact handling

Plans are limited to 1 MiB and checkpoints to 4 MiB. Both must be UTF-8 without a byte-order mark and are parsed with duplicate-key, case-conflict, unknown-property, schema-version, timestamp, identifier, lifecycle, path, and hash validation. Artifact paths are literal, traversal-safe, extension-bound, and cannot collide with configured result or log paths. New plans, approved plans, execution checkpoints, and JSON results refuse overwrite.

Atomic checkpoint replacement protects against partial writes, not deletion or malicious replacement by an identity that can write the directory. Store plans and checkpoints in an access-controlled location, separate plan authors from approvers where practical, retain approved plans with ticket evidence, and back up checkpoints during long runs.

Orchestration checkpoint records are recovery evidence, not substitutes for the opt-in JSON Lines audit contract. Plan operations intentionally do not accept `-AuditPath` or Event Log audit parameters in version 3.0. Capture the orchestration result, approved plan, checkpoint, ordinary log, and external change-system evidence together.

## Committed examples

Synthetic, non-secret examples are available in `examples/orchestration`:

- `pending-system-info.watplan.json`
- `approved-system-info.watplan.json`
- `completed-system-info.watcheckpoint.json`
- `completed-system-info-result.json`

The example hashes are internally consistent and are validated by the native test suite and the committed JSON Schemas.
