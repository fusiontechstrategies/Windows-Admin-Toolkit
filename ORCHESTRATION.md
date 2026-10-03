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

Execute and Resume hold exclusive checkpoint identity leases and one private read/write file object across import, every target claim, invocation, and revision. The file is opened relative to a retained no-follow parent handle; every ancestor remains pinned without write or delete sharing. Competing writers, leaf replacement and ancestor relocation fail before work is claimed. All revisions use the same object. Kernel handles release after a crash. Interrupted `InProgress` targets become `Unknown` during explicit recovery.

Checkpoint IDs also have an exclusive identity lease and a private durable ledger under the executing identity's Windows Local Application Data directory (`WindowsAdminToolkit-CheckpointLedger-v1`). Each record binds the ID to one canonical checkpoint path, approved plan hash, revision, and checkpoint hash. Copies, hard-link aliases, foreign-identity checkpoints, and stale snapshots cannot establish another execution authority. The ledger is flushed before the checkpoint is published. Interrupted ledger or artifact writes fail closed and require manual reconciliation.

Resume must use the original Windows identity, checkpoint path, and matching ledger. Earlier checkpoints without a ledger are not automatically adopted. Retain the ledger with recovery evidence; deleting or restoring only the checkpoint does not authorize a retry. Inspect affected targets and create a newly reviewed plan when further work is needed. The ledger has a 16 MiB limit per checkpoint ID and is not automatically discarded.

Approved external references use no-follow file handles and locked ancestor directories. Policy execution uses the profile parsed from the exact opened stream. PsExec is revalidated immediately before launch while the same path identity is locked. Protected input files require local absolute Windows paths and native handle support in a full PowerShell language session.

Targets are checkpointed one at a time in deterministic plan order. The durable identity ledger is flushed first, followed by an in-place checkpoint revision through the retained object before a target starts and after its terminal result is known. This retains object identity instead of reopening a pathname for atomic replacement. A crash can leave an incomplete revision or ledger mismatch; Resume refuses both and requires manual reconciliation. This is an explicit availability tradeoff.

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

Any `Unknown` or remaining `InProgress` target makes the aggregate `InternalFailure` with exit code 10. `PartialSuccess` requires at least one `Completed` target. With zero completions, failed or heterogeneous skipped states return execution failure, otherwise timed-out states return timeout.

Lifecycle completion and action outcome remain distinct. A target whose requested action finishes with `PartialSuccess` is terminal `Completed`, but the orchestration result remains `CompletedWithExceptions` with partial-success exit code 1. An all-skipped validation retains exit code 2, while an all-skipped authorization denial retains exit code 3.

## Strict artifact handling

Plans are limited to 1 MiB and checkpoints to 4 MiB. Both must be UTF-8 without a byte-order mark and are parsed with duplicate-key, case-conflict, unknown-property, schema-version, timestamp, identifier, lifecycle, path, and hash validation. Artifact paths are literal, traversal-safe, extension-bound, and cannot collide with configured result or log paths. New plans, approved plans, execution checkpoints, and JSON results refuse overwrite.

Checkpoint protection lasts through execution and result construction. After handles close, current-user and privileged filesystem authority can change artifacts; hashes and the separately flushed ledger refuse inconsistent recovery but are not immutable retention. Older checkpoints without protected current-identity DACLs require manual reconciliation. Store plans and checkpoints in an access-controlled location and back up the complete recovery evidence.

Orchestration checkpoint records are recovery evidence, not substitutes for the opt-in JSON Lines audit contract. Plan operations intentionally do not accept `-AuditPath` or Event Log audit parameters in version 3.0. Capture the orchestration result, approved plan, checkpoint, ordinary log, and external change-system evidence together.

## Committed examples

Synthetic, non-secret examples are available in `examples/orchestration`:

- `pending-system-info.watplan.json`
- `approved-system-info.watplan.json`
- `completed-system-info.watcheckpoint.json`
- `completed-system-info-result.json`

The example hashes are internally consistent and are validated by the native test suite and the committed JSON Schemas.

## Pending and approved plan publication

Create and Approve use the shared protected new-file publisher. Their local parent directories must already exist and pass ancestry/owner/DACL validation, with no junctions or symlinks and no less-privileged mutation rights. The parent and temporary object remain retained through private create-new, content flush, and same-parent no-replace native rename. Existing destinations are never overwritten; failure cleanup removes only the retained unpublished object. Missing parents are rejected without directory creation or ACL changes. Provision output directories before invoking the operation. This new-file atomic rename does not change the separate non-atomic checkpoint revision contract.

Publication paths must resolve to a direct local hard-disk volume. UNC paths, mapped network drives, substituted drive aliases and unknown device mappings are refused before filesystem-provider lookup. The current DOS drive mapping is checked without opening an endpoint, then native no-follow ancestry and identity checks remain required. Terminal publication parents also reject less-privileged file or subdirectory creation grants, including at a volume root; ancestor-only volume-root exceptions do not apply to that terminal parent. This conservative boundary does not support alternate drive providers.

Existence, type and collision preflight uses retained no-follow native objects. No pathname-based filesystem-provider lookup precedes ancestry validation, including for local-looking paths whose ancestors contain remote-targeting reparse points. New-output collision checks open only a strict relative leaf under the retained parent and never traverse reparse points; actual publication still enforces no replacement independently.

## Literal local file inputs

Policy, computer-list, custom-script and PsExec inputs are acquired through native no-follow handles before file metadata, content or hashes are inspected. Drive mappings must be direct local hard-disk volumes; UNC, network drive, substituted-drive and unknown mappings are refused. PsExec is a literal path. A basename resolves in the current directory, and the toolkit does not search PATH. Approval validates embedded policy and PsExec references through the same retained reads as execution. Ordinary schema imports remain structural validation only and do not grant file trust.
