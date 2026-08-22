# Responsible Use

Windows Admin Toolkit is built for legitimate Windows administration, maintenance, inventory, and troubleshooting.

## Authorization is required

Use this software only on systems that you own or are explicitly authorized to administer. Follow all applicable laws, organizational policies, change-management procedures, maintenance windows, and data-handling requirements.

## Review changes before execution

- Use `-WhatIf` when evaluating state-changing workflows.
- Use `-Preflight` to assess the selected action, identity, endpoint, and dependencies before execution.
- Start with one non-production target before operating on a larger list.
- Review the selected target count, action, and exact confirmation phrase.
- Confirm that backups, rollback procedures, and monitoring are appropriate for the intended change.
- Treat Windows Update, reboot, service, process, cleanup, custom CMD, and custom PowerShell actions as privileged operations.

## Remote administration

- Prefer WinRM with Kerberos or HTTPS according to your environment's security design.
- Do not weaken firewall, WinRM, TrustedHosts, or authentication policies solely to make the toolkit connect.
- Use a least-privileged administrative identity appropriate for the requested action.
- Use PsExec only when your organization permits its SMB and temporary-service model.
- When using JEA, design and test the endpoint separately with only the commands, providers, paths, and identity rights the approved actions need. The toolkit does not configure JEA.

## Custom execution

Custom CMD commands and PowerShell code run as supplied with the privileges of the current session or remote identity. They are not sandboxed. Review custom content carefully and never execute untrusted code.

## Unattended execution

- Run automation under a dedicated, authorized identity with only the rights required by the selected action.
- Restrict who can edit RMM jobs, scheduled tasks, target lists, custom script files, and toolkit command lines.
- Use `-WhatIf` and one non-production target before approving a state-changing unattended job.
- Treat exact confirmation text as an additional safety gate, not as a credential or a replacement for access control and change approval.
- Capture the process exit code as well as the JSON result. Exit code 1 is partial success and must not be treated as complete success.
- Treat a timeout as an unknown final target state. Verify the target before manually retrying any state-changing action.
- Give every run a new JSON destination or use a separately reviewed retention process. The toolkit refuses to overwrite earlier evidence.
- When audit evidence is required, give every run a new `.jsonl` `AuditPath` and verify `audit.complete`, the final record count, and the final summary hash before ingestion.
- Keep explicit working directories and absolute output paths in scheduled tasks so execution does not depend on an account's profile directory.
- Protect target lists and PowerShell files from unapproved modification. Both are security-sensitive inputs.
- Apply a reviewed least-privilege `PolicyPath` where practical. Restrict who can edit the profile, and treat policy denial as an authorization result that should not be bypassed by rerunning without the profile.
- Do not place credentials in command text, custom PowerShell, environment-specific examples, logs, or report paths.

## Controlled plans and resume

- Review the entire pending plan, not only its displayed hash. Confirm the canonical action, inputs, ordered targets, transport, policy reference, safety settings, current-identity boundary, and `WhatIf` state.
- Keep plan authors, approvers, and execution identities separate where practical. A hash is integrity evidence, not proof that the named approver performed the review.
- Store approved plans and checkpoints in access-controlled locations and retain them with the external change record and final result.
- Never edit an approved plan or checkpoint to force a retry. Create and review a new plan when additional work is required.
- Resume processes only `Pending` targets. Manually investigate `Failed`, `TimedOut`, `Skipped`, and `Unknown` targets before deciding on a new request.
- Treat a prior `InProgress` target converted to `Unknown` as potentially changed. The toolkit deliberately will not repeat it automatically.
- Keep the exact action, large-list, and PsExec confirmations in the executing workflow. Plan approval does not replace them.
- Do not embed credentials, secrets, real production evidence, or custom code in public plan examples. Version 1 plans intentionally reject credentials and both custom-code actions.

## Policy and preflight

A policy profile narrows toolkit behavior but does not prove that a caller is authorized by Windows or by the organization. Keep operating-system permissions, JEA role design, RMM controls, change approval, exact confirmation phrases, and `ShouldProcess` in place.

Review policy action, transport, target-mode, target-pattern, runtime, and action-input decisions before production use. Test a profile with `-ListActions -PolicyPath` and then run `-Preflight` against a nonproduction target. Never place credentials in the policy file.

Capability preflight reports observable readiness, not a guarantee that every later operating-system operation will succeed. Target state, network state, permissions, dependencies, and policy may change after the assessment. Preflight for custom CMD or PowerShell cannot infer dependencies inside operator-supplied content.

## Reports and logs

Reports may contain system inventory, user names, software lists, event details, or configuration data. Store, transmit, retain, and dispose of those reports according to your organization's requirements.

Audit files deliberately omit raw action output and custom source, but they still contain target names, action IDs, policy decisions, timings, outcomes, and normalized errors. Restrict access, retain them under the applicable audit policy, and move completed files and hashes to an external protected system when immutability matters. The toolkit does not rotate or delete them.

Treat `audit.complete: false`, a missing terminal summary, a sequence gap, a summary-hash mismatch, or exit code 10 as an incident requiring operator review. Never blindly retry a state-changing action solely because an audit or result sink failed after execution.

The software is provided under the MIT License without warranty. Operational responsibility remains with the administrator using it.
