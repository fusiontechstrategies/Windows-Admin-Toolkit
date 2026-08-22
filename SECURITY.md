# Security Policy

## Supported versions

Security fixes are provided for the newest published release of Windows Admin Toolkit.

## Report a vulnerability privately

Do not disclose a suspected vulnerability in a public issue, discussion, or pull request.

Use the repository Security tab and select **Report a vulnerability**. Include:

- A concise description of the issue and its impact
- The affected version and PowerShell edition
- Reproduction steps or a minimal proof of concept
- Any suggested mitigation

Do not include real credentials, production hostnames, private IP inventories, access tokens, or confidential logs.

Reports will be acknowledged as soon as practical. Valid reports will be investigated, corrected, tested in the supported matrix, and disclosed through a GitHub security advisory when appropriate.

## Security boundaries

- Run the toolkit only on systems you own or are explicitly authorized to administer.
- WinRM is the default remote transport.
- PsExec is optional, is not distributed in this repository, and must pass Microsoft signer, product, and minimum-version checks.
- Alternate credentials are supported only for WinRM. PsExec uses the current Windows identity.
- Custom CMD and PowerShell actions are intentionally unsandboxed and require explicit confirmation.
- The toolkit does not automatically enable WinRM, open firewall ports, change TrustedHosts, or bypass execution policy.
- Optional policy profiles are local security configuration. They narrow toolkit behavior but do not grant Windows authorization.
- Audit sinks are opt-in evidence destinations. They do not authorize an action or configure Windows security services.

## Automation security

Automation mode is noninteractive and fails closed when an action, target selector, action input, transport setting, output path, or authorization value is missing or invalid.

- Actual state-changing runs retain `ShouldProcess` and require the exact action-specific `ConfirmationText`.
- `WhatIf` validates the complete request and returns a preview without connecting to a target or making a change.
- State-changing actions are never retried. Only read-only remote actions may use the bounded retry controls.
- More than 25 targets require the exact `USE TARGET LIST` authorization, and the built-in target ceiling remains 500.
- PsExec requires the exact `USE PSEXEC` authorization in addition to signer, product, and version validation.
- Automation accepts alternate WinRM credentials only as in-memory `PSCredential` objects and rejects username strings before any credential prompt can open.
- JSON output excludes credentials, secure strings, scriptblocks, raw exceptions, invocation details, and remoting metadata.
- Logs contain action summaries but not credentials, custom source text, or custom-command output.
- Expert-action failures retain normalized categories but omit operator-supplied exception text from error fields and logs.
- Custom CMD and custom PowerShell are unsandboxed expert actions. Their exact confirmations do not make untrusted content safe.
- Existing JSON output files are not overwritten. Output is written atomically to a validated literal path.
- Capability preflight executes only built-in discovery logic. It does not execute the requested action or log supplied custom code.

## Policy security

Policy profiles use strict schema version 1.0 parsing and fail closed. The toolkit rejects invalid UTF-8, files over 1 MiB, duplicate or case-conflicting JSON properties, unknown fields, unsupported identifiers, conflicting rules, unsafe target patterns, limits above built-in ceilings, and unsupported action-input constraints.

- Required allow lists prevent an omitted rule from becoming implicit broad access.
- Explicit deny rules are checked before broader allow rules.
- Remote target rules accept only exact validated targets or one leading star-dot DNS suffix. They do not enumerate DNS or expand wildcards.
- Explicit command-line runtime values above policy caps are denied. Omitted values are clamped to the tighter policy value.
- Policy cannot weaken exact confirmations, `ShouldProcess`, protected processes, target-list authorization, PsExec validation, no-overwrite output, or zero retries for state changes.
- In automation mode, a policy-denied action stops before target connection or execution. Known action, target-mode, and transport denials occur before avoidable target-list, custom-source, or PsExec file reads.
- After target entry or literal list import, automation target-name and target-count denials occur before large-list authorization, PsExec validation, or custom-source reads.
- Interactive remote targets are checked against policy after entry or literal list import and before PsExec validation or TCP connectivity checks.
- Profiles have no credential fields. Never add credentials, tokens, or private key material to a profile.

Restrict write access to policy files. An identity that can edit an applied profile can change its allow rules up to the toolkit's built-in ceilings. Review [POLICY.md](POLICY.md) for the complete precedence, target, result-decision, preflight, and JEA-oriented deployment contract.

## Audit security

Audit schema version 1.0 records bounded run, request, policy, target, failure, and summary events. Records intentionally omit credentials, secure strings, custom action source, raw action output, raw exceptions, invocation details, and remoting metadata.

- Each `AuditPath` must be a new literal `.jsonl` file and cannot collide with another configured output. The toolkit never appends to or overwrites an existing audit file.
- A target-start record is flushed before connectivity or requested-action execution. Unexpected file-length changes fail closed.
- Per-run audit files have a 16 MiB hard ceiling. The toolkit performs no rotation, retention deletion, or log truncation.
- Windows Event Log forwarding is off by default and requires a pre-registered source. The toolkit never creates a source or changes Event Log configuration.
- A configured audit sink failure is visible as a validation failure before execution or internal failure after initialization. Completed target evidence is preserved without claiming audit completion.
- Stable target IDs are deterministic join keys derived from canonical target names. They are not anonymous identifiers.
- The SHA-256 run-summary hash detects changes to bounded summary evidence but is not a signature or proof of operator identity.
- If the JSON result destination fails after target execution, a still-writable audit sink receives `audit.failure` and an authoritative replacement `run.summary`.

Restrict read and write access to audit files because they may contain target names, policy profile names, action IDs, outcomes, timings, and normalized errors. Move completed files and expected hashes to an access-controlled external collector when stronger retention or immutability is required. Review [AUDITING.md](AUDITING.md) for the complete event, canonicalization, data-minimization, and sink-failure contract.

The JSON schema and stable exit codes are documented in [AUTOMATION.md](AUTOMATION.md). Treat changes to action IDs, classifications, confirmation phrases, result schema version 1.2, policy schema version 1.0, audit schema version 1.0, canonicalization identifier, or exit-code meanings as security-sensitive public-interface changes.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for operational guidance.
