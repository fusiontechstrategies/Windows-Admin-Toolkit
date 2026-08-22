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

The JSON schema and stable exit codes are documented in [AUTOMATION.md](AUTOMATION.md). Treat changes to action IDs, classifications, confirmation phrases, schema version 1.0, or exit-code meanings as security-sensitive public-interface changes.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for operational guidance.
