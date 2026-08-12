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

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for operational guidance.
