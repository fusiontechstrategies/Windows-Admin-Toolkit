# Responsible Use

Windows Admin Toolkit is built for legitimate Windows administration, maintenance, inventory, and troubleshooting.

## Authorization is required

Use this software only on systems that you own or are explicitly authorized to administer. Follow all applicable laws, organizational policies, change-management procedures, maintenance windows, and data-handling requirements.

## Review changes before execution

- Use `-WhatIf` when evaluating state-changing workflows.
- Start with one non-production target before operating on a larger list.
- Review the selected target count, action, and exact confirmation phrase.
- Confirm that backups, rollback procedures, and monitoring are appropriate for the intended change.
- Treat Windows Update, reboot, service, process, cleanup, custom CMD, and custom PowerShell actions as privileged operations.

## Remote administration

- Prefer WinRM with Kerberos or HTTPS according to your environment's security design.
- Do not weaken firewall, WinRM, TrustedHosts, or authentication policies solely to make the toolkit connect.
- Use a least-privileged administrative identity appropriate for the requested action.
- Use PsExec only when your organization permits its SMB and temporary-service model.

## Custom execution

Custom CMD commands and PowerShell code run as supplied with the privileges of the current session or remote identity. They are not sandboxed. Review custom content carefully and never execute untrusted code.

## Reports and logs

Reports may contain system inventory, user names, software lists, event details, or configuration data. Store, transmit, retain, and dispose of those reports according to your organization's requirements.

The software is provided under the MIT License without warranty. Operational responsibility remains with the administrator using it.
