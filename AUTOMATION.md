# Automation interface

Windows Admin Toolkit 2.1.0 can run one named action without menus, prompts, or credential UI. Automation mode uses the same 20 action implementations as the interactive menu and returns a versioned JSON result with a stable process exit code.

Use automation mode only in an already authorized Windows administration context. The toolkit does not enable WinRM, alter TrustedHosts, open firewall ports, bypass execution policy, or place passwords in process arguments.

## Basic contract

Every action run requires:

- `-Automation`
- `-Action <stable identifier>`
- Exactly one of `-Local`, `-ComputerName <target>`, or `-ComputerListPath <literal path>`
- `-JsonOutputPath -` or `-JsonOutputPath STDOUT` for JSON on stdout, or a new `.json` file path
- Any inputs required by the selected action
- The exact `-ConfirmationText` for an actual state-changing action

This local inventory command writes exactly one compressed JSON document to stdout:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -JsonOutputPath -
```

When a stdout destination is selected, stdout contains only JSON. Routine diagnostics go to the safe log. A destination-path error is returned as JSON on stderr because the requested file cannot be created safely. Use `STDOUT` when launching with `powershell.exe -File`; that host consumes a lone hyphen before script parameter binding. Omitting `JsonOutputPath` also selects stdout by default.

When a file path is selected, the toolkit resolves it as a literal path, requires a `.json` extension, creates the parent directory when permitted, writes UTF-8 without a byte-order mark, writes atomically, and refuses to overwrite an existing file. External file paths fail closed on control characters, wildcards, parent traversal, alternate data streams, Win32 device or named-pipe namespaces, overlong or trailing-dot segments, and Windows device names. `reportPaths` lists only files actually created by the run.

PowerShell performs native parameter binding before the script begins. Errors such as supplying nonnumeric text to an integer parameter are host-level binding failures. Well-typed requests that reach automation mode use the JSON envelope and exit-code contract documented below.

## Target selection

| Selector | Meaning |
| --- | --- |
| `-Local` | Run on the current Windows computer. Do not combine it with remote transport controls. |
| `-ComputerName server01.example.com` | Run on one validated hostname, FQDN, or canonical IPv4 address. |
| `-ComputerListPath C:\Ops\targets.txt` | Read a literal target-list file with one validated target per line. |

Target-list files must contain valid UTF-8 text and may contain blank lines and comments beginning with `#`. Targets are deduplicated case-insensitively in first-seen order. An invalid line fails the complete request. The built-in ceilings are 1 MiB and 500 unique targets. `PowerShellFile` inputs also require valid UTF-8 text and have a 1 MiB ceiling.

More than 25 targets require this additional exact authorization:

```powershell
-TargetListConfirmationText 'USE TARGET LIST'
```

Remote runs use WinRM by default. Available controls are:

| Parameter | Default | Allowed range or values |
| --- | --- | --- |
| `Transport` | `WinRM` | `WinRM`, `PsExec` |
| `Authentication` | `Default` | `Default`, `Kerberos`, `Negotiate` |
| `UseSsl` | Off | WinRM HTTPS on port 5986 |
| `WinRmIdentity` (`Credential` alias) | Current identity | In-memory `PSCredential` object; WinRM only |
| `MaxConcurrentJobs` | `8` | 1 through 32 |
| `RetryCount` | `1` | 0 through 3, read-only remote actions only |
| `RetryDelaySeconds` | `3` | 1 through 60 |
| `OperationTimeoutMinutes` | `30` | 1 through 180 |
| `ConnectivityTimeoutSeconds` | `5` | 1 through 60 |
| `SkipConnectivityCheck` | Off | Skips only the TCP preflight |

Automation mode rejects username strings for `WinRmIdentity` and its `Credential` alias so PowerShell cannot open credential UI during parameter binding. A calling PowerShell session may pass an already-created `PSCredential` object in memory. Native `powershell.exe -File` and `pwsh -File` command lines should run under the required Windows identity and must never contain a password.

The optional PsExec transport requires a Microsoft-signed Sysinternals PsExec 2.43 or newer executable, uses only the current Windows identity, and also requires:

```powershell
-PsExecConfirmationText 'USE PSEXEC'
```

## Stable action catalog

Action identifiers are case-insensitive on input and canonical in output. They are a public interface and are independent of menu position and display text.

| Identifier | Classification | Action inputs | Exact confirmation for execution |
| --- | --- | --- | --- |
| `SystemInfo` | Read-only | None | None |
| `DiskSpace` | Read-only | None | None |
| `HardwareInfo` | Read-only | None | None |
| `NetworkConfig` | Read-only | None | None |
| `LoggedOnUsers` | Read-only | None | None |
| `RunningProcesses` | Read-only | `TopCount` 1 through 100, default 20 | None |
| `SoftwareInventory` | Read-only | None | None |
| `LicenseStatus` | Read-only | None | None |
| `WindowsUpdate` | State-changing | Up to 100 optional `IncludeKB` values; empty selects all applicable software updates | `INSTALL UPDATES` |
| `ScheduleReboot` | State-changing | `RebootDelaySeconds` 30 through 3600, default 60 | `SCHEDULE REBOOT` |
| `PendingReboot` | Read-only | None | None |
| `ServiceManagement` | Conditional | Required `ServiceName`; `ServiceAction` is Query, Start, Stop, or Restart, default Query | `CHANGE SERVICE` for Start, Stop, or Restart |
| `TerminateProcess` | State-changing | Required exact `ProcessName`; protected Windows processes remain blocked | `TERMINATE PROCESS` |
| `ClearTempFiles` | State-changing | `MinimumAgeDays` 1 through 30, default 2; `MaximumFiles` 100 through 100000, default 50000 | `DELETE TEMP FILES` |
| `ScheduledTasks` | Read-only | `TaskPath`, default `\`; `MaximumTasks` 1 through 500, default 50 | None |
| `FirewallStatus` | Read-only | None | None |
| `EventLogQuery` | Read-only | `EventLogName`, default System; `EntryCount` 1 through 1000, default 20; `EventLevel` values Critical, Error, Warning, Information, or Verbose | None |
| `RegistryRead` | Read-only | Required `RegistryPath`; optional `RegistryValueName`, empty lists all values | None |
| `CustomCommand` | State-changing expert action | Required unsandboxed `CommandText`, maximum 32767 characters | `RUN COMMAND` |
| `CustomPowerShell` | State-changing expert action | Exactly one of unsandboxed `PowerShellText` or literal `.ps1` `PowerShellFile`; file maximum 1 MiB | `RUN SCRIPT` |

Enumerate the live catalog without executing an action:

```powershell
.\WindowsAdminToolkit.ps1 -Automation -ListActions -JsonOutputPath -
```

The returned `actions` array includes identifiers, display names, classifications, confirmation text, input types, defaults, allowed values, and numeric bounds. `-ListActions` accepts only the automation, catalog, and JSON destination controls.

## State-changing safety

Actual state-changing execution retains both safeguards:

1. PowerShell `ShouldProcess` approval remains effective. Automation mode rejects interactive `-Confirm` prompts and invokes the action with prompting disabled only after request authorization succeeds.
2. `-ConfirmationText` must match the action-specific value exactly, including case and spaces.

`-WhatIf` validates the complete request and returns a successful preview without connecting to or changing a target. Confirmation text is not required for a preview; if supplied, it must be exact. State-changing actions always use zero automatic retries.

Custom CMD and custom PowerShell remain unsandboxed expert actions. Their source text and returned output are excluded from logs, although their bounded output is present in the requested JSON result.

## Result schema

The machine contract is JSON Schema Draft 2020-12 in [`schemas/automation-result-v1.schema.json`](schemas/automation-result-v1.schema.json). Schema version `1.0` has 22 stable root fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion`, `toolkitVersion` | Result contract and toolkit versions |
| `runId` | Unique UUID for this invocation |
| `startedAtUtc`, `finishedAtUtc`, `durationMs` | UTC timestamps with millisecond precision and elapsed time |
| `actionId`, `actionName` | Canonical action identity, or null when the request cannot resolve a supported action |
| `readOnly`, `stateChanging` | Effective classification, including ServiceManagement Query behavior |
| `targetMode` | `Local`, `Remote`, or null before target resolution |
| `transport` | Canonical name, authentication mechanism, and SSL flag without secrets |
| `status`, `outcome`, `exitCode` | Overall machine-readable result |
| `targetCount`, `recordCount` | Requested targets and returned data records |
| `targets` | Deterministically ordered per-target status, timings, attempts, normalized error, and data array |
| `warnings`, `errors` | Safe summaries for incomplete, preview, and failed runs |
| `reportPaths` | JSON paths actually created |
| `actions` | Catalog descriptors for `-ListActions`, otherwise an empty array |

Arrays remain arrays even when empty or when they contain one item. Dates are formatted as `yyyy-MM-ddTHH:mm:ss.fffZ`. Credentials, secure strings, scriptblocks, raw exceptions, invocation details, and remoting metadata are excluded. Nested output is bounded to a safe serialization depth.

Examples for success, partial success, validation failure, timeout, `WhatIf`, and execution failure are in [`examples/automation/results`](examples/automation/results).

## Exit codes

| Code | Outcome | Meaning |
| ---: | --- | --- |
| 0 | `CompleteSuccess` | Every target succeeded, or a valid `WhatIf` preview completed |
| 1 | `PartialSuccess` | A multi-target run contains mixed success, partial, failure, or timeout results |
| 2 | `ValidationFailure` | Inputs, paths, targets, transport, or configuration are invalid |
| 3 | `AuthorizationFailure` | An exact confirmation or another authorization gate failed |
| 4 | `ExecutionFailure` | No target completed successfully and the run was not entirely timed out |
| 5 | `Timeout` | Every attempted target timed out |
| 10 | `InternalFailure` | The toolkit encountered an unhandled failure or best-effort cancellation |

If target execution finishes but the requested JSON sink fails afterward, the exit code is 10 and the fallback envelope is written to stderr. It preserves the completed target results, clears `reportPaths`, and warns the caller to review those results before retrying a state-changing action.

A failed target in a multi-target run is never reported as complete success. Unreachable targets use normalized `Connectivity` errors. Concurrent results are restored to validated input order before serialization.

A timeout means the toolkit stopped waiting for a definitive result; it does not prove that a remote operating-system operation was rolled back. Never manually retry a timed-out state-changing action until the target's actual state has been verified.

## Operational examples

Copy-pasteable WinRM, target-list, RMM, scheduled-task, CI, and `WhatIf` examples are in [`examples/automation/README.md`](examples/automation/README.md).
