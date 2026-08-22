# Policy profiles and least privilege

Windows Admin Toolkit 2.3.0 supports optional JSON policy profiles for both automation and interactive runs. A profile narrows what the toolkit may do. It never grants Windows permissions, relaxes a built-in safety ceiling, replaces `ShouldProcess`, or replaces an exact confirmation phrase.

The public policy contract is JSON Schema Draft 2020-12 in [`schemas/policy-profile-v1.schema.json`](schemas/policy-profile-v1.schema.json). The current `schemaVersion` is `1.0`.

## Apply a profile

Use a literal `.json` path:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -PolicyPath .\examples\policies\read-only-local.json `
  -JsonOutputPath -
```

Interactive mode accepts the same `-PolicyPath` parameter and filters each selected target context and action before execution. The menu remains unchanged when no profile is supplied.

To inspect action decisions without executing an action:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -ListActions `
  -PolicyPath .\examples\policies\read-only-local.json `
  -JsonOutputPath -
```

Each catalog entry includes `policyDecision` and `policyReasonCode`.

## Profile structure

Every profile must define:

- `schemaVersion`: exactly `1.0`
- `profileName`: a stable operator-readable name
- `actions.allow`: one or more canonical action identifiers
- `transports.allow`: one or more of `Local`, `WinRM`, or `PsExec`
- `targetModes.allow`: one or both of `Local` and `Remote`
- `targets.allow`: approved remote targets or patterns; it may be empty only when remote execution is not possible

Optional `deny` arrays take precedence over broader allow rules. Optional `limits` and `actionInputs` narrow runtime values and action inputs.

Allowed target modes and transport classes must align exactly: `Local` mode pairs with `Local` transport, while `Remote` mode pairs with one or both of `WinRM` and `PsExec`. A profile without remote execution must leave both target arrays empty. The parser rejects inert or contradictory rules instead of guessing intent.

The parser accepts only strict UTF-8 JSON in a literal `.json` file no larger than 1 MiB. It rejects duplicate or case-conflicting property names, unsupported properties, incorrectly cased schema keys and public identifiers, invalid values, empty required allow lists, conflicting rules, unsupported execution combinations, and constraints for actions that are not effectively allowed. Profiles contain no credential fields.

## Target rules

A target rule is either:

- One exact validated hostname, FQDN, or canonical IPv4 address, such as `server01.example.com`
- One leading star-dot DNS suffix, such as `*.example.com`

No other wildcard position is accepted. A suffix pattern is compared directly and case-insensitively. It does not perform DNS queries, expand into a target list, match the suffix root itself, or cross the literal suffix boundary. For example, `*.example.com` matches `server01.example.com` but not `example.com` or `server01.example.net`.

Target deny rules are evaluated before target allow rules. Local computer names are not compared with remote target patterns; local access is controlled by `targetModes` and `transports`.

## Precedence and limits

An automation request is determined in fail-closed phases:

1. PowerShell binding, automation output-destination preflight, strict profile loading, runtime configuration, action identity, and absolute built-in ceilings
2. Early policy action decisions, before target-selector or action-source file reads
3. Built-in action-input compatibility and target-selector structure validation
4. Early policy target-mode and transport decisions, before target-list or PsExec file reads
5. Remaining built-in target entry or list validation
6. Policy target and target-count decisions, before large-list authorization, PsExec validation, or custom-source reads
7. Remaining built-in transport-authorization, PsExec, and action-input validation
8. Policy runtime-cap and action-input decisions
9. Existing exact action confirmations, `ShouldProcess`, and Windows authorization on the selected host or endpoint

Built-in ceilings are absolute. A profile can make a limit smaller but cannot make it larger. If an operator explicitly supplies a runtime value above the policy cap, the request is denied with exit code 3. If the operator omits the value, the toolkit uses the smaller of its configured default and the policy cap.

| Limit | Built-in ceiling |
| --- | ---: |
| Targets | 500 |
| Concurrent jobs | 32 |
| Read-only retries | 3 |
| Retry delay | 60 seconds |
| Operation timeout | 180 minutes |
| Connectivity timeout | 60 seconds |

State-changing actions still receive zero automatic retries. More than 25 targets still require the exact `USE TARGET LIST` authorization even when a policy permits a larger target count. PsExec still requires the exact `USE PSEXEC` authorization and all signer, product, version, identity, and transport checks.

## Action-input constraints

Profiles can narrow supported integer ranges, string lengths, array sizes, and approved values for selected action inputs. The policy schema lists every supported action and constraint. Built-in action validation runs first, so a policy cannot authorize an otherwise invalid value.

Schema keys, action identifiers, and transport names use their documented casing. Approved Windows resource values such as service names are compared case-insensitively because Windows resolves those resources case-insensitively. Enumerated inputs are canonicalized before policy evaluation.

Custom CMD and custom PowerShell policy constraints can limit source length or deny the actions entirely. Policy does not sandbox operator-supplied content.

## Decisions and exit behavior

Result schema version `1.2` includes a required `policy` object:

| Field | Meaning |
| --- | --- |
| `applied` | Whether a profile was supplied |
| `schemaVersion` | Validated policy schema version, or `null` |
| `profileName` | Validated profile name, or `null` |
| `decision` | `NotApplied`, `NotEvaluated`, `Allowed`, `Denied`, or `Invalid` |
| `reasonCode` | Stable machine-readable reason |
| `reason` | Safe operator-readable explanation |

A malformed or unsupported profile is a validation failure with exit code 2 and decision `Invalid`. A valid policy denial is an authorization failure with exit code 3 and decision `Denied`. An allowed request records decision `Allowed`. Without `-PolicyPath`, the result records `NotApplied` and preserves the previous automation behavior.

In automation mode, policy-denied actions stop before target connections or action execution. A known denied action stops before target-list import or custom action-file reading. A denied target mode or transport stops before target-list import or PsExec authorization and executable validation. Resolved target names and target count are checked before large-list authorization, PsExec validation, or custom-source reading.

Interactive mode applies the same decisions around its prompts. It checks the selected mode and transport before requesting remote target input, then checks the resolved target names and count after target entry or import but before PsExec validation or TCP connectivity checks. After an allowed target context is prepared, it checks each selected action before action-specific prompts or execution.

## Capability preflight

Use `-Preflight` with a normal automation action request:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action EventLogQuery `
  -ComputerName server01.example.com `
  -PolicyPath .\examples\policies\helpdesk-winrm.json `
  -EventLogName System `
  -EntryCount 50 `
  -Preflight `
  -JsonOutputPath -
```

Preflight evaluates the complete request and policy, checks connectivity when enabled, enters the selected execution context, and reports required commands, executables, COM components, administrator status, PowerShell edition and version, and language mode. It does not execute the requested action. The result sets `preflight` to `true` and includes the assessment in each target's `data` array.

`-Preflight` and `-WhatIf` are mutually exclusive. Preflight does not require a missing state-change confirmation because no requested action is executed, but an incorrect supplied confirmation still fails closed. Custom-action preflight can verify the wrapper environment only; it cannot infer dependencies inside operator-supplied code.

## JEA-oriented deployment guidance

Just Enough Administration is configured outside this toolkit. The toolkit never creates, changes, or weakens a JEA endpoint.

For a JEA deployment:

1. Create a dedicated endpoint for a narrow role instead of exposing a general administration endpoint.
2. Allow only the toolkit file path, the selected stable actions, and the commands those actions require. Use `-Preflight` to inventory requirements from the actual endpoint identity.
3. Prefer a virtual account or a managed service identity appropriate to the approved resources. Do not place credentials in a policy profile or command line.
4. Restrict readable target-list, policy, custom-source, log, and result paths with NTFS access control. Operators who can edit a profile can change its allow rules within built-in ceilings.
5. Configure endpoint quotas, transcripts, module visibility, and language mode deliberately. Test both read-only and guarded state-changing paths in a nonproduction environment.
6. Keep exact confirmation phrases and `ShouldProcess` in the calling workflow. JEA authorization is an additional boundary, not a replacement.

WinRM can target an appropriately registered JEA endpoint only when the surrounding session configuration and caller setup select it. The toolkit does not currently add a session-configuration-name parameter. PsExec does not enter a JEA endpoint and should not be treated as JEA-compatible delegation.

## Protect policy files

Treat a policy profile as security configuration:

- Grant write access only to the identities that administer the policy.
- Grant read access only to identities that run the toolkit when the profile reveals sensitive naming conventions.
- Review changes through source control or another auditable configuration process.
- Use synthetic values in public examples.
- Never add passwords, tokens, private keys, or credential material.

The committed examples are [`read-only-local.json`](examples/policies/read-only-local.json) and [`helpdesk-winrm.json`](examples/policies/helpdesk-winrm.json).
