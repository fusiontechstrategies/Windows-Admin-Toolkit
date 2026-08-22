# Enterprise auditability

Windows Admin Toolkit 3.0.0 retains the 2.3 opt-in, machine-readable audit contract for direct automation runs. Audit output is designed for SIEM, RMM, ticketing, and change-review pipelines without changing the toolkit's authorization model or silently modifying Windows configuration.

Auditing does not grant access, configure remoting, register an Event Log source, replace a policy decision, replace `ShouldProcess`, or replace an exact confirmation phrase.

## Enable a per-run JSON Lines audit

Supply a new literal `.jsonl` path:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -AuditPath C:\Audit\wat-system-info-20260822.jsonl `
  -JsonOutputPath C:\Results\wat-system-info-20260822.json
```

`AuditPath` is optional and is valid only with `-Automation`. The toolkit:

- Resolves the destination as a literal path
- Requires the `.jsonl` extension
- Refuses stdout, wildcards, traversal, alternate data streams, device paths, and unsafe Windows path components
- Refuses an existing file instead of appending or overwriting it
- Refuses a collision with the requested JSON result path or safe text log
- Creates a missing parent directory when permitted
- Writes UTF-8 without a byte-order mark
- Flushes each record and checks that the file length has not changed unexpectedly

Each invocation uses a separate file. The toolkit does not rotate, truncate, rename, delete, or share audit files. A per-run hard limit of 16 MiB prevents unbounded growth. Retention, archival, access control, and rotation across completed per-run files belong to the operator or collecting platform.

## Optional Windows Event Log forwarding

Windows Event Log forwarding is off by default. Enable it only when an administrator has already registered an approved source:

```powershell
.\WindowsAdminToolkit.ps1 `
  -Automation `
  -Action SystemInfo `
  -Local `
  -AuditEventLog `
  -AuditEventSource WindowsAdminToolkit `
  -JsonOutputPath -
```

The toolkit validates the source and writes bounded JSON audit records through it. It never calls `New-EventLog`, creates a source, changes a log's access control, increases log size, changes retention, or weakens Event Log configuration. Source registration is an external deployment decision that should be handled under normal change control.

`AuditEventSource` is accepted only with `-AuditEventLog`. When both `AuditPath` and `AuditEventLog` are supplied, every record must reach both configured sinks for the composite audit write to count as successful.

## Audit event contract

Each nonblank line is one independent JSON object conforming to Draft 2020-12 schema [`schemas/audit-event-v1.schema.json`](schemas/audit-event-v1.schema.json). Audit schema version `1.0` uses these event types:

| Event type | Meaning |
| --- | --- |
| `run.started` | The audit sink was initialized before request or target execution |
| `request.resolved` | The request was resolved or its safe failure was captured |
| `policy.decision` | The explicit policy state and reason code were recorded |
| `target.started` | An authorized target entered connectivity or execution work |
| `target.completed` | A target reached a bounded terminal status |
| `audit.failure` | A post-execution machine-output delivery failure changed the final run outcome |
| `run.summary` | Counts, final outcome, exit code, and summary hash were recorded |

Every record contains:

- Audit schema and toolkit versions
- A unique run UUID and monotonically increasing sequence number
- An event ID formed as `<run UUID>:<six-digit sequence>`
- A UTC timestamp with millisecond precision
- A normalized lifecycle stage and outcome
- The canonical action ID when one was resolved
- A stable target identity when the event is target-specific
- A bounded normalized error when relevant
- An explicit policy object on policy and summary events

Arrays and raw action output are never written to the audit stream. A `target.started` record is flushed before connectivity or requested-action execution begins. Target completion records use the final target timestamps, durations, attempts, status, and normalized error category.

For a normal one-target run, the sequence is:

```text
run.started
request.resolved
policy.decision
target.started
target.completed
run.summary
```

If delivery to the requested JSON result destination fails after target execution, the audit stream appends `audit.failure` and a replacement `run.summary`. The highest-sequence `run.summary` is authoritative.

## Run IDs and stable target IDs

`runId` is a new UUID for each invocation. The same value appears in the result envelope and every audit event.

`targetId` is stable across runs for the same validated Windows target name. It is calculated as:

1. Uppercase the canonical validated target name using invariant rules.
2. Prefix it with the ASCII domain separator `WAT-TARGET-1|`.
3. Compute SHA-256 over the UTF-8 bytes without a byte-order mark.
4. Use the first 24 lowercase hexadecimal characters and prefix them with `t-`.

The target name remains present for operators and collectors. The identifier supplies a stable join key; it is not an anonymization mechanism or an authentication claim.

## Tamper-evident run-summary hash

Every completed audit stream ends in a `run.summary` record containing:

- Overall status, outcome, and exit code
- Target and returned-record counts
- Counts for success, partial, failed, timed-out, skipped, and `WhatIf` targets
- Final audit record count
- `hashAlgorithm: SHA-256`
- `canonicalization: WAT-AUDIT-SUMMARY-1`
- A 64-character lowercase `summaryHash`

`WAT-AUDIT-SUMMARY-1` hashes a bounded summary payload rather than raw action data. The payload contains the audit and toolkit versions, run and action identity, UTC run timing, target mode, transport, explicit policy decision metadata, final status/outcome/exit code, target and returned-record counts, final audit record count, and an input-ordered array of target identities, timings, attempts, terminal statuses, and normalized error categories.

Canonicalization rules are:

1. Sort every object property name by ordinal Unicode code-unit order.
2. Preserve array order.
3. Encode object names and string values as JSON strings.
4. Escape quotation mark, reverse solidus, JSON control characters, and every non-ASCII UTF-16 code unit. Unicode escapes use lowercase four-digit hexadecimal.
5. Encode integers in invariant base-10 form without leading zeros.
6. Encode booleans as `true` or `false` and null as `null`.
7. Reject non-finite numbers and nesting deeper than the documented internal bound.
8. Emit no insignificant whitespace.
9. Compute SHA-256 over the canonical ASCII JSON bytes encoded as UTF-8 without a byte-order mark.
10. Encode the digest as lowercase hexadecimal.

The hash detects changes to the summarized run evidence. It is not a digital signature, does not identify who ran the toolkit, and cannot prevent an attacker who can replace both the audit file and its external reference from recomputing a new hash. Store completed files and expected hashes in an access-controlled external system when stronger evidence retention is required.

## Result-envelope audit metadata

Automation result schema version `1.2` includes a required `audit` object:

| Field | Meaning |
| --- | --- |
| `enabled` | At least one audit sink was explicitly requested |
| `schemaVersion` | `1.0` when enabled, otherwise null |
| `path` | Resolved per-run JSONL path, or null |
| `eventLog`, `eventSource` | Event Log forwarding state without configuration changes |
| `recordCount` | Records successfully delivered to every configured sink |
| `complete` | A final authoritative summary reached every configured sink |
| `hashAlgorithm`, `canonicalization`, `summaryHash` | Hash metadata for a complete audit |

Every target result also includes its stable `targetId`.

## Safe failure behavior

Audit configuration is validated before target work. An unsafe path, existing file, path collision, unsupported source name, or missing Event Log registration returns validation exit code 2 without executing the requested action.

If a configured sink fails after initialization, the toolkit returns internal failure exit code 10. Completed target evidence is preserved in the result envelope, `audit.complete` is false unless a later authoritative failure summary reached every sink, and the warning explicitly tells the operator to inspect target state before retrying a state-changing action.

An audit failure never changes an unsuccessful run into success. A timeout still means the underlying remote operation may have continued after the toolkit stopped waiting.

## Data minimization

Audit records intentionally exclude:

- Credentials, passwords, secure strings, and alternate-identity material
- Custom CMD or PowerShell source text
- Raw custom-command output and raw action data
- Scriptblocks, raw exceptions, invocation information, and remoting metadata
- Target-list file contents and action-specific input payloads

Audit records may contain target names, policy profile names, action IDs, statuses, timings, and bounded normalized errors. Protect audit files accordingly.

The synthetic result and JSON Lines examples are in [`examples/automation/results/audited-success.json`](examples/automation/results/audited-success.json) and [`examples/audit/audited-success.jsonl`](examples/audit/audited-success.jsonl).

Controlled plan operations do not accept `AuditPath`, `AuditEventLog`, or `AuditEventSource` in orchestration schema 1.0. Their approved plan, result, and atomic checkpoint are recovery and change evidence, but they are not substitutes for this direct-run audit stream or an external change-system audit trail. Retain plan artifacts, checkpoint history, ordinary logs, result envelopes, and external approval evidence together as described in [ORCHESTRATION.md](ORCHESTRATION.md).
