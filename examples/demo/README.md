# Five-minute safe evaluation

This directory provides a deterministic first look at Windows Admin Toolkit without connecting to a system or executing an administration action.

The [JSON result](system-info-sample.json) is a synthetic schema 1.2 success envelope for three documentation-only `example.com` targets. The [HTML report](system-info-sample.html) is the matching flattened operator view. Both files are static samples, contain no real customer or environment data, and are clearly marked as synthetic.

## 1. Preview the outputs

```powershell
$sample = Get-Content -LiteralPath .\examples\demo\system-info-sample.json -Raw | ConvertFrom-Json
$sample | Select-Object actionId, outcome, exitCode, targetCount, durationMs
$sample.targets | Select-Object target, status, durationMs

Start-Process .\examples\demo\system-info-sample.html
```

This step only reads committed static files.

## 2. Inspect the action catalog

After completing the [signed installation](../../INSTALL.md), ask the toolkit for its stable action catalog:

```powershell
$toolkit = Join-Path $env:LOCALAPPDATA 'Programs\WindowsAdminToolkit\WindowsAdminToolkit.ps1'
& $toolkit -Automation -ListActions -JsonOutputPath -
```

Catalog discovery validates startup and enumerates action requirements. It does not select a target or execute an action.

## 3. Run a no-action capability preflight in a lab

Copy the synthetic read-only policy to a lab-controlled path, then assess a local read-only action:

```powershell
$toolkit = Join-Path $env:LOCALAPPDATA 'Programs\WindowsAdminToolkit\WindowsAdminToolkit.ps1'
$policy = Resolve-Path .\examples\policies\read-only-local.json

& $toolkit `
    -Automation `
    -Action SystemInfo `
    -Local `
    -PolicyPath $policy.Path `
    -Preflight `
    -JsonOutputPath -
```

Preflight validates the complete request and discovers whether the selected context has the required capability. It does not execute `SystemInfo`.

## 4. Cross the live-action boundary deliberately

Only after reviewing the catalog, policy decision, and preflight result should an authorized operator run a read-only action against an isolated lab machine:

```powershell
& $toolkit `
    -Automation `
    -Action SystemInfo `
    -Local `
    -PolicyPath $policy.Path `
    -JsonOutputPath -
```

Do not substitute a production RMM collection for this lab step. For managed deployment, stage the verified signed asset through the RMM content store, run under an approved Windows identity, retain the exact exit code, and begin with a restrictive policy. See the [RMM and scheduled-task examples](../automation/README.md) and [installation trust guide](../../INSTALL.md#controlled-rmm-or-msp-deployment).

## Interpreting the sample

- `outcome: CompleteSuccess` and `exitCode: 0` agree.
- `policy.decision: Allowed` records the evaluated least-privilege boundary.
- Every target has a stable opaque `targetId`, bounded timing, attempt count, normalized status, and an array of action data.
- The static report avoids credentials, custom source text, raw remoting metadata, and real customer identifiers.
- Real inventory and reports are administrative data. Protect and retain them according to the customer's policy.
