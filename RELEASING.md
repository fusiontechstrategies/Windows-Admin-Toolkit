# Release integrity

Windows Admin Toolkit releases are built from a reviewed clean commit. Publishing, tagging, certificate enrollment, trust configuration, and secret management remain explicit maintainer actions; the repository does not perform them automatically.

## Required release checks

Before creating a tag or public release:

1. Review the complete diff and confirm the documented version and schemas.
2. Run `tests/Run-Tests.ps1` under Windows PowerShell 5.1 and PowerShell 7.x.
3. Run PSScriptAnalyzer with `PSScriptAnalyzerSettings.psd1` and require zero findings.
4. Validate every committed JSON example against its Draft 2020-12 schema.
5. Run the release builder into a new directory outside the repository.
6. Verify Authenticode status when signing is requested, then independently verify every SHA-256 manifest entry and inspect the SPDX SBOM.
7. Create the annotated tag only after the candidate artifacts match the reviewed commit.

Do not rebuild a published version with different bytes. Correct a release with a new version.

## Build an unsigned candidate

The release builder copies an explicit allowlist of source, documentation, schema, example, test, and tool files. It never modifies or signs the repository copy. The destination parent must exist and the destination itself must not.

```powershell
./tools/New-ReleaseArtifacts.ps1 `
  -OutputDirectory 'C:\ReleaseStaging\WindowsAdminToolkit-3.0.0'
```

An unsigned candidate is useful for reproducibility review, testing, and environments that apply signatures in a separate protected build service. It is not represented as a signed official artifact.

## Build and Authenticode-sign a candidate

Import or provision the release certificate outside this repository. It must be currently valid, have an accessible private key, include the Code Signing enhanced key usage, chain to trust on the build system, and be protected according to the organization's key-management policy.

```powershell
./tools/New-ReleaseArtifacts.ps1 `
  -OutputDirectory 'C:\ReleaseStaging\WindowsAdminToolkit-3.0.0-signed' `
  -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -CertificateStoreLocation CurrentUser `
  -TimestampServer 'http://timestamp.digicert.com'
```

Only the copied `WindowsAdminToolkit.ps1` is signed. Signing uses SHA-256 and requires a successful timestamp and a final local Authenticode status of `Valid`; otherwise the build fails visibly. Network access is used only for the timestamp request when signing is enabled. The tool never creates a certificate, exports a private key, installs a root, alters execution policy, registers trust, or publishes files.

Certificate identity and trust must also be checked by the release reviewer:

```powershell
$signature = Get-AuthenticodeSignature `
  'C:\ReleaseStaging\WindowsAdminToolkit-3.0.0-signed\WindowsAdminToolkit.ps1'

$signature | Select-Object Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

Authenticode proves which certificate signed the bytes and whether Windows currently trusts that signature. It does not prove that every toolkit operation is appropriate for a particular environment. Pin the expected publisher or certificate according to organizational policy.

## SHA-256 manifest

`SHA256SUMS.txt` covers every copied payload file plus `WindowsAdminToolkit.spdx.json`; it excludes itself because a file cannot contain its own stable hash. Paths use forward slashes and binary-mode marker syntax. The builder verifies the generated manifest before returning success.

Independent PowerShell verification:

```powershell
$root = 'C:\ReleaseStaging\WindowsAdminToolkit-3.0.0-signed'
foreach ($line in Get-Content (Join-Path $root 'SHA256SUMS.txt')) {
  if ($line -notmatch '^(?<hash>[0-9a-f]{64}) \*(?<path>.+)$') { throw "Bad line: $line" }
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $root $Matches.path)).Hash
  if ($actual -cne $Matches.hash.ToUpperInvariant()) { throw "Mismatch: $($Matches.path)" }
}
```

Publish the manifest through the same authenticated release channel as the artifacts. A hash downloaded from the same compromised location as a replaced file is not an independent trust anchor; verify the release signature and channel identity too.

## SPDX software bill of materials

`WindowsAdminToolkit.spdx.json` uses SPDX 2.3 JSON and enumerates the exact copied payload before the SBOM and manifest are added. It records SHA-1 only where the SPDX 2.3 package verification-code algorithm requires it; file identity and release integrity are also recorded and enforced with SHA-256. The SBOM contains no runtime inventory, credentials, host data, or dependency download.

Review the SBOM for the expected toolkit version, payload list, checksums, license, package verification code, and unique document namespace. Consumers may ingest it into their normal software-composition and release-evidence systems.

## Publication discipline

- Keep work for the next release on a dedicated branch and use small reviewable commits.
- Never move or replace a public version tag.
- Never commit private keys, certificate exports, timestamp credentials, build output, real hostnames, or production change plans.
- Use synthetic examples and inspect packaged files for secrets before upload.
- Retain the commit ID, signed script, manifest, SBOM, test results, and release-channel audit evidence together.
- Treat any signature, manifest, SBOM, or provenance discrepancy as a release blocker.
