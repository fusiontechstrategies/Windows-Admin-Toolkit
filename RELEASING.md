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
  -OutputDirectory 'C:\ReleaseStaging\WindowsAdminToolkit-3.0.1'
```

An unsigned candidate is useful for reproducibility review, testing, and environments that apply signatures in a separate protected build service. It is not represented as a signed official artifact.

## Build and Authenticode-sign a candidate

Import or provision the release certificate outside this repository. It must be currently valid, have an accessible private key, include the Code Signing enhanced key usage, chain to trust on the build system, and be protected according to the organization's key-management policy.

```powershell
./tools/New-ReleaseArtifacts.ps1 `
  -OutputDirectory 'C:\ReleaseStaging\WindowsAdminToolkit-3.0.1-signed' `
  -CertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -CertificateStoreLocation CurrentUser `
  -TimestampServer 'http://timestamp.digicert.com'
```

Only the copied `WindowsAdminToolkit.ps1` is signed. Signing uses SHA-256 and requires a successful timestamp and a final local Authenticode status of `Valid`; otherwise the build fails visibly. Network access is used only for the timestamp request when signing is enabled. The tool never creates a certificate, exports a private key, installs a root, alters execution policy, registers trust, or publishes files.

Certificate identity and trust must also be checked by the release reviewer:

```powershell
$signature = Get-AuthenticodeSignature `
  'C:\ReleaseStaging\WindowsAdminToolkit-3.0.1-signed\WindowsAdminToolkit.ps1'

$signature | Select-Object Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

Authenticode proves which certificate signed the bytes and whether Windows currently trusts that signature. It does not prove that every toolkit operation is appropriate for a particular environment. Pin the expected publisher or certificate according to organizational policy.

### Rotate documented signer pins safely

The latest-release installers in `README.md` and `INSTALL.md` pin each approved signer as one tuple containing the exact full certificate subject, certificate thumbprint, and SHA-256 of `X509Certificate2.GetPublicKey()`. They also require trusted Authenticode status, a timestamp, and post-copy signature revalidation.

For a planned certificate renewal or replacement:

1. Independently validate the replacement certificate and protected key before using it.
2. Compute its tuple from a verified candidate, then add that complete tuple to both installers in one reviewed change. Do not maintain independent subject, thumbprint, or public-key allow lists that could match fields from different certificates.
3. Test both the current and replacement tuples under Windows PowerShell 5.1 and PowerShell 7.x while the current release is still latest.
4. Merge the dual-pin documentation before publishing the replacement-signed release, so the moving `releases/latest` URL remains usable throughout the transition.
5. Repeat the online installer, signature, timestamp, manifest, catalog, and installed-copy checks immediately after publication.
6. Remove the retired tuple only in a later reviewed change after rollout and rollback requirements permit it.

An unexpected signer tuple is a release blocker. Do not weaken the check to a common name, generic trust result, or execution-policy bypass.

## SHA-256 manifest

`SHA256SUMS.txt` covers every copied payload file plus `WindowsAdminToolkit.spdx.json`; it excludes itself because a file cannot contain its own stable hash. Paths use forward slashes and binary-mode marker syntax. The builder verifies the generated manifest before returning success.

Independent PowerShell verification:

```powershell
$root = 'C:\ReleaseStaging\WindowsAdminToolkit-3.0.1-signed'
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

## PowerShell Gallery candidate

The signed 3.0.0 release script does not contain the `PSScriptInfo` metadata required for a PowerShell Gallery script. Adding metadata would change its signed bytes. Never modify, re-sign, or publish a different script as version 3.0.0.

Prepare Gallery distribution only as part of a future versioned release:

1. Confirm that the intended Gallery name is available or controlled by the publisher. Do not publish a placeholder package to reserve it.
2. Update the canonical toolkit version and every version-bound schema, example, test, and document as one reviewed change.
3. Add a `PSScriptInfo` block before the comment-based help and before `#Requires`. It must include a matching semantic version, stable GUID, author, company, copyright, description, project URI, HTTPS license URI, release notes, and searchable Windows and PowerShell edition tags.
4. Run `Test-ScriptFileInfo` with the supported PowerShellGet baseline. When Microsoft.PowerShell.PSResourceGet is present, also run `Test-PSScriptFileInfo`. Treat a failure or metadata disagreement as a release blocker.
5. Run the complete Windows PowerShell 5.1 and PowerShell 7.x test suites and PSScriptAnalyzer before and after adding metadata.
6. Build and sign the normal release candidate. Re-run the metadata validators against the signed copy and confirm that the script version, release version, manifest, SBOM, and tag all agree.
7. Test `Publish-Script -WhatIf -Verbose` and a private local repository workflow without a production API key. Install the resulting package into an isolated current-user scope and repeat Authenticode, publisher, startup, catalog, preflight, and read-only smoke checks.
8. Obtain explicit publication approval. Keep the production Gallery API key outside source, logs, command history, and build artifacts.
9. After publication, use `Save-Script` or `Install-Script` from an isolated machine, verify the retrieved script's Authenticode signature and publisher, and compare it with the approved release script. Record the Gallery owner, package URL, version, and validation evidence.

Microsoft's current guidance requires script metadata and pre-validation, recommends signing and testing through a local repository, and notes that published packages cannot be casually deleted. Review the official [publishing workflow](https://learn.microsoft.com/powershell/gallery/how-to/publishing-packages/publishing-a-package), [publishing guidelines](https://learn.microsoft.com/powershell/gallery/concepts/publishing-guidelines), and current PowerShellGet or PSResourceGet command documentation again at release time.

## Publication discipline

- Keep work for the next release on a dedicated branch and use small reviewable commits.
- Never move or replace a public version tag.
- Never commit private keys, certificate exports, timestamp credentials, build output, real hostnames, or production change plans.
- Use synthetic examples and inspect packaged files for secrets before upload.
- Retain the commit ID, signed script, manifest, SBOM, test results, and release-channel audit evidence together.
- Treat any signature, manifest, SBOM, or provenance discrepancy as a release blocker.
