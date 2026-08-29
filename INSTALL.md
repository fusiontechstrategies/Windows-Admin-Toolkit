# Installation and release trust

The official executable distribution of Windows Admin Toolkit is the Authenticode-signed `WindowsAdminToolkit.ps1` asset attached to the GitHub release. The complete signed ZIP contains the same signed script plus documentation, schemas, examples, tests, release tooling, a SHA-256 manifest, and an SPDX 2.3 SBOM.

Repository clones and GitHub-generated source archives are useful for review and contribution, but they are not signed release assets.

## Verified current-user installation

The following block downloads the latest standalone script and its release manifest into a new temporary directory. It verifies the manifest entry, file hash, Windows Authenticode trust, and publisher identity. It then validates a unique candidate in the installation directory before using an atomic move for a first install or an atomic replacement with automatic rollback for an update.

```powershell
$releaseRoot = 'https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/releases/latest/download'
$installDirectory = Join-Path $env:LOCALAPPDATA 'Programs\WindowsAdminToolkit'
$installedScript = Join-Path $installDirectory 'WindowsAdminToolkit.ps1'
$stagingDirectory = Join-Path ([IO.Path]::GetTempPath()) ("wat-install-$([guid]::NewGuid().ToString('N'))")
$stagedScript = Join-Path $stagingDirectory 'WindowsAdminToolkit.ps1'
$stagedManifest = Join-Path $stagingDirectory 'SHA256SUMS.txt'

function Test-WatReleaseSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $approvedSigners = @(
        [pscustomobject]@{
            Subject = 'CN="Fusion Technology Strategies, Inc.", O="Fusion Technology Strategies, Inc.", L=Ormond Beach, S=Florida, C=US, SERIALNUMBER=P15000091612, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Florida, OID.1.3.6.1.4.1.311.60.2.1.3=US'
            Thumbprint = '44BB10D1C4ACB6B8A043BA136AE5442BEFD47131'
            PublicKeySha256 = '9ABCB20E3D546C2F2D0973AA98DC6E503387E88462EC9F9E5FD5DC5047A65275'
        }
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $LiteralPath
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
        throw "Authenticode verification failed: $($signature.StatusMessage)"
    }

    $certificate = $signature.SignerCertificate
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $publicKeySha256 = ([BitConverter]::ToString($sha256.ComputeHash($certificate.GetPublicKey())) -replace '-', '')
    }
    finally {
        $sha256.Dispose()
    }

    $matchingSigners = @(
        $approvedSigners | Where-Object {
            $_.Subject -ceq $certificate.Subject -and
            $_.Thumbprint -ceq $certificate.Thumbprint -and
            $_.PublicKeySha256 -ceq $publicKeySha256
        }
    )
    if ($matchingSigners.Count -ne 1) {
        throw "The signer certificate is valid but is not an approved release identity. Subject: $($certificate.Subject); thumbprint: $($certificate.Thumbprint); public-key SHA-256: $publicKeySha256"
    }
    if (-not $signature.TimeStamperCertificate) {
        throw 'The Authenticode signature does not contain a timestamp certificate.'
    }

    return $signature
}

function Install-WatVerifiedScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256
    )

    $sourceFullPath = [IO.Path]::GetFullPath($SourcePath)
    $destinationFullPath = [IO.Path]::GetFullPath($DestinationPath)
    $normalizedExpectedHash = $ExpectedSha256.ToUpperInvariant()
    if ($normalizedExpectedHash -cnotmatch '^[0-9A-F]{64}$') {
        throw 'The expected SHA-256 value is not canonical.'
    }

    $validatePayload = {
        param([string]$LiteralPath)

        if (-not [IO.File]::Exists($LiteralPath)) {
            throw "The file to validate does not exist: $LiteralPath"
        }
        $actualHash = (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -cne $normalizedExpectedHash) {
            throw "SHA-256 mismatch. Expected $normalizedExpectedHash; received $actualHash."
        }
        [void](Test-WatReleaseSignature -LiteralPath $LiteralPath)
    }

    & $validatePayload $sourceFullPath

    $destinationDirectory = [IO.Path]::GetDirectoryName($destinationFullPath)
    if ([string]::IsNullOrWhiteSpace($destinationDirectory)) {
        throw 'The installation path has no parent directory.'
    }
    [void](New-Item -ItemType Directory -Path $destinationDirectory -Force -ErrorAction Stop)

    $operationId = [guid]::NewGuid().ToString('N')
    $candidatePath = Join-Path $destinationDirectory ".WindowsAdminToolkit-$operationId.candidate.ps1"
    $rollbackPath = Join-Path $destinationDirectory ".WindowsAdminToolkit-$operationId.rollback.ps1"

    try {
        [IO.File]::Copy($sourceFullPath, $candidatePath, $false)
        Unblock-File -LiteralPath $candidatePath -ErrorAction Stop
        & $validatePayload $candidatePath

        if ([IO.File]::Exists($destinationFullPath)) {
            try {
                [IO.File]::Replace($candidatePath, $destinationFullPath, $rollbackPath)
            }
            catch {
                if ([IO.File]::Exists($rollbackPath)) {
                    throw "Atomic replacement failed. The recovery copy remains at '$rollbackPath'. $($_.Exception.Message)"
                }
                throw
            }

            try {
                & $validatePayload $destinationFullPath
            }
            catch {
                $verificationError = $_
                try {
                    if (-not [IO.File]::Exists($rollbackPath)) {
                        throw 'The rollback copy is missing.'
                    }
                    if ([IO.File]::Exists($destinationFullPath)) {
                        [IO.File]::Replace($rollbackPath, $destinationFullPath, $candidatePath)
                    }
                    else {
                        [IO.File]::Move($rollbackPath, $destinationFullPath)
                    }
                }
                catch {
                    throw "The promoted file failed verification and automatic rollback failed. The recovery copy, if available, remains at '$rollbackPath'. Verification error: $($verificationError.Exception.Message) Rollback error: $($_.Exception.Message)"
                }
                throw $verificationError
            }

            if ([IO.File]::Exists($rollbackPath)) {
                [IO.File]::Delete($rollbackPath)
            }
        }
        else {
            [IO.File]::Move($candidatePath, $destinationFullPath)
            try {
                & $validatePayload $destinationFullPath
            }
            catch {
                $verificationError = $_
                try {
                    [IO.File]::Move($destinationFullPath, $candidatePath)
                }
                catch {
                    throw "The first installation failed verification and could not be removed safely. Verification error: $($verificationError.Exception.Message) Cleanup error: $($_.Exception.Message)"
                }
                throw $verificationError
            }
        }
    }
    finally {
        if ([IO.File]::Exists($candidatePath)) {
            [IO.File]::Delete($candidatePath)
        }
    }
}

[void](New-Item -ItemType Directory -Path $stagingDirectory)
try {
    Invoke-WebRequest -Uri "$releaseRoot/WindowsAdminToolkit.ps1" -UseBasicParsing -OutFile $stagedScript
    Invoke-WebRequest -Uri "$releaseRoot/SHA256SUMS.txt" -UseBasicParsing -OutFile $stagedManifest

    $scriptEntries = @(
        Get-Content -LiteralPath $stagedManifest |
            Where-Object { $_ -cmatch '^[0-9a-f]{64} \*WindowsAdminToolkit\.ps1$' }
    )
    if ($scriptEntries.Count -ne 1) {
        throw 'The release manifest does not contain exactly one canonical toolkit entry.'
    }

    $expectedHash = $scriptEntries[0].Substring(0, 64).ToUpperInvariant()
    [void](Install-WatVerifiedScript -SourcePath $stagedScript -DestinationPath $installedScript -ExpectedSha256 $expectedHash)
}
finally {
    if ([IO.Directory]::Exists($stagingDirectory)) {
        [IO.Directory]::Delete($stagingDirectory, $true)
    }
}

& $installedScript -Automation -ListActions -JsonOutputPath -
```

The hash manifest and script are delivered through the same GitHub release channel, so the hash is an integrity check rather than an independent trust anchor. The installer separately requires a trusted Authenticode result, a timestamp, and one complete approved signer tuple: full certificate subject, exact certificate thumbprint, and SHA-256 of the public-key bytes. It validates the staged file, a unique same-directory candidate, and the promoted destination. Existing installs use an atomic replacement with a unique rollback file; a failed destination check restores the previous bytes atomically. First installs use an atomic same-directory move and remove the destination if its final check fails. An enterprise may additionally enforce the approved publisher through its own application-control policy.

## Verify an existing installation

Run this check before an RMM job or scheduled task if local modification is a concern:

```powershell
$installedScript = Join-Path $env:LOCALAPPDATA 'Programs\WindowsAdminToolkit\WindowsAdminToolkit.ps1'
$expectedSubject = 'CN="Fusion Technology Strategies, Inc.", O="Fusion Technology Strategies, Inc.", L=Ormond Beach, S=Florida, C=US, SERIALNUMBER=P15000091612, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Florida, OID.1.3.6.1.4.1.311.60.2.1.3=US'
$expectedThumbprint = '44BB10D1C4ACB6B8A043BA136AE5442BEFD47131'
$expectedPublicKeySha256 = '9ABCB20E3D546C2F2D0973AA98DC6E503387E88462EC9F9E5FD5DC5047A65275'
$signature = Get-AuthenticodeSignature -LiteralPath $installedScript
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) {
    throw "Toolkit trust verification failed: $($signature.StatusMessage)"
}

$certificate = $signature.SignerCertificate
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    $publicKeySha256 = ([BitConverter]::ToString($sha256.ComputeHash($certificate.GetPublicKey())) -replace '-', '')
}
finally {
    $sha256.Dispose()
}

if (
    $certificate.Subject -cne $expectedSubject -or
    $certificate.Thumbprint -cne $expectedThumbprint -or
    $publicKeySha256 -cne $expectedPublicKeySha256 -or
    -not $signature.TimeStamperCertificate
) {
    throw 'The installed toolkit does not match the complete approved signer identity.'
}
```

The installer and verification commands do not change execution policy. The effective execution policy, WDAC policy, AppLocker policy, and other application controls must still allow this trusted signed script. If organizational policy blocks it, use the organization's approved policy-change or exception process. Do not add an execution-policy bypass.

## Controlled RMM or MSP deployment

Use a staged rollout rather than having every endpoint fetch from the internet:

1. Download the release once in a controlled acquisition environment.
2. Verify the SHA-256 manifest, Authenticode status, expected publisher, timestamp, release notes, and SBOM.
3. Place the verified script in the RMM platform's protected content store or software repository.
4. Deploy it to a fixed path such as `C:\ProgramData\WindowsAdminToolkit\WindowsAdminToolkit.ps1` with write access limited to approved administrators and the deployment service.
5. Verify the endpoint copy again before execution.
6. Begin with `-ListActions`, a restrictive policy, and `-Preflight` in a lab collection. Move to a read-only action only after the preflight evidence is reviewed.
7. Run the RMM job under its approved Windows identity. Do not place usernames, passwords, API keys, or serialized credentials in command text.
8. Capture stdout JSON, the exact process exit code, and, when required, a unique per-run audit file. Treat every nonzero exit code as requiring review.

Example local preflight from an RMM agent, without executing the requested action:

```powershell
$ErrorActionPreference = 'Stop'
$toolkit = 'C:\ProgramData\WindowsAdminToolkit\WindowsAdminToolkit.ps1'
$enginePath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

if (-not [IO.File]::Exists($toolkit)) {
    [Console]::Error.WriteLine("Windows Admin Toolkit was not found: $toolkit")
    exit 10
}
if (-not [IO.File]::Exists($enginePath)) {
    [Console]::Error.WriteLine("The required child PowerShell executable was not found: $enginePath")
    exit 10
}

$childArguments = @(
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-File',
    $toolkit,
    '-Automation',
    '-Action',
    'SystemInfo',
    '-Local',
    '-PolicyPath',
    'C:\ProgramData\WindowsAdminToolkit\Policies\read-only-local.json',
    '-Preflight',
    '-JsonOutputPath',
    'STDOUT'
)

try {
    $LASTEXITCODE = $null
    & $enginePath @childArguments
    $childExitCode = $LASTEXITCODE
}
catch {
    [Console]::Error.WriteLine("Windows Admin Toolkit could not be started: $($_.Exception.Message)")
    exit 10
}

if ($null -eq $childExitCode) {
    [Console]::Error.WriteLine('The child PowerShell process did not return an exit code.')
    exit 10
}
exit $childExitCode
```

Paste this wrapper into an RMM inline PowerShell step that reports the wrapper process exit code. The toolkit runs in an explicit child process, so a toolkit outcome, an execution-policy refusal, or another child prelaunch failure returns a reliable nonzero code. Wrapper failures such as a missing script or engine return 10 on stderr instead of inheriting a stale `$LASTEXITCODE`.

The policy file in this example must be separately reviewed, deployed, and protected with least-privilege NTFS permissions. The repository's policy examples contain only synthetic values.

## Offline installation

Use the versioned `Windows-Admin-Toolkit-<version>-signed.zip` asset from the official release page. Acquire its adjacent `.sha256` file through the same authenticated release page, compare the ZIP hash, extract into a new staging directory, then verify `SHA256SUMS.txt` and the Authenticode signature on the extracted toolkit before deployment. Never replace the files attached to an existing version; use a newer version for corrections.

## Updating and rollback

Updates are explicit. Repeat the acquisition and verification process for the new release, preserve the previous verified package in the organization's normal software archive, test the new version in an isolated collection, and then advance deployment rings. Keep release version, commit ID, hashes, signer evidence, SBOM, and qualification evidence together.

Rolling back means redeploying a previously verified signed release. It does not mean moving a Git tag or rebuilding an old version with different bytes.

## Signer-pin rotation

The latest-release installers fail closed unless the release certificate matches one complete approved tuple: subject, certificate thumbprint, and public-key SHA-256. Certificate renewal or replacement therefore requires a coordinated, reviewed transition.

1. Validate the replacement certificate, private-key custody, code-signing EKU, trust chain, validity period, and publisher organization through the protected release process.
2. Derive the full subject, certificate thumbprint, and public-key SHA-256 from a separately verified candidate. Never copy identity text from an untrusted download or issue comment.
3. Before changing the latest release, add the replacement as a second complete tuple in both documented installers. Keep matching tuple-based so fields from two different certificates can never be combined.
4. Test the old and replacement tuples under Windows PowerShell 5.1 and PowerShell 7.x. Require trusted Authenticode status, a timestamp, post-copy revalidation, the expected toolkit version, and the normal catalog smoke test.
5. Merge the reviewed pin transition before publishing the replacement-signed release. During the short overlap, either the old current release or the new release can pass as one complete tuple.
6. After the replacement release is deployed and rollback requirements are satisfied, remove the retired tuple in a later reviewed change. Do not revoke trust prematurely when a valid incident-free rollback remains required.

Never work around a pin mismatch by checking only the certificate common name, accepting any trusted code-signing certificate, suppressing timestamp validation, or bypassing execution policy. A mismatch is a release blocker until the complete new identity and release evidence are independently verified.

## PowerShell Gallery status

Windows Admin Toolkit is not currently published in PowerShell Gallery. Do not assume that a similarly named Gallery package is official.

The signed 3.0.0 script predates the required `PSScriptInfo` publishing metadata. Adding metadata would change the signed bytes, so 3.0.0 must not be repackaged or re-signed under the same version. Gallery publication is therefore gated to a future version whose metadata is reviewed before signing. Maintainer validation and approval requirements are documented in [RELEASING.md](RELEASING.md#powershell-gallery-candidate).
