<#
.SYNOPSIS
    Builds a new Windows Admin Toolkit release directory with integrity metadata.

.DESCRIPTION
    Copies the documented release payload into a destination that must not already
    exist, optionally Authenticode-signs the copied toolkit script, writes an SPDX
    2.3 JSON software bill of materials, and writes and verifies SHA256SUMS.txt.
    Source files are never signed or modified.

.PARAMETER OutputDirectory
    New directory that will receive the release payload. The parent must exist.

.PARAMETER CertificateThumbprint
    Optional SHA-1 thumbprint of a code-signing certificate with a private key.

.PARAMETER CertificateStoreLocation
    Certificate store to inspect when CertificateThumbprint is supplied.

.PARAMETER TimestampServer
    RFC 3161/Authenticode timestamp service used only when signing is requested.
#>

#Requires -Version 5.1

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingBrokenHashAlgorithms',
    '',
    Justification = 'SPDX 2.3 package verification codes require SHA-1; release integrity is independently enforced with SHA-256.'
)]
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter()]
    [ValidatePattern('^[0-9A-Fa-f ]{40,80}$')]
    [string]$CertificateThumbprint = '',

    [Parameter()]
    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$CertificateStoreLocation = 'CurrentUser',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function ConvertTo-ReleaseRelativePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $rootWithSeparator = $SourceRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $LiteralPath.StartsWith($rootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release source is outside the repository root: $LiteralPath"
    }

    $relativePath = $LiteralPath.Substring($rootWithSeparator.Length).Replace([IO.Path]::DirectorySeparatorChar, '/')
    if ([string]::IsNullOrWhiteSpace($relativePath) -or $relativePath -match '[\x00-\x1F\x7F*]' -or $relativePath.StartsWith('/') -or $relativePath.EndsWith('/') -or $relativePath -match '(^|/)\.\.?(/|$)') {
        throw "Release path cannot be represented safely: $relativePath"
    }
    return $relativePath
}

function Write-ReleaseUtf8NoBom {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    [IO.File]::WriteAllText($LiteralPath, $Value, (New-Object Text.UTF8Encoding($false)))
}

function Get-ReleaseHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet('SHA1', 'SHA256')]
        [string]$Algorithm
    )

    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm).Hash.ToLowerInvariant()
}

function Get-ReleaseDirectoryFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $pendingDirectories = New-Object 'System.Collections.Generic.Queue[string]'
    $files = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
    $pendingDirectories.Enqueue([IO.Path]::GetFullPath($LiteralPath))
    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $currentDirectory -Force | Sort-Object Name)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Release source reparse points are not supported: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                $pendingDirectories.Enqueue($item.FullName)
            }
            elseif ($item -is [IO.FileInfo]) {
                $files.Add($item) | Out-Null
            }
            else {
                throw "Unsupported release source item: $($item.FullName)"
            }
        }
    }
    return $files.ToArray()
}

$sourceRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$toolkitSourcePath = Join-Path $sourceRoot 'WindowsAdminToolkit.ps1'
if (-not [IO.File]::Exists($toolkitSourcePath)) {
    throw "Toolkit source file not found: $toolkitSourcePath"
}

$toolkitSource = [IO.File]::ReadAllText($toolkitSourcePath)
$versionMatches = [regex]::Matches($toolkitSource, '(?m)^\$Script:ToolkitVersion\s*=\s*''(?<Version>[0-9]+\.[0-9]+\.[0-9]+)''\s*$')
if ($versionMatches.Count -ne 1) {
    throw 'The toolkit source must contain exactly one canonical ToolkitVersion assignment.'
}
$toolkitVersion = $versionMatches[0].Groups['Version'].Value

$resolvedOutput = [IO.Path]::GetFullPath($OutputDirectory)
$outputParent = [IO.Path]::GetDirectoryName($resolvedOutput)
if ([string]::IsNullOrWhiteSpace($outputParent) -or -not [IO.Directory]::Exists($outputParent)) {
    throw "The release output parent directory must already exist: $outputParent"
}
if ([IO.Directory]::Exists($resolvedOutput) -or [IO.File]::Exists($resolvedOutput)) {
    throw "The release output path already exists: $resolvedOutput"
}

$rootFileNames = @(
    'WindowsAdminToolkit.ps1',
    'README.md',
    'AUTOMATION.md',
    'ORCHESTRATION.md',
    'POLICY.md',
    'AUDITING.md',
    'SECURITY.md',
    'RESPONSIBLE_USE.md',
    'RELEASING.md',
    'CHANGELOG.md',
    'ROADMAP.md',
    'TESTING.md',
    'CONTRIBUTING.md',
    'SUPPORT.md',
    'CODE_OF_CONDUCT.md',
    'LICENSE',
    'PSScriptAnalyzerSettings.psd1',
    'computers_example.txt'
)
$releaseDirectories = @('schemas', 'examples', 'tests', 'tools')
$sourceFiles = New-Object 'System.Collections.Generic.List[System.IO.FileInfo]'
foreach ($rootFileName in $rootFileNames) {
    $sourcePath = Join-Path $sourceRoot $rootFileName
    if (-not [IO.File]::Exists($sourcePath)) {
        throw "Required release source file not found: $rootFileName"
    }
    $sourceFiles.Add((Get-Item -LiteralPath $sourcePath)) | Out-Null
}
foreach ($releaseDirectory in $releaseDirectories) {
    $directoryPath = Join-Path $sourceRoot $releaseDirectory
    if (-not [IO.Directory]::Exists($directoryPath)) {
        throw "Required release source directory not found: $releaseDirectory"
    }
    foreach ($sourceFile in @(Get-ReleaseDirectoryFile -LiteralPath $directoryPath | Sort-Object FullName)) {
        $sourceFiles.Add($sourceFile) | Out-Null
    }
}

$relativePathSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$releaseItems = New-Object 'System.Collections.Generic.List[object]'
foreach ($sourceFile in $sourceFiles) {
    if (($sourceFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Release source reparse points are not supported: $($sourceFile.FullName)"
    }
    $relativePath = ConvertTo-ReleaseRelativePath -SourceRoot $sourceRoot -LiteralPath $sourceFile.FullName
    if (-not $relativePathSet.Add($relativePath)) {
        throw "Duplicate release path detected: $relativePath"
    }
    $releaseItems.Add([pscustomobject]@{
            SourcePath   = $sourceFile.FullName
            RelativePath = $relativePath
        }) | Out-Null
}

[void][IO.Directory]::CreateDirectory($resolvedOutput)
$outputRootWithSeparator = $resolvedOutput.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
foreach ($releaseItem in $releaseItems) {
    $platformRelativePath = $releaseItem.RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $destinationPath = [IO.Path]::GetFullPath((Join-Path $resolvedOutput $platformRelativePath))
    if (-not $destinationPath.StartsWith($outputRootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release destination escaped the output directory: $($releaseItem.RelativePath)"
    }
    $destinationParent = [IO.Path]::GetDirectoryName($destinationPath)
    [void][IO.Directory]::CreateDirectory($destinationParent)
    [IO.File]::Copy($releaseItem.SourcePath, $destinationPath, $false)
    if ((Get-ReleaseHash -LiteralPath $releaseItem.SourcePath -Algorithm SHA256) -cne (Get-ReleaseHash -LiteralPath $destinationPath -Algorithm SHA256)) {
        throw "Release copy verification failed: $($releaseItem.RelativePath)"
    }
}

$signed = $false
$signerThumbprint = $null
if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
    $normalizedThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($normalizedThumbprint -cnotmatch '^[0-9A-F]{40}$') {
        throw 'CertificateThumbprint must contain exactly 40 hexadecimal characters after spaces are removed.'
    }

    $timestampUri = $null
    if (-not [Uri]::TryCreate($TimestampServer, [UriKind]::Absolute, [ref]$timestampUri) -or $timestampUri.Scheme -notin @('http', 'https')) {
        throw 'TimestampServer must be an absolute HTTP or HTTPS URI.'
    }

    $certificatePath = "Cert:\$CertificateStoreLocation\My\$normalizedThumbprint"
    $certificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
    if (-not $certificate.HasPrivateKey) {
        throw 'The selected code-signing certificate does not have an accessible private key.'
    }
    $codeSigningEku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | ForEach-Object { $_.EnhancedKeyUsages } | Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3' })
    if ($codeSigningEku.Count -eq 0) {
        throw 'The selected certificate is not valid for code signing.'
    }
    $now = Get-Date
    if ($now -lt $certificate.NotBefore -or $now -gt $certificate.NotAfter) {
        throw 'The selected code-signing certificate is not currently valid.'
    }

    $copiedToolkitPath = Join-Path $resolvedOutput 'WindowsAdminToolkit.ps1'
    $signature = Set-AuthenticodeSignature -LiteralPath $copiedToolkitPath -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $timestampUri.AbsoluteUri
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signing did not produce a valid signature: $($signature.StatusMessage)"
    }
    $verifiedSignature = Get-AuthenticodeSignature -LiteralPath $copiedToolkitPath
    if ($verifiedSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $verifiedSignature.SignerCertificate.Thumbprint -cne $normalizedThumbprint) {
        throw 'The copied toolkit failed Authenticode verification after signing.'
    }
    if ($null -eq $verifiedSignature.TimeStamperCertificate) {
        throw 'The copied toolkit signature does not contain a timestamp certificate.'
    }
    $signed = $true
    $signerThumbprint = $normalizedThumbprint
}

$payloadFiles = @(Get-ChildItem -LiteralPath $resolvedOutput -File -Recurse | Sort-Object FullName)
$spdxFiles = New-Object 'System.Collections.Generic.List[object]'
$relationships = New-Object 'System.Collections.Generic.List[object]'
$verificationSha1 = New-Object 'System.Collections.Generic.List[string]'
$fileIndex = 0
foreach ($payloadFile in $payloadFiles) {
    $fileIndex++
    $relativePath = ConvertTo-ReleaseRelativePath -SourceRoot $resolvedOutput -LiteralPath $payloadFile.FullName
    $sha1 = Get-ReleaseHash -LiteralPath $payloadFile.FullName -Algorithm SHA1
    $sha256 = Get-ReleaseHash -LiteralPath $payloadFile.FullName -Algorithm SHA256
    $verificationSha1.Add($sha1) | Out-Null
    $fileType = if ($payloadFile.Extension -ieq '.ps1' -or $payloadFile.Extension -ieq '.psd1') { 'SOURCE' } elseif ($payloadFile.Extension -ieq '.json') { 'DOCUMENTATION' } else { 'TEXT' }
    $fileSpdxId = 'SPDXRef-File-{0:D4}' -f $fileIndex
    $spdxFiles.Add([pscustomobject][ordered]@{
            fileName           = "./$relativePath"
            SPDXID             = $fileSpdxId
            checksums          = @(
                [pscustomobject][ordered]@{ algorithm = 'SHA1'; checksumValue = $sha1 },
                [pscustomobject][ordered]@{ algorithm = 'SHA256'; checksumValue = $sha256 }
            )
            fileTypes          = @($fileType)
            licenseConcluded   = 'NOASSERTION'
            licenseInfoInFiles = @('NOASSERTION')
            copyrightText      = 'NOASSERTION'
        }) | Out-Null
    $relationships.Add([pscustomobject][ordered]@{
            spdxElementId      = 'SPDXRef-Package'
            relationshipType   = 'CONTAINS'
            relatedSpdxElement = $fileSpdxId
        }) | Out-Null
}

$sha1Concat = (@($verificationSha1.ToArray() | Sort-Object) -join '')
$sha1Provider = [Security.Cryptography.SHA1]::Create()
try {
    $packageVerificationCode = ([BitConverter]::ToString($sha1Provider.ComputeHash([Text.Encoding]::UTF8.GetBytes($sha1Concat))) -replace '-', '').ToLowerInvariant()
}
finally {
    $sha1Provider.Dispose()
}

$documentNamespace = "https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/spdx/$toolkitVersion/$([guid]::NewGuid().ToString('D'))"
$documentRelationships = New-Object 'System.Collections.Generic.List[object]'
$documentRelationships.Add([pscustomobject][ordered]@{
        spdxElementId      = 'SPDXRef-DOCUMENT'
        relationshipType   = 'DESCRIBES'
        relatedSpdxElement = 'SPDXRef-Package'
    }) | Out-Null
foreach ($relationship in $relationships) {
    $documentRelationships.Add($relationship) | Out-Null
}
$sbom = [pscustomobject][ordered]@{
    spdxVersion       = 'SPDX-2.3'
    dataLicense       = 'CC0-1.0'
    SPDXID            = 'SPDXRef-DOCUMENT'
    name              = "Windows-Admin-Toolkit-$toolkitVersion"
    documentNamespace = $documentNamespace
    creationInfo      = [pscustomobject][ordered]@{
        created  = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture))
        creators = @('Tool: Windows Admin Toolkit release builder')
    }
    packages          = @(
        [pscustomobject][ordered]@{
            name                    = 'Windows Admin Toolkit'
            SPDXID                  = 'SPDXRef-Package'
            versionInfo             = $toolkitVersion
            downloadLocation        = "https://github.com/fusiontechstrategies/Windows-Admin-Toolkit/archive/refs/tags/v$toolkitVersion.tar.gz"
            filesAnalyzed           = $true
            packageVerificationCode = [pscustomobject][ordered]@{ packageVerificationCodeValue = $packageVerificationCode }
            licenseConcluded        = 'MIT'
            licenseDeclared         = 'MIT'
            copyrightText           = 'NOASSERTION'
        }
    )
    files             = @($spdxFiles.ToArray())
    relationships     = @($documentRelationships.ToArray())
}
$sbomPath = Join-Path $resolvedOutput 'WindowsAdminToolkit.spdx.json'
Write-ReleaseUtf8NoBom -LiteralPath $sbomPath -Value ((ConvertTo-Json -InputObject $sbom -Depth 12) + [Environment]::NewLine)

$manifestFiles = @(Get-ChildItem -LiteralPath $resolvedOutput -File -Recurse | Where-Object { $_.Name -cne 'SHA256SUMS.txt' } | Sort-Object FullName)
$manifestLines = New-Object 'System.Collections.Generic.List[string]'
foreach ($manifestFile in $manifestFiles) {
    $relativePath = ConvertTo-ReleaseRelativePath -SourceRoot $resolvedOutput -LiteralPath $manifestFile.FullName
    $manifestLines.Add("$(Get-ReleaseHash -LiteralPath $manifestFile.FullName -Algorithm SHA256) *$relativePath") | Out-Null
}
$manifestPath = Join-Path $resolvedOutput 'SHA256SUMS.txt'
Write-ReleaseUtf8NoBom -LiteralPath $manifestPath -Value (($manifestLines.ToArray() -join [Environment]::NewLine) + [Environment]::NewLine)

$verifiedCount = 0
foreach ($manifestLine in [IO.File]::ReadAllLines($manifestPath, [Text.Encoding]::UTF8)) {
    if ([string]::IsNullOrWhiteSpace($manifestLine)) { continue }
    if ($manifestLine -cnotmatch '^(?<Hash>[0-9a-f]{64}) \*(?<Path>[^\r\n]+)$') {
        throw "Invalid generated manifest line: $manifestLine"
    }
    $manifestExpectedHash = $Matches['Hash']
    $manifestRelativePath = $Matches['Path']
    if ($manifestRelativePath.Contains('\') -or $manifestRelativePath.StartsWith('/') -or $manifestRelativePath -match '(^|/)\.\.(/|$)') {
        throw "Unsafe generated manifest path: $manifestRelativePath"
    }
    $manifestTarget = [IO.Path]::GetFullPath((Join-Path $resolvedOutput $manifestRelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    if (-not $manifestTarget.StartsWith($outputRootWithSeparator, [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($manifestTarget)) {
        throw "Generated manifest path is invalid: $manifestRelativePath"
    }
    if ((Get-ReleaseHash -LiteralPath $manifestTarget -Algorithm SHA256) -cne $manifestExpectedHash) {
        throw "Generated manifest verification failed: $manifestRelativePath"
    }
    $verifiedCount++
}

[pscustomobject][ordered]@{
    ToolkitVersion    = $toolkitVersion
    OutputDirectory   = $resolvedOutput
    PayloadFileCount  = $payloadFiles.Count
    ManifestFileCount = $verifiedCount
    Signed            = $signed
    SignerThumbprint  = $signerThumbprint
    SbomPath          = $sbomPath
    ManifestPath      = $manifestPath
}
