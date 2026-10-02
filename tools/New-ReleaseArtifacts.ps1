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

    [WindowsAdminToolkit.Security.StorageSecurity]::AppendPrivateFile($LiteralPath, [Text.Encoding]::UTF8.GetBytes($Value), $true, 16777216)
}

function Test-ReleaseSignedSourceBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$UnsignedBytes, [Parameter(Mandatory = $true)][byte[]]$SignedBytes)
    if ($SignedBytes.Length -le $UnsignedBytes.Length) { throw 'The signed artifact does not contain the approved source followed by a signature.' }
    for ($index = 0; $index -lt $UnsignedBytes.Length; $index++) {
        if ($SignedBytes[$index] -ne $UnsignedBytes[$index]) { throw 'Signing changed the approved executable source bytes.' }
    }
    $trailer = (New-Object Text.UTF8Encoding($false, $true)).GetString($SignedBytes, $UnsignedBytes.Length, $SignedBytes.Length - $UnsignedBytes.Length)
    if ($trailer -cnotmatch '\A(?:\r?\n){0,2}# SIG # Begin signature block\r?\n(?:# [A-Za-z0-9+/=]+\r?\n)+# SIG # End signature block(?:\r?\n)?\z') {
        throw 'The signature trailer contains unexpected executable bytes.'
    }
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

function Test-ReleaseCertificateCodeSigningEku {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    foreach ($extension in $Certificate.Extensions) {
        if ($extension.Oid.Value -cne '2.5.29.37' -or $extension -isnot [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            continue
        }
        foreach ($usage in $extension.EnhancedKeyUsages) {
            if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') {
                return $true
            }
        }
    }
    return $false
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

# The release builder owns this helper; payload source is only read as data.
$releaseNativeSource = @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace WindowsAdminToolkit.Security {
    // Each ancestor is held without write/delete sharing until the leaf is consumed.
    // OPEN_REPARSE_POINT makes both the initial walk and later object inspection no-follow.
    public sealed class PathLease : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Info {
            public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
            public System.Runtime.InteropServices.ComTypes.FILETIME Access;
            public System.Runtime.InteropServices.ComTypes.FILETIME Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder name, uint size, uint flags);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref int delete, uint size);
        readonly List<SafeFileHandle> handles = new List<SafeFileHandle>();
        FileStream stream; SafeFileHandle leaf; Info info; bool disposed;
        public string Path { get; private set; }
        public string Identity { get { return info.Volume.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8"); } }
        public uint LinkCount { get { return info.Links; } }
        public bool IsDirectory { get { return (info.Attributes & 16) != 0; } }
        public long Length { get { return ((long)info.SizeHigh << 32) | info.SizeLow; } }
        public DateTime LastWriteUtc { get { return DateTime.FromFileTimeUtc(((long)info.Write.dwHighDateTime << 32) | (uint)info.Write.dwLowDateTime); } }

        public static PathLease Open(string path, bool directory, bool deleteAccess) {
            return OpenCore(path, directory, deleteAccess, false);
        }
        static PathLease OpenCore(string path, bool directory, bool deleteAccess, bool allowWrite) {
            string full = System.IO.Path.GetFullPath(path).TrimEnd('\\');
            if (full.Length < 3 || full[1] != ':' || full[2] != '\\')
                throw new IOException("Protected references must use a local absolute Windows path.");
            PathLease lease = new PathLease(); lease.Path = full;
            try {
                string root = System.IO.Path.GetPathRoot(full);
                string current = root;
                lease.Add(current, true, false, false);
                string[] parts = full.Substring(root.Length).Split('\\');
                for (int i = 0; i < parts.Length; i++) {
                    if (parts[i].Length == 0) continue;
                    current = System.IO.Path.Combine(current, parts[i]);
                    bool isLeaf = i == parts.Length - 1;
                    lease.Add(current, !isLeaf || directory, isLeaf && deleteAccess, isLeaf && allowWrite);
                }
                return lease;
            } catch { lease.Dispose(); throw; }
        }
        void Add(string path, bool directory, bool deleteAccess, bool allowWrite) {
            uint access = directory ? 0x80u : 0x80000000u;
            if (deleteAccess) access |= 0x10000u;
            access |= 0x20000u; // READ_CONTROL permits read-only owner/DACL inspection.
            SafeFileHandle handle = CreateFile(path, access, allowWrite ? 3u : 1u, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error, "Cannot lock protected path component: " + path); }
            handles.Add(handle);
            Info opened;
            if (!GetFileInformationByHandle(handle, out opened)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((opened.Attributes & 0x400) != 0) throw new IOException("Reparse points are forbidden in protected paths: " + path);
            if (((opened.Attributes & 16) != 0) != directory) throw new IOException("Protected path component has an unexpected type.");
            StringBuilder resolved = new StringBuilder(32768);
            uint count = GetFinalPathNameByHandle(handle, resolved, (uint)resolved.Capacity, 0);
            if (count == 0 || count >= resolved.Capacity) throw new IOException("Cannot prove the protected path identity.");
            string actual = resolved.ToString();
            if (!actual.Equals("\\\\?\\" + System.IO.Path.GetFullPath(path).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) &&
                !actual.TrimEnd('\\').Equals("\\\\?\\" + System.IO.Path.GetFullPath(path).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Protected path identity changed during opening.");
            leaf = handle; info = opened;
        }
        // HOST_TRUST_BEGIN: omitted from the isolated target cleanup helper.
        public static PathLease OpenTrusted(string path, bool directory, bool allowWrite, bool privateLeaf) {
            PathLease lease = OpenCore(path, directory, false, allowWrite);
            try {
                for (int i = 0; i < lease.handles.Count; i++)
                    StorageSecurity.Validate(lease.handles[i], i == lease.handles.Count - 1 && privateLeaf,
                        i != lease.handles.Count - 1 || directory);
                if (!directory && lease.LinkCount != 1) throw new IOException("Private artifacts cannot have multiple hard links.");
                return lease;
            } catch (Exception error) { lease.Dispose(); throw new IOException("Protected storage trust check failed for " + path + ": " + error.Message, error); }
        }
        // HOST_TRUST_END
        FileStream Reader() {
            if (disposed || IsDirectory) throw new IOException("A locked file is required.");
            if (stream == null) stream = new FileStream(leaf, FileAccess.Read);
            stream.Position = 0; return stream;
        }
        public byte[] ReadBytes(int maximum) {
            FileStream input = Reader();
            if (input.Length > maximum) throw new IOException("The input file exceeds the " + maximum + " byte limit.");
            byte[] bytes = new byte[(int)input.Length]; int offset = 0;
            while (offset < bytes.Length) {
                int read = input.Read(bytes, offset, bytes.Length - offset);
                if (read == 0) throw new IOException("The input file ended before it could be read completely.");
                offset += read;
            }
            if (input.ReadByte() != -1) throw new IOException("The input file grew during reading.");
            return bytes;
        }
        public string Sha256() {
            using (SHA256 hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(Reader())).Replace("-", "").ToLowerInvariant();
        }
        public void DeleteUnder(string root) {
            string approved = System.IO.Path.GetFullPath(root).TrimEnd('\\') + "\\";
            if (!Path.StartsWith(approved, StringComparison.OrdinalIgnoreCase) || IsDirectory || info.Links != 1)
                throw new IOException("Deletion is outside the approved root or the file has multiple links.");
            int delete = 1;
            if (!SetFileInformationByHandle(leaf, 4, ref delete, 4)) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public void Dispose() {
            if (disposed) return; disposed = true;
            if (stream != null) stream.Dispose();
            for (int i = handles.Count - 1; i >= 0; i--) handles[i].Dispose();
        }
    }
    public static class StorageSecurity {
        [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
        [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint information, out IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string path, uint access, uint share, ref SecurityAttributes security, uint mode, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandle(SafeFileHandle handle, StringBuilder name, uint size, uint flags);
        public static string CurrentSid { get { using (System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent()) return identity.User.Value; } }
        static bool Trusted(string sid, string user) {
            return sid == user || sid == "S-1-5-18" || sid == "S-1-5-32-544" ||
                sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
        }
        public static void ValidateDescriptor(byte[] bytes, bool privateLeaf, bool directory, bool volumeRoot) {
            System.Security.AccessControl.RawSecurityDescriptor descriptor = new System.Security.AccessControl.RawSecurityDescriptor(bytes, 0);
            string user = CurrentSid;
            if (descriptor.Owner == null || !Trusted(descriptor.Owner.Value, user) || (privateLeaf && descriptor.Owner.Value != user))
                throw new IOException("Protected storage has an untrusted owner.");
            if (descriptor.DiscretionaryAcl == null) throw new IOException("Protected storage has a NULL DACL.");
            if (privateLeaf && (descriptor.ControlFlags & System.Security.AccessControl.ControlFlags.DiscretionaryAclProtected) == 0)
                throw new IOException("Private storage must have a protected DACL.");
            if (descriptor.DiscretionaryAcl.Count > 4096) throw new IOException("Protected storage exceeds the ACL inspection budget.");
            uint dangerous = 0x40u | 0x40000u | 0x80000u;
            // A canonical volume anchor cannot be renamed and remains nonempty
            // while its independently protected immediate child is retained.
            if (!volumeRoot) dangerous |= 0x2u | 0x100u | 0x10000u;
            if (privateLeaf || !directory) dangerous |= 0x2u | 0x4u | 0x10u | 0x100u | 0x10000u;
            foreach (System.Security.AccessControl.GenericAce ace in descriptor.DiscretionaryAcl) {
                if ((ace.AceFlags & System.Security.AccessControl.AceFlags.InheritOnly) != 0) continue;
                System.Security.AccessControl.CommonAce common = ace as System.Security.AccessControl.CommonAce;
                if (common == null || common.IsCallback) throw new IOException("Unsupported protected storage ACE.");
                if (common.AceQualifier == System.Security.AccessControl.AceQualifier.AccessDenied) continue;
                if (common.AceQualifier != System.Security.AccessControl.AceQualifier.AccessAllowed) throw new IOException("Unsupported protected storage ACE.");
                uint mask = unchecked((uint)common.AccessMask);
                if ((mask & 0x10000000u) != 0) mask |= 0x1f01ffu;
                if ((mask & 0x40000000u) != 0) mask |= 0x120116u;
                string sid = common.SecurityIdentifier.Value;
                // OWNER RIGHTS belongs to the owner validated above.
                if ((mask & dangerous) != 0 && !Trusted(sid, user) && sid != "S-1-3-4")
                    throw new IOException("Protected storage can be changed by another principal.");
            }
        }
        public static void Validate(SafeFileHandle handle, bool privateLeaf, bool directory) {
            IntPtr owner, dacl, descriptor;
            uint error = GetSecurityInfo(handle, 1, 5, out owner, IntPtr.Zero, out dacl, IntPtr.Zero, out descriptor);
            if (error != 0) throw new Win32Exception((int)error);
            try {
                uint size = GetSecurityDescriptorLength(descriptor);
                if (size == 0 || size > 1048576) throw new IOException("Invalid protected storage descriptor size.");
                byte[] bytes = new byte[size]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                StringBuilder name = new StringBuilder(512);
                uint count = GetFinalPathNameByHandle(handle, name, (uint)name.Capacity, 1);
                bool root = directory && count > 0 && count < name.Capacity &&
                    System.Text.RegularExpressions.Regex.IsMatch(name.ToString(), @"^\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\$");
                ValidateDescriptor(bytes, privateLeaf, directory, root);
            } finally { LocalFree(descriptor); }
        }
        public static void CreatePrivateDirectory(string path) {
            string sid = CurrentSid;
            IntPtr descriptor; uint size;
            string sddl = "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                SecurityAttributes attributes = new SecurityAttributes(); attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes)); attributes.Descriptor = descriptor;
                if (!CreateDirectory(path, ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot create private storage directory.");
            } finally { LocalFree(descriptor); }
        }
        public static void AppendPrivateFile(string path, byte[] bytes, bool create, int maximum) {
            string sid = CurrentSid; IntPtr descriptor; uint size;
            string sddl = "O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out descriptor, out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                SecurityAttributes attributes = new SecurityAttributes(); attributes.Length = Marshal.SizeOf(typeof(SecurityAttributes)); attributes.Descriptor = descriptor;
                using (SafeFileHandle handle = CreateFile(path, 0xc0020000u, 1, ref attributes, create ? 1u : 3u, 0x00200000, IntPtr.Zero)) {
                    if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                    Validate(handle, true, false);
                    using (PathLease identity = PathLease.OpenTrusted(path, false, true, true)) {
                        using (FileStream output = new FileStream(handle, FileAccess.ReadWrite)) {
                            if (output.Length + bytes.Length > maximum) throw new IOException("Checkpoint ledger exceeds its durable storage budget.");
                            output.Position = output.Length; output.Write(bytes, 0, bytes.Length); output.Flush(true);
                        }
                    }
                }
            } finally { LocalFree(descriptor); }
        }
    }
}
'@
if (-not ('WindowsAdminToolkit.Security.StorageSecurity' -as [type])) {
    Add-Type -TypeDefinition $releaseNativeSource -ErrorAction Stop
}

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
    'INSTALL.md',
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
    'computers_example.txt',
    '.github/assets/social-preview.jpg'
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

$releaseLeases = New-Object 'System.Collections.Generic.List[System.IDisposable]'
try {
$releaseLeases.Add([WindowsAdminToolkit.Security.PathLease]::OpenTrusted($outputParent, $true, $false, $false))
[WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($resolvedOutput)
$releaseLeases.Add([WindowsAdminToolkit.Security.PathLease]::OpenTrusted($resolvedOutput, $true, $false, $true))
$sourceHashes = @{}
$unsignedToolkitBytes = $null
$outputRootWithSeparator = $resolvedOutput.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
foreach ($releaseItem in $releaseItems) {
    $platformRelativePath = $releaseItem.RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $destinationPath = [IO.Path]::GetFullPath((Join-Path $resolvedOutput $platformRelativePath))
    if (-not $destinationPath.StartsWith($outputRootWithSeparator, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release destination escaped the output directory: $($releaseItem.RelativePath)"
    }
    $destinationParent = [IO.Path]::GetDirectoryName($destinationPath)
    $pendingParents = New-Object 'System.Collections.Generic.Stack[string]'
    while (-not [IO.Directory]::Exists($destinationParent)) {
        $pendingParents.Push($destinationParent)
        $destinationParent = [IO.Path]::GetDirectoryName($destinationParent)
    }
    while ($pendingParents.Count -gt 0) { [WindowsAdminToolkit.Security.StorageSecurity]::CreatePrivateDirectory($pendingParents.Pop()) }
    $sourceLease = [WindowsAdminToolkit.Security.PathLease]::OpenTrusted($releaseItem.SourcePath, $false, $false, $false)
    $releaseLeases.Add($sourceLease)
    $sourceBytes = $sourceLease.ReadBytes(16777216)
    $sourceHashes[$releaseItem.RelativePath] = $sourceLease.Sha256()
    [WindowsAdminToolkit.Security.StorageSecurity]::AppendPrivateFile($destinationPath, $sourceBytes, $true, 16777216)
    if ((Get-ReleaseHash -LiteralPath $destinationPath -Algorithm SHA256) -cne $sourceHashes[$releaseItem.RelativePath]) {
        throw "Release copy verification failed: $($releaseItem.RelativePath)"
    }
    if ($releaseItem.RelativePath -ceq 'WindowsAdminToolkit.ps1') { $unsignedToolkitBytes = $sourceBytes }
    else { $releaseLeases.Add([WindowsAdminToolkit.Security.PathLease]::OpenTrusted($destinationPath, $false, $false, $true)) }
}

$signed = $false
$signerThumbprint = $null
$copiedToolkitPath = Join-Path $resolvedOutput 'WindowsAdminToolkit.ps1'
$signingLease = [WindowsAdminToolkit.Security.PathLease]::OpenTrusted($copiedToolkitPath, $false, $true, $true)
try {
if ($signingLease.Sha256() -cne $sourceHashes['WindowsAdminToolkit.ps1']) { throw 'The executable staging bytes changed before signing.' }
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
    if (-not (Test-ReleaseCertificateCodeSigningEku -Certificate $certificate)) {
        throw 'The selected certificate is not valid for code signing.'
    }
    $now = Get-Date
    if ($now -lt $certificate.NotBefore -or $now -gt $certificate.NotAfter) {
        throw 'The selected code-signing certificate is not currently valid.'
    }

    $signature = Set-AuthenticodeSignature -LiteralPath $copiedToolkitPath -Certificate $certificate -HashAlgorithm SHA256 -TimestampServer $timestampUri.AbsoluteUri
    Test-ReleaseSignedSourceBinding -UnsignedBytes $unsignedToolkitBytes -SignedBytes ($signingLease.ReadBytes(16777216))
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
}
finally { $signingLease.Dispose() }
$releaseLeases.Add([WindowsAdminToolkit.Security.PathLease]::OpenTrusted($copiedToolkitPath, $false, $false, $true))
$finalToolkitHash = Get-ReleaseHash -LiteralPath $copiedToolkitPath -Algorithm SHA256
if (-not $signed -and $finalToolkitHash -cne $sourceHashes['WindowsAdminToolkit.ps1']) { throw 'The unsigned executable bytes changed in staging.' }

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
    $extension = $payloadFile.Extension.ToLowerInvariant()
    $fileType = if ($extension -in @('.ps1', '.psd1')) {
        'SOURCE'
    }
    elseif ($extension -in @('.jpg', '.jpeg', '.png', '.gif', '.svg')) {
        'IMAGE'
    }
    elseif ($extension -ceq '.json') {
        'DOCUMENTATION'
    }
    else {
        'TEXT'
    }
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
}
finally {
    for ($leaseIndex = $releaseLeases.Count - 1; $leaseIndex -ge 0; $leaseIndex--) { $releaseLeases[$leaseIndex].Dispose() }
}
