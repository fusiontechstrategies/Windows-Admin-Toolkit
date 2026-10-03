# Evaluate synthetic descriptors against a real restricted kernel token. No
# filesystem ACL is set, token impersonation occurs, or process is launched.
if (-not ('WindowsAdminToolkit.Tests.SourceAuthz' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
namespace WindowsAdminToolkit.Tests {
    public static class SourceAuthz {
        [StructLayout(LayoutKind.Sequential)] struct SidAttributes { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] struct Request { public uint Access; public IntPtr Self, Types; public uint TypeCount; public IntPtr Arguments; }
        [StructLayout(LayoutKind.Sequential)] struct Reply { public uint Count; public IntPtr Granted, Sacl, Error; }
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSidToSid(string text, out IntPtr sid);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount,
            IntPtr disable, uint privilegeCount, IntPtr privileges, uint restrictCount, IntPtr restrictions, out IntPtr token);
        [DllImport("authz.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool AuthzInitializeResourceManager(uint flags,
            IntPtr check, IntPtr compute, IntPtr free, string name, out IntPtr manager);
        [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzInitializeContextFromToken(uint flags, IntPtr token,
            IntPtr manager, IntPtr expiration, Luid id, IntPtr args, out IntPtr context);
        [DllImport("authz.dll", SetLastError=true)] static extern bool AuthzAccessCheck(uint flags, IntPtr context, ref Request request,
            IntPtr audit, byte[] descriptor, IntPtr optional, uint optionalCount, ref Reply reply, IntPtr cache);
        [DllImport("authz.dll")] static extern bool AuthzFreeContext(IntPtr context);
        [DllImport("authz.dll")] static extern bool AuthzFreeResourceManager(IntPtr manager);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
        static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public static bool RestrictedAllows(string sddl, uint access) {
            IntPtr sid=IntPtr.Zero, disabled=IntPtr.Zero, token=IntPtr.Zero, manager=IntPtr.Zero, context=IntPtr.Zero, result=IntPtr.Zero;
            using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) {
                try {
                    Check(ConvertStringSidToSid("S-1-5-32-544", out sid));
                    SidAttributes group=new SidAttributes(); group.Sid=sid;
                    disabled=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SidAttributes))); Marshal.StructureToPtr(group, disabled, false);
                    // Administrators is deny-only; all removable privileges are disabled.
                    Check(CreateRestrictedToken(identity.Token, 1, 1, disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out token));
                    Check(AuthzInitializeResourceManager(1, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, "Offline source trust fixture", out manager));
                    Check(AuthzInitializeContextFromToken(0, token, manager, IntPtr.Zero, new Luid(), IntPtr.Zero, out context));
                    RawSecurityDescriptor sd=new RawSecurityDescriptor(sddl); byte[] bytes=new byte[sd.BinaryLength]; sd.GetBinaryForm(bytes, 0);
                    result=Marshal.AllocHGlobal(12); Marshal.WriteInt32(result, 0, 0); Marshal.WriteInt32(result, 4, 0); Marshal.WriteInt32(result, 8, 0);
                    Request request=new Request(); request.Access=access;
                    Reply reply=new Reply(); reply.Count=1; reply.Granted=result; reply.Sacl=IntPtr.Add(result, 4); reply.Error=IntPtr.Add(result, 8);
                    Check(AuthzAccessCheck(0, context, ref request, IntPtr.Zero, bytes, IntPtr.Zero, 0, ref reply, IntPtr.Zero));
                    uint granted=unchecked((uint)Marshal.ReadInt32(result)); int error=Marshal.ReadInt32(result, 8);
                    return error==0 && (granted & access)==access;
                }
                finally {
                    if (result!=IntPtr.Zero) Marshal.FreeHGlobal(result);
                    if (context!=IntPtr.Zero) AuthzFreeContext(context);
                    if (manager!=IntPtr.Zero) AuthzFreeResourceManager(manager);
                    if (token!=IntPtr.Zero) CloseHandle(token);
                    if (disabled!=IntPtr.Zero) Marshal.FreeHGlobal(disabled);
                    if (sid!=IntPtr.Zero) LocalFree(sid);
                }
            }
        }
    }
}
'@ -ErrorAction Stop
}
$protectedSourceSddl = 'O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)'
Test-ToolkitAssertion -Condition ([WindowsAdminToolkit.Tests.SourceAuthz]::RestrictedAllows($protectedSourceSddl, 1)) -Name 'Actual restricted kernel token can read protected administrator source'
foreach ($access in @([uint32]2, [uint32]4, [uint32]0x10000, [uint32]0x40000, [uint32]0x80000)) {
    Test-ToolkitAssertion -Condition (-not [WindowsAdminToolkit.Tests.SourceAuthz]::RestrictedAllows($protectedSourceSddl, $access)) -Name ("Actual restricted same-user token cannot mutate protected source: {0:x}" -f $access)
}
$currentSourceSid = [WindowsAdminToolkit.Security.StorageSecurity]::CurrentSid
$unsafeCurrentUserSddl = "O:BAG:BAD:P(A;;FA;;;$currentSourceSid)(A;;FA;;;BA)(A;;FA;;;SY)"
Test-ToolkitAssertion -Condition ([WindowsAdminToolkit.Tests.SourceAuthz]::RestrictedAllows($unsafeCurrentUserSddl, 2)) -Name 'Kernel positive control proves current-user write grants preserve the source attack'
