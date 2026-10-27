using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using ShareScope.Core;

namespace ShareScope.Windows;

internal static class ServerNames
{
    public static bool IsLocal(string server)
    {
        if (string.IsNullOrWhiteSpace(server))
            return true;
        var name = server.Trim().Trim('\\');
        if (name.Length == 0 || name is "." or "localhost" or "127.0.0.1" or "::1")
            return true;
        return name.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase);
    }

    public static string? NetApi(string server) => IsLocal(server) ? null : server.Trim().Trim('\\');

    public static string Display(string server) =>
        IsLocal(server) ? Environment.MachineName : server.Trim().Trim('\\');

    public static string UncHost(string server) => Display(server);
}

internal static class NativeShares
{
    private const int MaxPreferredLength = -1;
    private const int ErrorMoreData = 234;

    public static IReadOnlyList<ShareInfo> Enumerate(string server)
    {
        var results = new List<ShareInfo>();
        var resume = 0;
        var host = ServerNames.NetApi(server);
        var display = ServerNames.Display(server);

        while (true)
        {
            var status = NativeMethods.NetShareEnum(
                host,
                2,
                out var buffer,
                MaxPreferredLength,
                out var read,
                out _,
                ref resume);

            try
            {
                if (status != 0 && status != ErrorMoreData)
                    throw new Win32Exception(status, Describe(status));

                var size = Marshal.SizeOf<ShareInfo2>();
                for (var i = 0; i < read; i++)
                {
                    var item = Marshal.PtrToStructure<ShareInfo2>(IntPtr.Add(buffer, i * size));
                    var name = Marshal.PtrToStringUni(item.NetName) ?? "";
                    if (name.Length == 0)
                        continue;
                    var path = Marshal.PtrToStringUni(item.Path) ?? "";
                    var remark = Marshal.PtrToStringUni(item.Remark) ?? "";
                    var kind = ShareClassifier.Classify(item.Type, name);
                    int? connections = item.CurrentUses <= int.MaxValue ? (int)item.CurrentUses : null;
                    results.Add(new ShareInfo(display, name, path, kind, remark, connections));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NativeMethods.NetApiBufferFree(buffer);
            }

            if (status != ErrorMoreData)
                break;
        }

        return results;
    }

    public static AclSnapshot ReadShareAcl(string server, string share)
    {
        var status = NativeMethods.NetShareGetInfo(ServerNames.NetApi(server), share, 502, out var buffer);
        if (status != 0 || buffer == IntPtr.Zero)
        {
            if (buffer != IntPtr.Zero)
                NativeMethods.NetApiBufferFree(buffer);
            throw new Win32Exception(status, Describe(status));
        }

        try
        {
            var info = Marshal.PtrToStructure<ShareInfo502>(buffer);
            return SecurityDescriptorReader.FromPointer(info.SecurityDescriptor, PermissionLayer.Share);
        }
        finally
        {
            NativeMethods.NetApiBufferFree(buffer);
        }
    }

    private static string Describe(int code) => code switch
    {
        5 => "Access denied.",
        53 => "The network path was not found.",
        65 => "Network access is denied.",
        2250 => "The server or share name was not found.",
        _ => $"Windows networking error {code}."
    };
}

internal static class SecurityDescriptorReader
{
    public static AclSnapshot FromPointer(IntPtr securityDescriptor, PermissionLayer layer)
    {
        if (securityDescriptor == IntPtr.Zero)
            return new AclSnapshot(true, null, null, false, false, Array.Empty<AccessEntry>());

        var length = (int)NativeMethods.GetSecurityDescriptorLength(securityDescriptor);
        if (length <= 0)
            return new AclSnapshot(true, null, null, false, false, Array.Empty<AccessEntry>());

        var bytes = new byte[length];
        Marshal.Copy(securityDescriptor, bytes, 0, length);
        var raw = new RawSecurityDescriptor(bytes, 0);
        var owner = raw.Owner is null ? null : SidTranslator.ToName(raw.Owner, out _);
        if (raw.DiscretionaryAcl is null || (raw.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
            return new AclSnapshot(true, null, owner, false, false, Array.Empty<AccessEntry>());

        var entries = new List<AccessEntry>();
        foreach (GenericAce ace in raw.DiscretionaryAcl)
        {
            if (ace is not QualifiedAce qualified)
                continue;
            if (qualified.AceType is not (AceType.AccessAllowed or AceType.AccessDenied
                or AceType.AccessAllowedObject or AceType.AccessDeniedObject))
                continue;

            var sid = qualified.SecurityIdentifier;
            var identity = SidTranslator.ToName(sid, out var resolved);
            var effect = qualified.AceType is AceType.AccessDenied or AceType.AccessDeniedObject
                ? AceEffect.Deny
                : AceEffect.Allow;
            var applies = AppliesToFormatter.Describe(
                (int)qualified.InheritanceFlags,
                (int)qualified.PropagationFlags,
                layer);
            entries.Add(new AccessEntry(
                identity,
                resolved,
                sid.Value,
                RightsSummarizer.Summarize((uint)qualified.AccessMask, layer == PermissionLayer.Share ? PermissionLayer.Share : PermissionLayer.Ntfs),
                effect,
                qualified.IsInherited,
                applies,
                layer));
        }

        return AclSnapshot.FromEntries(entries, owner);
    }
}

internal static class SidTranslator
{
    public static string ToName(SecurityIdentifier sid, out bool resolved)
    {
        try
        {
            var account = (NTAccount)sid.Translate(typeof(NTAccount));
            resolved = true;
            return account.Value;
        }
        catch
        {
            resolved = false;
            return sid.Value;
        }
    }
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct ShareInfo2
{
    public IntPtr NetName;
    public uint Type;
    public IntPtr Remark;
    public uint Permissions;
    public uint MaxUses;
    public uint CurrentUses;
    public IntPtr Path;
    public IntPtr Password;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct ShareInfo502
{
    public IntPtr NetName;
    public uint Type;
    public IntPtr Remark;
    public uint Permissions;
    public uint MaxUses;
    public uint CurrentUses;
    public IntPtr Path;
    public IntPtr Password;
    public uint Reserved;
    public IntPtr SecurityDescriptor;
}

internal static class NativeMethods
{
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareEnum(
        string? serverName,
        int level,
        out IntPtr buffer,
        int prefMaxLen,
        out int entriesRead,
        out int totalEntries,
        ref int resumeHandle);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetShareGetInfo(
        string? serverName,
        string netName,
        int level,
        out IntPtr buffer);

    [DllImport("Netapi32.dll")]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);
}
