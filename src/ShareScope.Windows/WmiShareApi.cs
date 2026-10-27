using System.Management;
using ShareScope.Core;

namespace ShareScope.Windows;

internal static class WmiShares
{
    public static IReadOnlyList<ShareInfo> Enumerate(string server)
    {
        var scope = Connect(server);
        var query = new ObjectQuery("SELECT Name, Path, Description, Type FROM Win32_Share");
        using var searcher = new ManagementObjectSearcher(scope, query);
        var display = ServerNames.Display(server);
        var list = new List<ShareInfo>();
        foreach (ManagementObject item in searcher.Get())
        {
            using (item)
            {
                var name = item["Name"]?.ToString() ?? "";
                if (name.Length == 0)
                    continue;
                var path = item["Path"]?.ToString() ?? "";
                var description = item["Description"]?.ToString() ?? "";
                var type = ToUInt(item["Type"]);
                list.Add(new ShareInfo(display, name, path, ShareClassifier.Classify(type, name), description, null));
            }
        }

        return list;
    }

    public static AclSnapshot ReadShareAcl(string server, string share)
    {
        var scope = Connect(server);
        var escaped = share.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("'", "\\'", StringComparison.Ordinal);
        var path = new ManagementPath($"Win32_LogicalShareSecuritySetting.Name='{escaped}'");
        using var shareObject = new ManagementObject(scope, path, null);
        shareObject.Get();
        using var result = shareObject.InvokeMethod("GetSecurityDescriptor", null, null);
        if (result is null)
            return AclSnapshot.Failed("WMI did not return a share security descriptor.");

        var code = ToUInt(result["ReturnValue"]);
        if (code != 0)
            return AclSnapshot.Failed($"WMI GetSecurityDescriptor returned {code}.");

        if (result["Descriptor"] is not ManagementBaseObject descriptor)
            return new AclSnapshot(true, null, null, false, false, Array.Empty<AccessEntry>());

        if (descriptor["DACL"] is not ManagementBaseObject[] dacl)
            return new AclSnapshot(true, null, null, false, false, Array.Empty<AccessEntry>());

        var entries = new List<AccessEntry>();
        foreach (var ace in dacl)
        {
            var trustee = ace["Trustee"] as ManagementBaseObject;
            var sid = trustee?["SIDString"]?.ToString();
            var name = trustee?["Name"]?.ToString();
            var domain = trustee?["Domain"]?.ToString();
            var identity = !string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(name)
                ? $"{domain}\\{name}"
                : name;
            var resolved = !string.IsNullOrWhiteSpace(identity);
            if (!resolved)
                identity = string.IsNullOrWhiteSpace(sid) ? "Unknown" : sid;

            var flags = ToUInt(ace["AceFlags"]);
            var inheritance = 0;
            var propagation = 0;
            if ((flags & 0x2) != 0)
                inheritance |= AppliesToFormatter.ContainerInherit;
            if ((flags & 0x1) != 0)
                inheritance |= AppliesToFormatter.ObjectInherit;
            if ((flags & 0x4) != 0)
                propagation |= AppliesToFormatter.NoPropagateInherit;
            if ((flags & 0x8) != 0)
                propagation |= AppliesToFormatter.InheritOnly;

            var aceType = ToUInt(ace["AceType"]);
            var effect = aceType == 1 ? AceEffect.Deny : AceEffect.Allow;
            entries.Add(new AccessEntry(
                identity!,
                resolved,
                sid,
                RightsSummarizer.Summarize(ToUInt(ace["AccessMask"]), PermissionLayer.Share),
                effect,
                (flags & 0x10) != 0,
                AppliesToFormatter.Describe(inheritance, propagation, PermissionLayer.Share),
                PermissionLayer.Share));
        }

        return AclSnapshot.FromEntries(entries);
    }

    private static ManagementScope Connect(string server)
    {
        var path = ServerNames.IsLocal(server)
            ? @"\\.\root\cimv2"
            : $@"\\{ServerNames.Display(server)}\root\cimv2";
        var scope = new ManagementScope(path, new ConnectionOptions
        {
            Timeout = TimeSpan.FromSeconds(30),
            Authentication = AuthenticationLevel.PacketPrivacy
        });
        scope.Connect();
        return scope;
    }

    private static uint ToUInt(object? value) => value switch
    {
        null => 0,
        uint number => number,
        int number => unchecked((uint)number),
        long number => unchecked((uint)number),
        _ => Convert.ToUInt32(value)
    };
}
