namespace ShareScope.Core;

public static class ShareClassifier
{
    private static readonly HashSet<string> ReservedAdmin =
        new(StringComparer.OrdinalIgnoreCase) { "ADMIN$", "IPC$", "PRINT$" };

    public static bool IsHidden(string name) =>
        !string.IsNullOrEmpty(name) && name.EndsWith('$');

    public static bool IsAdministrative(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;
        if (ReservedAdmin.Contains(name))
            return true;
        return name.Length == 2 && name[1] == '$' && char.IsLetter(name[0]);
    }

    /// <summary>
    /// Maps the NetShareEnum type flags and the share name onto Disk, Printer, IPC, Admin, or Special.
    /// </summary>
    public static ShareKind Classify(uint shareType, string name)
    {
        if (name.Equals("IPC$", StringComparison.OrdinalIgnoreCase))
            return ShareKind.Ipc;

        if (IsAdministrative(name))
            return ShareKind.Admin;

        var baseType = shareType & 0x0FFF_FFFF;
        var kind = baseType switch
        {
            0 => ShareKind.Disk,
            1 => ShareKind.Printer,
            3 => ShareKind.Ipc,
            2 => ShareKind.Special,
            _ => ShareKind.Unknown
        };

        var specialFlag = (shareType & 0x8000_0000) != 0;
        if (kind == ShareKind.Disk && (IsHidden(name) || specialFlag))
            return ShareKind.Special;

        return kind;
    }

    public static string Display(ShareKind kind) => kind switch
    {
        ShareKind.Disk => "Disk",
        ShareKind.Printer => "Printer",
        ShareKind.Ipc => "IPC",
        ShareKind.Admin => "Admin",
        ShareKind.Special => "Special",
        _ => "Unknown"
    };
}

public static class UncPaths
{
    public static string Build(string server, string share, string? localComputerName = null)
    {
        var host = (server ?? "").Trim().Trim('\\');
        if (host.Length == 0 || host is "." or "localhost")
            host = string.IsNullOrWhiteSpace(localComputerName) ? "localhost" : localComputerName.Trim();
        return $@"\\{host}\{share}";
    }
}
