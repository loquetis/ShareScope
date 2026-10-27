namespace ShareScope.Core;

/// <summary>Product identity shared by the desktop app, reports, and CLI.</summary>
public static class AppInfo
{
    public const string Name = "ShareScope";
    public const string Version = "1.0.0";
    public const string Tagline = "Audit SMB shares and spot risky access";
    public const string ReadOnlyStatement =
        "ShareScope is read-only. It never changes share permissions, NTFS permissions, ownership, or files.";
}
