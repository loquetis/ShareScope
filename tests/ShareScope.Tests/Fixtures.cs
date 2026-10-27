using ShareScope.Core;

namespace ShareScope.Tests;

internal static class Fixtures
{
    public static AccessEntry Ace(
        string identity,
        uint mask,
        PermissionLayer layer,
        AceEffect effect = AceEffect.Allow,
        bool inherited = false,
        bool resolved = true,
        string? sid = null)
    {
        var rightsLayer = layer == PermissionLayer.Share ? PermissionLayer.Share : PermissionLayer.Ntfs;
        var applies = layer == PermissionLayer.Share ? "This share" : "This folder, subfolders and files";
        return new AccessEntry(
            identity,
            resolved,
            sid,
            RightsSummarizer.Summarize(mask, rightsLayer),
            effect,
            inherited,
            applies,
            layer);
    }

    public static ShareInfo Disk(string name, string path, string server = "CONTOSO-FS01") =>
        new(server, name, path, ShareKind.Disk, "Test share", 1);

    public static ShareAudit Analyze(
        ShareInfo share,
        IEnumerable<AccessEntry>? shareAces = null,
        IEnumerable<AccessEntry>? ntfsAces = null,
        bool broken = false,
        AclSnapshot? shareAcl = null,
        AclSnapshot? ntfsAcl = null,
        IReadOnlyList<SubfolderInspection>? subfolders = null)
    {
        var shareSnapshot = shareAcl ?? AclSnapshot.FromEntries(shareAces ?? Array.Empty<AccessEntry>());
        var ntfsSnapshot = ntfsAcl ?? AclSnapshot.FromEntries(ntfsAces ?? Array.Empty<AccessEntry>(), "CONTOSO\\FileAdmins", broken);
        return RiskAnalyzer.Analyze(share, shareSnapshot, ntfsSnapshot, subfolders);
    }
}
