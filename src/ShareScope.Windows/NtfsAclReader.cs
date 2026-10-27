using System.Security.AccessControl;
using System.Security.Principal;
using ShareScope.Core;

namespace ShareScope.Windows;

internal static class NtfsAclReader
{
    public static AclSnapshot Read(string path)
    {
        var directory = new DirectoryInfo(path);
        var security = directory.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access | AccessControlSections.Group);
        string? owner = null;
        var ownerSid = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (ownerSid is not null)
            owner = SidTranslator.ToName(ownerSid, out _);

        var entries = new List<AccessEntry>();
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IdentityReference is not SecurityIdentifier sid)
                continue;
            var identity = SidTranslator.ToName(sid, out var resolved);
            var effect = rule.AccessControlType == AccessControlType.Deny ? AceEffect.Deny : AceEffect.Allow;
            entries.Add(new AccessEntry(
                identity,
                resolved,
                sid.Value,
                RightsSummarizer.Summarize((uint)rule.FileSystemRights, PermissionLayer.Ntfs),
                effect,
                rule.IsInherited,
                AppliesToFormatter.Describe((int)rule.InheritanceFlags, (int)rule.PropagationFlags, PermissionLayer.Ntfs),
                PermissionLayer.Ntfs));
        }

        return AclSnapshot.FromEntries(entries, owner, security.AreAccessRulesProtected);
    }

    public static IReadOnlyList<SubfolderInspection> Walk(
        string root,
        int depth,
        CancellationToken cancellationToken,
        Action<string>? progress)
    {
        var results = new List<SubfolderInspection>();
        if (depth <= 0 || string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            return results;

        WalkLevel(root, root, 1, depth, results, cancellationToken, progress);
        return results;
    }

    private static void WalkLevel(
        string root,
        string current,
        int level,
        int maxDepth,
        List<SubfolderInspection> results,
        CancellationToken cancellationToken,
        Action<string>? progress)
    {
        IEnumerable<string> children;
        try
        {
            children = Directory.EnumerateDirectories(current);
        }
        catch
        {
            return;
        }

        foreach (var child in children)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DirectoryInfo info;
            try
            {
                info = new DirectoryInfo(child);
            }
            catch
            {
                continue;
            }

            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                continue;

            progress?.Invoke(child);
            AclSnapshot acl;
            try
            {
                acl = Read(child);
            }
            catch
            {
                acl = AclSnapshot.Failed("The folder permissions could not be read.");
            }

            if (IsInteresting(acl))
            {
                var relative = Relative(root, child);
                var layerEntries = acl.Entries
                    .Select(entry => entry with { Layer = PermissionLayer.Subfolder })
                    .ToList();
                results.Add(new SubfolderInspection(child, relative, level, acl.InheritanceProtected == true, layerEntries));
            }

            if (level < maxDepth)
                WalkLevel(root, child, level + 1, maxDepth, results, cancellationToken, progress);
        }
    }

    private static bool IsInteresting(AclSnapshot acl)
    {
        if (!acl.ReadSucceeded)
            return false;
        if (acl.InheritanceProtected == true)
            return true;
        return acl.Entries.Any(entry =>
            IdentityRules.IsOrphan(entry)
            || entry.Effect == AceEffect.Allow && IdentityRules.IsAnonymousOrGuest(entry)
            || entry.Effect == AceEffect.Allow && IdentityRules.IsBroadPrincipal(entry) && entry.Rights.IsWriteCapable);
    }

    private static string Relative(string root, string full)
    {
        try
        {
            var relative = Path.GetRelativePath(root, full);
            return string.IsNullOrWhiteSpace(relative) ? full : relative;
        }
        catch
        {
            return full;
        }
    }
}
