namespace ShareScope.Core;

public static class RiskAnalyzer
{
    public static ShareAudit Analyze(
        ShareInfo share,
        AclSnapshot shareAcl,
        AclSnapshot ntfsAcl,
        IReadOnlyList<SubfolderInspection>? subfolders = null)
    {
        var folders = subfolders ?? Array.Empty<SubfolderInspection>();
        var findings = new List<RiskFinding>();

        if (!shareAcl.ReadSucceeded)
        {
            findings.Add(Finding(
                RiskSeverity.Review,
                "SHARE_ACL_UNREAD",
                "Share permissions could not be read",
                $"Share permissions could not be read. {shareAcl.FailureReason}".Trim(),
                share.UncPath));
        }
        else if (shareAcl.DaclPresent == false)
        {
            findings.Add(Finding(
                RiskSeverity.High,
                "NULL_DACL",
                "Share has no access list",
                "This share has no discretionary access list. Windows treats a missing share ACL as unrestricted, so anyone who can reach the server can pass the share check.",
                share.UncPath));
        }

        var ntfsApplies = share.Kind is ShareKind.Disk or ShareKind.Admin or ShareKind.Special;
        if (ntfsApplies && !ntfsAcl.ReadSucceeded)
        {
            findings.Add(Finding(
                RiskSeverity.Review,
                "NTFS_ACL_UNREAD",
                "NTFS permissions could not be read",
                $"NTFS permissions on the share root could not be read. {ntfsAcl.FailureReason}".Trim(),
                string.IsNullOrWhiteSpace(share.Path) ? share.UncPath : share.Path));
        }

        AssessEntries(findings, shareAcl.Entries, "share", share.UncPath, subfolder: false);
        AssessEntries(findings, ntfsAcl.Entries, "folder", share.Path, subfolder: false);

        if (SensitivePathRules.IsSensitive(share.Name, share.Path))
        {
            foreach (var ace in shareAcl.Entries.Where(e => e.Effect == AceEffect.Allow && IdentityRules.IsEveryone(e)))
            {
                findings.Add(Finding(
                    RiskSeverity.High,
                    "EVERYONE_SENSITIVE_SHARE",
                    $"Everyone has {ace.Rights.Text} on a sensitive share",
                    $"Everyone has {ace.Rights.Text} at the share level on {share.Name}, which looks like a sensitive area. Anyone who can reach the server can pass the share check.",
                    share.UncPath));
            }
        }

        if (ntfsApplies && ntfsAcl.InheritanceProtected == true)
        {
            findings.Add(Finding(
                RiskSeverity.Review,
                "BROKEN_INHERITANCE",
                "Inheritance is broken on the share root",
                "Inheritance is broken on the share root. Permissions here do not flow from the parent folder, so access can drift away from the rest of the volume.",
                share.Path));
        }

        if (SensitivePathRules.IsSystemFolder(share.Path))
        {
            findings.Add(Finding(
                RiskSeverity.Review,
                "SYSTEM_FOLDER",
                "Share points at a system folder",
                $"This share exposes a system location ({share.Path}). Sharing a drive root, Windows, or Program Files opens a wide view of the server.",
                share.Path));
        }

        foreach (var folder in folders)
        {
            if (folder.InheritanceProtected)
            {
                findings.Add(Finding(
                    RiskSeverity.Review,
                    "SUBFOLDER_BROKEN_INHERITANCE",
                    $"Inheritance is broken on {folder.RelativePath}",
                    $"Inheritance is broken on {folder.RelativePath}. This folder keeps its own permission list instead of inheriting from the share root.",
                    folder.FullPath));
            }

            AssessEntries(findings, folder.Entries, $"subfolder {folder.RelativePath}", folder.FullPath, subfolder: true);
        }

        var distinct = Dedup(findings);
        var owner = ntfsAcl.Owner ?? shareAcl.Owner;
        return new ShareAudit(share, owner, shareAcl, ntfsAcl, folders.ToList(), distinct);
    }

    private static void AssessEntries(
        List<RiskFinding> findings,
        IReadOnlyList<AccessEntry> entries,
        string layerName,
        string? location,
        bool subfolder)
    {
        foreach (var ace in entries)
        {
            if (IdentityRules.IsOrphan(ace))
            {
                findings.Add(Finding(
                    RiskSeverity.Review,
                    "ORPHAN_SID",
                    $"Unresolvable identity {ace.Identity}",
                    $"The entry for {ace.Identity} on the {layerName} could not be resolved to an account. Orphaned SIDs usually belong to a deleted user or group, or to a domain this computer cannot name, and they still grant or deny access.",
                    location));
            }

            if (ace.Effect == AceEffect.Deny)
            {
                findings.Add(Finding(
                    RiskSeverity.Review,
                    "DENY_ACE",
                    $"Deny for {ace.Identity}",
                    $"A Deny entry for {ace.Identity} blocks {ace.Rights.Text} on the {layerName}. Deny wins over Allow, so confirm the block is intentional.",
                    location));
                continue;
            }

            if (IdentityRules.IsAnonymousOrGuest(ace))
            {
                var who = IdentityRules.IsAnonymous(ace) ? "Anonymous" : ace.Identity;
                findings.Add(Finding(
                    RiskSeverity.High,
                    "ANONYMOUS_OR_GUEST",
                    $"{ace.Identity} is allowed {ace.Rights.Text}",
                    $"{who} is allowed {ace.Rights.Text} on the {layerName}. Guest and anonymous access lets people in without a normal user account.",
                    location));
                continue;
            }

            if (!IdentityRules.IsBroadPrincipal(ace))
                continue;

            if (ace.Rights.IsWriteCapable)
            {
                findings.Add(Finding(
                    RiskSeverity.High,
                    subfolder ? "SUBFOLDER_BROAD_WRITE" : "BROAD_WRITE",
                    $"{ace.Identity} has {ace.Rights.Text}",
                    $"{ace.Identity} has {ace.Rights.Text} on the {layerName}. That is a wide group, so a large set of people can add or change data here.",
                    location));
            }
            else if (ace.Rights.Read)
            {
                findings.Add(Finding(
                    RiskSeverity.Review,
                    "BROAD_READ",
                    $"{ace.Identity} has {ace.Rights.Text}",
                    $"{ace.Identity} has {ace.Rights.Text} on the {layerName}. Read access for a wide group is common on share permissions, and it still exposes every file the NTFS check allows.",
                    location));
            }
        }
    }

    private static RiskFinding Finding(RiskSeverity severity, string code, string title, string explanation, string? location) =>
        new(severity, code, title, explanation, location);

    private static List<RiskFinding> Dedup(List<RiskFinding> findings)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<RiskFinding>();
        foreach (var finding in findings)
        {
            var key = $"{finding.Code}|{finding.Title}|{finding.Location}";
            if (seen.Add(key))
                result.Add(finding);
        }

        return result
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Code, StringComparer.Ordinal)
            .ToList();
    }
}
