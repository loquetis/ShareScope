namespace ShareScope.Core;

/// <summary>
/// Fictional Contoso network used by the hidden --demo switch. Nothing here is contacted over the network.
/// </summary>
public static class DemoCatalog
{
    public static IReadOnlyList<string> ServerNames { get; } =
        new[] { "CONTOSO-FS01", "CONTOSO-FS02", "CONTOSO-APP01" };

    public static IReadOnlyList<ShareAudit> SharesFor(string server, bool hideAdminAndHidden, int subfolderDepth)
    {
        return Templates()
            .Where(template => template.Share.Server.Equals(server, StringComparison.OrdinalIgnoreCase))
            .Where(template => !hideAdminAndHidden || (!template.Share.IsAdmin && !template.Share.IsHidden))
            .Select(template =>
            {
                var folders = template.Subfolders.Where(folder => folder.Depth <= Math.Max(0, subfolderDepth)).ToList();
                return RiskAnalyzer.Analyze(template.Share, template.ShareAcl, template.NtfsAcl, folders);
            })
            .ToList();
    }

    public static IReadOnlyList<ShareAudit> All(bool hideAdminAndHidden, int subfolderDepth) =>
        ServerNames.SelectMany(server => SharesFor(server, hideAdminAndHidden, subfolderDepth)).ToList();

    private sealed record Template(
        ShareInfo Share,
        AclSnapshot ShareAcl,
        AclSnapshot NtfsAcl,
        IReadOnlyList<SubfolderInspection> Subfolders);

    private static IReadOnlyList<Template> Templates()
    {
        var list = new List<Template>
        {
            Share(
                "CONTOSO-FS01", "Finance", @"D:\Shares\Finance", ShareKind.Disk,
                "Monthly close and accounts payable", 14, "CONTOSO\\FileAdmins",
                new[]
                {
                    Ace("Everyone", RightsSummarizer.FullControl, PermissionLayer.Share, sid: "S-1-1-0")
                },
                new[]
                {
                    Ace("CONTOSO\\Domain Users", RightsSummarizer.Modify, PermissionLayer.Ntfs, sid: "S-1-5-21-100000-200000-300000-513"),
                    Ace("CONTOSO\\Finance-Read", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true),
                    Ace("CONTOSO\\Finance-Managers", RightsSummarizer.Modify, PermissionLayer.Ntfs)
                },
                new[]
                {
                    Folder(@"\\CONTOSO-FS01\Finance\Payroll", "Payroll", 1, broken: true, new[]
                    {
                        Ace("Everyone", RightsSummarizer.Modify, PermissionLayer.Subfolder, sid: "S-1-1-0")
                    })
                }),
            Share(
                "CONTOSO-FS01", "HR", @"D:\Shares\HR", ShareKind.Disk,
                "Human resources and personnel files", 6, "CONTOSO\\HR-Managers",
                new[]
                {
                    Ace("NT AUTHORITY\\Authenticated Users", RightsSummarizer.Modify, PermissionLayer.Share, sid: "S-1-5-11")
                },
                new[]
                {
                    Ace("CONTOSO\\HR-Managers", RightsSummarizer.Modify, PermissionLayer.Ntfs),
                    Ace("CONTOSO\\Domain Users", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true, sid: "S-1-5-21-100000-200000-300000-513")
                }),
            Share(
                "CONTOSO-FS01", "Projects", @"D:\Shares\Projects", ShareKind.Disk,
                "Client project workspaces", 22, "CONTOSO\\FileAdmins",
                new[]
                {
                    Ace("CONTOSO\\All-Staff", RightsSummarizer.ReadAndExecute, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("CONTOSO\\Project-Leads", RightsSummarizer.Modify, PermissionLayer.Ntfs),
                    Ace("CONTOSO\\All-Staff", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true),
                    Ace("CONTOSO\\jsmith", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs)
                }),
            Share(
                "CONTOSO-FS01", "Public", @"D:\Shares\Public", ShareKind.Disk,
                "Company-wide read-only handouts", 11, "CONTOSO\\FileAdmins",
                new[]
                {
                    Ace("CONTOSO\\Domain Users", RightsSummarizer.ReadAndExecute, PermissionLayer.Share, sid: "S-1-5-21-100000-200000-300000-513")
                },
                new[]
                {
                    Ace("CONTOSO\\Domain Users", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true, sid: "S-1-5-21-100000-200000-300000-513")
                }),
            Share(
                "CONTOSO-FS01", "TeamDrop", @"D:\Shares\TeamDrop", ShareKind.Disk,
                "Department drop box", 4, "CONTOSO\\FileAdmins",
                new[]
                {
                    Ace("CONTOSO\\All-Staff", RightsSummarizer.Modify, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("BUILTIN\\Users", RightsSummarizer.Modify, PermissionLayer.Ntfs, sid: "S-1-5-32-545"),
                    Ace("CONTOSO\\All-Staff", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true)
                }),
            Share(
                "CONTOSO-FS01", "IPC$", "", ShareKind.Ipc,
                "Remote IPC", 2, null,
                new[]
                {
                    Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Share, sid: "S-1-5-32-544")
                },
                Array.Empty<AccessEntry>(),
                ntfs: AclSnapshot.NotApplicable()),
            Share(
                "CONTOSO-FS01", "C$", @"C:\", ShareKind.Admin,
                "Default share", 1, "NT AUTHORITY\\SYSTEM",
                new[]
                {
                    Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Share, sid: "S-1-5-32-544")
                },
                new[]
                {
                    Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Ntfs, sid: "S-1-5-32-544"),
                    Ace("NT AUTHORITY\\SYSTEM", RightsSummarizer.FullControl, PermissionLayer.Ntfs, sid: "S-1-5-18")
                }),
            Share(
                "CONTOSO-FS01", "ADMIN$", @"C:\Windows", ShareKind.Admin,
                "Remote Admin", 0, "NT AUTHORITY\\SYSTEM",
                new[]
                {
                    Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Share, sid: "S-1-5-32-544")
                },
                new[]
                {
                    Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Ntfs, sid: "S-1-5-32-544"),
                    Ace("NT AUTHORITY\\SYSTEM", RightsSummarizer.FullControl, PermissionLayer.Ntfs, inherited: true, sid: "S-1-5-18")
                }),
            Share(
                "CONTOSO-FS02", "Contracts", @"E:\Legal\Contracts", ShareKind.Disk,
                "Customer and vendor contracts", 5, "CONTOSO\\Legal",
                new[]
                {
                    Ace("Everyone", RightsSummarizer.ReadAndExecute, PermissionLayer.Share, sid: "S-1-1-0")
                },
                new[]
                {
                    Ace("CONTOSO\\Legal", RightsSummarizer.Modify, PermissionLayer.Ntfs),
                    Ace("CONTOSO\\Executives", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true)
                }),
            Share(
                "CONTOSO-FS02", "GuestWiFi", @"E:\Shares\GuestWiFi", ShareKind.Disk,
                "Lobby kiosk handouts", 9, "CONTOSO\\Facilities",
                new[]
                {
                    Ace("CONTOSO\\Guest", RightsSummarizer.ReadAndExecute, PermissionLayer.Share, sid: "S-1-5-21-100000-200000-300000-501")
                },
                new[]
                {
                    Ace("NT AUTHORITY\\ANONYMOUS LOGON", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, sid: "S-1-5-7")
                }),
            Share(
                "CONTOSO-FS02", "Archive", @"E:\Archive", ShareKind.Disk,
                "Closed projects kept for records", 1, "CONTOSO\\FileAdmins",
                new[]
                {
                    Ace("CONTOSO\\Archive-Readers", RightsSummarizer.ReadAndExecute, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("CONTOSO\\Archive-Readers", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true),
                    Ace("S-1-5-21-1111111111-2222222222-3333333333-9876", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs,
                        resolved: false, sid: "S-1-5-21-1111111111-2222222222-3333333333-9876")
                }),
            Share(
                "CONTOSO-FS02", "Engineering", @"E:\Eng", ShareKind.Disk,
                "CAD drawings and specifications", 7, "CONTOSO\\Engineering-Leads",
                new[]
                {
                    Ace("CONTOSO\\Engineers", RightsSummarizer.Modify, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("CONTOSO\\Engineers", RightsSummarizer.Modify, PermissionLayer.Ntfs),
                    Ace("CONTOSO\\Engineering-Leads", RightsSummarizer.FullControl, PermissionLayer.Ntfs)
                },
                inheritanceProtected: true),
            Share(
                "CONTOSO-FS02", "DenverPrinter", "", ShareKind.Printer,
                "2nd floor copier", 1, null,
                new[]
                {
                    Ace("CONTOSO\\All-Staff", RightsSummarizer.ReadAndExecute, PermissionLayer.Share)
                },
                Array.Empty<AccessEntry>(),
                ntfs: AclSnapshot.NotApplicable()),
            Share(
                "CONTOSO-FS02", "IT$", @"E:\IT\Private", ShareKind.Special,
                "IT internal tools", 2, "CONTOSO\\IT-Admins",
                new[]
                {
                    Ace("CONTOSO\\IT-Admins", RightsSummarizer.FullControl, PermissionLayer.Share),
                    Ace("CONTOSO\\Contractors", RightsSummarizer.FullControl, PermissionLayer.Share, effect: AceEffect.Deny)
                },
                new[]
                {
                    Ace("CONTOSO\\IT-Admins", RightsSummarizer.FullControl, PermissionLayer.Ntfs)
                }),
            Share(
                "CONTOSO-APP01", "AppData", @"C:\Program Files\ContosoApp\Data", ShareKind.Disk,
                "Line-of-business application data", 3, "CONTOSO\\App-Service",
                new[]
                {
                    Ace("CONTOSO\\App-Service", RightsSummarizer.Modify, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("CONTOSO\\App-Service", RightsSummarizer.Modify, PermissionLayer.Ntfs),
                    Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Ntfs, inherited: true, sid: "S-1-5-32-544")
                }),
            Share(
                "CONTOSO-APP01", "Logs", @"D:\App\Logs", ShareKind.Disk,
                "Application trace logs", 2, "CONTOSO\\Ops",
                new[]
                {
                    Ace("CONTOSO\\Ops", RightsSummarizer.ReadAndExecute, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("BUILTIN\\Users", RightsSummarizer.Write, PermissionLayer.Ntfs, sid: "S-1-5-32-545"),
                    Ace("CONTOSO\\Ops", RightsSummarizer.Modify, PermissionLayer.Ntfs)
                }),
            Share(
                "CONTOSO-APP01", "Deploy", @"D:\Deploy", ShareKind.Disk,
                "Release packages", 0, "CONTOSO\\Release-Managers",
                new[]
                {
                    Ace("CONTOSO\\Release-Managers", RightsSummarizer.Modify, PermissionLayer.Share)
                },
                new[]
                {
                    Ace("CONTOSO\\Release-Managers", RightsSummarizer.Modify, PermissionLayer.Ntfs),
                    Ace("CONTOSO\\Ops", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, inherited: true)
                })
        };

        return list;
    }

    private static Template Share(
        string server,
        string name,
        string path,
        ShareKind kind,
        string description,
        int? connections,
        string? owner,
        IReadOnlyList<AccessEntry> shareAces,
        IReadOnlyList<AccessEntry> ntfsAces,
        IReadOnlyList<SubfolderInspection>? subfolders = null,
        AclSnapshot? ntfs = null,
        bool inheritanceProtected = false)
    {
        var info = new ShareInfo(server, name, path, kind, description, connections);
        var shareAcl = AclSnapshot.FromEntries(shareAces);
        var ntfsAcl = ntfs ?? AclSnapshot.FromEntries(ntfsAces, owner, inheritanceProtected);
        return new Template(info, shareAcl, ntfsAcl, subfolders ?? Array.Empty<SubfolderInspection>());
    }

    private static SubfolderInspection Folder(string fullPath, string relative, int depth, bool broken, IReadOnlyList<AccessEntry> entries) =>
        new(fullPath, relative, depth, broken, entries);

    private static AccessEntry Ace(
        string identity,
        uint mask,
        PermissionLayer layer,
        bool inherited = false,
        bool resolved = true,
        string? sid = null,
        AceEffect effect = AceEffect.Allow)
    {
        var rightsLayer = layer == PermissionLayer.Share ? PermissionLayer.Share : PermissionLayer.Ntfs;
        var applies = layer == PermissionLayer.Share
            ? "This share"
            : "This folder, subfolders and files";
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
}

public sealed class DemoServerAuditor : IServerAuditor
{
    public Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
        string server,
        bool hideAdminAndHidden,
        int subfolderDepth,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var shares = DemoCatalog.SharesFor(server, hideAdminAndHidden, subfolderDepth);
        progress?.Report(new ScanProgress($"Demo data for {server}", 0, 1));
        return Task.FromResult<IReadOnlyList<ShareAudit>>(shares);
    }
}

public sealed class DemoGroupResolver : IGroupMembershipResolver
{
    private static readonly Dictionary<string, string[]> Memberships = new(StringComparer.OrdinalIgnoreCase)
    {
        ["jsmith"] = new[] { "CONTOSO\\jsmith", "CONTOSO\\Finance-Read", "CONTOSO\\Domain Users", "CONTOSO\\All-Staff" },
        ["mchen"] = new[] { "CONTOSO\\mchen", "CONTOSO\\HR-Managers" },
        ["guest"] = new[] { "CONTOSO\\Guest" }
    };

    public GroupExpansion Expand(string identity)
    {
        var simple = IdentityRules.SimpleName(identity ?? "");
        if (Memberships.TryGetValue(simple, out var groups))
        {
            return new GroupExpansion(
                groups,
                true,
                "Memberships were read from the fictional Contoso directory (demo). No directory server was contacted.");
        }

        return new GroupExpansion(
            string.IsNullOrWhiteSpace(identity) ? Array.Empty<string>() : new[] { identity.Trim() },
            false,
            "That account is not in the fictional directory. Showing direct ACE matches only.");
    }
}

public sealed class DemoComputerDirectory : IComputerDirectory
{
    public ComputerQueryResult Query(bool serversOrganizationalUnitOnly) =>
        new(
            false,
            Array.Empty<string>(),
            "Demo mode does not query Active Directory. The target list is the fictional Contoso servers.");
}
