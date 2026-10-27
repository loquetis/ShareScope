using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using ShareScope.Core;

namespace ShareScope.Windows;

public sealed class WindowsServerAuditor : IServerAuditor
{
    public async Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
        string server,
        bool hideAdminAndHidden,
        int subfolderDepth,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var shares = await Task.Run(() => ListShares(server), cancellationToken).ConfigureAwait(false);
        var audits = new List<ShareAudit>();
        foreach (var share in shares)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (hideAdminAndHidden && (share.IsAdmin || share.IsHidden))
                continue;

            progress?.Report(new ScanProgress($"Reading {share.Server}\\{share.Name}", 0, 0));
            audits.Add(await Task.Run(() => AuditOne(share, subfolderDepth, progress, cancellationToken), cancellationToken).ConfigureAwait(false));
        }

        return audits;
    }

    private static IReadOnlyList<ShareInfo> ListShares(string server)
    {
        try
        {
            return NativeShares.Enumerate(server);
        }
        catch (Exception nativeError)
        {
            try
            {
                return WmiShares.Enumerate(server);
            }
            catch (Exception wmiError)
            {
                throw new InvalidOperationException(
                    $"Could not list shares on {server}. NetShareEnum: {nativeError.Message} WMI: {wmiError.Message}");
            }
        }
    }

    private static ShareAudit AuditOne(
        ShareInfo share,
        int subfolderDepth,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var shareAcl = ReadShareAcl(share);
        var ntfs = AclSnapshot.NotApplicable();
        IReadOnlyList<SubfolderInspection> folders = Array.Empty<SubfolderInspection>();
        if (share.Kind is ShareKind.Disk or ShareKind.Admin or ShareKind.Special)
        {
            var unc = UncPaths.Build(share.Server, share.Name);
            try
            {
                ntfs = NtfsAclReader.Read(unc);
            }
            catch (Exception ex)
            {
                ntfs = AclSnapshot.Failed(ex.Message);
            }

            if (subfolderDepth > 0 && ntfs.ReadSucceeded)
            {
                try
                {
                    folders = NtfsAclReader.Walk(
                        unc,
                        subfolderDepth,
                        cancellationToken,
                        path => progress?.Report(new ScanProgress($"Walking {path}", 0, 0)));
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    var partial = RiskAnalyzer.Analyze(share, shareAcl, ntfs);
                    var withNote = partial.Findings.ToList();
                    withNote.Add(new RiskFinding(
                        RiskSeverity.Review,
                        "SUBFOLDER_WALK_FAILED",
                        "Subfolder walk did not finish",
                        $"The subfolder walk stopped early. {ex.Message}",
                        unc));
                    return partial with { Findings = withNote };
                }
            }
        }

        return RiskAnalyzer.Analyze(share, shareAcl, ntfs, folders);
    }

    private static AclSnapshot ReadShareAcl(ShareInfo share)
    {
        try
        {
            return NativeShares.ReadShareAcl(share.Server, share.Name);
        }
        catch (Exception nativeError)
        {
            try
            {
                return WmiShares.ReadShareAcl(share.Server, share.Name);
            }
            catch (Exception wmiError)
            {
                return AclSnapshot.Failed($"{nativeError.Message} {wmiError.Message}".Trim());
            }
        }
    }
}

public sealed class WindowsComputerDirectory : IComputerDirectory
{
    public ComputerQueryResult Query(bool serversOrganizationalUnitOnly)
    {
        try
        {
            using var root = new DirectoryEntry("LDAP://RootDSE");
            var naming = root.Properties["defaultNamingContext"]?.Value as string;
            if (string.IsNullOrWhiteSpace(naming))
            {
                return new ComputerQueryResult(
                    false,
                    Array.Empty<string>(),
                    "This computer does not appear to be domain-joined. Active Directory was not queried.");
            }

            var distinguished = serversOrganizationalUnitOnly ? $"OU=Servers,{naming}" : naming;
            using var entry = new DirectoryEntry($"LDAP://{distinguished}");
            using var searcher = new DirectorySearcher(entry)
            {
                Filter = "(&(objectCategory=computer)(operatingSystem=Windows Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                PageSize = 300
            };
            searcher.PropertiesToLoad.Add("cn");
            searcher.PropertiesToLoad.Add("dNSHostName");

            var names = new List<string>();
            using var results = searcher.FindAll();
            foreach (SearchResult result in results)
            {
                string? name = null;
                if (result.Properties["dNSHostName"].Count > 0)
                    name = result.Properties["dNSHostName"][0]?.ToString();
                if (string.IsNullOrWhiteSpace(name) && result.Properties["cn"].Count > 0)
                    name = result.Properties["cn"][0]?.ToString();
                if (!string.IsNullOrWhiteSpace(name))
                    names.Add(name.Trim());
            }

            var distinct = names
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var place = serversOrganizationalUnitOnly ? "the Servers OU" : "the domain";
            return new ComputerQueryResult(
                true,
                distinct,
                $"Found {distinct.Count} Windows Server computer{(distinct.Count == 1 ? "" : "s")} in {place}.");
        }
        catch (Exception ex)
        {
            return new ComputerQueryResult(
                false,
                Array.Empty<string>(),
                "Active Directory could not be queried. Add server names manually. " + ex.Message);
        }
    }
}

public sealed class WindowsGroupResolver : IGroupMembershipResolver
{
    public GroupExpansion Expand(string identity)
    {
        if (string.IsNullOrWhiteSpace(identity))
            return new GroupExpansion(Array.Empty<string>(), false, "Enter a user or group name.");

        try
        {
            using var context = new PrincipalContext(ContextType.Domain);
            using var principal = Principal.FindByIdentity(context, identity.Trim())
                ?? Principal.FindByIdentity(context, IdentityType.SamAccountName, IdentityRules.SimpleName(identity));
            if (principal is null)
            {
                return new GroupExpansion(
                    new[] { identity.Trim() },
                    false,
                    "Active Directory did not find that account. Showing direct ACE matches only.");
            }

            var names = new List<string>();
            AddName(names, principal);
            if (principal is UserPrincipal user)
            {
                PrincipalSearchResult<Principal>? groups = null;
                try
                {
                    groups = user.GetAuthorizationGroups();
                }
                catch
                {
                    try
                    {
                        groups = user.GetGroups();
                    }
                    catch
                    {
                        groups = null;
                    }
                }

                if (groups is not null)
                {
                    using (groups)
                    {
                        foreach (var group in groups)
                        {
                            using (group)
                                AddName(names, group);
                        }
                    }
                }
            }

            return new GroupExpansion(names, true, "Memberships were read from Active Directory.");
        }
        catch (Exception ex)
        {
            return new GroupExpansion(
                new[] { identity.Trim() },
                false,
                "Group membership was not expanded. Showing direct ACE matches only. " + ex.Message);
        }
    }

    private static void AddName(List<string> names, Principal principal)
    {
        string? display = null;
        try
        {
            if (principal.Sid is not null)
                display = principal.Sid.Translate(typeof(NTAccount)).Value;
        }
        catch
        {
            display = null;
        }

        if (string.IsNullOrWhiteSpace(display))
            display = principal.SamAccountName ?? principal.Name;
        if (string.IsNullOrWhiteSpace(display))
            return;
        if (names.Any(existing => existing.Equals(display, StringComparison.OrdinalIgnoreCase)))
            return;
        names.Add(display);
    }
}
