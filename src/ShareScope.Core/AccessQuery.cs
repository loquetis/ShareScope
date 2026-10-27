namespace ShareScope.Core;

public static class AccessQuery
{
    public static IReadOnlyList<AccessHit> Find(
        IReadOnlyList<ShareAudit> shares,
        string identity,
        GroupExpansion expansion)
    {
        if (string.IsNullOrWhiteSpace(identity))
            return Array.Empty<AccessHit>();

        var principals = new List<string> { identity.Trim() };
        foreach (var extra in expansion.Identities)
        {
            if (string.IsNullOrWhiteSpace(extra))
                continue;
            if (principals.Any(existing => existing.Equals(extra.Trim(), StringComparison.OrdinalIgnoreCase)))
                continue;
            if (principals.Any(existing => IdentityRules.SimpleName(existing).Equals(IdentityRules.SimpleName(extra), StringComparison.OrdinalIgnoreCase)
                && IdentityRules.SimpleName(existing).Equals(IdentityRules.SimpleName(identity), StringComparison.OrdinalIgnoreCase)))
                continue;
            principals.Add(extra.Trim());
        }

        var hits = new List<AccessHit>();
        foreach (var share in shares)
        {
            Collect(hits, share.Share, share.Share.UncPath, share.ShareAcl.Entries, identity, principals);
            var ntfsPath = string.IsNullOrWhiteSpace(share.Share.Path) ? share.Share.UncPath : share.Share.Path;
            Collect(hits, share.Share, ntfsPath, share.NtfsAcl.Entries, identity, principals);
            foreach (var folder in share.Subfolders)
                Collect(hits, share.Share, folder.FullPath, folder.Entries, identity, principals);
        }

        return hits
            .OrderBy(h => h.Server, StringComparer.OrdinalIgnoreCase)
            .ThenBy(h => h.Share, StringComparer.OrdinalIgnoreCase)
            .ThenBy(h => h.Path, StringComparer.OrdinalIgnoreCase)
            .ThenBy(h => h.Layer)
            .ToList();
    }

    private static void Collect(
        List<AccessHit> hits,
        ShareInfo share,
        string path,
        IReadOnlyList<AccessEntry> entries,
        string queried,
        IReadOnlyList<string> principals)
    {
        foreach (var entry in entries)
        {
            string? via = null;
            if (IdentityRules.SameIdentity(queried, entry))
            {
                via = "Direct";
            }
            else
            {
                foreach (var principal in principals)
                {
                    if (IdentityRules.SameIdentity(principal, entry))
                    {
                        via = "Via " + principal;
                        break;
                    }
                }
            }

            if (via is null)
                continue;

            hits.Add(new AccessHit(
                share.Server,
                share.Name,
                path,
                entry.Layer,
                entry.Identity,
                via,
                entry.Rights.Text,
                entry.Effect,
                entry.Inherited,
                entry.AppliesTo));
        }
    }
}
