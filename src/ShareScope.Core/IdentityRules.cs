using System.Text.RegularExpressions;

namespace ShareScope.Core;

public static class IdentityRules
{
    private static readonly Regex SidPattern = new(@"^S-\d-\d+(-\d+)+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex DomainUsersSid = new(@"^S-1-5-21(-\d+)+-513$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex DomainGuestSid = new(@"^S-1-5-21(-\d+)+-501$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static bool IsEveryone(AccessEntry entry) =>
        SidIs(entry, "S-1-1-0") || NameIs(entry, "Everyone");

    public static bool IsAuthenticatedUsers(AccessEntry entry) =>
        SidIs(entry, "S-1-5-11") || NameIs(entry, "Authenticated Users");

    public static bool IsDomainUsers(AccessEntry entry)
    {
        if (SidMatches(entry.Sid, DomainUsersSid) || SidMatches(entry.Identity, DomainUsersSid))
            return true;
        return SimpleName(entry.Identity).Equals("Domain Users", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsBuiltinUsers(AccessEntry entry)
    {
        if (SidIs(entry, "S-1-5-32-545"))
            return true;
        return SimpleName(entry.Identity).Equals("Users", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsBroadPrincipal(AccessEntry entry) =>
        IsEveryone(entry) || IsAuthenticatedUsers(entry) || IsDomainUsers(entry) || IsBuiltinUsers(entry);

    public static bool IsAnonymous(AccessEntry entry) =>
        SidIs(entry, "S-1-5-7") || NameIs(entry, "ANONYMOUS LOGON");

    public static bool IsGuest(AccessEntry entry)
    {
        if (SidIs(entry, "S-1-5-32-546"))
            return true;
        if (SidMatches(entry.Sid, DomainGuestSid) || SidMatches(entry.Identity, DomainGuestSid))
            return true;
        return SimpleName(entry.Identity).Equals("Guest", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsAnonymousOrGuest(AccessEntry entry) => IsAnonymous(entry) || IsGuest(entry);

    public static bool IsOrphan(AccessEntry entry)
    {
        if (!entry.IdentityResolved || LooksLikeSid(entry.Identity))
            return true;
        return false;
    }

    public static bool LooksLikeSid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        return SidPattern.IsMatch(value.Trim());
    }

    public static string SimpleName(string identity)
    {
        var trimmed = identity.Trim();
        var index = trimmed.LastIndexOf('\\');
        if (index >= 0 && index < trimmed.Length - 1)
            return trimmed[(index + 1)..].Trim();
        index = trimmed.LastIndexOf('/');
        if (index >= 0 && index < trimmed.Length - 1)
            return trimmed[(index + 1)..].Trim();
        return trimmed;
    }

    public static bool SameIdentity(string candidate, AccessEntry entry)
    {
        if (string.IsNullOrWhiteSpace(candidate))
            return false;

        var query = candidate.Trim();
        if (LooksLikeSid(query))
            return SidEquals(query, entry.Sid) || SidEquals(query, entry.Identity);

        if (!string.IsNullOrWhiteSpace(entry.Sid) && SidEquals(query, entry.Sid))
            return true;

        if (query.Equals(entry.Identity.Trim(), StringComparison.OrdinalIgnoreCase))
            return true;

        return SimpleName(query).Equals(SimpleName(entry.Identity), StringComparison.OrdinalIgnoreCase);
    }

    private static bool SidIs(AccessEntry entry, string sid) =>
        SidEquals(entry.Sid, sid) || SidEquals(entry.Identity, sid);

    private static bool NameIs(AccessEntry entry, string simple) =>
        SimpleName(entry.Identity).Equals(simple, StringComparison.OrdinalIgnoreCase);

    private static bool SidMatches(string? value, Regex pattern) =>
        !string.IsNullOrWhiteSpace(value) && pattern.IsMatch(value.Trim());

    private static bool SidEquals(string? left, string? right) =>
        !string.IsNullOrWhiteSpace(left)
        && !string.IsNullOrWhiteSpace(right)
        && left.Trim().Equals(right.Trim(), StringComparison.OrdinalIgnoreCase);
}
