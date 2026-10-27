using System.Text.RegularExpressions;

namespace ShareScope.Core;

public static class SensitivePathRules
{
    private static readonly HashSet<string> Keywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "finance", "payroll", "salary", "salaries", "hr", "humanresources", "confidential", "secret",
        "executive", "executives", "legal", "contract", "contracts", "personal", "personnel",
        "medical", "hipaa", "ssn", "tax", "taxes", "board", "merger", "acquisition", "benefits",
        "compensation"
    };

    public static bool IsSensitive(string? shareName, string? path) =>
        ContainsKeyword(shareName) || ContainsKeyword(path);

    public static bool IsSystemFolder(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;

        var normalized = path.Replace('/', '\\').Trim().TrimEnd();
        if (normalized.StartsWith(@"\\?\", StringComparison.Ordinal))
            normalized = normalized[4..];
        normalized = normalized.TrimEnd();

        if (Regex.IsMatch(normalized, @"^[A-Za-z]:\\?$"))
            return true;
        if (Regex.IsMatch(normalized, @"^[A-Za-z]:\\Windows(\\.*)?$", RegexOptions.IgnoreCase))
            return true;
        if (Regex.IsMatch(normalized, @"^[A-Za-z]:\\Program Files(\\.*)?$", RegexOptions.IgnoreCase))
            return true;
        if (Regex.IsMatch(normalized, @"^[A-Za-z]:\\Program Files \(x86\)(\\.*)?$", RegexOptions.IgnoreCase))
            return true;
        return false;
    }

    private static bool ContainsKeyword(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var tokens = Regex.Split(value, @"[^A-Za-z0-9]+")
            .Where(part => part.Length > 0)
            .Select(part => part.ToLowerInvariant())
            .ToList();

        for (var i = 0; i < tokens.Count; i++)
        {
            if (Keywords.Contains(tokens[i]))
                return true;
            if (i + 1 < tokens.Count && Keywords.Contains(tokens[i] + tokens[i + 1]))
                return true;
        }

        return false;
    }
}
