using System.Text;

namespace ShareScope.Core;

public static class TargetListParser
{
    private static readonly HashSet<string> HeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "server", "servers", "computer", "computername", "name", "host", "hostname", "ip", "ipaddress", "fqdn"
    };

    public static IReadOnlyList<string> Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<string>();

        var rows = new List<List<string>>();
        foreach (var raw in text.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
                continue;
            if (line.StartsWith("//", StringComparison.Ordinal))
                continue;

            var fields = SplitFields(line);
            if (fields.Count > 0)
                rows.Add(fields);
        }

        if (rows.Count == 0)
            return Array.Empty<string>();

        var column = 0;
        var start = 0;
        var hasHeader = TryFindHeaderColumn(rows[0], out column);
        if (hasHeader)
            start = 1;

        var tokens = new List<string>();
        for (var i = start; i < rows.Count; i++)
        {
            var row = rows[i];
            if (hasHeader)
            {
                if (column < row.Count)
                    tokens.Add(row[column]);
            }
            else
            {
                tokens.AddRange(row);
            }
        }

        return Dedup(tokens);
    }

    public static string Format(IEnumerable<string> servers)
    {
        var builder = new StringBuilder();
        foreach (var server in servers)
        {
            if (string.IsNullOrWhiteSpace(server))
                continue;
            if (builder.Length > 0)
                builder.AppendLine();
            builder.Append(server.Trim());
        }

        return builder.ToString();
    }

    public static bool LooksLikeTarget(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var text = value.Trim();
        if (text.Length > 253)
            return false;
        if (text is ".")
            return true;

        foreach (var c in text)
        {
            if (char.IsLetterOrDigit(c) || c is '.' or '-' or '_' or ':')
                continue;
            return false;
        }

        return true;
    }

    private static bool TryFindHeaderColumn(IReadOnlyList<string> fields, out int column)
    {
        for (var i = 0; i < fields.Count; i++)
        {
            if (HeaderNames.Contains(fields[i].Trim()))
            {
                column = i;
                return true;
            }
        }

        column = 0;
        return false;
    }

    private static List<string> SplitFields(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        foreach (var c in line)
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (!inQuotes && c is ',' or ';' or '\t')
            {
                Add(fields, current);
                continue;
            }

            current.Append(c);
        }

        Add(fields, current);
        return fields;
    }

    private static void Add(List<string> fields, StringBuilder current)
    {
        var value = current.ToString().Trim();
        current.Clear();
        if (value.Length > 0)
            fields.Add(value);
    }

    private static IReadOnlyList<string> Dedup(IEnumerable<string> tokens)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var token in tokens)
        {
            var value = token.Trim().Trim('"');
            if (!LooksLikeTarget(value))
                continue;
            if (seen.Add(value))
                result.Add(value);
        }

        return result;
    }
}
