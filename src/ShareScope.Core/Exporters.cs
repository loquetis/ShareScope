using System.Text;

namespace ShareScope.Core;

public static class CsvExporter
{
    public static readonly string[] Headers =
    [
        "Server", "Share", "UncPath", "Path", "Type", "Description", "CurrentConnections",
        "Owner", "Risk", "SharePermissions", "NtfsPermissions", "Findings", "SubfolderNotes"
    ];

    public static string Build(ScanOutcome outcome)
    {
        var builder = new StringBuilder();
        builder.AppendLine(string.Join(",", Headers));
        foreach (var audit in outcome.Shares)
        {
            var cells = new[]
            {
                audit.Share.Server,
                audit.Share.Name,
                audit.Share.UncPath,
                audit.Share.Path,
                ShareClassifier.Display(audit.Share.Kind),
                audit.Share.Description,
                audit.Share.CurrentConnections?.ToString() ?? "",
                audit.Owner ?? "",
                audit.OverallRisk.ToString(),
                AuditText.FormatAcl(audit.ShareAcl.Entries),
                AuditText.FormatAcl(audit.NtfsAcl.Entries),
                AuditText.FormatFindings(audit.Findings),
                AuditText.FormatSubfolders(audit.Subfolders)
            };
            builder.AppendLine(string.Join(",", cells.Select(Escape)));
        }

        return builder.ToString();
    }

    public static void Write(string path, ScanOutcome outcome)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        File.WriteAllText(path, Build(outcome), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
    }

    public static string Escape(string? value)
    {
        var text = value ?? "";
        if (text.Contains('"') || text.Contains(',') || text.Contains('\n') || text.Contains('\r'))
            return "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        return text;
    }
}

public static class HtmlExporter
{
    public static string Build(ScanOutcome outcome, DateTimeOffset? generated = null)
    {
        var when = generated ?? DateTimeOffset.Now;
        var high = outcome.Count(ShareRisk.High);
        var review = outcome.Count(ShareRisk.Review);
        var ok = outcome.Count(ShareRisk.Ok);
        var servers = outcome.Shares.Select(s => s.Share.Server).Distinct(StringComparer.OrdinalIgnoreCase).Count();

        var builder = new StringBuilder();
        builder.AppendLine("<!DOCTYPE html>");
        builder.AppendLine("<html lang=\"en\">");
        builder.AppendLine("<head>");
        builder.AppendLine("<meta charset=\"utf-8\"/>");
        builder.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>");
        builder.AppendLine($"<title>{Encode(AppInfo.Name)} audit report</title>");
        builder.AppendLine("<style>");
        builder.AppendLine(Css);
        builder.AppendLine("</style>");
        builder.AppendLine("</head>");
        builder.AppendLine("<body>");
        builder.AppendLine("<header>");
        builder.AppendLine($"<div><h1>{Encode(AppInfo.Name)}</h1><p>{Encode(AppInfo.Tagline)}</p></div>");
        builder.AppendLine($"<div class=\"version\">v{Encode(AppInfo.Version)}</div>");
        builder.AppendLine("</header>");
        builder.AppendLine("<main>");
        builder.AppendLine($"<p class=\"meta\">Generated {Encode(when.ToString("yyyy-MM-dd HH:mm"))}. {Encode(AppInfo.ReadOnlyStatement)}</p>");
        builder.AppendLine("<section class=\"cards\">");
        Card(builder, "Servers", servers.ToString());
        Card(builder, "Shares", outcome.Shares.Count.ToString());
        Card(builder, "High", high.ToString());
        Card(builder, "Review", review.ToString());
        Card(builder, "OK", ok.ToString());
        builder.AppendLine("</section>");

        if (outcome.Canceled)
            builder.AppendLine("<p class=\"banner\">The scan was canceled. This report contains the shares read before it stopped.</p>");

        builder.AppendLine("<table>");
        builder.AppendLine("<thead><tr><th>Server</th><th>Share</th><th>Path</th><th>Type</th><th>Risk</th><th>Top note</th></tr></thead>");
        builder.AppendLine("<tbody>");
        foreach (var audit in outcome.Shares)
        {
            var risk = audit.OverallRisk.ToString().ToLowerInvariant();
            builder.Append("<tr>");
            builder.Append($"<td>{Encode(audit.Share.Server)}</td>");
            builder.Append($"<td>{Encode(audit.Share.Name)}</td>");
            builder.Append($"<td>{Encode(audit.Share.Path)}</td>");
            builder.Append($"<td>{Encode(ShareClassifier.Display(audit.Share.Kind))}</td>");
            builder.Append($"<td><span class=\"pill {risk}\">{Encode(audit.OverallRisk.ToString())}</span></td>");
            builder.Append($"<td>{Encode(audit.TopTitle)}</td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table>");

        foreach (var audit in outcome.Shares)
        {
            builder.AppendLine("<article>");
            builder.AppendLine($"<h2>{Encode(audit.Share.UncPath)} <span class=\"pill {audit.OverallRisk.ToString().ToLowerInvariant()}\">{Encode(audit.OverallRisk.ToString())}</span></h2>");
            builder.AppendLine("<p>");
            builder.Append(Encode($"Path {audit.Share.Path}. Type {ShareClassifier.Display(audit.Share.Kind)}. "));
            builder.Append(Encode($"Owner {(audit.Owner ?? "not available")}. "));
            builder.Append(Encode(string.IsNullOrWhiteSpace(audit.Share.Description) ? "" : audit.Share.Description));
            builder.AppendLine("</p>");
            builder.AppendLine("<h3>Share permissions</h3>");
            AclTable(builder, audit.ShareAcl);
            builder.AppendLine("<h3>NTFS permissions</h3>");
            AclTable(builder, audit.NtfsAcl);
            if (audit.Subfolders.Count > 0)
            {
                builder.AppendLine("<h3>Subfolders</h3>");
                builder.AppendLine("<ul>");
                foreach (var folder in audit.Subfolders)
                {
                    var inheritance = folder.InheritanceProtected ? "Inheritance broken." : "Inheritance intact.";
                    builder.AppendLine($"<li><strong>{Encode(folder.RelativePath)}</strong> {Encode(inheritance)}");
                    if (folder.Entries.Count > 0)
                    {
                        builder.AppendLine("<ul>");
                        foreach (var entry in folder.Entries)
                            builder.AppendLine($"<li>{Encode(AuditText.FormatAce(entry))}</li>");
                        builder.AppendLine("</ul>");
                    }
                    builder.AppendLine("</li>");
                }
                builder.AppendLine("</ul>");
            }

            builder.AppendLine("<h3>Risk notes</h3>");
            if (audit.Findings.Count == 0)
                builder.AppendLine("<p>No risk flags.</p>");
            else
            {
                builder.AppendLine("<ul class=\"notes\">");
                foreach (var finding in audit.Findings)
                {
                    builder.Append("<li>");
                    builder.Append($"<span class=\"pill {finding.Severity.ToString().ToLowerInvariant()}\">{Encode(finding.Severity.ToString())}</span> ");
                    builder.Append($"<strong>{Encode(finding.Title)}</strong> {Encode(finding.Explanation)}");
                    builder.AppendLine("</li>");
                }
                builder.AppendLine("</ul>");
            }
            builder.AppendLine("</article>");
        }

        if (outcome.Issues.Count > 0)
        {
            builder.AppendLine("<h2>Scan issues</h2><ul>");
            foreach (var issue in outcome.Issues)
            {
                var where = string.IsNullOrWhiteSpace(issue.Share) ? issue.Server : $"{issue.Server}\\{issue.Share}";
                builder.AppendLine($"<li>{Encode(where)}: {Encode(issue.Message)}</li>");
            }
            builder.AppendLine("</ul>");
        }

        builder.AppendLine("</main>");
        builder.AppendLine($"<footer>{Encode(AppInfo.Name)} {Encode(AppInfo.Version)}. {Encode(AppInfo.ReadOnlyStatement)}</footer>");
        builder.AppendLine("</body></html>");
        return builder.ToString();
    }

    public static void Write(string path, ScanOutcome outcome)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        File.WriteAllText(path, Build(outcome), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    public static string Encode(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        return value
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);
    }

    private static void Card(StringBuilder builder, string label, string value)
    {
        builder.Append("<div class=\"card\"><span>");
        builder.Append(Encode(label));
        builder.Append("</span><strong>");
        builder.Append(Encode(value));
        builder.AppendLine("</strong></div>");
    }

    private static void AclTable(StringBuilder builder, AclSnapshot acl)
    {
        if (!acl.ReadSucceeded)
        {
            builder.AppendLine($"<p>Not read: {Encode(acl.FailureReason)}</p>");
            return;
        }

        if (acl.DaclPresent == false)
        {
            builder.AppendLine("<p>No discretionary access list.</p>");
            return;
        }

        if (acl.Entries.Count == 0)
        {
            builder.AppendLine("<p>No entries.</p>");
            return;
        }

        builder.AppendLine("<table><thead><tr><th>Identity</th><th>Rights</th><th>Type</th><th>Inherited</th><th>Applies to</th></tr></thead><tbody>");
        foreach (var entry in acl.Entries)
        {
            builder.Append("<tr>");
            builder.Append($"<td>{Encode(entry.Identity)}</td>");
            builder.Append($"<td>{Encode(entry.Rights.Text)}</td>");
            builder.Append($"<td>{Encode(AuditText.Effect(entry.Effect))}</td>");
            builder.Append($"<td>{Encode(AuditText.Inherited(entry.Inherited))}</td>");
            builder.Append($"<td>{Encode(entry.AppliesTo)}</td>");
            builder.AppendLine("</tr>");
        }
        builder.AppendLine("</tbody></table>");
    }

    private const string Css = """
        :root { color-scheme: light; }
        body { margin: 0; font: 15px/1.45 "Segoe UI", system-ui, sans-serif; color: #0f172a; background: #f4f7fb; }
        header { background: #0b2545; color: #f8fafc; padding: 20px 28px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }
        header h1 { margin: 0; font-size: 28px; }
        header p { margin: 4px 0 0; color: #cbd5e1; }
        .version { color: #99f6e4; font-weight: 600; }
        main { padding: 20px 28px 40px; }
        .meta { color: #475569; }
        .cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 12px 0 20px; }
        .card { background: white; border: 1px solid #dbe3ee; border-radius: 10px; padding: 12px 16px; min-width: 100px; }
        .card span { display: block; color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
        .card strong { font-size: 24px; }
        table { width: 100%; border-collapse: collapse; background: white; margin: 8px 0 18px; }
        th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
        th { background: #0f2a4a; color: white; font-weight: 600; }
        article { background: white; border: 1px solid #dbe3ee; border-radius: 12px; padding: 16px 18px; margin: 16px 0; }
        article h2 { margin: 0 0 8px; font-size: 20px; }
        h3 { margin: 16px 0 6px; font-size: 15px; color: #0f766e; }
        .pill { display: inline-block; border-radius: 999px; padding: 2px 8px; font-size: 12px; font-weight: 700; }
        .high { background: #fee2e2; color: #991b1b; }
        .review { background: #fef3c7; color: #92400e; }
        .ok, .info { background: #d1fae5; color: #065f46; }
        .banner { background: #fef3c7; border-radius: 8px; padding: 10px 12px; }
        .notes { padding-left: 18px; }
        footer { padding: 16px 28px 28px; color: #64748b; }
        """;
}
