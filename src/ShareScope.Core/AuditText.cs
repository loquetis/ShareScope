using System.Text;

namespace ShareScope.Core;

public static class AuditText
{
    public static string Effect(AceEffect effect) => effect == AceEffect.Allow ? "Allow" : "Deny";

    public static string Inherited(bool inherited) => inherited ? "Inherited" : "Not inherited";

    public static string FormatAce(AccessEntry entry) =>
        $"{entry.Identity} | {entry.Rights.Text} | {Effect(entry.Effect)} | {Inherited(entry.Inherited)} | {entry.AppliesTo}";

    public static string FormatAcl(IReadOnlyList<AccessEntry> entries) =>
        entries.Count == 0 ? "" : string.Join(" || ", entries.Select(FormatAce));

    public static string FormatFindings(IReadOnlyList<RiskFinding> findings) =>
        findings.Count == 0
            ? ""
            : string.Join(" || ", findings.Select(f => $"[{f.Severity}] {f.Title}: {f.Explanation}"));

    public static string FormatSubfolders(IReadOnlyList<SubfolderInspection> folders)
    {
        if (folders.Count == 0)
            return "";

        return string.Join(" || ", folders.Select(folder =>
        {
            var notes = new List<string>();
            if (folder.InheritanceProtected)
                notes.Add("broken inheritance");
            if (folder.Entries.Count > 0)
                notes.Add(FormatAcl(folder.Entries));
            var detail = notes.Count == 0 ? "checked" : string.Join("; ", notes);
            return $"{folder.RelativePath} ({detail})";
        }));
    }

    public static string FormatDetails(ShareAudit audit)
    {
        var builder = new StringBuilder();
        builder.AppendLine($"{AppInfo.Name} share details");
        builder.AppendLine($"Server: {audit.Share.Server}");
        builder.AppendLine($"Share: {audit.Share.Name}");
        builder.AppendLine($"UNC: {audit.Share.UncPath}");
        builder.AppendLine($"Path: {audit.Share.Path}");
        builder.AppendLine($"Type: {ShareClassifier.Display(audit.Share.Kind)}");
        builder.AppendLine($"Description: {audit.Share.Description}");
        builder.AppendLine($"Connections: {audit.Share.CurrentConnections?.ToString() ?? "n/a"}");
        builder.AppendLine($"Owner: {audit.Owner ?? "Not available"}");
        builder.AppendLine($"Risk: {audit.OverallRisk}");
        builder.AppendLine();
        builder.AppendLine("Share permissions:");
        AppendAces(builder, audit.ShareAcl);
        builder.AppendLine();
        builder.AppendLine("NTFS permissions:");
        AppendAces(builder, audit.NtfsAcl);
        if (audit.Subfolders.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("Subfolders:");
            foreach (var folder in audit.Subfolders)
            {
                builder.AppendLine($"- {folder.RelativePath} (inheritance {(folder.InheritanceProtected ? "broken" : "intact")})");
                foreach (var entry in folder.Entries)
                    builder.AppendLine($"  {FormatAce(entry)}");
            }
        }

        builder.AppendLine();
        builder.AppendLine("Risk notes:");
        if (audit.Findings.Count == 0)
            builder.AppendLine("- None");
        else
        {
            foreach (var finding in audit.Findings)
                builder.AppendLine($"- [{finding.Severity}] {finding.Title}. {finding.Explanation}");
        }

        return builder.ToString().TrimEnd();
    }

    private static void AppendAces(StringBuilder builder, AclSnapshot acl)
    {
        if (!acl.ReadSucceeded)
        {
            builder.AppendLine($"- Not read: {acl.FailureReason}");
            return;
        }

        if (acl.DaclPresent == false)
        {
            builder.AppendLine("- No discretionary access list.");
            return;
        }

        if (acl.Entries.Count == 0)
        {
            builder.AppendLine("- No entries.");
            return;
        }

        foreach (var entry in acl.Entries)
            builder.AppendLine($"- {FormatAce(entry)}");
    }
}
