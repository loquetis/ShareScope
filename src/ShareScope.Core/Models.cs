namespace ShareScope.Core;

public enum ShareKind
{
    Disk,
    Printer,
    Ipc,
    Admin,
    Special,
    Unknown
}

public enum AceEffect
{
    Allow,
    Deny
}

public enum PermissionLayer
{
    Share,
    Ntfs,
    Subfolder
}

public enum RiskSeverity
{
    Info = 0,
    Review = 1,
    High = 2
}

public enum ShareRisk
{
    Ok = 0,
    Review = 1,
    High = 2
}

/// <summary>Plain-language rights plus flags the risk rules can test without parsing text.</summary>
public sealed record RightsSummary(
    string Text,
    bool FullControl,
    bool ChangeOrModify,
    bool Write,
    bool Read,
    bool Special)
{
    public bool IsWriteCapable => FullControl || ChangeOrModify || Write;

    public static RightsSummary None { get; } = new("None", false, false, false, false, false);
}

public sealed record AccessEntry(
    string Identity,
    bool IdentityResolved,
    string? Sid,
    RightsSummary Rights,
    AceEffect Effect,
    bool Inherited,
    string AppliesTo,
    PermissionLayer Layer);

public sealed record AclSnapshot(
    bool ReadSucceeded,
    string? FailureReason,
    string? Owner,
    bool? InheritanceProtected,
    bool? DaclPresent,
    IReadOnlyList<AccessEntry> Entries)
{
    public static AclSnapshot Failed(string reason) =>
        new(false, reason, null, null, null, Array.Empty<AccessEntry>());

    public static AclSnapshot NotApplicable() =>
        new(true, null, null, null, true, Array.Empty<AccessEntry>());

    public static AclSnapshot FromEntries(
        IEnumerable<AccessEntry> entries,
        string? owner = null,
        bool inheritanceProtected = false,
        bool daclPresent = true) =>
        new(true, null, owner, inheritanceProtected, daclPresent, entries.ToList());
}

public sealed record ShareInfo(
    string Server,
    string Name,
    string Path,
    ShareKind Kind,
    string Description,
    int? CurrentConnections)
{
    public bool IsHidden => ShareClassifier.IsHidden(Name);

    public bool IsAdmin => ShareClassifier.IsAdministrative(Name);

    public string UncPath => UncPaths.Build(Server, Name);
}

public sealed record SubfolderInspection(
    string FullPath,
    string RelativePath,
    int Depth,
    bool InheritanceProtected,
    IReadOnlyList<AccessEntry> Entries);

public sealed record RiskFinding(
    RiskSeverity Severity,
    string Code,
    string Title,
    string Explanation,
    string? Location);

public sealed record ShareAudit(
    ShareInfo Share,
    string? Owner,
    AclSnapshot ShareAcl,
    AclSnapshot NtfsAcl,
    IReadOnlyList<SubfolderInspection> Subfolders,
    IReadOnlyList<RiskFinding> Findings)
{
    public ShareRisk OverallRisk
    {
        get
        {
            var max = RiskSeverity.Info;
            foreach (var finding in Findings)
            {
                if (finding.Severity > max)
                    max = finding.Severity;
            }

            return max switch
            {
                RiskSeverity.High => ShareRisk.High,
                RiskSeverity.Review => ShareRisk.Review,
                _ => ShareRisk.Ok
            };
        }
    }

    public RiskFinding? TopFinding =>
        Findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => FindingOrder(f.Code))
            .FirstOrDefault();

    public string TopTitle => TopFinding?.Title ?? "";

    private static int FindingOrder(string code) => code switch
    {
        "NULL_DACL" => 0,
        "ANONYMOUS_OR_GUEST" => 1,
        "EVERYONE_SENSITIVE_SHARE" => 2,
        "BROAD_WRITE" => 3,
        "SUBFOLDER_BROAD_WRITE" => 4,
        "BROAD_READ" => 5,
        "SYSTEM_FOLDER" => 6,
        "BROKEN_INHERITANCE" => 7,
        "SUBFOLDER_BROKEN_INHERITANCE" => 8,
        "ORPHAN_SID" => 9,
        "DENY_ACE" => 10,
        _ => 20
    };
}

public sealed record ScanIssue(string Server, string? Share, string Message);

public sealed record ScanProgress(string Message, int CompletedServers, int TotalServers);

public sealed record ScanRequest(
    IReadOnlyList<string> Servers,
    bool HideAdminAndHidden,
    int SubfolderDepth,
    int MaxParallelServers = 4);

public sealed record ScanOutcome(
    IReadOnlyList<ShareAudit> Shares,
    IReadOnlyList<ScanIssue> Issues,
    bool Canceled)
{
    public int Count(ShareRisk risk) => Shares.Count(s => s.OverallRisk == risk);
}

public sealed record GroupExpansion(
    IReadOnlyList<string> Identities,
    bool ExpandedFromDirectory,
    string Note);

public sealed record AccessHit(
    string Server,
    string Share,
    string Path,
    PermissionLayer Layer,
    string IdentityOnAce,
    string Via,
    string Rights,
    AceEffect Effect,
    bool Inherited,
    string AppliesTo);

public sealed record ComputerQueryResult(
    bool Succeeded,
    IReadOnlyList<string> Computers,
    string Message);
