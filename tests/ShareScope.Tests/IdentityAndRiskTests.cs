using ShareScope.Core;
using Xunit;

namespace ShareScope.Tests;

public class IdentityRulesTests
{
    [Fact]
    public void RecognizesBroadPrincipalsByNameOrSid()
    {
        Assert.True(IdentityRules.IsEveryone(Entry("Everyone")));
        Assert.True(IdentityRules.IsEveryone(Entry("S-1-1-0", sid: "S-1-1-0")));
        Assert.True(IdentityRules.IsAuthenticatedUsers(Entry("NT AUTHORITY\\Authenticated Users", sid: "S-1-5-11")));
        Assert.True(IdentityRules.IsDomainUsers(Entry("CONTOSO\\Domain Users")));
        Assert.True(IdentityRules.IsDomainUsers(Entry("S-1-5-21-1-2-3-513", sid: "S-1-5-21-1-2-3-513")));
        Assert.True(IdentityRules.IsBuiltinUsers(Entry("BUILTIN\\Users", sid: "S-1-5-32-545")));
        Assert.False(IdentityRules.IsBuiltinUsers(Entry("CONTOSO\\Domain Users")));
        Assert.True(IdentityRules.IsBroadPrincipal(Entry("Users")));
        Assert.False(IdentityRules.IsBroadPrincipal(Entry("CONTOSO\\Finance-Read")));
    }

    [Fact]
    public void RecognizesGuestAnonymousAndOrphans()
    {
        Assert.True(IdentityRules.IsAnonymous(Entry("NT AUTHORITY\\ANONYMOUS LOGON", sid: "S-1-5-7")));
        Assert.True(IdentityRules.IsGuest(Entry("CONTOSO\\Guest")));
        Assert.True(IdentityRules.IsGuest(Entry("S-1-5-21-9-9-9-501", sid: "S-1-5-21-9-9-9-501")));
        Assert.True(IdentityRules.IsOrphan(Entry("S-1-5-21-1-2-3-999", resolved: false, sid: "S-1-5-21-1-2-3-999")));
        Assert.False(IdentityRules.IsOrphan(Entry("CONTOSO\\jsmith")));
    }

    [Theory]
    [InlineData("jsmith", "CONTOSO\\jsmith", true)]
    [InlineData("Users", "BUILTIN\\Users", true)]
    [InlineData("Users", "CONTOSO\\Domain Users", false)]
    [InlineData("S-1-1-0", "Everyone", true)]
    public void SameIdentityMatchesTheAccountNotASubstring(string query, string ace, bool expected)
    {
        var sid = ace == "Everyone" ? "S-1-1-0" : null;
        Assert.Equal(expected, IdentityRules.SameIdentity(query, Entry(ace, sid: sid)));
    }

    private static AccessEntry Entry(string identity, bool resolved = true, string? sid = null) =>
        Fixtures.Ace(identity, RightsSummarizer.Read, PermissionLayer.Ntfs, resolved: resolved, sid: sid);
}

public class SensitivePathTests
{
    [Theory]
    [InlineData("HR", @"D:\Shares\Notes", true)]
    [InlineData("Handouts", @"D:\Shares\Finance\Q1", true)]
    [InlineData("Policies", @"E:\Human Resources\Files", true)]
    [InlineData("Shard", @"D:\Shares\Shard", false)]
    [InlineData("Public", @"D:\Shares\Public", false)]
    public void SensitiveNamesUseWholeWords(string share, string path, bool expected) =>
        Assert.Equal(expected, SensitivePathRules.IsSensitive(share, path));

    [Theory]
    [InlineData(@"C:\", true)]
    [InlineData(@"C:", true)]
    [InlineData(@"D:\Windows\Temp", true)]
    [InlineData(@"C:\Program Files\ContosoApp\Data", true)]
    [InlineData(@"C:\Program Files (x86)\Vendor", true)]
    [InlineData(@"D:\Shares\WindowsWallpapers", false)]
    [InlineData(@"C:\WindowsApps", false)]
    [InlineData(@"\\CONTOSO-FS01\Finance", false)]
    public void SystemFoldersAreDriveRootsWindowsAndProgramFiles(string path, bool expected) =>
        Assert.Equal(expected, SensitivePathRules.IsSystemFolder(path));
}

public class RiskAnalyzerTests
{
    [Fact]
    public void BroadWriteIsHigh()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Team", @"D:\Shares\Team"),
            ntfsAces: new[] { Fixtures.Ace("BUILTIN\\Users", RightsSummarizer.Modify, PermissionLayer.Ntfs, sid: "S-1-5-32-545") });
        Assert.Equal(ShareRisk.High, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "BROAD_WRITE" && finding.Severity == RiskSeverity.High);
    }

    [Fact]
    public void BroadReadIsReview()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Public", @"D:\Shares\Public"),
            shareAces: new[] { Fixtures.Ace("NT AUTHORITY\\Authenticated Users", RightsSummarizer.ReadAndExecute, PermissionLayer.Share, sid: "S-1-5-11") });
        Assert.Equal(ShareRisk.Review, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "BROAD_READ");
        Assert.DoesNotContain(audit.Findings, finding => finding.Severity == RiskSeverity.High);
    }

    [Fact]
    public void EveryoneOnASensitiveShareIsHighEvenForRead()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Contracts", @"E:\Legal\Contracts"),
            shareAces: new[] { Fixtures.Ace("Everyone", RightsSummarizer.ReadAndExecute, PermissionLayer.Share, sid: "S-1-1-0") });
        Assert.Equal(ShareRisk.High, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "EVERYONE_SENSITIVE_SHARE");
    }

    [Fact]
    public void EveryoneReadOnNtfsAloneDoesNotUseTheShareSensitiveRule()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Contracts", @"E:\Legal\Contracts"),
            shareAces: new[] { Fixtures.Ace("CONTOSO\\Legal", RightsSummarizer.ReadAndExecute, PermissionLayer.Share) },
            ntfsAces: new[] { Fixtures.Ace("Everyone", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, sid: "S-1-1-0") });
        Assert.DoesNotContain(audit.Findings, finding => finding.Code == "EVERYONE_SENSITIVE_SHARE");
        Assert.Contains(audit.Findings, finding => finding.Code == "BROAD_READ");
    }

    [Fact]
    public void AnonymousAndGuestAllowAreHigh()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Lobby", @"E:\Lobby"),
            shareAces: new[] { Fixtures.Ace("CONTOSO\\Guest", RightsSummarizer.Read, PermissionLayer.Share) },
            ntfsAces: new[] { Fixtures.Ace("NT AUTHORITY\\ANONYMOUS LOGON", RightsSummarizer.Read, PermissionLayer.Ntfs, sid: "S-1-5-7") });
        Assert.Equal(ShareRisk.High, audit.OverallRisk);
        Assert.Equal(2, audit.Findings.Count(finding => finding.Code == "ANONYMOUS_OR_GUEST"));
    }

    [Fact]
    public void DenyIsNotedAndDoesNotCountAsBroadWrite()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("IT", @"E:\IT"),
            shareAces: new[]
            {
                Fixtures.Ace("Everyone", RightsSummarizer.FullControl, PermissionLayer.Share, effect: AceEffect.Deny, sid: "S-1-1-0"),
                Fixtures.Ace("CONTOSO\\IT-Admins", RightsSummarizer.FullControl, PermissionLayer.Share)
            });
        Assert.Equal(ShareRisk.Review, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "DENY_ACE");
        Assert.DoesNotContain(audit.Findings, finding => finding.Code == "BROAD_WRITE");
    }

    [Fact]
    public void OrphanedSidIsReview()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Archive", @"E:\Archive"),
            ntfsAces: new[]
            {
                Fixtures.Ace("S-1-5-21-1-2-3-9876", RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs, resolved: false, sid: "S-1-5-21-1-2-3-9876")
            });
        Assert.Equal(ShareRisk.Review, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "ORPHAN_SID" && finding.Explanation.Contains("deleted", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BrokenInheritanceAndSystemFoldersAreReview()
    {
        var broken = Fixtures.Analyze(
            Fixtures.Disk("Engineering", @"E:\Eng"),
            ntfsAces: new[] { Fixtures.Ace("CONTOSO\\Engineers", RightsSummarizer.Modify, PermissionLayer.Ntfs) },
            broken: true);
        Assert.Contains(broken.Findings, finding => finding.Code == "BROKEN_INHERITANCE");

        var system = Fixtures.Analyze(
            new ShareInfo("CONTOSO-FS01", "C$", @"C:\", ShareKind.Admin, "", 0),
            ntfsAces: new[] { Fixtures.Ace("BUILTIN\\Administrators", RightsSummarizer.FullControl, PermissionLayer.Ntfs, sid: "S-1-5-32-544") });
        Assert.Equal(ShareRisk.Review, system.OverallRisk);
        Assert.Contains(system.Findings, finding => finding.Code == "SYSTEM_FOLDER");
        Assert.DoesNotContain(system.Findings, finding => finding.Code == "BROAD_WRITE");
    }

    [Fact]
    public void SpecificGroupFullControlIsOk()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Deploy", @"D:\Deploy"),
            shareAces: new[] { Fixtures.Ace("CONTOSO\\Release-Managers", RightsSummarizer.FullControl, PermissionLayer.Share) },
            ntfsAces: new[] { Fixtures.Ace("CONTOSO\\Release-Managers", RightsSummarizer.Modify, PermissionLayer.Ntfs) });
        Assert.Equal(ShareRisk.Ok, audit.OverallRisk);
        Assert.Empty(audit.Findings);
    }

    [Fact]
    public void NullShareDaclIsHighAndUnreadableAclsAreReview()
    {
        var missing = Fixtures.Analyze(
            Fixtures.Disk("Open", @"D:\Open"),
            shareAcl: new AclSnapshot(true, null, null, false, false, Array.Empty<AccessEntry>()));
        Assert.Equal(ShareRisk.High, missing.OverallRisk);
        Assert.Contains(missing.Findings, finding => finding.Code == "NULL_DACL");

        var unread = Fixtures.Analyze(
            Fixtures.Disk("Locked", @"D:\Locked"),
            shareAcl: AclSnapshot.Failed("Access denied."));
        Assert.Contains(unread.Findings, finding => finding.Code == "SHARE_ACL_UNREAD");
        Assert.Equal(ShareRisk.Review, unread.OverallRisk);
    }

    [Fact]
    public void PrinterSharesDoNotRequireNtfs()
    {
        var printer = new ShareInfo("CONTOSO-FS02", "DenverPrinter", "", ShareKind.Printer, "copier", 1);
        var audit = RiskAnalyzer.Analyze(printer, AclSnapshot.FromEntries(Array.Empty<AccessEntry>()), AclSnapshot.Failed("no folder"));
        Assert.DoesNotContain(audit.Findings, finding => finding.Code == "NTFS_ACL_UNREAD");
        Assert.Equal(ShareRisk.Ok, audit.OverallRisk);
    }

    [Fact]
    public void SubfoldersAddBrokenInheritanceAndBroadWrite()
    {
        var folder = new SubfolderInspection(
            @"\\CONTOSO-FS01\Finance\Payroll",
            "Payroll",
            1,
            true,
            new[] { Fixtures.Ace("Everyone", RightsSummarizer.Modify, PermissionLayer.Subfolder, sid: "S-1-1-0") });
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Finance", @"D:\Shares\Finance"),
            shareAces: new[] { Fixtures.Ace("CONTOSO\\Finance-Managers", RightsSummarizer.Modify, PermissionLayer.Share) },
            subfolders: new[] { folder });
        Assert.Equal(ShareRisk.High, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "SUBFOLDER_BROKEN_INHERITANCE" && finding.Title.Contains("Payroll", StringComparison.Ordinal));
        Assert.Contains(audit.Findings, finding => finding.Code == "SUBFOLDER_BROAD_WRITE" && finding.Explanation.Contains("Payroll", StringComparison.Ordinal));
    }

    [Fact]
    public void HighOutranksReview()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Mixed", @"C:\Windows\Logs"),
            ntfsAces: new[] { Fixtures.Ace("BUILTIN\\Users", RightsSummarizer.Write, PermissionLayer.Ntfs, sid: "S-1-5-32-545") },
            broken: true);
        Assert.Equal(ShareRisk.High, audit.OverallRisk);
        Assert.Contains(audit.Findings, finding => finding.Code == "SYSTEM_FOLDER");
        Assert.Contains(audit.Findings, finding => finding.Code == "BROAD_WRITE");
    }

    [Fact]
    public void DomainUsersModifyIsHighAndNotConfusedWithBuiltinUsers()
    {
        var audit = Fixtures.Analyze(
            Fixtures.Disk("Staff", @"D:\Staff"),
            ntfsAces: new[] { Fixtures.Ace("CONTOSO\\Domain Users", RightsSummarizer.Modify, PermissionLayer.Ntfs, sid: "S-1-5-21-5-5-5-513") });
        Assert.Equal(ShareRisk.High, audit.OverallRisk);
        Assert.Single(audit.Findings, finding => finding.Code == "BROAD_WRITE");
        Assert.Contains("Domain Users", audit.TopTitle);
    }
}
