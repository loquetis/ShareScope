using ShareScope.Core;
using Xunit;

namespace ShareScope.Tests;

public class TargetListParserTests
{
    [Fact]
    public void EmptyInputYieldsNoTargets()
    {
        Assert.Empty(TargetListParser.Parse(null));
        Assert.Empty(TargetListParser.Parse("   \n\n  "));
    }

    [Fact]
    public void ParsesLinesCommentsAndSeparators()
    {
        var text = """
            # file servers
            CONTOSO-FS01
            // ignored
            CONTOSO-FS02, 10.0.20.15; contoso-fs03.contoso.local
            """;
        var targets = TargetListParser.Parse(text);
        Assert.Equal(new[] { "CONTOSO-FS01", "CONTOSO-FS02", "10.0.20.15", "contoso-fs03.contoso.local" }, targets);
    }

    [Fact]
    public void DeduplicatesIgnoringCase()
    {
        var targets = TargetListParser.Parse("FS01\nfs01\nFs01");
        Assert.Equal(new[] { "FS01" }, targets);
    }

    [Fact]
    public void ReadsNamedCsvColumnAndSkipsTheHeader()
    {
        var text = """
            Role,Computer,Site
            file,CONTOSO-FS01,east
            app,CONTOSO-APP01,west
            """;
        Assert.Equal(new[] { "CONTOSO-FS01", "CONTOSO-APP01" }, TargetListParser.Parse(text));
    }

    [Fact]
    public void DropsTokensThatAreNotHostNames()
    {
        var targets = TargetListParser.Parse("good-host, not a host, D:\\Shares, ok_1");
        Assert.Equal(new[] { "good-host", "ok_1" }, targets);
    }

    [Fact]
    public void AcceptsQuotedFieldsLocalDotAndIpv6()
    {
        var targets = TargetListParser.Parse("\"CONTOSO-FS01\"\n.\nfe80::1");
        Assert.Equal(new[] { "CONTOSO-FS01", ".", "fe80::1" }, targets);
    }

    [Fact]
    public void FormatRoundTripsASavedList()
    {
        var formatted = TargetListParser.Format(new[] { "CONTOSO-FS01", "10.1.1.8" });
        Assert.Equal(new[] { "CONTOSO-FS01", "10.1.1.8" }, TargetListParser.Parse(formatted));
    }

    [Theory]
    [InlineData("", false)]
    [InlineData(".", true)]
    [InlineData("has space", false)]
    [InlineData("bad/name", false)]
    [InlineData("server_1.contoso.local", true)]
    public void LooksLikeTargetRejectsUnsafeText(string value, bool expected) =>
        Assert.Equal(expected, TargetListParser.LooksLikeTarget(value));
}

public class ShareClassifierTests
{
    [Theory]
    [InlineData(0u, "Finance", ShareKind.Disk)]
    [InlineData(1u, "DenverPrinter", ShareKind.Printer)]
    [InlineData(3u, "IPC$", ShareKind.Ipc)]
    [InlineData(0u, "C$", ShareKind.Admin)]
    [InlineData(0u, "admin$", ShareKind.Admin)]
    [InlineData(0u, "PRINT$", ShareKind.Admin)]
    [InlineData(0u, "IT$", ShareKind.Special)]
    [InlineData(0x80000000u, "Secret$", ShareKind.Special)]
    public void ClassifiesShareTypeAndName(uint type, string name, ShareKind expected) =>
        Assert.Equal(expected, ShareClassifier.Classify(type, name));

    [Fact]
    public void AdministrativeNamesIncludeDriveRoots()
    {
        Assert.True(ShareClassifier.IsAdministrative("E$"));
        Assert.False(ShareClassifier.IsAdministrative("Finance"));
        Assert.True(ShareClassifier.IsHidden("IT$"));
        Assert.Equal(@"\\CONTOSO-FS01\Finance", UncPaths.Build("CONTOSO-FS01", "Finance"));
        Assert.Equal(@"\\FILE01\Public", UncPaths.Build(".", "Public", "FILE01"));
    }

    [Theory]
    [InlineData(ShareKind.Disk, "Disk")]
    [InlineData(ShareKind.Ipc, "IPC")]
    [InlineData(ShareKind.Admin, "Admin")]
    [InlineData(ShareKind.Special, "Special")]
    public void DisplayNamesAreTheWordsOperatorsExpect(ShareKind kind, string text) =>
        Assert.Equal(text, ShareClassifier.Display(kind));
}

public class RightsSummarizerTests
{
    [Fact]
    public void ShareLevelsUseFullChangeAndRead()
    {
        var full = RightsSummarizer.Summarize(RightsSummarizer.FullControl, PermissionLayer.Share);
        var change = RightsSummarizer.Summarize(RightsSummarizer.Modify, PermissionLayer.Share);
        var read = RightsSummarizer.Summarize(RightsSummarizer.ReadAndExecute, PermissionLayer.Share);
        Assert.Equal("Full Control", full.Text);
        Assert.True(full.FullControl && full.IsWriteCapable);
        Assert.Equal("Change", change.Text);
        Assert.True(change.ChangeOrModify && change.IsWriteCapable);
        Assert.Equal("Read", read.Text);
        Assert.True(read.Read);
        Assert.False(read.IsWriteCapable);
    }

    [Fact]
    public void NtfsLevelsUseModifyReadExecuteAndWrite()
    {
        Assert.Equal("Modify", RightsSummarizer.Summarize(RightsSummarizer.Modify, PermissionLayer.Ntfs).Text);
        Assert.Equal("Read & Execute", RightsSummarizer.Summarize(RightsSummarizer.ReadAndExecute, PermissionLayer.Ntfs).Text);
        Assert.Equal("Read", RightsSummarizer.Summarize(RightsSummarizer.Read, PermissionLayer.Ntfs).Text);
        var write = RightsSummarizer.Summarize(RightsSummarizer.Write, PermissionLayer.Ntfs);
        Assert.Equal("Write", write.Text);
        Assert.True(write.IsWriteCapable);
        Assert.False(write.Read);
        Assert.Equal("Write", RightsSummarizer.Summarize(RightsSummarizer.FileGenericWrite, PermissionLayer.Ntfs).Text);
    }

    [Fact]
    public void GenericAllIsFullControl()
    {
        var rights = RightsSummarizer.Summarize(RightsSummarizer.GenericAll, PermissionLayer.Ntfs);
        Assert.Equal("Full Control", rights.Text);
        Assert.True(rights.FullControl);
    }

    [Fact]
    public void PartialMasksStayInPlainWordsAndStillCountAsWrite()
    {
        var deleted = RightsSummarizer.Summarize(RightsSummarizer.Delete, PermissionLayer.Ntfs);
        Assert.Contains("Delete", deleted.Text);
        Assert.True(deleted.Special && deleted.IsWriteCapable);

        var control = RightsSummarizer.Summarize(RightsSummarizer.WriteDac, PermissionLayer.Ntfs);
        Assert.Equal("Change permissions", control.Text);
        Assert.True(control.IsWriteCapable);

        Assert.Equal("None", RightsSummarizer.Summarize(0, PermissionLayer.Ntfs).Text);
    }

    [Fact]
    public void SubfolderLayerUsesNtfsWords()
    {
        var rights = RightsSummarizer.Summarize(RightsSummarizer.Modify, PermissionLayer.Subfolder);
        Assert.Equal("Modify", rights.Text);
    }
}

public class AppliesToFormatterTests
{
    [Fact]
    public void ShareAcesApplyToTheShare() =>
        Assert.Equal("This share", AppliesToFormatter.Describe(3, 0, PermissionLayer.Share));

    [Fact]
    public void DescribesFolderFileAndInheritOnlyScopes()
    {
        Assert.Equal("This folder only", AppliesToFormatter.Describe(0, 0, PermissionLayer.Ntfs));
        Assert.Equal(
            "This folder, subfolders and files",
            AppliesToFormatter.Describe(AppliesToFormatter.ContainerInherit | AppliesToFormatter.ObjectInherit, 0, PermissionLayer.Ntfs));
        Assert.Equal(
            "Subfolders and files only",
            AppliesToFormatter.Describe(
                AppliesToFormatter.ContainerInherit | AppliesToFormatter.ObjectInherit,
                AppliesToFormatter.InheritOnly,
                PermissionLayer.Ntfs));
        Assert.Equal(
            "This folder and subfolders",
            AppliesToFormatter.Describe(AppliesToFormatter.ContainerInherit, 0, PermissionLayer.Ntfs));
        Assert.Equal(
            "Files only",
            AppliesToFormatter.Describe(AppliesToFormatter.ObjectInherit, AppliesToFormatter.InheritOnly, PermissionLayer.Ntfs));
        Assert.Equal(
            "This folder, subfolders and files (one level)",
            AppliesToFormatter.Describe(
                AppliesToFormatter.ContainerInherit | AppliesToFormatter.ObjectInherit,
                AppliesToFormatter.NoPropagateInherit,
                PermissionLayer.Ntfs));
    }
}
