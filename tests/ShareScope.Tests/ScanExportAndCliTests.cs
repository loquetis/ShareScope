using ShareScope.Core;
using Xunit;

namespace ShareScope.Tests;

public class AccessQueryTests
{
    [Fact]
    public void DirectMatchDoesNotExpandGroups()
    {
        var shares = DemoCatalog.All(hideAdminAndHidden: true, subfolderDepth: 2);
        var expansion = new DirectOnlyGroupResolver().Expand("jsmith");
        var hits = AccessQuery.Find(shares, "jsmith", expansion);
        Assert.Contains(hits, hit => hit.Share == "Projects" && hit.Via == "Direct");
        Assert.DoesNotContain(hits, hit => hit.Share == "Finance");
        Assert.False(expansion.ExpandedFromDirectory);
        Assert.Contains("direct ACE", expansion.Note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DemoDirectoryExpandsGroupMembership()
    {
        var shares = DemoCatalog.All(hideAdminAndHidden: true, subfolderDepth: 2);
        var expansion = new DemoGroupResolver().Expand("CONTOSO\\jsmith");
        var hits = AccessQuery.Find(shares, "jsmith", expansion);
        Assert.True(expansion.ExpandedFromDirectory);
        Assert.Contains(hits, hit => hit.Share == "Finance" && hit.Via.Contains("Finance-Read", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(hits, hit => hit.Share == "Public" && hit.Via.Contains("Domain Users", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("fictional", expansion.Note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnknownAccountSaysMatchesAreDirectOnly()
    {
        var expansion = new DemoGroupResolver().Expand("CONTOSO\\nobody");
        Assert.False(expansion.ExpandedFromDirectory);
        Assert.Contains("direct ACE", expansion.Note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HrManagerMatchesTheHrShare()
    {
        var shares = DemoCatalog.All(true, 1);
        var hits = AccessQuery.Find(shares, "mchen", new DemoGroupResolver().Expand("mchen"));
        Assert.Contains(hits, hit => hit.Share == "HR" && hit.Via.Contains("HR-Managers", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BlankIdentityMatchesNothing()
    {
        var shares = DemoCatalog.All(true, 0);
        Assert.Empty(AccessQuery.Find(shares, "  ", new DirectOnlyGroupResolver().Expand("  ")));
    }
}

public class ExporterTests
{
    [Fact]
    public void CsvEscapesCommasQuotesAndNewlines()
    {
        Assert.Equal("plain", CsvExporter.Escape("plain"));
        Assert.Equal("\"a,b\"", CsvExporter.Escape("a,b"));
        Assert.Equal("\"say \"\"hi\"\"\"", CsvExporter.Escape("say \"hi\""));
        var cell = CsvExporter.Escape("line\n2");
        Assert.StartsWith("\"", cell);
        Assert.Contains("\n", cell);
    }

    [Fact]
    public void CsvContainsHeaderRiskAndShareRows()
    {
        var outcome = new ScanOutcome(DemoCatalog.All(true, 2), Array.Empty<ScanIssue>(), false);
        var csv = CsvExporter.Build(outcome);
        Assert.StartsWith("Server,Share,UncPath", csv);
        Assert.Contains("Finance", csv);
        Assert.Contains("High", csv);
        Assert.Contains(@"\\CONTOSO-FS01\Finance", csv);
    }

    [Fact]
    public void HtmlReportIsSelfContainedAndEscapesMarkup()
    {
        var share = Fixtures.Disk("Ops", @"D:\Ops");
        var audit = Fixtures.Analyze(share, shareAces: new[]
        {
            Fixtures.Ace("CONTOSO\\<script>", RightsSummarizer.ReadAndExecute, PermissionLayer.Share)
        });
        var html = HtmlExporter.Build(new ScanOutcome(new[] { audit }, new[] { new ScanIssue("bad", null, "down") }, false));
        Assert.Contains("<style>", html);
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains(AppInfo.ReadOnlyStatement, html);
        Assert.Contains("Scan issues", html);
        Assert.DoesNotContain("http://", html);
        Assert.DoesNotContain("https://", html);
    }

    [Fact]
    public void HtmlEncodesAmpersands() =>
        Assert.Equal("A &amp; B", HtmlExporter.Encode("A & B"));

    [Fact]
    public void DetailsTextIncludesAcesAndRiskNotes()
    {
        var audit = DemoCatalog.SharesFor("CONTOSO-FS01", true, 2).Single(item => item.Share.Name == "Finance");
        var text = AuditText.FormatDetails(audit);
        Assert.Contains(@"\\CONTOSO-FS01\Finance", text);
        Assert.Contains("Everyone", text);
        Assert.Contains("High", text);
        Assert.Contains("read-only", AppInfo.ReadOnlyStatement, StringComparison.OrdinalIgnoreCase);
    }
}

public class DemoCatalogTests
{
    [Fact]
    public void HiddenDemoSetCoversEveryRiskLevelWithoutAdminShares()
    {
        var shares = DemoCatalog.All(hideAdminAndHidden: true, subfolderDepth: 2);
        Assert.Contains(shares, share => share.OverallRisk == ShareRisk.High);
        Assert.Contains(shares, share => share.OverallRisk == ShareRisk.Review);
        Assert.Contains(shares, share => share.OverallRisk == ShareRisk.Ok);
        Assert.DoesNotContain(shares, share => share.Share.IsAdmin || share.Share.IsHidden);
        Assert.Contains(shares, share => share.Share.Name == "Finance" && share.OverallRisk == ShareRisk.High);
        Assert.Contains(shares, share => share.Share.Name == "Projects" && share.OverallRisk == ShareRisk.Ok);
    }

    [Fact]
    public void DepthZeroOmitsSubfolderFindings()
    {
        var finance = DemoCatalog.SharesFor("CONTOSO-FS01", true, 0).Single(share => share.Share.Name == "Finance");
        Assert.Empty(finance.Subfolders);
        Assert.DoesNotContain(finance.Findings, finding => finding.Code.StartsWith("SUBFOLDER", StringComparison.Ordinal));
    }

    [Fact]
    public void ShowingHiddenSharesIncludesTheSystemDrive()
    {
        var shares = DemoCatalog.All(false, 0);
        Assert.Contains(shares, share => share.Share.Name == "C$" && share.Findings.Any(finding => finding.Code == "SYSTEM_FOLDER"));
        Assert.Contains(shares, share => share.Share.Name == "IPC$" && share.Share.Kind == ShareKind.Ipc);
    }

    [Fact]
    public void ServersAreTheFictionalContosoSet()
    {
        Assert.Equal(new[] { "CONTOSO-FS01", "CONTOSO-FS02", "CONTOSO-APP01" }, DemoCatalog.ServerNames);
        Assert.Equal(AppInfo.Version, "1.0.0");
    }
}

public class ScanOrchestratorTests
{
    [Fact]
    public async Task LimitsHowManyServersRunAtOnce()
    {
        var auditor = new HoldAuditor();
        var session = new ScanOrchestrator(auditor);
        var servers = Enumerable.Range(1, 6).Select(index => "FS" + index).ToArray();
        var outcome = await session.ScanAsync(new ScanRequest(servers, false, 0, MaxParallelServers: 2), null, CancellationToken.None);
        Assert.Equal(6, outcome.Shares.Count);
        Assert.InRange(auditor.Peak, 2, 2);
    }

    [Fact]
    public async Task RecordsAServerFailureAndKeepsTheRest()
    {
        var session = new ScanOrchestrator(new ScriptedAuditor(server =>
        {
            if (server == "bad")
                throw new InvalidOperationException("offline");
            return new[] { Ok(server) };
        }));
        var outcome = await session.ScanAsync(new ScanRequest(new[] { "bad", "good" }, false, 0), null, CancellationToken.None);
        Assert.Single(outcome.Shares);
        Assert.Equal("good", outcome.Shares[0].Share.Server);
        Assert.Contains("offline", outcome.Issues.Single().Message);
    }

    [Fact]
    public async Task CancelReturnsPartialResults()
    {
        var session = new ScanOrchestrator(new ScriptedAuditor(_ => throw new OperationCanceledException()));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var outcome = await session.ScanAsync(new ScanRequest(new[] { "FS01", "FS02" }, false, 0), null, cts.Token);
        Assert.True(outcome.Canceled);
    }

    [Fact]
    public async Task PassesHideAndDepthThroughToTheAuditor()
    {
        var auditor = new RecordingAuditor();
        var session = new ScanOrchestrator(auditor);
        await session.ScanAsync(new ScanRequest(new[] { "CONTOSO-FS01" }, true, 2), null, CancellationToken.None);
        Assert.True(auditor.Hide);
        Assert.Equal(2, auditor.Depth);
    }

    [Fact]
    public async Task OrdersHighRiskAheadOfOk()
    {
        var session = new ScanOrchestrator(new DemoServerAuditor());
        var outcome = await session.ScanAsync(new ScanRequest(DemoCatalog.ServerNames, true, 2), null, CancellationToken.None);
        Assert.Equal(ShareRisk.High, outcome.Shares[0].OverallRisk);
        Assert.True(outcome.Count(ShareRisk.High) > 0);
    }

    private static ShareAudit Ok(string server) =>
        Fixtures.Analyze(
            new ShareInfo(server, "Data", @"D:\Data", ShareKind.Disk, "", 0),
            shareAces: new[] { Fixtures.Ace("CONTOSO\\Ops", RightsSummarizer.ReadAndExecute, PermissionLayer.Share) });

    private sealed class HoldAuditor : IServerAuditor
    {
        private int _current;
        private int _entered;
        public int Peak;

        public async Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
            string server,
            bool hideAdminAndHidden,
            int subfolderDepth,
            IProgress<ScanProgress>? progress,
            CancellationToken cancellationToken)
        {
            var now = Interlocked.Increment(ref _current);
            UpdatePeak(now);
            var seen = Interlocked.Increment(ref _entered);
            try
            {
                await Task.Delay(seen < 2 ? 150 : 40, cancellationToken);
                return new[] { Ok(server) };
            }
            finally
            {
                Interlocked.Decrement(ref _current);
            }
        }

        private void UpdatePeak(int now)
        {
            int observed;
            do
            {
                observed = Peak;
                if (now <= observed)
                    return;
            }
            while (Interlocked.CompareExchange(ref Peak, now, observed) != observed);
        }
    }

    private sealed class ScriptedAuditor : IServerAuditor
    {
        private readonly Func<string, IReadOnlyList<ShareAudit>> _build;
        public ScriptedAuditor(Func<string, IReadOnlyList<ShareAudit>> build) => _build = build;

        public Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
            string server,
            bool hideAdminAndHidden,
            int subfolderDepth,
            IProgress<ScanProgress>? progress,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_build(server));
        }
    }

    private sealed class RecordingAuditor : IServerAuditor
    {
        public bool Hide;
        public int Depth;

        public Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
            string server,
            bool hideAdminAndHidden,
            int subfolderDepth,
            IProgress<ScanProgress>? progress,
            CancellationToken cancellationToken)
        {
            Hide = hideAdminAndHidden;
            Depth = subfolderDepth;
            return Task.FromResult<IReadOnlyList<ShareAudit>>(new[] { Ok(server) });
        }
    }
}

public class CliRunnerTests
{
    [Fact]
    public void HelpSucceedsAndDoesNotAdvertiseDemo()
    {
        var stdout = new StringWriter();
        var code = CliRunner.Run(new[] { "--help" }, stdout, new StringWriter());
        Assert.Equal(0, code);
        Assert.Contains("--scan", stdout.ToString());
        Assert.Contains("High-risk share", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("--demo", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains(AppInfo.ReadOnlyStatement, stdout.ToString());
    }

    [Theory]
    [InlineData("--frob")]
    [InlineData("--depth|99")]
    [InlineData("--scan")]
    [InlineData("--depth|nope")]
    public void BadArgumentsReturnExitCode2(string packed)
    {
        var args = packed.Split('|', StringSplitOptions.RemoveEmptyEntries);
        var code = CliRunner.Run(args, new StringWriter(), new StringWriter());
        Assert.Equal(2, code);
    }

    [Fact]
    public void MissingServerListReturnsExitCode2()
    {
        var stderr = new StringWriter();
        var code = CliRunner.Run(new[] { "--scan", Path.Combine(Path.GetTempPath(), "missing-sharescope-servers.txt") }, new StringWriter(), stderr);
        Assert.Equal(2, code);
        Assert.Contains("not found", stderr.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EmptyServerListReturnsExitCode2()
    {
        var path = Path.Combine(Path.GetTempPath(), "sharescope-empty-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "# nothing\n\n");
        try
        {
            var code = CliRunner.Run(new[] { "--scan", path }, new StringWriter(), new StringWriter());
            Assert.Equal(2, code);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void DemoScanWritesReportsAndReturnsHighRisk()
    {
        var root = Path.Combine(Path.GetTempPath(), "sharescope-cli-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var csv = Path.Combine(root, "out.csv");
        var html = Path.Combine(root, "out.html");
        try
        {
            var stdout = new StringWriter();
            var code = CliRunner.Run(
                new[] { "--demo", "--scan", "ignored.txt", "--csv", csv, "--html", html, "--hide-admin", "--depth", "2" },
                stdout,
                new StringWriter());
            Assert.Equal(1, code);
            Assert.Contains("High-risk", stdout.ToString());
            Assert.Contains("No network", stdout.ToString());
            Assert.Contains("Finance", File.ReadAllText(csv));
            Assert.Contains("ShareScope", File.ReadAllText(html));
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    [Fact]
    public void CleanScanReturnsZero()
    {
        var path = Path.Combine(Path.GetTempPath(), "sharescope-ok-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "good\n");
        try
        {
            var code = CliRunner.Run(
                new[] { "--scan", path, "--csv", Path.Combine(Path.GetTempPath(), "unused.csv") },
                new StringWriter(),
                new StringWriter(),
                _ => new ScanOrchestrator(new OkAuditor()));
            Assert.Equal(0, code);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void UnsupportedPlatformWithoutDemoReturnsExitCode2()
    {
        var path = Path.Combine(Path.GetTempPath(), "sharescope-win-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, "CONTOSO-FS01\n");
        try
        {
            var stderr = new StringWriter();
            var code = CliRunner.Run(new[] { "--scan", path }, new StringWriter(), stderr);
            Assert.Equal(2, code);
            Assert.Contains("Windows", stderr.ToString());
        }
        finally
        {
            File.Delete(path);
        }
    }

    private sealed class OkAuditor : IServerAuditor
    {
        public Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
            string server,
            bool hideAdminAndHidden,
            int subfolderDepth,
            IProgress<ScanProgress>? progress,
            CancellationToken cancellationToken)
        {
            var audit = Fixtures.Analyze(
                new ShareInfo(server, "Data", @"D:\Data", ShareKind.Disk, "", 0),
                new[] { Fixtures.Ace("CONTOSO\\Ops", RightsSummarizer.ReadAndExecute, PermissionLayer.Share) });
            return Task.FromResult<IReadOnlyList<ShareAudit>>(new[] { audit });
        }
    }
}
