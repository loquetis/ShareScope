namespace ShareScope.Core;

public interface IServerAuditor
{
    Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
        string server,
        bool hideAdminAndHidden,
        int subfolderDepth,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken);
}

public interface IAuditSession
{
    Task<ScanOutcome> ScanAsync(
        ScanRequest request,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken);
}

public interface IGroupMembershipResolver
{
    GroupExpansion Expand(string identity);
}

public interface IComputerDirectory
{
    ComputerQueryResult Query(bool serversOrganizationalUnitOnly);
}

public sealed class ScanOrchestrator : IAuditSession
{
    private readonly IServerAuditor _auditor;

    public ScanOrchestrator(IServerAuditor auditor) => _auditor = auditor;

    public async Task<ScanOutcome> ScanAsync(
        ScanRequest request,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken)
    {
        var shares = new System.Collections.Concurrent.ConcurrentBag<ShareAudit>();
        var issues = new System.Collections.Concurrent.ConcurrentBag<ScanIssue>();
        var servers = request.Servers
            .Where(server => !string.IsNullOrWhiteSpace(server))
            .Select(server => server.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var total = servers.Count;
        var completed = 0;
        var canceled = 0;
        var parallelism = Math.Max(1, request.MaxParallelServers);
        using var gate = new SemaphoreSlim(parallelism);

        var tasks = servers.Select(async server =>
        {
            try
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Interlocked.Exchange(ref canceled, 1);
                return;
            }

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new ScanProgress($"Reading shares on {server}", Volatile.Read(ref completed), total));
                var audited = await _auditor
                    .AuditServerAsync(server, request.HideAdminAndHidden, request.SubfolderDepth, progress, cancellationToken)
                    .ConfigureAwait(false);
                foreach (var share in audited)
                    shares.Add(share);
            }
            catch (OperationCanceledException)
            {
                Interlocked.Exchange(ref canceled, 1);
            }
            catch (Exception ex)
            {
                issues.Add(new ScanIssue(server, null, ex.Message));
            }
            finally
            {
                var done = Interlocked.Increment(ref completed);
                progress?.Report(new ScanProgress($"Finished {server}", done, total));
                gate.Release();
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);

        var ordered = shares
            .OrderByDescending(share => share.OverallRisk)
            .ThenBy(share => share.Share.Server, StringComparer.OrdinalIgnoreCase)
            .ThenBy(share => share.Share.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var orderedIssues = issues
            .OrderBy(issue => issue.Server, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ScanOutcome(ordered, orderedIssues, canceled == 1);
    }
}

public sealed class DirectOnlyGroupResolver : IGroupMembershipResolver
{
    public GroupExpansion Expand(string identity) =>
        new(
            string.IsNullOrWhiteSpace(identity) ? Array.Empty<string>() : new[] { identity.Trim() },
            false,
            "Group membership was not expanded. Showing direct ACE matches only.");
}

public sealed class UnsupportedPlatformAuditor : IServerAuditor
{
    public Task<IReadOnlyList<ShareAudit>> AuditServerAsync(
        string server,
        bool hideAdminAndHidden,
        int subfolderDepth,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken) =>
        throw new InvalidOperationException(
            "Share enumeration uses Windows networking APIs and is available in the Windows build of ShareScope.");
}

public sealed class UnavailableComputerDirectory : IComputerDirectory
{
    private readonly string _message;

    public UnavailableComputerDirectory(string? message = null) =>
        _message = message ?? "Active Directory is not available. Add server names manually.";

    public ComputerQueryResult Query(bool serversOrganizationalUnitOnly) =>
        new(false, Array.Empty<string>(), _message);
}
