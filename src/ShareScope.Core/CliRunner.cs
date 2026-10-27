namespace ShareScope.Core;

public sealed class CliOptions
{
    public bool Help { get; init; }
    public bool Demo { get; init; }
    public string? ScanFile { get; init; }
    public string? CsvFile { get; init; }
    public string? HtmlFile { get; init; }
    public bool HideAdmin { get; init; }
    public int Depth { get; init; }
    public string? Error { get; init; }

    public bool IsCliRequest =>
        Help || Demo || ScanFile is not null || CsvFile is not null || HtmlFile is not null || HideAdmin || Depth > 0 || Error is not null;
}

public static class CliParser
{
    public const int MaxDepth = 10;

    public static string HelpText { get; } =
        $"""
        {AppInfo.Name} {AppInfo.Version}
        {AppInfo.Tagline}
        {AppInfo.ReadOnlyStatement}

        Usage:
          ShareScope.exe
          ShareScope.exe --scan servers.txt --csv out.csv --html out.html

        Options:
          --scan <file>    Text or CSV list of servers to audit
          --csv <file>     Write CSV results
          --html <file>    Write a self-contained HTML report
          --hide-admin     Skip administrative and hidden $ shares
          --depth <0-10>   How many subfolder levels to walk (default 0)
          --help           Show this help

        Exit codes:
          0  Completed with no High-risk shares
          1  Completed and at least one High-risk share was found
          2  Invalid arguments, unreadable input, or the scan could not run
        """;

    public static CliOptions Parse(string[] args)
    {
        string? scan = null;
        string? csv = null;
        string? html = null;
        var help = false;
        var demo = false;
        var hide = false;
        var depth = 0;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (Is(arg, "--help") || arg is "-h" or "/?")
            {
                help = true;
                continue;
            }

            if (Is(arg, "--demo"))
            {
                demo = true;
                continue;
            }

            if (Is(arg, "--hide-admin"))
            {
                hide = true;
                continue;
            }

            if (Is(arg, "--scan"))
            {
                if (!TryValue(args, ref i, out scan))
                    return Error("--scan needs a file path.");
                continue;
            }

            if (Is(arg, "--csv"))
            {
                if (!TryValue(args, ref i, out csv))
                    return Error("--csv needs a file path.");
                continue;
            }

            if (Is(arg, "--html"))
            {
                if (!TryValue(args, ref i, out html))
                    return Error("--html needs a file path.");
                continue;
            }

            if (Is(arg, "--depth"))
            {
                if (!TryValue(args, ref i, out var raw) || !int.TryParse(raw, out depth) || depth < 0 || depth > MaxDepth)
                    return Error($"--depth needs a whole number from 0 through {MaxDepth}.");
                continue;
            }

            return Error($"Unknown option: {arg}");
        }

        return new CliOptions
        {
            Help = help,
            Demo = demo,
            ScanFile = scan,
            CsvFile = csv,
            HtmlFile = html,
            HideAdmin = hide,
            Depth = depth
        };
    }

    private static CliOptions Error(string message) => new() { Error = message };

    private static bool Is(string arg, string name) =>
        arg.Equals(name, StringComparison.OrdinalIgnoreCase);

    private static bool TryValue(string[] args, ref int index, out string value)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
        {
            value = "";
            return false;
        }

        index++;
        value = args[index];
        return true;
    }
}

public static class CliRunner
{
    public static int Run(string[] args, TextWriter stdout, TextWriter stderr) =>
        Run(args, stdout, stderr, sessionFactory: null);

    public static int Run(
        string[] args,
        TextWriter stdout,
        TextWriter stderr,
        Func<CliOptions, IAuditSession>? sessionFactory)
    {
        var options = CliParser.Parse(args);
        if (options.Help)
        {
            stdout.WriteLine(CliParser.HelpText);
            return 0;
        }

        if (options.Error is not null)
        {
            stderr.WriteLine(options.Error);
            stderr.WriteLine();
            stderr.WriteLine(CliParser.HelpText);
            return 2;
        }

        var wantsWork = options.ScanFile is not null || options.CsvFile is not null || options.HtmlFile is not null || options.Demo;
        if (!wantsWork)
        {
            stdout.WriteLine(CliParser.HelpText);
            return args.Length == 0 ? 0 : 2;
        }

        if (options.ScanFile is null && !options.Demo)
        {
            stderr.WriteLine("Provide --scan <servers.txt>.");
            return 2;
        }

        IReadOnlyList<string> servers;
        if (options.Demo)
        {
            servers = DemoCatalog.ServerNames;
            stdout.WriteLine("Demo mode: fictional Contoso servers were used. No network calls were made.");
        }
        else
        {
            if (!File.Exists(options.ScanFile))
            {
                stderr.WriteLine($"Server list not found: {options.ScanFile}");
                return 2;
            }

            string text;
            try
            {
                text = File.ReadAllText(options.ScanFile!);
            }
            catch (Exception ex)
            {
                stderr.WriteLine($"Could not read {options.ScanFile}: {ex.Message}");
                return 2;
            }

            servers = TargetListParser.Parse(text);
            if (servers.Count == 0)
            {
                stderr.WriteLine($"No server names found in {options.ScanFile}.");
                return 2;
            }
        }

        var session = sessionFactory?.Invoke(options) ?? new ScanOrchestrator(
            options.Demo ? new DemoServerAuditor() : new UnsupportedPlatformAuditor());

        ScanOutcome outcome;
        try
        {
            outcome = session.ScanAsync(
                new ScanRequest(servers, options.HideAdmin, options.Depth),
                progress: null,
                CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            stderr.WriteLine($"Scan failed: {ex.Message}");
            return 2;
        }

        if (outcome.Shares.Count == 0 && outcome.Issues.Count > 0)
        {
            foreach (var issue in outcome.Issues)
                stderr.WriteLine($"{issue.Server}: {issue.Message}");
            stderr.WriteLine("The scan did not read any shares.");
            return 2;
        }

        try
        {
            if (!string.IsNullOrWhiteSpace(options.CsvFile))
            {
                CsvExporter.Write(options.CsvFile!, outcome);
                stdout.WriteLine($"CSV: {options.CsvFile}");
            }

            if (!string.IsNullOrWhiteSpace(options.HtmlFile))
            {
                HtmlExporter.Write(options.HtmlFile!, outcome);
                stdout.WriteLine($"HTML: {options.HtmlFile}");
            }
        }
        catch (Exception ex)
        {
            stderr.WriteLine($"Could not write the report: {ex.Message}");
            return 2;
        }

        stdout.WriteLine(
            $"Shares: {outcome.Shares.Count}  High: {outcome.Count(ShareRisk.High)}  Review: {outcome.Count(ShareRisk.Review)}  OK: {outcome.Count(ShareRisk.Ok)}");
        foreach (var issue in outcome.Issues)
            stderr.WriteLine($"{issue.Server}: {issue.Message}");

        if (outcome.Shares.Any(share => share.OverallRisk == ShareRisk.High))
        {
            stdout.WriteLine("High-risk shares were found.");
            return 1;
        }

        stdout.WriteLine("No High-risk shares were found.");
        return 0;
    }
}
