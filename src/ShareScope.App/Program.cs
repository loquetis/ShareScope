using ShareScope.Core;
using ShareScope.Windows;

namespace ShareScope;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var options = CliParser.Parse(args);
        var guiDemo = options.Demo
            && options.Error is null
            && !options.Help
            && options.ScanFile is null
            && options.CsvFile is null
            && options.HtmlFile is null;
        var runCli = args.Length > 0 && !guiDemo;

        if (runCli)
        {
            return CliRunner.Run(args, Console.Out, Console.Error, opt =>
                new ScanOrchestrator(opt.Demo ? new DemoServerAuditor() : new WindowsServerAuditor()));
        }

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm(guiDemo));
        return 0;
    }
}
