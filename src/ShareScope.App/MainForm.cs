using ShareScope.Core;
using ShareScope.Windows;

namespace ShareScope;

internal sealed class MainForm : Form
{
    private readonly bool _demo;
    private readonly IAuditSession _session;
    private readonly IGroupMembershipResolver _groups;
    private readonly IComputerDirectory _directory;
    private readonly List<ShareAudit> _audits = new();
    private readonly Font _riskFont;

    private readonly ListBox _targets = new();
    private readonly DataGridView _grid = new();
    private readonly DataGridView _shareAcl = new();
    private readonly DataGridView _ntfsAcl = new();
    private readonly DataGridView _risks = new();
    private readonly Label _status = new();
    private readonly Label _banner = new();
    private readonly Label _meta = new();
    private readonly Label _empty = new();
    private readonly ProgressBar _progress = new();
    private readonly CheckBox _hideAdmin = new();
    private readonly CheckBox _deep = new();
    private readonly NumericUpDown _depth = new();
    private Button _scan = null!;
    private Button _cancel = null!;
    private Button _open = null!;
    private Button _copyUnc = null!;
    private Button _copyDetails = null!;

    private CancellationTokenSource? _scanCancellation;
    private bool _scanning;

    public MainForm(bool demo)
        : this(
            demo,
            new ScanOrchestrator(demo ? new DemoServerAuditor() : new WindowsServerAuditor()),
            demo ? new DemoGroupResolver() : new WindowsGroupResolver(),
            demo ? new DemoComputerDirectory() : new WindowsComputerDirectory())
    {
    }

    public MainForm(bool demo, IAuditSession session, IGroupMembershipResolver groups, IComputerDirectory directory)
    {
        _demo = demo;
        _session = session;
        _groups = groups;
        _directory = directory;
        _riskFont = new Font(Theme.Ui, FontStyle.Bold);

        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        Font = Theme.Ui;
        Text = AppInfo.Name;
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(1280, 800);
        MinimumSize = new Size(1100, 720);
        BackColor = Theme.Page;
        Theme.EnableDoubleBuffer(this);

        var header = BuildHeader();
        var toolbar = BuildToolbar();
        var status = BuildStatus();
        var details = BuildDetails();
        var body = BuildBody();

        toolbar.Dock = DockStyle.Top;
        status.Dock = DockStyle.Bottom;
        details.Dock = DockStyle.Bottom;
        body.Dock = DockStyle.Fill;

        Controls.Add(body);
        Controls.Add(details);
        Controls.Add(status);
        Controls.Add(toolbar);
        Controls.Add(header);

        _hideAdmin.Checked = true;
        _deep.Checked = demo;
        _depth.Value = 2;
        _depth.Enabled = _deep.Checked;
        _cancel.Enabled = false;
        SetDetailButtons(false);

        if (demo)
        {
            foreach (var server in DemoCatalog.ServerNames)
                _targets.Items.Add(server);
            var outcome = _session.ScanAsync(CurrentRequest(), progress: null, CancellationToken.None)
                .GetAwaiter().GetResult();
            Bind(outcome);
            _status.Text = "Demo data for a fictional Contoso network. No servers were contacted. Read-only.";
        }
        else
        {
            _targets.Items.Add(Environment.MachineName);
            ShowEmpty();
            _status.Text = "Add servers and scan. The local computer is included. Read-only — permissions are never changed.";
        }

        Shown += (_, _) => SelectPreferredShare();
    }

    private Panel BuildHeader()
    {
        var header = new Panel
        {
            BackColor = Theme.Navy,
            Dock = DockStyle.Top,
            Height = 78,
            MinimumSize = new Size(0, 68)
        };
        var mark = new MarkBadge { Location = new Point(16, 18), Size = new Size(40, 40) };
        var title = new Label
        {
            Text = AppInfo.Name,
            Font = Theme.Title,
            ForeColor = Color.White,
            AutoSize = true,
            BackColor = Theme.Navy,
            Location = new Point(68, 12)
        };
        var tagline = new Label
        {
            Text = AppInfo.Tagline,
            Font = Theme.Tagline,
            ForeColor = Color.FromArgb(203, 213, 225),
            AutoSize = true,
            BackColor = Theme.Navy,
            Location = new Point(70, 44)
        };
        var version = new Label
        {
            Text = "v" + AppInfo.Version,
            Font = Theme.UiBold,
            ForeColor = Color.FromArgb(153, 246, 228),
            AutoSize = true,
            BackColor = Theme.Navy,
            Anchor = AnchorStyles.Top | AnchorStyles.Right
        };
        header.Controls.Add(mark);
        header.Controls.Add(title);
        header.Controls.Add(tagline);
        header.Controls.Add(version);
        header.Resize += (_, _) =>
        {
            version.Left = Math.Max(title.Right + 12, header.ClientSize.Width - version.Width - 16);
            version.Top = 26;
        };
        return header;
    }

    private Control BuildToolbar()
    {
        var bar = new FlowLayoutPanel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = true,
            Dock = DockStyle.Top,
            Padding = new Padding(8, 6, 8, 6),
            MinimumSize = new Size(0, 84),
            BackColor = Theme.Page
        };

        _scan = Theme.Primary("Scan shares");
        _scan.Click += async (_, _) => await ScanAsync();
        _cancel = Theme.Secondary("Cancel");
        _cancel.Click += (_, _) => _scanCancellation?.Cancel();

        var who = Theme.Secondary("Who has access");
        who.Click += (_, _) => ShowAccess();
        var csv = Theme.Secondary("Export CSV");
        csv.Click += (_, _) => Export(html: false);
        var html = Theme.Secondary("Export HTML");
        html.Click += (_, _) => Export(html: true);
        var about = Theme.Secondary("About");
        about.Click += (_, _) => new AboutForm().ShowDialog(this);

        _hideAdmin.Text = "Hide admin and hidden shares";
        _hideAdmin.AutoSize = true;
        _hideAdmin.Margin = new Padding(12, 8, 4, 4);
        _hideAdmin.Font = Theme.Ui;

        _deep.Text = "Scan subfolders";
        _deep.AutoSize = true;
        _deep.Margin = new Padding(8, 8, 4, 4);
        _deep.CheckedChanged += (_, _) => _depth.Enabled = _deep.Checked;

        var depthLabel = new Label
        {
            Text = "Depth",
            AutoSize = true,
            Margin = new Padding(8, 10, 2, 4),
            Font = Theme.Ui
        };
        _depth.Minimum = 1;
        _depth.Maximum = CliParser.MaxDepth;
        _depth.Width = 56;
        _depth.Margin = new Padding(2, 6, 4, 4);
        _depth.Font = Theme.Ui;

        bar.Controls.Add(_scan);
        bar.Controls.Add(_cancel);
        bar.Controls.Add(_hideAdmin);
        bar.Controls.Add(_deep);
        bar.Controls.Add(depthLabel);
        bar.Controls.Add(_depth);
        bar.Controls.Add(who);
        bar.Controls.Add(csv);
        bar.Controls.Add(html);
        bar.Controls.Add(about);
        return bar;
    }

    private Control BuildBody()
    {
        var body = new Panel { Padding = new Padding(8, 0, 8, 0), BackColor = Theme.Page };
        var targets = new Panel
        {
            Dock = DockStyle.Left,
            Width = 230,
            MinimumSize = new Size(200, 0),
            Padding = new Padding(0, 0, 8, 0),
            BackColor = Theme.Page
        };
        var caption = new Label
        {
            Text = "Targets",
            Dock = DockStyle.Top,
            AutoSize = true,
            Font = Theme.UiBold,
            ForeColor = Theme.Navy,
            Padding = new Padding(0, 0, 0, 4)
        };
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            AutoSize = true,
            WrapContents = true,
            Padding = new Padding(0, 6, 0, 0)
        };
        AddTargetButton(buttons, "Add", (_, _) => AddServer());
        AddTargetButton(buttons, "Remove", (_, _) => RemoveServer());
        AddTargetButton(buttons, "Paste list", (_, _) => PasteServers());
        AddTargetButton(buttons, "Import", (_, _) => ImportServers());
        AddTargetButton(buttons, "From Active Directory", (_, _) => ImportDirectory());
        AddTargetButton(buttons, "Save list", (_, _) => SaveTargets());
        AddTargetButton(buttons, "Load list", (_, _) => LoadTargets());

        _targets.Dock = DockStyle.Fill;
        _targets.IntegralHeight = false;
        _targets.Font = Theme.Ui;
        _targets.BorderStyle = BorderStyle.FixedSingle;

        targets.Controls.Add(_targets);
        targets.Controls.Add(buttons);
        targets.Controls.Add(caption);

        Theme.StyleGrid(_grid);
        _grid.Dock = DockStyle.Fill;
        AddColumn(_grid, "Server", 16, 100);
        AddColumn(_grid, "Share", 12, 90);
        AddColumn(_grid, "Path", 20, 140);
        AddColumn(_grid, "Type", 9, 70);
        AddColumn(_grid, "Description", 16, 110);
        AddColumn(_grid, "Connections", 10, 90);
        AddColumn(_grid, "Risk", 8, 70);
        AddColumn(_grid, "Notes", 22, 160);
        _grid.SelectionChanged += (_, _) => ShowSelected();
        _grid.CellFormatting += OnGridFormatting;
        _grid.SortCompare += OnSortCompare;

        _empty.Text = "No shares yet. Add a server, or paste a list, then scan.";
        _empty.Dock = DockStyle.Fill;
        _empty.TextAlign = ContentAlignment.MiddleCenter;
        _empty.ForeColor = Theme.Muted;
        _empty.Font = Theme.Ui;
        _empty.Visible = false;
        _empty.BackColor = Theme.Card;

        var gridHost = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Card, Padding = new Padding(1) };
        gridHost.Controls.Add(_empty);
        gridHost.Controls.Add(_grid);

        body.Controls.Add(gridHost);
        body.Controls.Add(targets);
        return body;
    }

    private Control BuildDetails()
    {
        var panel = new Panel
        {
            Height = 268,
            MinimumSize = new Size(0, 200),
            Padding = new Padding(8, 4, 8, 8),
            BackColor = Theme.Page
        };

        _banner.Dock = DockStyle.Top;
        _banner.AutoSize = true;
        _banner.MaximumSize = new Size(1400, 0);
        _banner.Padding = new Padding(10, 8, 10, 8);
        _banner.Margin = new Padding(0, 0, 0, 4);
        _banner.Font = Theme.UiBold;
        _banner.Text = "Select a share to see permissions and risk notes.";
        _banner.BackColor = Theme.Card;
        _banner.ForeColor = Theme.Ink;

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = true,
            Padding = new Padding(0, 4, 0, 4)
        };
        _meta.AutoSize = true;
        _meta.MaximumSize = new Size(760, 0);
        _meta.Margin = new Padding(0, 8, 12, 4);
        _meta.ForeColor = Theme.Muted;
        _meta.Text = "Owner and path appear here.";
        _open = Theme.Secondary("Open in Explorer");
        _open.Click += (_, _) => OpenExplorer();
        _copyUnc = Theme.Secondary("Copy UNC path");
        _copyUnc.Click += (_, _) => CopyText(SelectedAudit()?.Share.UncPath, "UNC path copied.");
        _copyDetails = Theme.Secondary("Copy details");
        _copyDetails.Click += (_, _) =>
        {
            var audit = SelectedAudit();
            if (audit is null)
                return;
            CopyText(AuditText.FormatDetails(audit), "Share details copied.");
        };
        actions.Controls.Add(_meta);
        actions.Controls.Add(_open);
        actions.Controls.Add(_copyUnc);
        actions.Controls.Add(_copyDetails);

        var columns = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 3,
            RowCount = 1,
            BackColor = Theme.Page
        };
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
        columns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 32));
        columns.Controls.Add(AcePanel("Share permissions", _shareAcl), 0, 0);
        columns.Controls.Add(AcePanel("NTFS permissions", _ntfsAcl), 1, 0);
        columns.Controls.Add(RiskPanel(), 2, 0);

        panel.Resize += (_, _) =>
        {
            var width = Math.Max(200, panel.ClientSize.Width - 16);
            _banner.MaximumSize = new Size(width, 0);
            _meta.MaximumSize = new Size(Math.Max(200, width - 460), 0);
        };

        panel.Controls.Add(columns);
        panel.Controls.Add(actions);
        panel.Controls.Add(_banner);
        return panel;
    }

    private Control AcePanel(string title, DataGridView grid)
    {
        var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0, 0, 6, 0), BackColor = Theme.Page };
        var label = SectionLabel(title);
        Theme.StyleGrid(grid);
        grid.Dock = DockStyle.Fill;
        AddColumn(grid, "Identity", 28, 90);
        AddColumn(grid, "Rights", 18, 70);
        AddColumn(grid, "Type", 14, 60);
        AddColumn(grid, "Inherited", 18, 80);
        AddColumn(grid, "Applies to", 22, 90);
        host.Controls.Add(grid);
        host.Controls.Add(label);
        return host;
    }

    private Control RiskPanel()
    {
        var host = new Panel { Dock = DockStyle.Fill, Padding = new Padding(0), BackColor = Theme.Page };
        var label = SectionLabel("Risk notes");
        Theme.StyleGrid(_risks);
        _risks.Dock = DockStyle.Fill;
        _risks.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
        _risks.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        AddColumn(_risks, "Severity", 22, 70);
        AddColumn(_risks, "Note", 78, 120);
        _risks.CellFormatting += (_, e) =>
        {
            if (e.RowIndex < 0 || e.CellStyle is null || _risks.Columns[e.ColumnIndex].Name != "Severity" || e.Value is not string severity)
                return;
            PaintRisk(e.CellStyle, severity);
        };
        host.Controls.Add(_risks);
        host.Controls.Add(label);
        return host;
    }

    private static Label SectionLabel(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Top,
        AutoSize = true,
        Font = Theme.UiBold,
        ForeColor = Theme.TealDark,
        Padding = new Padding(0, 0, 0, 4)
    };

    private Control BuildStatus()
    {
        var bar = new Panel
        {
            AutoSize = true,
            Padding = new Padding(10, 6, 10, 6),
            BackColor = Color.White
        };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            ColumnCount = 3,
            BackColor = Color.White
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _status.AutoSize = true;
        _status.Dock = DockStyle.Fill;
        _status.TextAlign = ContentAlignment.MiddleLeft;
        _status.ForeColor = Theme.Ink;
        _progress.Dock = DockStyle.Fill;
        _progress.Height = 18;
        _progress.Margin = new Padding(8, 4, 8, 4);
        _progress.Minimum = 0;
        _progress.Maximum = 1;
        var readOnly = new Label
        {
            Text = "Read-only",
            AutoSize = true,
            Font = Theme.UiBold,
            ForeColor = Theme.TealDark,
            TextAlign = ContentAlignment.MiddleRight,
            Margin = new Padding(8, 6, 0, 0)
        };
        layout.Controls.Add(_status, 0, 0);
        layout.Controls.Add(_progress, 1, 0);
        layout.Controls.Add(readOnly, 2, 0);
        bar.Controls.Add(layout);
        return bar;
    }

    private static void AddTargetButton(FlowLayoutPanel panel, string text, EventHandler click)
    {
        var button = Theme.Secondary(text);
        button.Margin = new Padding(0, 2, 4, 2);
        button.Click += click;
        panel.Controls.Add(button);
    }

    private static void AddColumn(DataGridView grid, string name, float weight, int minWidth)
    {
        var column = new DataGridViewTextBoxColumn
        {
            Name = name,
            HeaderText = name,
            FillWeight = weight,
            MinimumWidth = minWidth,
            SortMode = DataGridViewColumnSortMode.Automatic
        };
        grid.Columns.Add(column);
    }

    private ScanRequest CurrentRequest()
    {
        var servers = _targets.Items.Cast<object>().Select(item => item.ToString() ?? "").ToList();
        var depth = _deep.Checked ? (int)_depth.Value : 0;
        return new ScanRequest(servers, _hideAdmin.Checked, depth);
    }

    private async Task ScanAsync()
    {
        if (_scanning)
            return;
        var request = CurrentRequest();
        if (request.Servers.Count == 0)
        {
            MessageBox.Show(this, "Add at least one server name or IP address.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        _scanning = true;
        _scan.Enabled = false;
        _cancel.Enabled = true;
        _progress.Style = ProgressBarStyle.Marquee;
        _status.Text = "Scanning…";
        _scanCancellation = new CancellationTokenSource();
        var progress = new Progress<ScanProgress>(update =>
        {
            _status.Text = update.Message;
            if (update.TotalServers > 0)
            {
                _progress.Style = ProgressBarStyle.Continuous;
                _progress.Maximum = update.TotalServers;
                _progress.Value = Math.Min(update.CompletedServers, update.TotalServers);
            }
        });

        try
        {
            var outcome = await _session.ScanAsync(request, progress, _scanCancellation.Token);
            Bind(outcome);
            var high = outcome.Count(ShareRisk.High);
            var review = outcome.Count(ShareRisk.Review);
            var ok = outcome.Count(ShareRisk.Ok);
            var suffix = outcome.Canceled ? " Scan canceled." : "";
            _status.Text = $"Shares {outcome.Shares.Count}. High {high}. Review {review}. OK {ok}.{suffix}";
            if (outcome.Issues.Count > 0 && !outcome.Canceled)
            {
                var lines = string.Join(Environment.NewLine, outcome.Issues.Take(8).Select(issue => $"{issue.Server}: {issue.Message}"));
                MessageBox.Show(this, lines, "Some servers could not be read", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        catch (Exception ex)
        {
            _status.Text = "Scan failed.";
            MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            _scanning = false;
            _scan.Enabled = true;
            _cancel.Enabled = false;
            _progress.Style = ProgressBarStyle.Continuous;
            _scanCancellation.Dispose();
            _scanCancellation = null;
        }
    }

    private void Bind(ScanOutcome outcome)
    {
        _audits.Clear();
        _audits.AddRange(outcome.Shares);
        _grid.Rows.Clear();
        foreach (var audit in _audits)
        {
            var index = _grid.Rows.Add(
                audit.Share.Server,
                audit.Share.Name,
                audit.Share.Path,
                ShareClassifier.Display(audit.Share.Kind),
                audit.Share.Description,
                audit.Share.CurrentConnections?.ToString() ?? "",
                audit.OverallRisk.ToString(),
                audit.TopTitle);
            _grid.Rows[index].Tag = audit;
        }

        _empty.Visible = _grid.Rows.Count == 0;
        _grid.Visible = _grid.Rows.Count > 0;
        if (_grid.Rows.Count == 0)
            ClearDetails();
    }

    private void ShowEmpty()
    {
        _empty.Visible = true;
        _grid.Visible = false;
        ClearDetails();
    }

    private void SelectPreferredShare()
    {
        if (_grid.Rows.Count == 0)
            return;
        var index = -1;
        for (var i = 0; i < _audits.Count; i++)
        {
            if (_audits[i].Share.Name.Equals("Finance", StringComparison.OrdinalIgnoreCase)
                && _audits[i].OverallRisk == ShareRisk.High)
            {
                index = i;
                break;
            }
        }

        if (index < 0)
        {
            for (var i = 0; i < _audits.Count; i++)
            {
                if (_audits[i].OverallRisk == ShareRisk.High)
                {
                    index = i;
                    break;
                }
            }
        }

        if (index < 0)
            index = 0;
        _grid.ClearSelection();
        _grid.Rows[index].Selected = true;
        _grid.CurrentCell = _grid.Rows[index].Cells[0];
        ShowSelected();
    }

    private ShareAudit? SelectedAudit()
    {
        if (_grid.CurrentRow?.Tag is ShareAudit audit)
            return audit;
        return null;
    }

    private void ShowSelected()
    {
        var audit = SelectedAudit();
        if (audit is null)
        {
            ClearDetails();
            return;
        }

        SetDetailButtons(true);
        var top = audit.TopFinding;
        _banner.Text = top is null
            ? "OK — no risk flags on this share."
            : $"{audit.OverallRisk} — {top.Title}. {top.Explanation}";
        (_banner.BackColor, _banner.ForeColor) = audit.OverallRisk switch
        {
            ShareRisk.High => (Theme.HighBg, Theme.High),
            ShareRisk.Review => (Theme.ReviewBg, Theme.Review),
            _ => (Theme.OkBg, Theme.Ok)
        };
        var connections = audit.Share.CurrentConnections?.ToString() ?? "n/a";
        _meta.Text = $"{audit.Share.UncPath}    Path {Display(audit.Share.Path)}    Owner {audit.Owner ?? "not available"}    Connections {connections}";

        FillAcl(_shareAcl, audit.ShareAcl);
        FillAcl(_ntfsAcl, audit.NtfsAcl);
        _risks.Rows.Clear();
        if (audit.Findings.Count == 0)
            _risks.Rows.Add("OK", "No risk flags.");
        else
        {
            foreach (var finding in audit.Findings)
                _risks.Rows.Add(finding.Severity.ToString(), finding.Title + " — " + finding.Explanation);
        }

        foreach (var folder in audit.Subfolders)
        {
            var inheritance = folder.InheritanceProtected ? "inheritance broken" : "checked";
            _risks.Rows.Add("Info", $"Subfolder {folder.RelativePath}: {inheritance}.");
        }
    }

    private void ClearDetails()
    {
        SetDetailButtons(false);
        _banner.Text = "Select a share to see permissions and risk notes.";
        _banner.BackColor = Theme.Card;
        _banner.ForeColor = Theme.Ink;
        _meta.Text = "Owner and path appear here.";
        _shareAcl.Rows.Clear();
        _ntfsAcl.Rows.Clear();
        _risks.Rows.Clear();
    }

    private static void FillAcl(DataGridView grid, AclSnapshot acl)
    {
        grid.Rows.Clear();
        if (!acl.ReadSucceeded)
        {
            grid.Rows.Add("Not read", acl.FailureReason ?? "Unknown error", "", "", "");
            return;
        }

        if (acl.DaclPresent == false)
        {
            grid.Rows.Add("No access list", "Unrestricted", "", "", "");
            return;
        }

        foreach (var entry in acl.Entries)
        {
            grid.Rows.Add(
                entry.Identity,
                entry.Rights.Text,
                AuditText.Effect(entry.Effect),
                AuditText.Inherited(entry.Inherited),
                entry.AppliesTo);
        }

        if (grid.Rows.Count == 0)
            grid.Rows.Add("No entries", "", "", "", "");
    }

    private void SetDetailButtons(bool enabled)
    {
        _open.Enabled = enabled;
        _copyUnc.Enabled = enabled;
        _copyDetails.Enabled = enabled;
    }

    private void OnGridFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0 || e.CellStyle is null || _grid.Columns[e.ColumnIndex].Name != "Risk" || e.Value is not string risk)
            return;
        PaintRisk(e.CellStyle, risk);
        e.CellStyle.Font = _riskFont;
    }

    private static void PaintRisk(DataGridViewCellStyle style, string risk)
    {
        switch (risk)
        {
            case "High":
                style.ForeColor = Theme.High;
                style.BackColor = Theme.HighBg;
                style.SelectionForeColor = Theme.High;
                style.SelectionBackColor = Theme.HighBg;
                break;
            case "Review":
                style.ForeColor = Theme.Review;
                style.BackColor = Theme.ReviewBg;
                style.SelectionForeColor = Theme.Review;
                style.SelectionBackColor = Theme.ReviewBg;
                break;
            default:
                style.ForeColor = Theme.Ok;
                style.BackColor = Theme.OkBg;
                style.SelectionForeColor = Theme.Ok;
                style.SelectionBackColor = Theme.OkBg;
                break;
        }
    }

    private void OnSortCompare(object? sender, DataGridViewSortCompareEventArgs e)
    {
        if (e.Column.Name == "Risk")
        {
            e.SortResult = RiskRank(e.CellValue1).CompareTo(RiskRank(e.CellValue2));
            e.Handled = true;
        }
        else if (e.Column.Name == "Connections")
        {
            e.SortResult = ConnectionRank(e.CellValue1).CompareTo(ConnectionRank(e.CellValue2));
            e.Handled = true;
        }
    }

    private static int RiskRank(object? value) => value?.ToString() switch
    {
        "High" => 0,
        "Review" => 1,
        "OK" => 2,
        _ => 3
    };

    private static int ConnectionRank(object? value) =>
        int.TryParse(value?.ToString(), out var number) ? number : -1;

    private void AddServer()
    {
        var name = PromptDialog.Ask(this, "Add server", "Server name or IP address");
        if (string.IsNullOrWhiteSpace(name))
            return;
        AddNames(TargetListParser.Parse(name));
    }

    private void RemoveServer()
    {
        if (_targets.SelectedIndex < 0)
            return;
        _targets.Items.RemoveAt(_targets.SelectedIndex);
    }

    private void PasteServers()
    {
        var text = PromptDialog.Ask(this, "Paste servers", "One server per line, or a CSV export.", multiline: true);
        if (string.IsNullOrWhiteSpace(text))
            return;
        AddNames(TargetListParser.Parse(text));
    }

    private void ImportServers()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Server lists (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*",
            Title = "Import servers"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        try
        {
            AddNames(TargetListParser.Parse(File.ReadAllText(dialog.FileName)));
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void ImportDirectory()
    {
        using var dialog = new DirectoryImportForm(_directory);
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        AddNames(dialog.Computers);
    }

    private void SaveTargets()
    {
        using var dialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|CSV files (*.csv)|*.csv",
            Title = "Save target list",
            FileName = "servers.txt"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        var names = _targets.Items.Cast<object>().Select(item => item.ToString() ?? "");
        File.WriteAllText(dialog.FileName, TargetListParser.Format(names));
        _status.Text = "Target list saved.";
    }

    private void LoadTargets()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Server lists (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*",
            Title = "Load target list"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        try
        {
            var names = TargetListParser.Parse(File.ReadAllText(dialog.FileName));
            _targets.Items.Clear();
            AddNames(names);
            _status.Text = $"Loaded {names.Count} servers.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void AddNames(IReadOnlyList<string> names)
    {
        var existing = new HashSet<string>(_targets.Items.Cast<object>().Select(item => item.ToString() ?? ""), StringComparer.OrdinalIgnoreCase);
        var added = 0;
        foreach (var name in names)
        {
            if (!existing.Add(name))
                continue;
            _targets.Items.Add(name);
            added++;
        }

        if (added == 0 && names.Count == 0)
            _status.Text = "No server names found in that list.";
        else
            _status.Text = $"Targets: {_targets.Items.Count}.";
    }

    private void ShowAccess()
    {
        if (_audits.Count == 0)
        {
            MessageBox.Show(this, "Scan shares before asking who has access.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new WhoHasAccessForm(_audits, _groups);
        dialog.ShowDialog(this);
    }

    private void Export(bool html)
    {
        if (_audits.Count == 0)
        {
            MessageBox.Show(this, "Scan shares before exporting.", AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var outcome = new ScanOutcome(_audits, Array.Empty<ScanIssue>(), false);
        using var dialog = new SaveFileDialog
        {
            Filter = html ? "HTML report (*.html)|*.html" : "CSV files (*.csv)|*.csv",
            FileName = html ? "ShareScope-report.html" : "ShareScope-report.csv",
            Title = html ? "Export HTML report" : "Export CSV"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
            return;
        try
        {
            if (html)
                HtmlExporter.Write(dialog.FileName, outcome);
            else
                CsvExporter.Write(dialog.FileName, outcome);
            _status.Text = "Exported " + dialog.FileName;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OpenExplorer()
    {
        var audit = SelectedAudit();
        if (audit is null)
            return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = "\"" + audit.Share.UncPath + "\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Explorer could not open " + audit.Share.UncPath + ". " + ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }

    private void CopyText(string? value, string confirmation)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;
        try
        {
            Clipboard.SetText(value);
            _status.Text = confirmation;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private static string Display(string? value) => string.IsNullOrWhiteSpace(value) ? "n/a" : value;

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _scanCancellation?.Cancel();
        _riskFont.Dispose();
        base.OnFormClosed(e);
    }
}
