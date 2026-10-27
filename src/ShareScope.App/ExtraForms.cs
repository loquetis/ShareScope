using ShareScope.Core;

namespace ShareScope;

internal static class PromptDialog
{
    public static string? Ask(IWin32Window owner, string title, string label, bool multiline = false)
    {
        using var form = new Form
        {
            Text = title,
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false,
            ShowInTaskbar = false,
            AutoScaleMode = AutoScaleMode.Dpi,
            AutoScaleDimensions = new SizeF(96f, 96f),
            Font = Theme.Ui,
            BackColor = Theme.Page,
            MinimumSize = multiline ? new Size(480, 320) : new Size(420, 180),
            ClientSize = multiline ? new Size(520, 360) : new Size(460, 168)
        };

        var caption = new Label
        {
            Text = label,
            Dock = DockStyle.Top,
            AutoSize = true,
            Padding = new Padding(12, 12, 12, 6),
            MaximumSize = new Size(640, 0)
        };
        var box = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = multiline,
            ScrollBars = multiline ? ScrollBars.Vertical : ScrollBars.None,
            Font = Theme.Ui,
            Margin = new Padding(12)
        };
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(12)
        };
        var ok = Theme.Primary("OK");
        var cancel = Theme.Secondary("Cancel");
        ok.DialogResult = DialogResult.OK;
        cancel.DialogResult = DialogResult.Cancel;
        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);
        form.AcceptButton = ok;
        form.CancelButton = cancel;
        form.Controls.Add(box);
        form.Controls.Add(buttons);
        form.Controls.Add(caption);
        return form.ShowDialog(owner) == DialogResult.OK ? box.Text : null;
    }
}

internal sealed class AboutForm : Form
{
    public AboutForm()
    {
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        Font = Theme.Ui;
        Text = "About " + AppInfo.Name;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Page;
        MinimumSize = new Size(480, 360);
        ClientSize = new Size(520, 420);

        var header = new Panel { Dock = DockStyle.Top, Height = 72, BackColor = Theme.Navy, Padding = new Padding(16, 12, 16, 12) };
        var title = new Label
        {
            Text = AppInfo.Name + "  v" + AppInfo.Version,
            ForeColor = Color.White,
            Font = Theme.Title,
            AutoSize = true,
            Dock = DockStyle.Top,
            BackColor = Theme.Navy
        };
        var tagline = new Label
        {
            Text = AppInfo.Tagline,
            ForeColor = Color.FromArgb(203, 213, 225),
            AutoSize = true,
            Dock = DockStyle.Top,
            BackColor = Theme.Navy
        };
        header.Controls.Add(tagline);
        header.Controls.Add(title);

        var body = new Label
        {
            Dock = DockStyle.Fill,
            AutoSize = false,
            Padding = new Padding(16),
            Text = string.Join(Environment.NewLine + Environment.NewLine, new[]
            {
                "ShareScope audits SMB file shares and the permissions on them, then flags access that is broader than it should be.",
                AppInfo.ReadOnlyStatement + " Opening a share in Explorer only launches the shell. Copy and export write a file you chose. Nothing else is modified.",
                "It belongs with the Scope family of Windows IT tools: FolderScope, NetScope, ADScope, EventScope, SysScope, PingScope, and CertScope.",
                "Scheduled audits can use the command line:",
                "ShareScope.exe --scan servers.txt --csv out.csv --html out.html",
                "The process returns exit code 1 when any High-risk share is found."
            })
        };

        var close = Theme.Primary("Close");
        close.DialogResult = DialogResult.OK;
        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(12)
        };
        footer.Controls.Add(close);
        AcceptButton = close;
        CancelButton = close;
        Controls.Add(body);
        Controls.Add(footer);
        Controls.Add(header);
    }
}

internal sealed class DirectoryImportForm : Form
{
    private readonly IComputerDirectory _directory;
    private readonly RadioButton _serversOu = new() { Text = "Computers in the Servers OU", AutoSize = true, Checked = true };
    private readonly RadioButton _allServers = new() { Text = "All Windows Server computers", AutoSize = true };
    private readonly Label _message = new() { AutoSize = true, MaximumSize = new Size(460, 0), Padding = new Padding(0, 8, 0, 0) };

    public IReadOnlyList<string> Computers { get; private set; } = Array.Empty<string>();

    public DirectoryImportForm(IComputerDirectory directory)
    {
        _directory = directory;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        Font = Theme.Ui;
        Text = "Active Directory";
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Page;
        MinimumSize = new Size(460, 240);
        ClientSize = new Size(480, 260);
        Padding = new Padding(16);

        var intro = new Label
        {
            Text = "Optional. If this PC is not domain-joined, ShareScope leaves the target list alone.",
            AutoSize = true,
            MaximumSize = new Size(440, 0),
            Dock = DockStyle.Top
        };
        var options = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            Padding = new Padding(0, 12, 0, 0)
        };
        options.Controls.Add(_serversOu);
        options.Controls.Add(_allServers);
        _message.Dock = DockStyle.Top;
        _message.Text = "Choose a scope, then query.";

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true
        };
        var add = Theme.Primary("Add computers");
        add.Enabled = false;
        var query = Theme.Secondary("Query");
        var cancel = Theme.Secondary("Cancel");
        cancel.DialogResult = DialogResult.Cancel;
        query.Click += (_, _) =>
        {
            var result = _directory.Query(_serversOu.Checked);
            _message.Text = result.Message;
            Computers = result.Computers;
            add.Enabled = result.Succeeded && result.Computers.Count > 0;
        };
        add.Click += (_, _) => DialogResult = DialogResult.OK;
        buttons.Controls.Add(add);
        buttons.Controls.Add(query);
        buttons.Controls.Add(cancel);
        CancelButton = cancel;

        Controls.Add(buttons);
        Controls.Add(_message);
        Controls.Add(options);
        Controls.Add(intro);
    }
}

internal sealed class WhoHasAccessForm : Form
{
    private readonly IReadOnlyList<ShareAudit> _shares;
    private readonly IGroupMembershipResolver _resolver;
    private readonly TextBox _identity = new() { Width = 280, Font = Theme.Ui };
    private readonly Label _note = new() { AutoSize = true, MaximumSize = new Size(860, 0), ForeColor = Theme.Muted, Padding = new Padding(0, 6, 0, 6) };
    private readonly DataGridView _grid = new();

    public WhoHasAccessForm(IReadOnlyList<ShareAudit> shares, IGroupMembershipResolver resolver)
    {
        _shares = shares;
        _resolver = resolver;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoScaleDimensions = new SizeF(96f, 96f);
        Font = Theme.Ui;
        Text = "Who has access";
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        ShowInTaskbar = false;
        BackColor = Theme.Page;
        MinimumSize = new Size(760, 460);
        ClientSize = new Size(920, 560);

        var bar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            WrapContents = true,
            Padding = new Padding(12, 12, 12, 4)
        };
        var label = new Label
        {
            Text = "User or group",
            AutoSize = true,
            Margin = new Padding(0, 8, 6, 0)
        };
        var check = Theme.Primary("Show access");
        check.Click += (_, _) => RunQuery();
        bar.Controls.Add(label);
        bar.Controls.Add(_identity);
        bar.Controls.Add(check);

        _note.Dock = DockStyle.Top;
        _note.Padding = new Padding(12, 0, 12, 8);
        _note.Text = "Enter an account such as CONTOSO\\jsmith. Group expansion uses Active Directory when this computer can reach it.";

        Theme.StyleGrid(_grid);
        _grid.Dock = DockStyle.Fill;
        Add("Server", 14, 90);
        Add("Share", 12, 80);
        Add("Path", 22, 140);
        Add("Level", 10, 70);
        Add("Rights", 12, 80);
        Add("Type", 8, 60);
        Add("Via", 14, 90);
        Add("Applies to", 14, 100);

        var close = Theme.Secondary("Close");
        close.DialogResult = DialogResult.OK;
        var footer = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            Padding = new Padding(12)
        };
        footer.Controls.Add(close);
        CancelButton = close;
        AcceptButton = check;

        Controls.Add(_grid);
        Controls.Add(footer);
        Controls.Add(_note);
        Controls.Add(bar);
    }

    private void Add(string name, float weight, int min)
    {
        _grid.Columns.Add(new DataGridViewTextBoxColumn
        {
            Name = name,
            HeaderText = name,
            FillWeight = weight,
            MinimumWidth = min,
            SortMode = DataGridViewColumnSortMode.Automatic
        });
    }

    private void RunQuery()
    {
        var name = _identity.Text.Trim();
        if (name.Length == 0)
        {
            _note.Text = "Type a user or group name first.";
            return;
        }

        var expansion = _resolver.Expand(name);
        var hits = AccessQuery.Find(_shares, name, expansion);
        _grid.Rows.Clear();
        foreach (var hit in hits)
        {
            _grid.Rows.Add(
                hit.Server,
                hit.Share,
                hit.Path,
                hit.Layer.ToString(),
                hit.Rights,
                AuditText.Effect(hit.Effect),
                hit.Via,
                hit.AppliesTo);
        }

        _note.Text = hits.Count == 0
            ? expansion.Note + " No matching access entries were found."
            : $"{hits.Count} matching entries. {expansion.Note}";
    }
}
