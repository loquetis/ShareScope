namespace ShareScope;

internal static class Theme
{
    public static readonly Color Navy = Color.FromArgb(11, 37, 69);
    public static readonly Color NavyHeader = Color.FromArgb(15, 42, 74);
    public static readonly Color Teal = Color.FromArgb(13, 148, 136);
    public static readonly Color TealDark = Color.FromArgb(15, 118, 110);
    public static readonly Color Page = Color.FromArgb(244, 247, 251);
    public static readonly Color Card = Color.White;
    public static readonly Color Line = Color.FromArgb(218, 226, 236);
    public static readonly Color Ink = Color.FromArgb(15, 23, 42);
    public static readonly Color Muted = Color.FromArgb(71, 85, 105);
    public static readonly Color High = Color.FromArgb(153, 27, 27);
    public static readonly Color HighBg = Color.FromArgb(254, 226, 226);
    public static readonly Color Review = Color.FromArgb(146, 64, 14);
    public static readonly Color ReviewBg = Color.FromArgb(254, 243, 199);
    public static readonly Color Ok = Color.FromArgb(6, 95, 70);
    public static readonly Color OkBg = Color.FromArgb(209, 250, 229);

    public static readonly Font Ui = FontAt(9f, FontStyle.Regular);
    public static readonly Font UiBold = FontAt(9f, FontStyle.Bold);
    public static readonly Font Title = FontAt(18f, FontStyle.Bold);
    public static readonly Font Tagline = FontAt(9.5f, FontStyle.Regular);

    public static Font FontAt(float size, FontStyle style)
    {
        try
        {
            return new Font("Segoe UI", size, style, GraphicsUnit.Point);
        }
        catch (ArgumentException)
        {
            return new Font(FontFamily.GenericSansSerif, size, style, GraphicsUnit.Point);
        }
    }

    public static Button Primary(string text)
    {
        var button = Base(text);
        button.BackColor = Teal;
        button.ForeColor = Color.White;
        button.FlatAppearance.BorderSize = 0;
        button.MouseEnter += (_, _) => button.BackColor = TealDark;
        button.MouseLeave += (_, _) => button.BackColor = Teal;
        return button;
    }

    public static Button Secondary(string text)
    {
        var button = Base(text);
        button.BackColor = Card;
        button.ForeColor = Navy;
        button.FlatAppearance.BorderColor = Line;
        button.FlatAppearance.BorderSize = 1;
        return button;
    }

    private static Button Base(string text)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Padding = new Padding(10, 6, 10, 6),
            Margin = new Padding(4, 3, 4, 3),
            FlatStyle = FlatStyle.Flat,
            UseVisualStyleBackColor = false,
            Cursor = Cursors.Hand,
            Font = Ui
        };
        return button;
    }

    public static void StyleGrid(DataGridView grid)
    {
        grid.BackgroundColor = Card;
        grid.BorderStyle = BorderStyle.None;
        grid.RowHeadersVisible = false;
        grid.AllowUserToAddRows = false;
        grid.AllowUserToDeleteRows = false;
        grid.AllowUserToResizeRows = false;
        grid.ReadOnly = true;
        grid.MultiSelect = false;
        grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        grid.EnableHeadersVisualStyles = false;
        grid.ColumnHeadersDefaultCellStyle.BackColor = NavyHeader;
        grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
        grid.ColumnHeadersDefaultCellStyle.Font = UiBold;
        grid.ColumnHeadersDefaultCellStyle.Padding = new Padding(4, 6, 4, 6);
        grid.DefaultCellStyle.Font = Ui;
        grid.DefaultCellStyle.ForeColor = Ink;
        grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(204, 251, 241);
        grid.DefaultCellStyle.SelectionForeColor = Ink;
        grid.DefaultCellStyle.Padding = new Padding(2, 2, 2, 2);
        grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(248, 250, 252);
        grid.GridColor = Line;
        grid.RowTemplate.Height = 28;
        grid.AutoGenerateColumns = false;
        EnableDoubleBuffer(grid);
    }

    public static void EnableDoubleBuffer(Control control)
    {
        typeof(Control).GetProperty("DoubleBuffered", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(control, true);
    }
}

internal sealed class MarkBadge : Control
{
    public MarkBadge()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        Size = new Size(36, 36);
        MinimumSize = new Size(32, 32);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        var bounds = new Rectangle(1, 1, Math.Max(1, Width - 3), Math.Max(1, Height - 3));
        using var brush = new SolidBrush(Theme.Teal);
        e.Graphics.FillEllipse(brush, bounds);
        using var font = Theme.FontAt(12f, FontStyle.Bold);
        using var text = new SolidBrush(Color.White);
        using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        e.Graphics.DrawString("S", font, text, bounds, format);
    }
}
