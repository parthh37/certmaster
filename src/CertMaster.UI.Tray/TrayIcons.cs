using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using CertMaster.Client.Monitoring;

namespace CertMaster.UI.Tray;

/// <summary>The app icon with a coloured status dot in the corner, one per <see cref="MonitorLevel"/>, built once.</summary>
public sealed class TrayIcons : IDisposable
{
    private readonly Dictionary<MonitorLevel, Icon> _icons = new();

    public Icon AppIcon { get; }

    public TrayIcons()
    {
        using var stream = typeof(TrayIcons).Assembly.GetManifestResourceStream("certmaster.ico")!;
        var size = SystemInformation.SmallIconSize;
        AppIcon = new Icon(stream, size);
        foreach (var level in Enum.GetValues<MonitorLevel>()) _icons[level] = Build(AppIcon, size, Color(level), level == MonitorLevel.Offline);
    }

    public Icon For(MonitorLevel level) => _icons[level];

    private static Color Color(MonitorLevel level) => level switch
    {
        MonitorLevel.Ok => System.Drawing.Color.FromArgb(0x2E, 0x7D, 0x32),
        MonitorLevel.Warning => System.Drawing.Color.FromArgb(0xEF, 0x8C, 0x00),
        MonitorLevel.Error => System.Drawing.Color.FromArgb(0xC6, 0x28, 0x28),
        _ => System.Drawing.Color.FromArgb(0x75, 0x75, 0x75),
    };

    private static Icon Build(Icon baseIcon, Size size, Color dot, bool dim)
    {
        using var bmp = new Bitmap(size.Width, size.Height);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            using (var source = baseIcon.ToBitmap())
            {
                if (dim)
                {
                    // Greyed out while the agent can't be reached.
                    using var attributes = new System.Drawing.Imaging.ImageAttributes();
                    var m = new System.Drawing.Imaging.ColorMatrix(new[]
                    {
                        new[] { 0.30f, 0.30f, 0.30f, 0, 0 },
                        new[] { 0.59f, 0.59f, 0.59f, 0, 0 },
                        new[] { 0.11f, 0.11f, 0.11f, 0, 0 },
                        new[] { 0f, 0, 0, 0.75f, 0 },
                        new[] { 0f, 0, 0, 0, 1 },
                    });
                    attributes.SetColorMatrix(m);
                    g.DrawImage(source, new Rectangle(Point.Empty, size), 0, 0, source.Width, source.Height, GraphicsUnit.Pixel, attributes);
                }
                else g.DrawImage(source, new Rectangle(Point.Empty, size));
            }

            var d = (int)Math.Round(size.Width * 0.5);
            var rect = new Rectangle(size.Width - d, size.Height - d, d - 1, d - 1);
            using var fill = new SolidBrush(dot);
            using var border = new Pen(System.Drawing.Color.White, Math.Max(1f, size.Width / 16f));
            g.FillEllipse(fill, rect);
            g.DrawEllipse(border, rect);
        }

        var handle = bmp.GetHicon();
        try { return (Icon)Icon.FromHandle(handle).Clone(); }
        finally { DestroyIcon(handle); }
    }

    public void Dispose()
    {
        foreach (var i in _icons.Values) i.Dispose();
        AppIcon.Dispose();
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);
}
