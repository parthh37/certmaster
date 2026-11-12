// Generates assets/certmaster.ico (16..256 px PNG entries): a white lock glyph on a rounded blue square.
// Usage: dotnet run build/make-icon.cs -- <output.ico>
#:package System.Drawing.Common@10.0.0
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;

#pragma warning disable CA1416
var output = args.Length > 0 ? args[0] : "certmaster.ico";
int[] sizes = { 16, 24, 32, 48, 64, 128, 256 };
var images = new List<byte[]>();
foreach (var s in sizes)
{
    using var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb);
    using (var g = Graphics.FromImage(bmp))
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        g.Clear(Color.Transparent);
        var r = s / 5f;
        using var path = new GraphicsPath();
        path.AddArc(0, 0, r, r, 180, 90); path.AddArc(s - r - 1, 0, r, r, 270, 90);
        path.AddArc(s - r - 1, s - r - 1, r, r, 0, 90); path.AddArc(0, s - r - 1, r, r, 90, 90);
        path.CloseFigure();
        using var bg = new LinearGradientBrush(new Rectangle(0, 0, s, s), Color.FromArgb(30, 136, 229), Color.FromArgb(13, 71, 161), 90f);
        g.FillPath(bg, path);
        using var font = new Font("Segoe MDL2 Assets", s * 0.52f, GraphicsUnit.Pixel);
        var glyph = ""; // lock
        var size = g.MeasureString(glyph, font);
        g.DrawString(glyph, font, Brushes.White, (s - size.Width) / 2f + s * 0.02f, (s - size.Height) / 2f + s * 0.03f);
    }
    using var ms = new MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    images.Add(ms.ToArray());
}

using var fs = File.Create(output);
using var w = new BinaryWriter(fs);
w.Write((short)0); w.Write((short)1); w.Write((short)images.Count);
var offset = 6 + 16 * images.Count;
for (var i = 0; i < images.Count; i++)
{
    var s = sizes[i];
    w.Write((byte)(s >= 256 ? 0 : s)); w.Write((byte)(s >= 256 ? 0 : s));
    w.Write((byte)0); w.Write((byte)0); w.Write((short)1); w.Write((short)32);
    w.Write(images[i].Length); w.Write(offset);
    offset += images[i].Length;
}
foreach (var img in images) w.Write(img);
Console.WriteLine($"Wrote {output}");
