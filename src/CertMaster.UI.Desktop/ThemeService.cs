using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using ControlzEx.Theming;
using Microsoft.Win32;

namespace CertMaster.UI.Desktop;

public enum AppTheme { System, Light, Dark }

/// <summary>
/// Applies the Windows 11 (Fluent) look: light or dark tokens (following Windows unless the user picked one), the
/// Windows accent color, and rounded window corners. MahApps controls get a matching runtime theme so their own
/// accents (toggles, check boxes, progress) use the same color.
/// </summary>
internal static class ThemeService
{
    // Windows 11 default blue, used when the accent palette cannot be read.
    private static readonly Color DefaultAccentDark1 = Color.FromRgb(0x00, 0x5F, 0xB8);
    private static readonly Color DefaultAccentDark2 = Color.FromRgb(0x00, 0x3E, 0x92);
    private static readonly Color DefaultAccentLight2 = Color.FromRgb(0x60, 0xCD, 0xFF);
    private static readonly Color DefaultAccentLight3 = Color.FromRgb(0x99, 0xEB, 0xFF);

    private static readonly string PreferenceFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CertMaster", "desktop-theme.txt");

    private static readonly Dictionary<string, Theme> RuntimeThemes = new();
    private static ResourceDictionary? _tokens;
    private static bool _initialized;

    public static AppTheme Mode { get; private set; } = AppTheme.System;
    public static bool IsDark { get; private set; }

    public static void Initialize()
    {
        if (_initialized) return;
        _initialized = true;
        Mode = LoadMode();
        Apply();
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
        EventManager.RegisterClassHandler(typeof(Window), FrameworkElement.LoadedEvent, new RoutedEventHandler((s, _) => ApplyWindowFrame((Window)s)));
        Application.Current.Exit += (_, _) => SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
    }

    public static void SetMode(AppTheme mode)
    {
        if (mode == Mode) return;
        Mode = mode;
        SaveMode(mode);
        Apply();
    }

    private static void OnUserPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
    {
        // Light/dark and accent changes arrive as General (ImmersiveColorSet) or Color.
        if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color or UserPreferenceCategory.VisualStyle)
            Application.Current?.Dispatcher.BeginInvoke(Apply);
    }

    private static void Apply()
    {
        var app = Application.Current;
        if (app == null) return;
        var dark = Mode switch { AppTheme.Dark => true, AppTheme.Light => false, _ => SystemUsesDarkTheme() };
        IsDark = dark;
        var accent = ReadAccentPalette();
        var fill = dark ? accent.Light2 : accent.Dark1;

        ApplyMahAppsTheme(app, dark, fill);

        var tokens = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/CertMaster.UI.Desktop;component/Themes/{(dark ? "Dark" : "Light")}.xaml"),
        };
        AddAccentBrushes(tokens, accent, dark);

        // Keep the tokens last so they win over the MahApps theme dictionary, which ChangeTheme re-adds.
        var merged = app.Resources.MergedDictionaries;
        if (_tokens != null) merged.Remove(_tokens);
        merged.Add(tokens);
        _tokens = tokens;

        foreach (Window w in app.Windows) ApplyWindowFrame(w);
    }

    private static void ApplyMahAppsTheme(Application app, bool dark, Color accent)
    {
        var baseColor = dark ? ThemeManager.BaseColorDark : ThemeManager.BaseColorLight;
        var key = baseColor + accent;
        try
        {
            if (!RuntimeThemes.TryGetValue(key, out var theme))
            {
                var generated = RuntimeThemeGenerator.Current.GenerateRuntimeTheme(baseColor, accent);
                if (generated != null) RuntimeThemes[key] = theme = ThemeManager.Current.AddTheme(generated);
            }
            if (theme != null) { ThemeManager.Current.ChangeTheme(app, theme); return; }
        }
        catch (Exception) { /* fall back to a built-in MahApps theme below */ }
        ThemeManager.Current.ChangeTheme(app, baseColor + ".Blue");
    }

    private static void AddAccentBrushes(ResourceDictionary d, AccentPalette p, bool dark)
    {
        var fill = dark ? p.Light2 : p.Dark1;
        var text = dark ? p.Light3 : p.Dark2;
        var onAccent = dark ? Colors.Black : Colors.White;

        d["Cm.AccentColor"] = fill;
        d["Cm.AccentFill"] = Freeze(new SolidColorBrush(fill));
        d["Cm.AccentFillHover"] = Freeze(new SolidColorBrush(WithAlpha(fill, 0xE6)));
        d["Cm.AccentFillPressed"] = Freeze(new SolidColorBrush(WithAlpha(fill, 0xCC)));
        d["Cm.AccentFillDisabled"] = Freeze(new SolidColorBrush(dark ? Color.FromArgb(0x28, 0xFF, 0xFF, 0xFF) : Color.FromArgb(0x37, 0, 0, 0)));
        d["Cm.AccentText"] = Freeze(new SolidColorBrush(text));
        d["Cm.AccentSubtle"] = Freeze(new SolidColorBrush(WithAlpha(fill, dark ? (byte)0x26 : (byte)0x1A)));
        d["Cm.TextOnAccent"] = Freeze(new SolidColorBrush(onAccent));
        d["Cm.TextOnAccentSecondary"] = Freeze(new SolidColorBrush(WithAlpha(onAccent, 0xB3)));
        d["Cm.TextOnAccentDisabled"] = Freeze(new SolidColorBrush(dark ? Color.FromArgb(0x87, 0xFF, 0xFF, 0xFF) : Colors.White));

        // Accent buttons: a light top edge and a darker bottom edge (WinUI AccentControlElevationBorderBrush).
        d["Cm.AccentElevationBorder"] = Freeze(FlippedEdgeBrush(3,
            (0.33, dark ? Color.FromArgb(0x23, 0, 0, 0) : Color.FromArgb(0x66, 0, 0, 0)),
            (1.0, Color.FromArgb(0x14, 0xFF, 0xFF, 0xFF))));
        // Focused text input: 2px accent line at the bottom, neutral stroke elsewhere.
        var stroke = ((SolidColorBrush)d["Cm.ControlStroke"]).Color;
        d["Cm.TextControlBorderFocused"] = Freeze(FlippedEdgeBrush(3, (0.66, fill), (0.66, stroke)));

        // MahApps selection colors (data grid rows) toned down to Fluent's subtle selection.
        var subtle = (Brush)d["Cm.SubtleFillSelected"];
        var primary = (Brush)d["Cm.TextPrimary"];
        foreach (var k in new[] { "", ".Inactive", ".MouseOver" })
        {
            d["MahApps.Brushes.DataGrid.Selection.Background" + k] = subtle;
            d["MahApps.Brushes.DataGrid.Selection.Text" + k] = primary;
            d["MahApps.Brushes.DataGrid.Selection.BorderBrush" + k] = Brushes.Transparent;
        }
        d["MahApps.Brushes.DataGrid.Selection.BorderBrush.Focus"] = Brushes.Transparent;
        d["MahApps.Brushes.ThemeBackground"] = d["Cm.FlyoutBackground"];
        d["MahApps.Brushes.ComboBox.PopupBorder"] = d["Cm.FlyoutStroke"];
    }

    /// <summary>A vertical gradient measured in pixels from the bottom edge, so a thin line sits along the bottom.</summary>
    private static LinearGradientBrush FlippedEdgeBrush(double height, params (double Offset, Color Color)[] stops)
    {
        var b = new LinearGradientBrush { MappingMode = BrushMappingMode.Absolute, StartPoint = new Point(0, 0), EndPoint = new Point(0, height) };
        b.RelativeTransform = new ScaleTransform(1, -1, 0.5, 0.5);
        foreach (var (o, c) in stops) b.GradientStops.Add(new GradientStop(c, o));
        return b;
    }

    private static T Freeze<T>(T f) where T : Freezable { f.Freeze(); return f; }
    private static Color WithAlpha(Color c, byte a) => Color.FromArgb(a, c.R, c.G, c.B);

    // ---------- Windows settings ----------

    private static bool SystemUsesDarkTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception) { return false; }
    }

    private readonly record struct AccentPalette(Color Light3, Color Light2, Color Dark1, Color Dark2);

    /// <summary>Reads the Windows accent palette (8 RGBA entries: Light3, Light2, Light1, Base, Dark1, Dark2, Dark3, unused).</summary>
    private static AccentPalette ReadAccentPalette()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent");
            if (key?.GetValue("AccentPalette") is byte[] { Length: >= 24 } p)
            {
                Color At(int i) => Color.FromRgb(p[i * 4], p[i * 4 + 1], p[i * 4 + 2]);
                return new AccentPalette(At(0), At(1), At(4), At(5));
            }
        }
        catch (Exception) { /* use the default palette */ }
        return new AccentPalette(DefaultAccentLight3, DefaultAccentLight2, DefaultAccentDark1, DefaultAccentDark2);
    }

    private static AppTheme LoadMode()
    {
        try { return File.Exists(PreferenceFile) && Enum.TryParse<AppTheme>(File.ReadAllText(PreferenceFile).Trim(), out var m) ? m : AppTheme.System; }
        catch (Exception) { return AppTheme.System; }
    }

    private static void SaveMode(AppTheme mode)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PreferenceFile)!);
            File.WriteAllText(PreferenceFile, mode.ToString());
        }
        catch (Exception) { /* preference is a convenience; ignore write failures */ }
    }

    // ---------- window frame ----------

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWCP_ROUND = 2;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    /// <summary>Rounded corners on Windows 11 and a dark system frame (menus, borders) in dark mode. No-op on older Windows.</summary>
    private static void ApplyWindowFrame(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero || !OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) return;
        var round = DWMWCP_ROUND;
        var dark = IsDark ? 1 : 0;
        DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref round, sizeof(int));
        DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref dark, sizeof(int));
    }
}
