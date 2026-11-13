using MudBlazor;

namespace CertMaster.UI.Blazor.Layout;

/// <summary>
/// MudBlazor theme following the Windows 11 / Fluent design language, matching the desktop app: Windows accent blue,
/// neutral layered surfaces, Segoe UI Variable, a 4px control radius and soft, low elevation shadows.
/// Component-level details (cards, navigation, tables) are in wwwroot/css/app.css.
/// </summary>
public static class FluentTheme
{
    private static readonly string[] Font = ["Segoe UI Variable Text", "Segoe UI", "-apple-system", "BlinkMacSystemFont", "Roboto", "Helvetica Neue", "sans-serif"];
    private static readonly string[] DisplayFont = ["Segoe UI Variable Display", "Segoe UI", "-apple-system", "BlinkMacSystemFont", "Roboto", "Helvetica Neue", "sans-serif"];

    public static MudTheme Theme { get; } = new()
    {
        PaletteLight = new PaletteLight
        {
            Primary = "#005FB8",
            PrimaryContrastText = "#FFFFFF",
            Secondary = "#616161",
            SecondaryContrastText = "#FFFFFF",
            Tertiary = "#8764B8",
            Info = "#005FB8",
            Success = "#0F7B0F",
            Warning = "#9D5D00",
            Error = "#C42B1C",
            Dark = "#1B1B1B",
            TextPrimary = "#1B1B1B",
            TextSecondary = "#616161",
            TextDisabled = "#A0A0A0",
            ActionDefault = "#5F5F5F",
            ActionDisabled = "#A0A0A0",
            ActionDisabledBackground = "#F0F0F0",
            Background = "#F9F9F9",
            BackgroundGray = "#F3F3F3",
            Surface = "#FFFFFF",
            AppbarBackground = "#F3F3F3",
            AppbarText = "#1B1B1B",
            DrawerBackground = "#F3F3F3",
            DrawerText = "#1B1B1B",
            DrawerIcon = "#5F5F5F",
            LinesDefault = "#E5E5E5",
            LinesInputs = "#8A8A8A",
            TableLines = "#EBEBEB",
            TableHover = "rgba(0,0,0,0.035)",
            TableStriped = "rgba(0,0,0,0.02)",
            Divider = "#E5E5E5",
            DividerLight = "#EDEDED",
            Skeleton = "rgba(0,0,0,0.06)",
        },
        PaletteDark = new PaletteDark
        {
            Primary = "#60CDFF",
            PrimaryContrastText = "#000000",
            Secondary = "#C8C8C8",
            SecondaryContrastText = "#000000",
            Tertiary = "#D6B4FF",
            Info = "#60CDFF",
            InfoContrastText = "#000000",
            Success = "#6CCB5F",
            SuccessContrastText = "#000000",
            Warning = "#FCE100",
            WarningContrastText = "#000000",
            Error = "#FF99A4",
            ErrorContrastText = "#000000",
            Dark = "#202020",
            TextPrimary = "#FFFFFF",
            TextSecondary = "#C8C8C8",
            TextDisabled = "#717171",
            ActionDefault = "#C8C8C8",
            ActionDisabled = "#717171",
            ActionDisabledBackground = "#333333",
            Background = "#272727",
            BackgroundGray = "#202020",
            Surface = "#2D2D2D",
            AppbarBackground = "#202020",
            AppbarText = "#FFFFFF",
            DrawerBackground = "#202020",
            DrawerText = "#FFFFFF",
            DrawerIcon = "#C8C8C8",
            LinesDefault = "#3A3A3A",
            LinesInputs = "#9A9A9A",
            TableLines = "#383838",
            TableHover = "rgba(255,255,255,0.04)",
            TableStriped = "rgba(255,255,255,0.02)",
            Divider = "#3A3A3A",
            DividerLight = "#333333",
            Skeleton = "rgba(255,255,255,0.08)",
        },
        Typography = new Typography
        {
            Default = new DefaultTypography { FontFamily = Font, FontSize = ".875rem", LineHeight = "1.43", LetterSpacing = "normal" },
            H1 = new H1Typography { FontFamily = DisplayFont, FontSize = "4.25rem", FontWeight = "600", LineHeight = "1.35", LetterSpacing = "normal" },
            H2 = new H2Typography { FontFamily = DisplayFont, FontSize = "2.5rem", FontWeight = "600", LineHeight = "1.3", LetterSpacing = "normal" },
            H3 = new H3Typography { FontFamily = DisplayFont, FontSize = "2rem", FontWeight = "600", LineHeight = "1.3", LetterSpacing = "normal" },
            H4 = new H4Typography { FontFamily = DisplayFont, FontSize = "1.75rem", FontWeight = "600", LineHeight = "1.3", LetterSpacing = "normal" },
            H5 = new H5Typography { FontFamily = DisplayFont, FontSize = "1.25rem", FontWeight = "600", LineHeight = "1.4", LetterSpacing = "normal" },
            H6 = new H6Typography { FontFamily = Font, FontSize = "1rem", FontWeight = "600", LineHeight = "1.5", LetterSpacing = "normal" },
            Subtitle1 = new Subtitle1Typography { FontFamily = Font, FontSize = "1rem", FontWeight = "600", LineHeight = "1.5", LetterSpacing = "normal" },
            Subtitle2 = new Subtitle2Typography { FontFamily = Font, FontSize = ".875rem", FontWeight = "600", LineHeight = "1.43", LetterSpacing = "normal" },
            Body1 = new Body1Typography { FontFamily = Font, FontSize = ".875rem", FontWeight = "400", LineHeight = "1.43", LetterSpacing = "normal" },
            Body2 = new Body2Typography { FontFamily = Font, FontSize = ".875rem", FontWeight = "400", LineHeight = "1.43", LetterSpacing = "normal" },
            Button = new ButtonTypography { FontFamily = Font, FontSize = ".875rem", FontWeight = "600", LineHeight = "1.43", LetterSpacing = "normal", TextTransform = "none" },
            Caption = new CaptionTypography { FontFamily = Font, FontSize = ".75rem", FontWeight = "400", LineHeight = "1.33", LetterSpacing = "normal" },
            Overline = new OverlineTypography { FontFamily = Font, FontSize = ".75rem", FontWeight = "600", LineHeight = "1.33", LetterSpacing = "normal", TextTransform = "none" },
        },
        LayoutProperties = new LayoutProperties
        {
            DefaultBorderRadius = "4px",
            AppbarHeight = "48px",
            DrawerWidthLeft = "264px",
        },
        Shadows = new Shadow { Elevation = Elevations() },
    };

    /// <summary>Fluent shadows: soft, two-layer and low contrast. Index = MudBlazor elevation (0-25).</summary>
    private static string[] Elevations()
    {
        var e = new string[26];
        e[0] = "none";
        for (var i = 1; i < e.Length; i++)
        {
            var (y, blur) = i switch
            {
                1 => (1, 2),
                2 => (2, 4),
                <= 4 => (4, 8),
                <= 8 => (8, 16),
                <= 16 => (14, 28),
                _ => (32, 64),
            };
            e[i] = $"0 {y}px {blur}px rgba(0,0,0,0.14), 0 0 2px rgba(0,0,0,0.12)";
        }
        return e;
    }
}
