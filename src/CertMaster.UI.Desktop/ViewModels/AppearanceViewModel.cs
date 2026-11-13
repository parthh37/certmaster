using CommunityToolkit.Mvvm.ComponentModel;

namespace CertMaster.UI.Desktop.ViewModels;

/// <summary>App theme choice (Settings > General > Appearance). Stored per user on this machine, applied immediately.</summary>
public partial class AppearanceViewModel : ObservableObject
{
    public IReadOnlyList<Option<AppTheme>> Themes { get; } =
    [
        new(AppTheme.System, "Use system setting"),
        new(AppTheme.Light, "Light"),
        new(AppTheme.Dark, "Dark"),
    ];

    [ObservableProperty] private AppTheme _theme = ThemeService.Mode;

    partial void OnThemeChanged(AppTheme value) => ThemeService.SetMode(value);
}

public sealed record Option<T>(T Value, string Title);
