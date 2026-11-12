using Microsoft.Win32;

namespace CertMaster.UI.Tray;

/// <summary>
/// Start-at-sign-in. Setup registers the tray for all users (HKLM Run, with --autostart); each user can turn it off for
/// themselves, which is remembered in HKCU because a standard user can't change HKLM. A user can also turn it on when
/// setup didn't register it, through their own HKCU Run value.
/// </summary>
public static class AutoStart
{
    public const string RunValueName = "CertMaster Tray";
    public const string AutoStartArgument = "--autostart";
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string SettingsKey = @"Software\CertMaster\Tray";
    private const string OptOutValue = "DisableAutoStart";

    private static bool MachineEntryExists()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RunKey);
        return key?.GetValue(RunValueName) != null;
    }

    private static bool UserEntryExists()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(RunValueName) != null;
    }

    public static bool IsOptedOut()
    {
        using var key = Registry.CurrentUser.OpenSubKey(SettingsKey);
        return key?.GetValue(OptOutValue) is int v && v != 0;
    }

    public static bool IsEnabled() => !IsOptedOut() && (MachineEntryExists() || UserEntryExists());

    public static void SetEnabled(bool enabled)
    {
        using (var settings = Registry.CurrentUser.CreateSubKey(SettingsKey))
        {
            if (enabled) settings.DeleteValue(OptOutValue, throwOnMissingValue: false);
            else settings.SetValue(OptOutValue, 1, RegistryValueKind.DWord);
        }

        using var run = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled && !MachineEntryExists())
            run.SetValue(RunValueName, $"\"{Environment.ProcessPath}\" {AutoStartArgument}");
        else
            run.DeleteValue(RunValueName, throwOnMissingValue: false);
    }
}
