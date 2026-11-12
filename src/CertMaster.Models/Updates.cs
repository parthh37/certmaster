namespace CertMaster.Models;

/// <summary>How an agent or hub keeps itself up to date. Stored per install (agent database / hub database).</summary>
public class UpdateSettings
{
    /// <summary>Check GitHub Releases for a newer version on a schedule.</summary>
    public bool CheckForUpdates { get; set; } = true;
    /// <summary>Download and install a newer version automatically (silent installer run by the service).</summary>
    public bool InstallAutomatically { get; set; }
    /// <summary>Offer pre-release versions too.</summary>
    public bool IncludePrereleases { get; set; }
    /// <summary>Hours between scheduled checks (clamped to 1-168).</summary>
    public int CheckIntervalHours { get; set; } = 24;
    /// <summary>
    /// Automatic installs only start during this local hour window (start inclusive, end exclusive, 0-23).
    /// Equal values allow any time. Default 02:00-05:00.
    /// </summary>
    public int InstallWindowStartHour { get; set; } = 2;
    public int InstallWindowEndHour { get; set; } = 5;
}

public enum UpdateState
{
    Idle,
    Checking,
    Downloading,
    Installing,
    Failed,
}

/// <summary>Result of the latest update check plus what the updater is doing right now.</summary>
public class UpdateStatus
{
    /// <summary>"agent" or "hub".</summary>
    public string Product { get; set; } = "agent";
    public string CurrentVersion { get; set; } = "";
    public string? LatestVersion { get; set; }
    public bool IsUpdateAvailable { get; set; }
    public string? ReleaseName { get; set; }
    public string? ReleaseUrl { get; set; }
    public string? ReleaseNotes { get; set; }
    public bool IsPrerelease { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
    public string? AssetName { get; set; }
    public long? AssetSize { get; set; }
    public DateTimeOffset? LastChecked { get; set; }
    public UpdateState State { get; set; } = UpdateState.Idle;
    /// <summary>Human readable state, error or last result.</summary>
    public string? Message { get; set; }
    /// <summary>False when this build cannot install itself (e.g. not installed by the Windows installer).</summary>
    public bool CanInstall { get; set; } = true;
}
