using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CertMaster.Core.Updates;

/// <summary>An installable CertMaster product: which release asset it installs from and which service it restarts.</summary>
public sealed record UpdateProduct(string Key, string AssetPrefix, string ServiceName)
{
    public static readonly UpdateProduct Agent = new("agent", "certmaster-windows-x64-", "CertMaster Agent");
    public static readonly UpdateProduct Hub = new("hub", "certmaster-hub-windows-x64-", "CertMaster Management Hub");

    public bool Matches(string assetName) =>
        assetName.StartsWith(AssetPrefix, StringComparison.OrdinalIgnoreCase) && assetName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
}

/// <summary>A release picked as the update target.</summary>
public sealed record AvailableUpdate(ReleaseVersion Version, string Tag, string? Name, string? Url, string? Notes, bool IsPrerelease,
    DateTimeOffset? PublishedAt, string AssetName, string AssetUrl, long AssetSize, string? Sha256);

/// <summary>
/// Checks GitHub Releases for a newer CertMaster version, downloads the matching installer, verifies its SHA-256 against
/// the digest GitHub publishes for the asset, and runs it silently. The installer stops and restarts the service itself;
/// a wrapper restarts the service even if the installer fails, so a failed update never leaves it stopped.
/// </summary>
public class UpdateManager
{
    public const string DefaultReleasesUrl = "https://api.github.com/repos/parthh37/certmaster/releases?per_page=30";
    private const string SettingsKey = "updates";
    private static readonly TimeSpan Tick = TimeSpan.FromMinutes(15);

    private readonly UpdateProduct _product;
    private readonly ReleaseVersion _current;
    private readonly DataPaths _paths;
    private readonly DocumentStore _store;
    private readonly HttpClient _http;
    private readonly ILogger _logger;
    private readonly string _releasesUrl;
    private readonly string? _installRoot;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _sync = new();
    private UpdateStatus _status;
    private AvailableUpdate? _available;

    /// <summary>Returns a reason when installing must wait (e.g. certificate requests are running), else null.</summary>
    public Func<string?>? InstallBlocker { get; set; }

    /// <summary>Starts the installer. Replaceable for tests.</summary>
    public Func<ProcessStartInfo, Process?> Launcher { get; set; } = Process.Start;

    /// <summary>Local clock for the install window. Replaceable for tests.</summary>
    public Func<DateTimeOffset> Now { get; set; } = () => DateTimeOffset.Now;

    public UpdateManager(UpdateProduct product, string currentVersion, DataPaths paths, DocumentStore store,
        HttpClient? http = null, ILogger? logger = null, string? releasesUrl = null, string? installRoot = null)
    {
        _product = product;
        _current = ReleaseVersion.Parse(currentVersion) ?? new ReleaseVersion(new Version(0, 0, 0), null);
        _paths = paths;
        _store = store;
        _http = http ?? CreateHttpClient(currentVersion);
        _logger = logger ?? NullLogger.Instance;
        _releasesUrl = string.IsNullOrWhiteSpace(releasesUrl) ? DefaultReleasesUrl : releasesUrl;
        // Inno Setup puts unins000.exe in {app}; the services run from {app}\Service.
        _installRoot = installRoot ?? Path.GetDirectoryName(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        _status = new UpdateStatus { Product = product.Key, CurrentVersion = _current.ToString(), CanInstall = IsInstalledCopy() };
        ReadPreviousInstallOutcome();
    }

    public static HttpClient CreateHttpClient(string version)
    {
        var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("CertMaster", version));
        return http;
    }

    public string UpdatesFolder => _paths.Combine("updates");
    private string MarkerFile => Path.Combine(UpdatesFolder, "last-install.json");

    public UpdateStatus GetStatus() { lock (_sync) return JsonDefaults.Clone(_status); }

    private void SetStatus(Action<UpdateStatus> change) { lock (_sync) change(_status); }

    // ---------- settings ----------

    public async Task<UpdateSettings> GetSettingsAsync() => Normalize(await _store.GetSettingAsync<UpdateSettings>(SettingsKey));

    public async Task<UpdateSettings> SetSettingsAsync(UpdateSettings settings)
    {
        var s = Normalize(settings);
        await _store.SetSettingAsync(SettingsKey, s);
        return s;
    }

    private static UpdateSettings Normalize(UpdateSettings s)
    {
        s.CheckIntervalHours = Math.Clamp(s.CheckIntervalHours, 1, 168);
        s.InstallWindowStartHour = Math.Clamp(s.InstallWindowStartHour, 0, 23);
        s.InstallWindowEndHour = Math.Clamp(s.InstallWindowEndHour, 0, 23);
        return s;
    }

    public static bool IsInWindow(UpdateSettings s, DateTimeOffset localNow)
    {
        if (s.InstallWindowStartHour == s.InstallWindowEndHour) return true;
        var h = localNow.Hour;
        return s.InstallWindowStartHour < s.InstallWindowEndHour
            ? h >= s.InstallWindowStartHour && h < s.InstallWindowEndHour
            : h >= s.InstallWindowStartHour || h < s.InstallWindowEndHour; // window wraps midnight, e.g. 22-04
    }

    // ---------- check ----------

    public async Task<UpdateStatus> CheckAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try { await CheckCoreAsync(ct); }
        finally { _gate.Release(); }
        return GetStatus();
    }

    private async Task CheckCoreAsync(CancellationToken ct)
    {
        var settings = await GetSettingsAsync();
        SetStatus(s => { s.State = UpdateState.Checking; s.Message = "Checking for updates..."; });
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            using var req = new HttpRequestMessage(HttpMethod.Get, _releasesUrl);
            req.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var resp = await _http.SendAsync(req, timeout.Token);
            if (!resp.IsSuccessStatusCode)
                throw new HttpRequestException($"GitHub returned {(int)resp.StatusCode} {resp.ReasonPhrase}");
            var json = await resp.Content.ReadAsStringAsync(timeout.Token);
            var latest = SelectUpdate(json, _product, settings.IncludePrereleases);
            var newer = latest != null && latest.Version > _current ? latest : null;
            _available = newer;
            SetStatus(s =>
            {
                s.LastChecked = DateTimeOffset.UtcNow;
                s.State = UpdateState.Idle;
                s.IsUpdateAvailable = newer != null;
                s.LatestVersion = latest?.Version.ToString() ?? s.CurrentVersion;
                s.ReleaseName = latest?.Name;
                s.ReleaseUrl = latest?.Url;
                s.ReleaseNotes = latest?.Notes;
                s.IsPrerelease = latest?.IsPrerelease ?? false;
                s.PublishedAt = latest?.PublishedAt;
                s.AssetName = newer?.AssetName;
                s.AssetSize = newer?.AssetSize;
                s.Message = newer != null ? $"CertMaster {newer.Version} is available (you have {_current})." : $"CertMaster {_current} is up to date.";
            });
            if (newer != null) _logger.LogInformation("Update available: {Latest} (current {Current})", newer.Version, _current);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            _logger.LogWarning(ex, "Update check failed");
            SetStatus(s => { s.LastChecked = DateTimeOffset.UtcNow; s.State = UpdateState.Failed; s.Message = "Update check failed: " + ex.Message; });
        }
    }

    /// <summary>Picks the highest non-draft release (pre-releases only when allowed) that has an installer for this product.</summary>
    public static AvailableUpdate? SelectUpdate(string releasesJson, UpdateProduct product, bool includePrereleases)
    {
        using var doc = JsonDocument.Parse(releasesJson);
        var releases = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : [doc.RootElement];
        AvailableUpdate? best = null;
        foreach (var r in releases)
        {
            if (Bool(r, "draft")) continue;
            var pre = Bool(r, "prerelease");
            if (pre && !includePrereleases) continue;
            var tag = Str(r, "tag_name");
            var version = ReleaseVersion.Parse(tag);
            if (version == null || (version.Prerelease != null && !includePrereleases)) continue;
            if (best != null && !(version > best.Version)) continue;
            if (!r.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array) continue;
            foreach (var a in assets.EnumerateArray())
            {
                var name = Str(a, "name");
                var url = Str(a, "browser_download_url");
                if (name == null || url == null || !product.Matches(name)) continue;
                var digest = Str(a, "digest");
                var sha = digest != null && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) ? digest[7..].ToLowerInvariant() : null;
                best = new AvailableUpdate(version, tag!, Str(r, "name"), Str(r, "html_url"), Str(r, "body"), pre,
                    DateTimeOffset.TryParse(Str(r, "published_at"), out var p) ? p : null,
                    name, url, a.TryGetProperty("size", out var size) && size.TryGetInt64(out var sz) ? sz : 0, sha);
                break;
            }
        }
        return best;

        static string? Str(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        static bool Bool(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
    }

    // ---------- install ----------

    /// <summary>
    /// Validates that an update can be installed now, then downloads and installs it in the background (for API callers
    /// that should not wait for the download). Progress and errors are reported through <see cref="GetStatus"/>.
    /// </summary>
    public async Task<ActionResult> BeginInstallAsync(CancellationToken stopping)
    {
        if (!GetStatus().CanInstall) return ActionResult.Fail(NotInstalledMessage);
        if (GetStatus().State is UpdateState.Downloading or UpdateState.Installing) return ActionResult.Fail("An update is already being installed.");
        if (_available == null) await CheckAsync(stopping);
        var update = _available;
        if (update == null)
            return GetStatus().State == UpdateState.Failed ? ActionResult.Fail(GetStatus().Message ?? "Update check failed") : ActionResult.Ok($"CertMaster {_current} is up to date.");
        if (InstallBlocker?.Invoke() is { } reason) return ActionResult.Fail(reason);
        _ = Task.Run(async () =>
        {
            try
            {
                var r = await InstallAsync(stopping);
                if (!r.IsSuccess) SetStatus(s => s.Message = r.Message);
            }
            catch (Exception ex) { SetStatus(s => { s.State = UpdateState.Failed; s.Message = "Update failed: " + ex.Message; }); }
        }, CancellationToken.None);
        return ActionResult.Ok($"Downloading CertMaster {update.Version}. The service restarts when it is installed.");
    }

    private const string NotInstalledMessage =
        "This copy of CertMaster was not installed with the Windows installer, so it cannot update itself. Download the new version from the releases page.";

    /// <summary>Downloads, verifies and starts the installer for the update found by the last check (checking first if needed).</summary>
    public async Task<ActionResult> InstallAsync(CancellationToken ct = default)
    {
        if (!await _gate.WaitAsync(0, ct)) return ActionResult.Fail("An update check or install is already running.");
        try
        {
            if (!GetStatus().CanInstall) return ActionResult.Fail(NotInstalledMessage);
            if (_available == null) await CheckCoreAsync(ct);
            var update = _available;
            if (update == null) return GetStatus().State == UpdateState.Failed ? ActionResult.Fail(GetStatus().Message ?? "Update check failed") : ActionResult.Ok($"CertMaster {_current} is up to date.");
            if (InstallBlocker?.Invoke() is { } reason) return ActionResult.Fail(reason);

            string file;
            try
            {
                SetStatus(s => { s.State = UpdateState.Downloading; s.Message = $"Downloading {update.AssetName}..."; });
                file = await DownloadAsync(update, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                _logger.LogWarning(ex, "Update download failed");
                SetStatus(s => { s.State = UpdateState.Failed; s.Message = "Update download failed: " + ex.Message; });
                return ActionResult.Fail("Update download failed: " + ex.Message);
            }

            // Re-check: a request may have started while downloading.
            if (InstallBlocker?.Invoke() is { } late)
            {
                SetStatus(s => { s.State = UpdateState.Idle; s.Message = late; });
                return ActionResult.Fail(late);
            }
            StartInstaller(update, file);
            return ActionResult.Ok($"Installing CertMaster {update.Version}. The service restarts when setup finishes (usually within a minute or two).");
        }
        finally { _gate.Release(); }
    }

    /// <summary>Downloads the installer into the (administrator-only) data folder and verifies its SHA-256.</summary>
    public async Task<string> DownloadAsync(AvailableUpdate update, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(update.AssetUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("The release asset URL is not HTTPS.");
        if (string.IsNullOrEmpty(update.Sha256))
            throw new InvalidOperationException($"GitHub publishes no SHA-256 digest for {update.AssetName}, so it cannot be verified. Install it manually.");
        if (update.AssetName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || update.AssetName.Contains(".."))
            throw new InvalidOperationException("Unexpected asset file name.");

        Directory.CreateDirectory(UpdatesFolder);
        foreach (var old in Directory.GetFiles(UpdatesFolder, "*.exe").Concat(Directory.GetFiles(UpdatesFolder, "*.partial")))
            try { File.Delete(old); } catch (IOException) { }

        var target = Path.Combine(UpdatesFolder, update.AssetName);
        var partial = target + ".partial";
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(30));
        try
        {
            using (var resp = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token))
            {
                resp.EnsureSuccessStatusCode();
                await using var src = await resp.Content.ReadAsStreamAsync(timeout.Token);
                await using var dst = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[81920];
                long total = 0;
                int read;
                var header = new byte[2];
                while ((read = await src.ReadAsync(buffer, timeout.Token)) > 0)
                {
                    if (total < 2) Array.Copy(buffer, 0, header, (int)total, (int)Math.Min(2 - total, read));
                    total += read;
                    sha.AppendData(buffer, 0, read);
                    await dst.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
                }
                var hash = Convert.ToHexStringLower(sha.GetHashAndReset());
                if (!string.Equals(hash, update.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"Downloaded installer failed verification (SHA-256 {hash}, expected {update.Sha256}).");
                if (header[0] != (byte)'M' || header[1] != (byte)'Z')
                    throw new InvalidOperationException("Downloaded file is not a Windows executable.");
            }
            File.Move(partial, target, overwrite: true);
            return target;
        }
        catch
        {
            try { File.Delete(partial); } catch (IOException) { }
            throw;
        }
    }

    private record InstallMarker(string Version, string Log, DateTimeOffset Started);

    private void StartInstaller(AvailableUpdate update, string installer)
    {
        var log = Path.Combine(_paths.Logs, $"update-{update.Version}.log");
        var sys = Environment.SystemDirectory;
        var sc = Path.Combine(sys, "sc.exe");
        // cmd /s /c strips the outer quotes. The service is started again after setup exits whatever the outcome.
        var args = $"/d /s /c \"\"{installer}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG=\"{log}\" & \"{sc}\" start \"{_product.ServiceName}\"\"";
        var psi = new ProcessStartInfo(Path.Combine(sys, "cmd.exe"), args)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = UpdatesFolder,
        };
        File.WriteAllText(MarkerFile, JsonDefaults.Serialize(new InstallMarker(update.Version.ToString(), log, DateTimeOffset.UtcNow)));
        _logger.LogInformation("Starting update to {Version}: {Installer} (log {Log})", update.Version, installer, log);
        SetStatus(s => { s.State = UpdateState.Installing; s.Message = $"Installing CertMaster {update.Version}. The service will restart."; });
        Process? process;
        try { process = Launcher(psi); }
        catch (Exception ex)
        {
            try { File.Delete(MarkerFile); } catch (IOException) { }
            SetStatus(s => { s.State = UpdateState.Failed; s.Message = "Could not start the installer: " + ex.Message; });
            throw;
        }
        if (process != null) _ = WatchInstallerAsync(process, update, log);
    }

    /// <summary>
    /// A successful install stops this process before setup exits. If setup exits while we are still running, it failed
    /// before replacing anything (e.g. it could not start), so report that instead of showing "Installing" forever.
    /// </summary>
    private async Task WatchInstallerAsync(Process process, AvailableUpdate update, string log)
    {
        using (process)
        {
            try { await process.WaitForExitAsync(); } catch (Exception ex) { _logger.LogDebug(ex, "Could not watch the installer"); return; }
        }
        await Task.Delay(TimeSpan.FromSeconds(5));
        try { File.Delete(MarkerFile); } catch (IOException) { }
        _logger.LogWarning("Setup for {Version} exited without updating this service. Installer log: {Log}", update.Version, log);
        SetStatus(s => { s.State = UpdateState.Failed; s.Message = $"The update to CertMaster {update.Version} did not complete. Installer log: {log}"; });
    }

    /// <summary>After a restart, reports whether the last automatic install reached the version it was installing.</summary>
    private void ReadPreviousInstallOutcome()
    {
        try
        {
            if (!File.Exists(MarkerFile)) return;
            var m = JsonDefaults.Deserialize<InstallMarker>(File.ReadAllText(MarkerFile));
            File.Delete(MarkerFile);
            if (m == null) return;
            var target = ReleaseVersion.Parse(m.Version);
            if (target != null && _current.CompareTo(target) >= 0)
            {
                _logger.LogInformation("Updated to {Version}", _current);
                _status.Message = $"Updated to CertMaster {_current} on {m.Started.ToLocalTime():g}.";
            }
            else
            {
                _logger.LogWarning("The update to {Version} did not complete. Installer log: {Log}", m.Version, m.Log);
                _status.State = UpdateState.Failed;
                _status.Message = $"The update to CertMaster {m.Version} did not complete. Installer log: {m.Log}";
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Could not read the previous update result"); }
    }

    private bool IsInstalledCopy() =>
        OperatingSystem.IsWindows() && _installRoot != null && File.Exists(Path.Combine(_installRoot, "unins000.exe"));

    // ---------- schedule ----------

    /// <summary>
    /// Background loop for the host service: checks every CheckIntervalHours and, when InstallAutomatically is on, installs
    /// a found update inside the install window once nothing blocks it.
    /// </summary>
    public async Task RunScheduleAsync(TimeSpan initialDelay, CancellationToken ct)
    {
        try { await Task.Delay(initialDelay, ct); } catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            try { await RunOnceAsync(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { _logger.LogWarning(ex, "Scheduled update run failed"); }
            try { await Task.Delay(Tick, ct); } catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>One scheduler pass. Returns true when an automatic install was started.</summary>
    public async Task<bool> RunOnceAsync(CancellationToken ct)
    {
        var settings = await GetSettingsAsync();
        if (!settings.CheckForUpdates) return false;
        var last = GetStatus().LastChecked;
        var since = last == null ? TimeSpan.MaxValue : DateTimeOffset.UtcNow - last.Value;
        if (since >= TimeSpan.FromHours(settings.CheckIntervalHours) || (GetStatus().State == UpdateState.Failed && since >= TimeSpan.FromHours(1)))
            await CheckAsync(ct);

        if (!settings.InstallAutomatically || _available == null || !GetStatus().CanInstall) return false;
        // After a failed download or install, wait for the next (hourly) re-check instead of retrying every tick.
        if (GetStatus().State is UpdateState.Installing or UpdateState.Downloading or UpdateState.Failed) return false;
        if (!IsInWindow(settings, Now())) return false;
        if (InstallBlocker?.Invoke() is { } reason)
        {
            _logger.LogInformation("Automatic update to {Version} postponed: {Reason}", _available.Version, reason);
            return false;
        }
        var r = await InstallAsync(ct);
        if (!r.IsSuccess) _logger.LogWarning("Automatic update failed: {Message}", r.Message);
        return r.IsSuccess && GetStatus().State == UpdateState.Installing;
    }
}
