using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using CertMaster.Core.Storage;
using CertMaster.Core.Updates;
using CertMaster.Models;
using Xunit;

namespace CertMaster.Tests.Core;

public class ReleaseVersionTests
{
    [Theory]
    [InlineData("v1.2.3", "1.2.2", 1)]
    [InlineData("1.2.3", "v1.2.3", 0)]
    [InlineData("1.2", "1.2.0", 0)]
    [InlineData("1.10.0", "1.9.9", 1)]
    [InlineData("1.3.0-beta.2", "1.3.0", -1)]
    [InlineData("1.3.0-beta.10", "1.3.0-beta.2", 1)]
    [InlineData("1.3.0-rc.1", "1.3.0-beta.9", 1)]
    [InlineData("1.3.0+build.5", "1.3.0", 0)]
    public void Compares(string a, string b, int expected) =>
        Assert.Equal(expected, Math.Sign(ReleaseVersion.Parse(a)!.CompareTo(ReleaseVersion.Parse(b))));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("latest")]
    public void RejectsNonVersions(string? text) => Assert.Null(ReleaseVersion.Parse(text));
}

public sealed class UpdateManagerTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cm-upd-" + Guid.NewGuid().ToString("N"));
    private readonly string _installRoot;
    private readonly DataPaths _paths;
    private readonly DocumentStore _store;
    private readonly byte[] _installer = Encoding.ASCII.GetBytes("MZ fake installer payload");
    private readonly List<ProcessStartInfo> _launched = new();
    private string _releasesJson = "[]";
    private HttpStatusCode _apiStatus = HttpStatusCode.OK;
    private int _downloads;

    public UpdateManagerTests()
    {
        _paths = new DataPaths(Path.Combine(_root, "data"));
        _store = new DocumentStore(_paths.Database);
        _installRoot = Path.Combine(_root, "app");
        Directory.CreateDirectory(_installRoot);
        File.WriteAllText(Path.Combine(_installRoot, "unins000.exe"), "");
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => Task.FromResult(respond(request));
    }

    private string Sha(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    private static string Release(string tag, bool pre = false, bool draft = false, string? sha = null, params string[] assets) =>
        $$"""
        {"tag_name":"{{tag}}","name":"CertMaster {{tag.TrimStart('v')}}","html_url":"https://github.com/x/y/releases/tag/{{tag}}","body":"notes",
         "draft":{{(draft ? "true" : "false")}},"prerelease":{{(pre ? "true" : "false")}},"published_at":"2026-11-01T00:00:00Z",
         "assets":[{{string.Join(",", assets.Select(a =>
            $$"""{"name":"{{a}}","size":25,"browser_download_url":"https://github.com/x/y/releases/download/{{tag}}/{{a}}"{{(sha == null ? "" : $",\"digest\":\"sha256:{sha}\"")}}}"""))}}]}
        """;

    private UpdateManager Create(string current = "1.0.1", UpdateProduct? product = null, string? installRoot = null)
    {
        var http = new HttpClient(new Handler(req =>
        {
            if (req.RequestUri!.Host == "api.github.com")
                return new HttpResponseMessage(_apiStatus) { Content = new StringContent(_releasesJson) };
            _downloads++;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(_installer) };
        }));
        return new UpdateManager(product ?? UpdateProduct.Agent, current, _paths, _store, http, installRoot: installRoot ?? _installRoot)
        {
            Launcher = psi => { _launched.Add(psi); return null; },
            Now = () => new DateTimeOffset(2026, 11, 12, 3, 0, 0, TimeSpan.Zero),
        };
    }

    [Fact]
    public void SelectsHighestStableReleaseWithMatchingAsset()
    {
        var json = "[" + string.Join(",",
            Release("v1.3.0", pre: true, sha: "aa", assets: "certmaster-windows-x64-1.3.0.exe"),
            Release("v1.2.5", draft: true, sha: "bb", assets: "certmaster-windows-x64-1.2.5.exe"),
            Release("v1.2.1", sha: "cc", assets: "certmaster-hub-windows-x64-1.2.1.exe"),
            Release("v1.2.0", sha: "DD", assets: ["certmaster-hub-windows-x64-1.2.0.exe", "certmaster-windows-x64-1.2.0.exe"]),
            Release("v1.1.0", sha: "ee", assets: "certmaster-windows-x64-1.1.0.exe")) + "]";

        var agent = UpdateManager.SelectUpdate(json, UpdateProduct.Agent, includePrereleases: false)!;
        Assert.Equal("1.2.0", agent.Version.ToString());
        Assert.Equal("certmaster-windows-x64-1.2.0.exe", agent.AssetName);
        Assert.Equal("dd", agent.Sha256);

        Assert.Equal("1.2.1", UpdateManager.SelectUpdate(json, UpdateProduct.Hub, false)!.Version.ToString());
        Assert.Equal("1.3.0", UpdateManager.SelectUpdate(json, UpdateProduct.Agent, includePrereleases: true)!.Version.ToString());
    }

    [Fact]
    public void AgentPrefixDoesNotMatchHubInstaller()
    {
        Assert.False(UpdateProduct.Agent.Matches("certmaster-hub-windows-x64-1.0.0.exe"));
        Assert.True(UpdateProduct.Hub.Matches("certmaster-hub-windows-x64-1.0.0.exe"));
        Assert.False(UpdateProduct.Agent.Matches("certmaster-windows-x64-1.0.0.zip"));
    }

    [Fact]
    public async Task CheckReportsNewerVersion()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var s = await Create("1.0.1").CheckAsync();
        Assert.True(s.IsUpdateAvailable);
        Assert.Equal("1.1.0", s.LatestVersion);
        Assert.Equal(UpdateState.Idle, s.State);
        Assert.NotNull(s.LastChecked);
        Assert.Equal("certmaster-windows-x64-1.1.0.exe", s.AssetName);
    }

    [Fact]
    public async Task CheckReportsUpToDate()
    {
        _releasesJson = "[" + Release("v1.0.1", sha: Sha(_installer), assets: "certmaster-windows-x64-1.0.1.exe") + "]";
        var s = await Create("1.0.1").CheckAsync();
        Assert.False(s.IsUpdateAvailable);
        Assert.Contains("up to date", s.Message);
    }

    [Fact]
    public async Task CheckFailureIsReportedNotThrown()
    {
        _apiStatus = HttpStatusCode.Forbidden;
        var s = await Create().CheckAsync();
        Assert.Equal(UpdateState.Failed, s.State);
        Assert.Contains("403", s.Message);
    }

    [Fact]
    public async Task InstallDownloadsVerifiesAndLaunchesSilentSetup()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var m = Create();
        var r = await m.InstallAsync();

        Assert.True(r.IsSuccess, r.Message);
        var psi = Assert.Single(_launched);
        Assert.EndsWith("cmd.exe", psi.FileName, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("certmaster-windows-x64-1.1.0.exe\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART", psi.Arguments);
        Assert.Contains("start \"CertMaster Agent\"", psi.Arguments);
        Assert.True(File.Exists(Path.Combine(m.UpdatesFolder, "certmaster-windows-x64-1.1.0.exe")));
        Assert.True(File.Exists(Path.Combine(m.UpdatesFolder, "last-install.json")));
        Assert.Equal(UpdateState.Installing, m.GetStatus().State);
    }

    [Fact]
    public async Task InstallRejectsDigestMismatch()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: new string('0', 64), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var m = Create();
        var r = await m.InstallAsync();

        Assert.False(r.IsSuccess);
        Assert.Contains("verification", r.Message);
        Assert.Empty(_launched);
        Assert.Empty(Directory.GetFiles(m.UpdatesFolder));
        Assert.Equal(UpdateState.Failed, m.GetStatus().State);
    }

    [Fact]
    public async Task InstallRefusesAssetWithoutDigest()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: null, assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var r = await Create().InstallAsync();
        Assert.False(r.IsSuccess);
        Assert.Contains("SHA-256", r.Message);
        Assert.Empty(_launched);
    }

    [Fact]
    public async Task InstallWaitsForBlocker()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var m = Create();
        m.InstallBlocker = () => "busy";
        var r = await m.InstallAsync();
        Assert.False(r.IsSuccess);
        Assert.Equal("busy", r.Message);
        Assert.Equal(0, _downloads);
        Assert.Empty(_launched);
    }

    [Fact]
    public async Task NonInstalledCopyCannotInstall()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var m = Create(installRoot: Path.Combine(_root, "nowhere"));
        Assert.False(m.GetStatus().CanInstall);
        var r = await m.InstallAsync();
        Assert.False(r.IsSuccess);
        Assert.Empty(_launched);
    }

    [Fact]
    public async Task HubUsesHubInstallerAndService()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: ["certmaster-windows-x64-1.1.0.exe", "certmaster-hub-windows-x64-1.1.0.exe"]) + "]";
        var r = await Create(product: UpdateProduct.Hub).InstallAsync();
        Assert.True(r.IsSuccess, r.Message);
        Assert.Contains("certmaster-hub-windows-x64-1.1.0.exe", _launched[0].Arguments);
        Assert.Contains("start \"CertMaster Management Hub\"", _launched[0].Arguments);
    }

    [Theory]
    [InlineData(2, 5, 3, true)]
    [InlineData(2, 5, 5, false)]
    [InlineData(2, 5, 1, false)]
    [InlineData(22, 4, 23, true)]
    [InlineData(22, 4, 2, true)]
    [InlineData(22, 4, 12, false)]
    [InlineData(0, 0, 15, true)]
    public void InstallWindow(int start, int end, int hour, bool expected) =>
        Assert.Equal(expected, UpdateManager.IsInWindow(new UpdateSettings { InstallWindowStartHour = start, InstallWindowEndHour = end },
            new DateTimeOffset(2026, 1, 1, hour, 30, 0, TimeSpan.Zero)));

    [Fact]
    public async Task ScheduleInstallsOnlyWhenEnabledAndInWindow()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var m = Create();

        Assert.False(await m.RunOnceAsync(CancellationToken.None)); // automatic install off by default
        Assert.True(m.GetStatus().IsUpdateAvailable);
        Assert.Empty(_launched);

        await m.SetSettingsAsync(new UpdateSettings { InstallAutomatically = true, InstallWindowStartHour = 10, InstallWindowEndHour = 12 });
        Assert.False(await m.RunOnceAsync(CancellationToken.None)); // 03:00 is outside 10-12
        Assert.Empty(_launched);

        await m.SetSettingsAsync(new UpdateSettings { InstallAutomatically = true });
        Assert.True(await m.RunOnceAsync(CancellationToken.None)); // default window 02-05 includes 03:00
        Assert.Single(_launched);
    }

    [Fact]
    public async Task ScheduleDoesNothingWhenChecksDisabled()
    {
        await Create().SetSettingsAsync(new UpdateSettings { CheckForUpdates = false, InstallAutomatically = true });
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        var m = Create();
        Assert.False(await m.RunOnceAsync(CancellationToken.None));
        Assert.Null(m.GetStatus().LastChecked);
    }

    [Fact]
    public async Task SettingsAreClamped()
    {
        var s = await Create().SetSettingsAsync(new UpdateSettings { CheckIntervalHours = 0, InstallWindowStartHour = 30, InstallWindowEndHour = -1 });
        Assert.Equal(1, s.CheckIntervalHours);
        Assert.Equal(23, s.InstallWindowStartHour);
        Assert.Equal(0, s.InstallWindowEndHour);
    }

    [Fact]
    public async Task ReportsOutcomeOfPreviousInstallAfterRestart()
    {
        _releasesJson = "[" + Release("v1.1.0", sha: Sha(_installer), assets: "certmaster-windows-x64-1.1.0.exe") + "]";
        Assert.True((await Create("1.0.1").InstallAsync()).IsSuccess);

        var updated = Create("1.1.0"); // the service came back on the new version
        Assert.Contains("Updated to CertMaster 1.1.0", updated.GetStatus().Message);
        Assert.False(File.Exists(Path.Combine(updated.UpdatesFolder, "last-install.json")));

        Assert.True((await Create("1.0.1").InstallAsync()).IsSuccess);
        var failed = Create("1.0.1"); // the service came back on the old version: setup failed
        Assert.Equal(UpdateState.Failed, failed.GetStatus().State);
        Assert.Contains("did not complete", failed.GetStatus().Message);
    }
}
