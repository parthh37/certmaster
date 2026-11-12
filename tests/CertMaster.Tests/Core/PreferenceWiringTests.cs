using System.Text.Json;
using CertMaster.Core;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Providers;
using CertMaster.Core.Storage;
using CertMaster.Models;
using CertMaster.Tests.Deployment;
using CertMaster.Tests.Iis;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CertMaster.Tests.Core;

public class PercentageRenewalTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static Preferences Pct(int pct) => new() { RenewalIntervalMode = RenewalIntervalModes.PercentageOfLifetime, RenewalLifetimePercentage = pct, RenewalIntervalDays = 30 };

    private static ManagedCertificate Cert(int lifetimeDays, double daysRemaining) => new()
    {
        DateStart = Now.AddDays(daysRemaining - lifetimeDays),
        DateExpiry = Now.AddDays(daysRemaining),
    };

    [Theory]
    [InlineData(90, 75, 23, false)]  // 75% of 90 days: renew with 22.5 days left
    [InlineData(90, 75, 22, true)]
    [InlineData(6, 75, 2, false)]    // short-lived: 1.5 days left
    [InlineData(6, 75, 1.5, true)]
    [InlineData(90, 50, 46, false)]
    [InlineData(90, 50, 45, true)]
    [InlineData(90, 150, 0.8, true)] // out-of-range values are clamped to 99%: 0.9 days left
    [InlineData(90, 150, 1, false)]
    public void RenewsAtShareOfLifetime(int lifetime, int pct, double remaining, bool due) =>
        Assert.Equal(due, CertManager.IsRenewalDue(Cert(lifetime, remaining), Pct(pct), Now, out _));

    [Fact]
    public void PerItemDaysOverridesPercentage()
    {
        var c = Cert(90, 25); c.CustomRenewalDaysBeforeExpiry = 10;
        Assert.False(CertManager.IsRenewalDue(c, Pct(75), Now, out _));
    }

    [Fact]
    public void WithoutStartDate_FallsBackToDays()
    {
        var c = new ManagedCertificate { DateExpiry = Now.AddDays(29) };
        Assert.True(CertManager.IsRenewalDue(c, Pct(75), Now, out _));
        c.DateExpiry = Now.AddDays(31);
        Assert.False(CertManager.IsRenewalDue(c, Pct(75), Now, out _));
    }

    [Fact]
    public void DaysModeIsDefault() => Assert.Equal(RenewalIntervalModes.DaysBeforeExpiry, new Preferences().RenewalIntervalMode);
}

public class KeyTypeDefaultTests
{
    [Theory]
    [InlineData("", "ES256", "ES256")]
    [InlineData(null, "ES384", "ES384")]
    [InlineData("  ", null, "RS256")]
    [InlineData("RS256-4096", "ES256", "RS256-4096")]
    public void ItemValueWinsElseInstanceDefault(string? item, string? instanceDefault, string expected) =>
        Assert.Equal(expected, CertManager.ResolveKeyAlg(item, new Preferences { DefaultKeyType = instanceDefault }));

    [Fact] public void NewItemsFollowTheDefault() => Assert.Equal("", new CertRequestConfig().CSRKeyAlg);
}

public class NotificationEventTests
{
    [Theory]
    [InlineData(RequestState.NotRunning, RequestState.Error, false, false, NotificationEvents.RequestFailed)]
    [InlineData(RequestState.Error, RequestState.Error, false, false, NotificationEvents.RequestFailed)]
    [InlineData(RequestState.Success, RequestState.Warning, false, true, NotificationEvents.DeploymentTasksFailed)]
    [InlineData(RequestState.Success, RequestState.Warning, false, false, null)] // a task warning is not a failure
    [InlineData(RequestState.Error, RequestState.Success, false, false, NotificationEvents.Recovered)]
    [InlineData(RequestState.Warning, RequestState.Success, false, false, NotificationEvents.Recovered)]
    [InlineData(RequestState.Success, RequestState.Success, false, false, null)]
    [InlineData(RequestState.NotRunning, RequestState.Success, false, false, null)]
    [InlineData(RequestState.NotRunning, RequestState.Error, true, false, null)]
    public void PicksEvent(RequestState previous, RequestState current, bool cancelled, bool tasksFailed, string? expected) =>
        Assert.Equal(expected, CertManager.GetNotificationEvent(previous, current, cancelled, tasksFailed));
}

public sealed class NotificationDeliveryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"));
    private readonly RecordingHandler _http = new();
    private readonly CertManager _manager;

    public NotificationDeliveryTests()
    {
        var paths = new DataPaths(_root);
        var store = new DocumentStore(paths.Database);
        _manager = new CertManager(store, new CredentialsManager(store, new SecretProtector(paths)),
            new AcmeService(store, NullLogger<AcmeService>.Instance), new ProviderRegistry(),
            new HttpChallengeServer(NullLogger<HttpChallengeServer>.Instance), paths, NullLogger<CertManager>.Instance,
            new HttpClient(_http)) { WebServer = new FakeWebServer() };
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch { /* best effort */ }
    }

    private async Task<string> AddItemAsync(bool notify)
    {
        // No ACME account is registered, so the request fails before any network call.
        var item = new ManagedCertificate
        {
            Name = "Notify Test",
            RequestConfig = new CertRequestConfig { PrimaryDomain = "notify.example.test", SubjectAlternativeNames = { "notify.example.test" }, EnableFailureNotifications = notify },
        };
        var saved = await _manager.UpdateManagedCertificateAsync(item);
        Assert.True(saved.IsSuccess, saved.Message);
        return saved.Result!.Id;
    }

    [Fact]
    public async Task FailedRequest_PostsFailureToInstanceWebhook()
    {
        await _manager.SetPreferencesAsync(new Preferences { NotificationWebhookUrl = "https://hooks.example.test/alerts" });
        var id = await AddItemAsync(notify: true);

        var result = await _manager.PerformCertificateRequestAsync(id);

        Assert.False(result.IsSuccess);
        var (req, body) = Assert.Single(_http.Requests);
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("https://hooks.example.test/alerts", req.RequestUri!.ToString());
        using var doc = JsonDocument.Parse(body!);
        Assert.Equal(NotificationEvents.RequestFailed, doc.RootElement.GetProperty("event").GetString());
        Assert.Equal(id, doc.RootElement.GetProperty("managedCertificateId").GetString());
        Assert.Equal(1, doc.RootElement.GetProperty("failureCount").GetInt32());
        Assert.Contains("notify.example.test", doc.RootElement.GetProperty("domains").EnumerateArray().Select(e => e.GetString()));
        Assert.Contains("No ACME account", doc.RootElement.GetProperty("text").GetString());
    }

    [Fact]
    public async Task ItemOptOut_SendsNothing()
    {
        await _manager.SetPreferencesAsync(new Preferences { NotificationWebhookUrl = "https://hooks.example.test/alerts" });
        var id = await AddItemAsync(notify: false);
        await _manager.PerformCertificateRequestAsync(id);
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task NoWebhookUrl_SendsNothing()
    {
        var id = await AddItemAsync(notify: true);
        await _manager.PerformCertificateRequestAsync(id);
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task WebhookError_DoesNotChangeRequestOutcome()
    {
        _http.Status = System.Net.HttpStatusCode.InternalServerError;
        await _manager.SetPreferencesAsync(new Preferences { NotificationWebhookUrl = "https://hooks.example.test/alerts" });
        var id = await AddItemAsync(notify: true);
        var result = await _manager.PerformCertificateRequestAsync(id);
        Assert.False(result.IsSuccess);
        Assert.Contains("No ACME account", result.Message);
        Assert.Single(_http.Requests);
    }

    [Fact]
    public async Task TestNotification_UsesGivenUrlOrSavedOne()
    {
        var r = await _manager.SendTestNotificationAsync("https://hooks.example.test/given");
        Assert.True(r.IsSuccess, r.Message);
        Assert.Equal("https://hooks.example.test/given", _http.Requests[0].Request.RequestUri!.ToString());
        Assert.Contains("\"event\":\"test\"", _http.Requests[0].Body);

        Assert.False((await _manager.SendTestNotificationAsync(null)).IsSuccess); // nothing saved yet
        await _manager.SetPreferencesAsync(new Preferences { NotificationWebhookUrl = "https://hooks.example.test/saved" });
        Assert.True((await _manager.SendTestNotificationAsync(null)).IsSuccess);
        Assert.Equal("https://hooks.example.test/saved", _http.Requests[1].Request.RequestUri!.ToString());
    }

    [Theory]
    [InlineData("ftp://hooks.example.test/x")]
    [InlineData("not a url")]
    public async Task TestNotification_RejectsNonHttpUrls(string url)
    {
        var r = await _manager.SendTestNotificationAsync(url);
        Assert.False(r.IsSuccess);
        Assert.Contains("http(s)", r.Message);
        Assert.Empty(_http.Requests);
    }

    [Fact]
    public async Task Preview_ShowsInstanceDefaultKeyType()
    {
        await _manager.SetPreferencesAsync(new Preferences { DefaultKeyType = "ES384" });
        var item = new ManagedCertificate { RequestConfig = new CertRequestConfig { PrimaryDomain = "a.example.test", SubjectAlternativeNames = { "a.example.test" } } };
        var steps = await _manager.GeneratePreviewAsync(item);
        Assert.Contains(steps[0].Substeps, s => s.Title == "Key type" && s.Description!.StartsWith("ECDSA P-384 (instance default)"));
    }
}
