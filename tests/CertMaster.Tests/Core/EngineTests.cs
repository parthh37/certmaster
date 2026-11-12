using CertMaster.Core;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Xunit;

namespace CertMaster.Tests.Core;

public class RenewalTests
{
    private static readonly Preferences Prefs = new() { RenewalIntervalDays = 30 };
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private static ManagedCertificate Cert(int lifetimeDays, int daysRemaining) => new()
    {
        DateStart = Now.AddDays(daysRemaining - lifetimeDays),
        DateExpiry = Now.AddDays(daysRemaining),
    };

    [Fact] public void NeverRequested_IsDue() => Assert.True(CertManager.IsRenewalDue(new ManagedCertificate(), Prefs, Now, out _));

    [Theory]
    [InlineData(90, 31, false)]
    [InlineData(90, 30, true)]
    [InlineData(90, 5, true)]
    [InlineData(6, 3, false)]   // short-lived: threshold is a third of lifetime (2 days)
    [InlineData(6, 2, true)]
    [InlineData(47, 16, false)] // 47-day certs renew at ~15.7 days remaining
    [InlineData(47, 15, true)]
    public void ThresholdScalesWithLifetime(int lifetime, int remaining, bool due) =>
        Assert.Equal(due, CertManager.IsRenewalDue(Cert(lifetime, remaining), Prefs, Now, out _));

    [Fact]
    public void AutoRenewDisabled_NotDue()
    {
        var c = Cert(90, 1); c.IncludeInAutoRenew = false;
        Assert.False(CertManager.IsRenewalDue(c, Prefs, Now, out _));
    }

    [Fact]
    public void BackoffBlocksRetry()
    {
        var c = Cert(90, 1); c.DateNextScheduledRenewalAttempt = Now.AddHours(1);
        Assert.False(CertManager.IsRenewalDue(c, Prefs, Now, out var reason));
        Assert.Contains("back-off", reason);
    }

    [Fact]
    public void RevokedIsDue()
    {
        var c = Cert(90, 80); c.CertificateRevoked = true;
        Assert.True(CertManager.IsRenewalDue(c, Prefs, Now, out _));
    }

    [Fact]
    public void CustomDaysOverridesDefault()
    {
        var c = Cert(90, 40); c.CustomRenewalDaysBeforeExpiry = 45;
        Assert.False(CertManager.IsRenewalDue(c, Prefs, Now, out _)); // capped by lifetime/3 = 30
        var c2 = Cert(90, 20); c2.CustomRenewalDaysBeforeExpiry = 10;
        Assert.False(CertManager.IsRenewalDue(c2, Prefs, Now, out _));
    }
}

public class ChallengeSelectionTests
{
    private static ManagedCertificate Item(params CertRequestChallengeConfig[] configs) =>
        new() { RequestConfig = new CertRequestConfig { Challenges = configs.ToList() } };

    [Fact]
    public void FallsBackToConfigWithoutDomainMatch()
    {
        var http = new CertRequestChallengeConfig { ChallengeType = ChallengeTypes.Http01 };
        var dns = new CertRequestChallengeConfig { ChallengeType = ChallengeTypes.Dns01, DomainMatch = "*.example.com" };
        var item = Item(dns, http);
        Assert.Same(http, CertManager.SelectChallengeConfig(item, "other.org"));
        Assert.Same(dns, CertManager.SelectChallengeConfig(item, "www.example.com"));
        Assert.Same(dns, CertManager.SelectChallengeConfig(item, "*.example.com"));
    }

    [Fact]
    public void ParentDomainMatchCoversSubdomains()
    {
        var a = new CertRequestChallengeConfig { DomainMatch = "example.com; test.org" };
        var b = new CertRequestChallengeConfig();
        var item = Item(a, b);
        Assert.Same(a, CertManager.SelectChallengeConfig(item, "deep.sub.example.com"));
        Assert.Same(a, CertManager.SelectChallengeConfig(item, "test.org"));
        Assert.Same(b, CertManager.SelectChallengeConfig(item, "notexample.com"));
    }

    [Theory]
    [InlineData("example.com", null, "_acme-challenge.example.com")]
    [InlineData("*.example.com", null, "_acme-challenge.example.com")]
    [InlineData("www.example.com", "*.example.com:*.auth.example.net", "_acme-challenge.www.auth.example.net")]
    [InlineData("www.other.com", "*.example.com:*.auth.example.net", "_acme-challenge.www.other.com")]
    public void DnsRecordNameAndDelegation(string domain, string? rule, string expected) =>
        Assert.Equal(expected, CertManager.GetDnsRecordName(domain, rule));

    [Fact]
    public void MergeParametersUsesDefaultsForBlanks()
    {
        var def = new ChallengeProviderDefinition
        {
            ProviderParameters =
            {
                new ProviderParameter { Key = "a", Value = "default-a" },
                new ProviderParameter { Key = "b", Value = "default-b" },
                new ProviderParameter { Key = "secret", Value = "x", IsCredential = true },
            }
        };
        var merged = CertManager.MergeParameters(def, new[] { new ProviderParameterSetting("a", "custom"), new ProviderParameterSetting("b", "") });
        Assert.Equal("custom", merged["a"]);
        Assert.Equal("default-b", merged["b"]);
        Assert.False(merged.ContainsKey("secret"));
    }
}

public sealed class StorageTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cm-tests-" + Guid.NewGuid().ToString("N"));
    private readonly DataPaths _paths;

    public StorageTests()
    {
        _paths = new DataPaths(_dir);
    }

    [Fact]
    public async Task DocumentStore_RoundTripsAndDeletes()
    {
        var store = new DocumentStore(_paths.Database);
        var item = new ManagedCertificate { Name = "a", RequestConfig = { PrimaryDomain = "a.example.com" } };
        await store.UpsertAsync("managedcertificates", item.Id, item);
        item.Name = "b";
        await store.UpsertAsync("managedcertificates", item.Id, item);
        var all = await store.GetAllAsync<ManagedCertificate>("managedcertificates");
        Assert.Single(all);
        Assert.Equal("b", all[0].Name);
        Assert.True(await store.DeleteAsync("managedcertificates", item.Id));
        Assert.Empty(await store.GetAllAsync<ManagedCertificate>("managedcertificates"));
    }

    [Fact]
    public async Task DocumentStore_ConcurrentWritesAreSafe()
    {
        var store = new DocumentStore(_paths.Database);
        await Task.WhenAll(Enumerable.Range(0, 50).Select(i => store.UpsertAsync("c", i.ToString(), new { i })));
        Assert.Equal(50, (await store.GetAllAsync<Dictionary<string, int>>("c")).Count);
    }

    [Fact]
    public async Task DocumentStore_BackupKeepsNewest()
    {
        var store = new DocumentStore(_paths.Database);
        await store.UpsertAsync("x", "1", new { v = 1 });
        var folder = Path.Combine(_dir, "backups");
        for (var i = 0; i < 3; i++) { await store.BackupAsync(folder, keep: 2); await Task.Delay(1100); }
        var files = Directory.GetFiles(folder, "*.db");
        Assert.Equal(2, files.Length);
        var restored = new DocumentStore(files[0]);
        Assert.NotNull(await restored.GetAsync<Dictionary<string, int>>("x", "1"));
    }

    [Fact]
    public async Task Credentials_EncryptedAtRestAndNeverReturned()
    {
        var store = new DocumentStore(_paths.Database);
        var creds = new CredentialsManager(store, new SecretProtector(_paths));
        var saved = await creds.UpdateAsync(new StoredCredential { ProviderType = "ApiToken", Title = "t", Secret = "{\"api_token\":\"super-secret-value\"}" });
        Assert.Null(saved.Secret);
        Assert.All(await creds.GetCredentialsAsync(), c => Assert.Null(c.Secret));
        Assert.Equal("super-secret-value", (await creds.GetUnlockedCredentialsDictionaryAsync(saved.StorageKey))["api_token"]);

        // update without a secret keeps the existing one
        await creds.UpdateAsync(new StoredCredential { StorageKey = saved.StorageKey, ProviderType = "ApiToken", Title = "renamed" });
        Assert.Equal("super-secret-value", (await creds.GetUnlockedCredentialsDictionaryAsync(saved.StorageKey))["api_token"]);

        var raw = await store.GetAsync<StoredCredential>("credentials", saved.StorageKey);
        Assert.DoesNotContain("super-secret-value", raw!.Secret);
    }

    [Fact]
    public async Task Credentials_RejectNonObjectSecret()
    {
        var creds = new CredentialsManager(new DocumentStore(_paths.Database), new SecretProtector(_paths));
        await Assert.ThrowsAnyAsync<Exception>(() => creds.UpdateAsync(new StoredCredential { ProviderType = "x", Secret = "[1,2]" }));
    }

    [Fact]
    public void ItemLog_ParsesWhatItWrites()
    {
        var log = new ItemLog(_paths, "abc", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        log.Info("hello"); log.Error("bad [thing]");
        var entries = ItemLog.Read(_paths, "abc");
        Assert.Equal(2, entries.Count);
        Assert.Equal("ERR", entries[1].Level);
        Assert.Equal("bad [thing]", entries[1].Message);
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(_dir, true); } catch { /* best effort */ }
    }
}

public class SummaryTests
{
    [Fact]
    public void SummaryCountsByHealth()
    {
        var items = new[]
        {
            new ManagedCertificate { Health = ManagedCertificateHealth.OK, DateExpiry = DateTimeOffset.UtcNow.AddDays(60) },
            new ManagedCertificate { Health = ManagedCertificateHealth.Error },
            new ManagedCertificate { Health = ManagedCertificateHealth.Warning, DateExpiry = DateTimeOffset.UtcNow.AddDays(3) },
            new ManagedCertificate { Health = ManagedCertificateHealth.AwaitingUser },
        };
        var s = ManagedInstanceSummary.From(items);
        Assert.Equal((4, 1, 1, 1, 1, 1), (s.Total, s.Healthy, s.Error, s.Warning, s.AwaitingUser, s.ExpiringSoon));
    }

    [Fact]
    public void JsonRoundTripPreservesEnumsAsStrings()
    {
        var json = JsonDefaults.Serialize(new ManagedCertificate { RequestConfig = { DeploymentSiteOption = DeploymentOption.AllSites } });
        Assert.Contains("\"AllSites\"", json);
        Assert.Equal(DeploymentOption.AllSites, JsonDefaults.Deserialize<ManagedCertificate>(json)!.RequestConfig.DeploymentSiteOption);
    }
}
