using CertMaster.Core;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Providers;
using CertMaster.Core.Storage;
using CertMaster.Models;
using CertMaster.Server.Core;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CertMaster.Tests.Core;

/// <summary>Rules that keep an auto-renewed certificate from expiring: back-off limits, ARI, the per-run cap, warnings, scheduling.</summary>
public class RenewalEnforcementTests
{
    private static readonly Preferences Prefs = new() { RenewalIntervalDays = 30 };
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private static ManagedCertificate Cert(double lifetimeDays, double daysRemaining, string name = "c") => new()
    {
        Name = name,
        DateStart = Now.AddDays(daysRemaining - lifetimeDays),
        DateExpiry = Now.AddDays(daysRemaining),
    };

    // ---------- back-off ----------

    [Theory]
    [InlineData(1, false, 1000, 1)]
    [InlineData(3, false, 1000, 4)]
    [InlineData(10, false, 1000, 24)]  // far from expiry: the normal 24 h ceiling
    [InlineData(10, false, 48, 6)]     // 2 days left: at least every 6 hours
    [InlineData(10, false, 4, 1)]      // hours left: hourly
    [InlineData(10, false, -10, 1)]    // already expired: hourly
    [InlineData(1, true, 1000, 3)]     // rate limited: at least 3 hours ...
    [InlineData(1, true, 12, 1.5)]     // ... unless expiry is too close for that
    public void Backoff_never_outlasts_the_time_left(int failures, bool rateLimited, double hoursLeft, double expectedHours) =>
        Assert.Equal(expectedHours, CertManager.RetryBackoff(failures, rateLimited, Now.AddHours(hoursLeft), Now).TotalHours, 3);

    [Fact]
    public void Backoff_without_a_certificate_uses_the_24h_ceiling() =>
        Assert.Equal(24, CertManager.RetryBackoff(20, false, null, Now).TotalHours);

    [Fact]
    public void An_earlier_long_backoff_ends_early_when_expiry_gets_close()
    {
        // A 24 h back-off set 7 hours ago, with 2 days left now: the 6 h ceiling has passed, so retry now.
        var c = Cert(90, 2);
        c.DateLastRenewalAttempt = Now.AddHours(-7);
        c.DateNextScheduledRenewalAttempt = Now.AddHours(17);
        Assert.True(CertManager.IsRenewalDue(c, Prefs, Now, out _));

        c.DateLastRenewalAttempt = Now.AddHours(-1);
        Assert.False(CertManager.IsRenewalDue(c, Prefs, Now, out var reason));
        Assert.Contains("back-off", reason);
    }

    [Fact]
    public void Expired_certificate_is_due()
    {
        var c = Cert(90, -1);
        Assert.True(CertManager.IsRenewalDue(c, Prefs, Now, out var reason));
        Assert.Contains("expired", reason);
    }

    // ---------- ARI ----------

    [Fact]
    public void Ari_renewal_time_makes_a_certificate_due_early()
    {
        var c = Cert(90, 60);
        Assert.False(CertManager.IsRenewalDue(c, Prefs, Now, out _));
        c.AriRenewalTime = Now.AddMinutes(-1);
        Assert.True(CertManager.IsRenewalDue(c, Prefs, Now, out var reason));
        Assert.Contains("ARI", reason);
        c.AriRenewalTime = Now.AddDays(1);
        Assert.False(CertManager.IsRenewalDue(c, Prefs, Now, out _));
    }

    [Fact]
    public void Ari_time_is_picked_inside_the_window_and_kept_while_it_is_unchanged()
    {
        var c = Cert(90, 40);
        var start = Now.AddDays(5); var end = Now.AddDays(7);
        Assert.True(CertManager.ApplyRenewalInfo(c, start, end, "https://ca.test/why", Now.AddHours(6), Now, new Random(1)));
        Assert.InRange(c.AriRenewalTime!.Value, start, end);
        Assert.Equal(Now.AddHours(6), c.DateNextAriCheck);
        Assert.Equal("https://ca.test/why", c.AriExplanationUrl);

        var picked = c.AriRenewalTime;
        Assert.False(CertManager.ApplyRenewalInfo(c, start, end, null, Now.AddHours(12), Now, new Random(2)));
        Assert.Equal(picked, c.AriRenewalTime);
        Assert.Equal(Now.AddHours(12), c.DateNextAriCheck);
    }

    [Fact]
    public void Ari_window_that_already_ended_means_renew_now()
    {
        var c = Cert(90, 40);
        CertManager.ApplyRenewalInfo(c, Now.AddDays(-3), Now.AddDays(-2), null, Now.AddHours(6), Now, new Random(1));
        Assert.Equal(Now, c.AriRenewalTime);
        Assert.True(CertManager.IsRenewalDue(c, Prefs, Now, out _));
    }

    [Fact]
    public void Invalid_or_missing_ari_window_only_schedules_the_next_check()
    {
        var c = Cert(90, 40);
        Assert.False(CertManager.ApplyRenewalInfo(c, Now.AddDays(2), Now.AddDays(1), null, Now.AddHours(3), Now, new Random(1)));
        Assert.False(CertManager.ApplyRenewalInfo(c, null, null, null, Now.AddHours(3), Now, new Random(1)));
        Assert.Null(c.AriRenewalTime);
        Assert.Equal(Now.AddHours(3), c.DateNextAriCheck);
    }

    [Theory]
    [InlineData(null, 6)]
    [InlineData(0.0, 6)]
    [InlineData(0.1, 1)]
    [InlineData(6.0, 6)]
    [InlineData(72.0, 24)]
    public void Ari_recheck_follows_retry_after_within_bounds(double? retryAfterHours, double expected) =>
        Assert.Equal(expected, CertManager.AriRecheckDelay(retryAfterHours is { } h ? TimeSpan.FromHours(h) : null).TotalHours);

    [Fact]
    public void Ari_is_checked_only_for_live_auto_renewed_certificates()
    {
        var c = Cert(90, 40); c.ARICertificateId = "aki.serial";
        Assert.True(CertManager.NeedsAriCheck(c, Now));
        c.DateNextAriCheck = Now.AddHours(1);
        Assert.False(CertManager.NeedsAriCheck(c, Now));
        c.DateNextAriCheck = null; c.IncludeInAutoRenew = false;
        Assert.False(CertManager.NeedsAriCheck(c, Now));
        c.IncludeInAutoRenew = true; c.ARICertificateId = null;
        Assert.False(CertManager.NeedsAriCheck(c, Now));
    }

    // ---------- per-run limit ----------

    [Fact]
    public void Per_run_limit_takes_the_most_urgent_first_and_never_holds_back_an_expiring_certificate()
    {
        var prefs = new Preferences { RenewalIntervalDays = 30, MaxRenewalRequests = 1 };
        var items = new[]
        {
            Cert(90, 25, "a-routine"),
            Cert(90, 20, "b-routine"),
            Cert(90, 3, "z-expiring"),
            Cert(90, 2, "y-expiring"),
        };
        var due = CertManager.SelectDueItems(items, prefs, Now).Select(i => i.Name).ToList();
        // Soonest expiry first; both inside the warning window get through despite the limit of 1; routine ones wait.
        Assert.Equal(new[] { "y-expiring", "z-expiring" }, due);

        var calm = new[] { Cert(90, 25, "a"), Cert(90, 20, "b") };
        Assert.Equal(new[] { "b" }, CertManager.SelectDueItems(calm, prefs, Now).Select(i => i.Name));
    }

    [Fact]
    public void Revoked_certificates_come_first()
    {
        var revoked = Cert(90, 80, "revoked"); revoked.CertificateRevoked = true;
        var due = CertManager.SelectDueItems(new[] { Cert(90, 10, "soon"), revoked }, Prefs, Now);
        Assert.Equal("revoked", due[0].Name);
    }

    // ---------- expiry warning ----------

    [Fact]
    public void Expiry_warning_fires_inside_the_window_at_most_once_a_day()
    {
        var c = Cert(90, 3);
        Assert.True(CertManager.NeedsExpiryWarning(c, Now));
        c.DateLastExpiryWarning = Now.AddHours(-2);
        Assert.False(CertManager.NeedsExpiryWarning(c, Now));
        c.DateLastExpiryWarning = Now.AddHours(-25);
        Assert.True(CertManager.NeedsExpiryWarning(c, Now));
        Assert.False(CertManager.NeedsExpiryWarning(Cert(90, 20), Now));
        Assert.True(CertManager.NeedsExpiryWarning(Cert(6, 1), Now)); // short-lived: a fifth of the lifetime
    }

    [Fact]
    public void Expiry_warning_text_says_why_it_was_not_renewed()
    {
        var c = Cert(90, 2); c.RenewalFailureMessage = "DNS API refused the token";
        Assert.Contains("DNS API refused the token", CertManager.ExpiryWarningText(c, Now));
        c.IncludeInAutoRenew = false;
        Assert.Contains("auto-renew is turned off", CertManager.ExpiryWarningText(c, Now));
        Assert.Contains("expired", CertManager.ExpiryWarningText(Cert(90, -1), Now));
    }

    // ---------- scheduling ----------

    [Fact]
    public void Wake_time_is_the_earliest_pending_retry_or_ari_time()
    {
        var a = Cert(90, 40, "a"); a.DateNextScheduledRenewalAttempt = Now.AddHours(5); a.DateLastRenewalAttempt = Now.AddHours(-1);
        var b = Cert(90, 40, "b"); b.AriRenewalTime = Now.AddHours(2);
        var c = Cert(90, 40, "c"); c.DateNextAriCheck = Now.AddMinutes(-5); // in the past: handled by the run that just finished
        var d = Cert(90, 40, "d"); d.AriRenewalTime = Now.AddMinutes(10); d.IncludeInAutoRenew = false;
        Assert.Equal(Now.AddHours(2), CertManager.NextWakeTime(new[] { a, b, c, d }, Now));
        Assert.Null(CertManager.NextWakeTime(new[] { c, d }, Now));
    }

    [Fact]
    public void Next_run_is_pulled_forward_by_a_wake_time_but_never_closer_than_a_minute()
    {
        var hour = TimeSpan.FromHours(1);
        Assert.Equal(Now + hour, RenewalBackgroundService.NextRunTime(Now, hour, null));
        Assert.Equal(Now.AddMinutes(20), RenewalBackgroundService.NextRunTime(Now, hour, Now.AddMinutes(20)));
        Assert.Equal(Now.AddMinutes(1), RenewalBackgroundService.NextRunTime(Now, hour, Now.AddSeconds(5)));
        Assert.Equal(Now + hour, RenewalBackgroundService.NextRunTime(Now, hour, Now.AddHours(3)));
    }

    [Fact]
    public async Task Wait_uses_the_wall_clock_and_never_exceeds_the_maximum()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await RenewalBackgroundService.WaitUntilAsync(DateTimeOffset.UtcNow.AddSeconds(-1), TimeSpan.FromHours(1), CancellationToken.None);
        // A due time far ahead (e.g. after the clock was set back) is capped by maxWait.
        await RenewalBackgroundService.WaitUntilAsync(DateTimeOffset.UtcNow.AddDays(30), TimeSpan.FromMilliseconds(200), CancellationToken.None, TimeSpan.FromMilliseconds(50));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), sw.Elapsed.ToString());
    }
}

/// <summary>The renewal run against a real store: failures get a capped back-off and expiring items are flagged.</summary>
public sealed class RenewalRunTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"));
    private readonly CertManager _manager;

    public RenewalRunTests()
    {
        var paths = new DataPaths(_root);
        var store = new DocumentStore(paths.Database);
        _manager = new CertManager(store, new CredentialsManager(store, new SecretProtector(paths)),
            new AcmeService(store, NullLogger<AcmeService>.Instance), new ProviderRegistry(),
            new HttpChallengeServer(NullLogger<HttpChallengeServer>.Instance), paths, NullLogger<CertManager>.Instance);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task Failing_renewal_close_to_expiry_retries_soon_and_raises_an_expiry_warning()
    {
        var now = DateTimeOffset.UtcNow;
        // No ACME account is registered, so the request fails without contacting a CA.
        var saved = await _manager.UpdateManagedCertificateAsync(new ManagedCertificate
        {
            Name = "expiring", RequestConfig = { PrimaryDomain = "expiring.example.test" },
            DateStart = now.AddDays(-88), DateExpiry = now.AddHours(30), RenewalFailureCount = 9,
        });
        Assert.True(saved.IsSuccess, saved.Message);

        var results = await _manager.PerformRenewAllAsync();
        Assert.Single(results);
        Assert.False(results[0].IsSuccess);

        var item = (await _manager.GetManagedCertificateAsync(saved.Result!.Id))!;
        Assert.Equal(10, item.RenewalFailureCount);
        // 30 hours left: the retry comes within 30/8 = 3.75 hours, not the usual 24.
        Assert.InRange(item.DateNextScheduledRenewalAttempt!.Value - item.DateLastRenewalAttempt!.Value, TimeSpan.FromHours(3.5), TimeSpan.FromHours(3.8));
        Assert.NotNull(item.DateLastExpiryWarning);
        Assert.Contains(_manager.GetItemLog(item.Id), e => e.Message.Contains("has not been renewed"));

        var wake = await _manager.GetNextRenewalWakeTimeAsync();
        Assert.NotNull(wake);
        Assert.True((item.DateNextScheduledRenewalAttempt!.Value - wake!.Value).Duration() < TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task Saving_an_edit_keeps_the_engine_owned_ari_and_warning_fields()
    {
        var now = DateTimeOffset.UtcNow;
        var first = await _manager.UpdateManagedCertificateAsync(new ManagedCertificate
        {
            Name = "ari", RequestConfig = { PrimaryDomain = "ari.example.test" },
            AriWindowStart = now.AddDays(1), AriWindowEnd = now.AddDays(2), AriRenewalTime = now.AddDays(1.5),
            DateNextAriCheck = now.AddHours(6), DateLastExpiryWarning = now, AriExplanationUrl = "https://ca.test/x",
        });
        Assert.True(first.IsSuccess, first.Message);

        var edit = new ManagedCertificate { Id = first.Result!.Id, Name = "ari renamed", RequestConfig = { PrimaryDomain = "ari.example.test" } };
        var second = await _manager.UpdateManagedCertificateAsync(edit);
        Assert.True(second.IsSuccess, second.Message);

        var item = (await _manager.GetManagedCertificateAsync(edit.Id))!;
        Assert.Equal("ari renamed", item.Name);
        Assert.Equal(first.Result.AriRenewalTime, item.AriRenewalTime);
        Assert.Equal(first.Result.AriWindowEnd, item.AriWindowEnd);
        Assert.Equal(first.Result.DateNextAriCheck, item.DateNextAriCheck);
        Assert.Equal(first.Result.DateLastExpiryWarning, item.DateLastExpiryWarning);
        Assert.Equal("https://ca.test/x", item.AriExplanationUrl);
    }
}
