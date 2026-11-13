using Certes;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core;

/// <summary>
/// Renewal scheduling. The rules all aim at one thing: a certificate under auto-renew is never left to expire.
/// <list type="bullet">
/// <item>Renewal is due at the configured threshold, or earlier when the CA's ARI window (RFC 9773) says so, e.g. before a mass revocation.</item>
/// <item>The retry back-off after a failure shrinks as expiry gets closer, so failures cannot push the next attempt past expiry.</item>
/// <item>The per-run limit (MaxRenewalRequests) takes the most urgent items first and never holds back one that is about to expire.</item>
/// <item>A certificate that is inside its expiry warning window and still not renewed raises a warning (log and webhook) once a day.</item>
/// </list>
/// </summary>
public partial class CertManager
{
    /// <summary>True while a renewal run (scheduled or manual) is in progress.</summary>
    public bool IsRenewAllRunning => _renewAllLock.CurrentCount == 0;

    public static bool IsRenewalDue(ManagedCertificate item, Preferences prefs, DateTimeOffset now, out string reason)
    {
        reason = "";
        if (item.ItemType != ManagedCertificateType.SSL_ACME || !item.IncludeInAutoRenew) { reason = "auto-renew disabled"; return false; }
        if (item.DateNextScheduledRenewalAttempt is { } next && next > now && !IsBackoffCutShort(item, now))
        { reason = $"waiting for retry back-off until {next:u}"; return false; }
        if (item.DateExpiry == null) { reason = "no certificate yet"; return true; }
        if (item.CertificateRevoked) { reason = "certificate revoked"; return true; }
        if (item.DateExpiry <= now) { reason = "certificate expired"; return true; }
        if (item.AriRenewalTime is { } ari && ari <= now) { reason = "the CA's suggested renewal window (ARI) has started"; return true; }

        double? lifetime = item.DateStart != null ? (item.DateExpiry.Value - item.DateStart.Value).TotalDays : null;
        double days;
        if (item.CustomRenewalDaysBeforeExpiry == null && lifetime != null
            && string.Equals(prefs.RenewalIntervalMode, RenewalIntervalModes.PercentageOfLifetime, StringComparison.OrdinalIgnoreCase))
        {
            // Renew once the configured share of the lifetime has passed, i.e. when (100 - pct)% remains.
            var pct = Math.Clamp(prefs.RenewalLifetimePercentage, 1, 99);
            days = lifetime.Value * (100 - pct) / 100.0;
        }
        else
        {
            days = item.CustomRenewalDaysBeforeExpiry ?? prefs.RenewalIntervalDays;
            if (lifetime != null) days = Math.Min(days, lifetime.Value / 3.0);
        }
        var remaining = (item.DateExpiry.Value - now).TotalDays;
        if (remaining <= days) { reason = $"{remaining:0.#} days remaining (threshold {days:0.#})"; return true; }
        reason = "not due";
        return false;
    }

    // ---------- Retry back-off ----------

    /// <summary>
    /// Longest wait between attempts given the time left: an eighth of the remaining lifetime, between 1 and 24 hours.
    /// A certificate with 2 days left retries at least every 6 hours; one that expires within 8 hours (or has expired), hourly.
    /// </summary>
    internal static double MaxBackoffHours(DateTimeOffset? expiry, DateTimeOffset now) =>
        expiry == null ? 24 : Math.Clamp((expiry.Value - now).TotalHours / 8, 1, 24);

    /// <summary>Back-off after the <paramref name="failureCount"/>th consecutive failure: 1, 2, 4 ... 24 hours, never longer than <see cref="MaxBackoffHours"/>.</summary>
    internal static TimeSpan RetryBackoff(int failureCount, bool rateLimited, DateTimeOffset? expiry, DateTimeOffset now)
    {
        var hours = Math.Min(Math.Pow(2, Math.Max(failureCount, 1) - 1), 24);
        // Hammering a CA that is rate limiting us only extends the limit; wait at least 3 hours unless expiry is closer than that allows.
        if (rateLimited) hours = Math.Max(hours, 3);
        return TimeSpan.FromHours(Math.Min(hours, MaxBackoffHours(expiry, now)));
    }

    /// <summary>A back-off set while expiry was further away (or by an older version) ends early once the time left calls for more frequent attempts.</summary>
    private static bool IsBackoffCutShort(ManagedCertificate item, DateTimeOffset now) =>
        item.DateLastRenewalAttempt is { } last && last.AddHours(MaxBackoffHours(item.DateExpiry, now)) <= now;

    // ---------- Selection ----------

    /// <summary>Close to expiry (inside the warning window) or revoked: renewed even beyond the per-run limit.</summary>
    internal static bool IsUrgent(ManagedCertificate item, DateTimeOffset now) =>
        item.CertificateRevoked || (item.DateExpiry is { } expiry && expiry - now <= WarningWindow(item));

    /// <summary>Items due for renewal, most urgent first (revoked, then soonest expiry, then never issued), within the per-run limit.</summary>
    internal static List<ManagedCertificate> SelectDueItems(IEnumerable<ManagedCertificate> items, Preferences prefs, DateTimeOffset now)
    {
        var due = items.Where(i => IsRenewalDue(i, prefs, now, out _))
            .OrderBy(i => i.CertificateRevoked ? 0 : 1)
            .ThenBy(i => i.DateExpiry ?? DateTimeOffset.MaxValue)
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        // The limit spreads routine renewals over several runs. It must never be the reason a certificate expires.
        if (prefs.MaxRenewalRequests > 0)
            due = due.Where((i, index) => index < prefs.MaxRenewalRequests || IsUrgent(i, now)).ToList();
        return due;
    }

    /// <summary>
    /// Earliest future time at which something could become due (a back-off ending, an ARI renewal time, an ARI re-check),
    /// so the scheduler does not wait a whole check interval past it. Null when nothing is pending.
    /// </summary>
    internal static DateTimeOffset? NextWakeTime(IEnumerable<ManagedCertificate> items, DateTimeOffset now)
    {
        DateTimeOffset? best = null;
        void Consider(DateTimeOffset? t) { if (t > now && (best == null || t < best)) best = t; }
        foreach (var i in items.Where(i => i.ItemType == ManagedCertificateType.SSL_ACME && i.IncludeInAutoRenew))
        {
            Consider(i.DateNextScheduledRenewalAttempt);
            if (i.DateNextScheduledRenewalAttempt > now && i.DateLastRenewalAttempt is { } last)
                Consider(last.AddHours(MaxBackoffHours(i.DateExpiry, now)));
            Consider(i.AriRenewalTime);
            Consider(i.DateNextAriCheck);
        }
        return best;
    }

    public async Task<DateTimeOffset?> GetNextRenewalWakeTimeAsync() =>
        NextWakeTime(await _store.GetAllAsync<ManagedCertificate>(ItemsCollection), DateTimeOffset.UtcNow);

    /// <summary>Renew all items that are due. Returns the results for items attempted.</summary>
    public async Task<List<CertificateRequestResult>> PerformRenewAllAsync(bool forceAll = false, CancellationToken ct = default)
    {
        var results = new List<CertificateRequestResult>();
        if (!await _renewAllLock.WaitAsync(0, ct)) return results;
        try
        {
            var prefs = await GetPreferencesAsync();
            var items = await GetManagedCertificatesAsync();

            // A failed ARI check only means the CA's hint is missing; the normal threshold still applies.
            try { await RefreshRenewalInfoAsync(items, ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { _logger.LogWarning(ex, "Checking the CA renewal windows (ARI) failed"); }

            var due = forceAll
                ? items.Where(i => i.IncludeInAutoRenew).ToList()
                : SelectDueItems(items, prefs, DateTimeOffset.UtcNow);
            if (due.Count > 0) _logger.LogInformation("Renewal: {Count} item(s) due", due.Count);
            foreach (var item in due)
            {
                ct.ThrowIfCancellationRequested();
                if (IsRequestInProgress(item.Id)) continue;
                // One item failing in an unexpected way must not stop the renewal of the others.
                try { results.Add(await PerformCertificateRequestAsync(item.Id, ct)); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Renewal of {Name} failed unexpectedly", item.Name);
                    results.Add(new CertificateRequestResult { ManagedItem = item, Message = ex.Message });
                }
            }

            try { await WarnExpiringAsync(prefs, ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { _logger.LogWarning(ex, "Checking for expiring certificates failed"); }
        }
        finally { _renewAllLock.Release(); }
        return results;
    }

    // ---------- ACME Renewal Information (RFC 9773) ----------

    private static readonly TimeSpan AriTimeout = TimeSpan.FromSeconds(60);

    internal static bool NeedsAriCheck(ManagedCertificate item, DateTimeOffset now) =>
        item.ItemType == ManagedCertificateType.SSL_ACME && item.IncludeInAutoRenew && !item.CertificateRevoked
        && !string.IsNullOrEmpty(item.ARICertificateId) && item.DateExpiry > now
        && (item.DateNextAriCheck == null || item.DateNextAriCheck <= now);

    /// <summary>The CA's Retry-After, kept between 1 and 24 hours; 6 hours when it sends none.</summary>
    internal static TimeSpan AriRecheckDelay(TimeSpan? retryAfter) =>
        retryAfter is { } r && r > TimeSpan.Zero
            ? TimeSpan.FromTicks(Math.Clamp(r.Ticks, TimeSpan.FromHours(1).Ticks, TimeSpan.FromHours(24).Ticks))
            : TimeSpan.FromHours(6);

    /// <summary>
    /// Stores a suggested window and picks the renewal time uniformly inside it (RFC 9773 section 4.2), keeping the earlier
    /// pick while the window is unchanged. A window that has already ended means renew now. Returns true when the window changed.
    /// </summary>
    internal static bool ApplyRenewalInfo(ManagedCertificate item, DateTimeOffset? start, DateTimeOffset? end, string? explanationUrl,
        DateTimeOffset nextCheck, DateTimeOffset now, Random rng)
    {
        item.DateNextAriCheck = nextCheck;
        if (start == null || end == null || end <= start) return false;
        var changed = item.AriWindowStart != start || item.AriWindowEnd != end;
        if (!changed && item.AriRenewalTime != null) return false;
        item.AriWindowStart = start;
        item.AriWindowEnd = end;
        item.AriExplanationUrl = explanationUrl;
        item.AriRenewalTime = end <= now ? now : start.Value + TimeSpan.FromTicks((long)((end.Value - start.Value).Ticks * rng.NextDouble()));
        return changed;
    }

    private async Task RefreshRenewalInfoAsync(List<ManagedCertificate> items, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var contexts = new Dictionary<(string, bool), IAcmeContext>();
        foreach (var item in items.Where(i => NeedsAriCheck(i, now) && !IsRequestInProgress(i.Id)))
        {
            ct.ThrowIfCancellationRequested();
            DateTimeOffset? start = null, end = null;
            string? explanation = null;
            DateTimeOffset nextCheck;
            try
            {
                // The certificate was issued by the CA of the last attempt (the configured CA may have changed since).
                var key = (item.LastAttemptedCA ?? item.CertificateAuthorityId ?? "letsencrypt.org", item.UseStagingMode);
                if (!contexts.TryGetValue(key, out var acme))
                    contexts[key] = acme = (await _acme.GetContextAsync(key.Item1, key.Item2)).ctx;
                var info = await acme.GetRenewalInfo(item.ARICertificateId!).WaitAsync(AriTimeout, ct);
                start = info.SuggestedWindow?.Start;
                end = info.SuggestedWindow?.End;
                explanation = info.ExplanationUrl?.ToString();
                nextCheck = now + AriRecheckDelay(info.RetryAfter);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (NotSupportedException) { nextCheck = now.AddDays(1); } // CA without ARI
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "ARI check for {Name} failed", item.Name);
                nextCheck = now.AddHours(3);
            }

            var changed = false;
            var stored = await PatchItemAsync(item.Id, s =>
            {
                if (s.ARICertificateId != item.ARICertificateId) return false; // replaced by a new certificate meanwhile
                changed = ApplyRenewalInfo(s, start, end, explanation, nextCheck, now, Random.Shared);
                return true;
            });
            if (stored == null) continue;
            item.AriWindowStart = stored.AriWindowStart; item.AriWindowEnd = stored.AriWindowEnd;
            item.AriExplanationUrl = stored.AriExplanationUrl; item.AriRenewalTime = stored.AriRenewalTime;
            item.DateNextAriCheck = stored.DateNextAriCheck;
            if (changed)
                new ItemLog(_paths, item.Id, _logger).Info(
                    $"The CA suggests renewing between {stored.AriWindowStart:u} and {stored.AriWindowEnd:u}; renewal scheduled for {stored.AriRenewalTime:u}"
                    + (string.IsNullOrEmpty(stored.AriExplanationUrl) ? "." : $" ({stored.AriExplanationUrl})."));
        }
    }

    /// <summary>Changes one stored item under the write lock. Skips items that are being requested (the request saves its own copy) or were deleted.</summary>
    private async Task<ManagedCertificate?> PatchItemAsync(string id, Func<ManagedCertificate, bool> change)
    {
        await _itemWriteLock.WaitAsync();
        try
        {
            if (IsRequestInProgress(id)) return null;
            var stored = await _store.GetAsync<ManagedCertificate>(ItemsCollection, id);
            if (stored == null || !change(stored)) return null;
            await _store.UpsertAsync(ItemsCollection, id, stored);
            return stored;
        }
        finally { _itemWriteLock.Release(); }
    }

    // ---------- Expiry warning ----------

    /// <summary>Inside its warning window (7 days, or a fifth of a short lifetime) and not warned about in the last 24 hours.</summary>
    internal static bool NeedsExpiryWarning(ManagedCertificate item, DateTimeOffset now) =>
        item.ItemType == ManagedCertificateType.SSL_ACME && item.DateExpiry is { } expiry && expiry - now <= WarningWindow(item)
        && (item.DateLastExpiryWarning == null || now - item.DateLastExpiryWarning >= TimeSpan.FromHours(24));

    internal static string ExpiryWarningText(ManagedCertificate item, DateTimeOffset now)
    {
        var expiry = item.DateExpiry!.Value;
        var when = expiry <= now ? $"expired on {expiry:u}" : $"expires {expiry:u} (in {(expiry - now).TotalHours:0} hours)";
        var why = !item.IncludeInAutoRenew ? "auto-renew is turned off for it"
            : item.RenewalFailureMessage is { Length: > 0 } err ? $"the last attempt failed: {err}"
            : "no renewal has succeeded yet";
        return $"The certificate {when} and has not been renewed: {why}";
    }

    private async Task WarnExpiringAsync(Preferences prefs, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var item in (await GetManagedCertificatesAsync()).Where(i => NeedsExpiryWarning(i, now)))
        {
            ct.ThrowIfCancellationRequested();
            var text = ExpiryWarningText(item, now);
            _logger.LogWarning("{Name}: {Text}", item.Name, text);
            var log = new ItemLog(_paths, item.Id, _logger);
            log.Warn(text);
            if (item.RequestConfig.EnableFailureNotifications && !string.IsNullOrWhiteSpace(prefs.NotificationWebhookUrl))
            {
                var r = await PostNotificationAsync(prefs.NotificationWebhookUrl, BuildNotification(NotificationEvents.CertificateExpiring, item, text));
                if (r.IsSuccess) log.Info($"Notification ({NotificationEvents.CertificateExpiring}) sent: {r.Message}");
                else log.Warn($"Notification ({NotificationEvents.CertificateExpiring}) failed: {r.Message}");
            }
            await PatchItemAsync(item.Id, s => { s.DateLastExpiryWarning = now; return true; });
        }
    }
}
