using CertMaster.Core;

namespace CertMaster.Server.Core;

/// <summary>Periodically renews certificates that are due (equivalent of the agent's scheduled renewal task).</summary>
public class RenewalBackgroundService : BackgroundService
{
    private static readonly TimeSpan MinGap = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan BusyRetry = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan ErrorRetry = TimeSpan.FromMinutes(5);

    private readonly CertManager _manager;
    private readonly ILogger<RenewalBackgroundService> _logger;

    public RenewalBackgroundService(CertManager manager, ILogger<RenewalBackgroundService> logger)
    {
        _manager = manager;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(60);
        var nextRun = DateTimeOffset.UtcNow + MinGap;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await WaitUntilAsync(nextRun, interval, stoppingToken); } catch (OperationCanceledException) { break; }

            // A manual "renew all" holds the run lock: check again shortly instead of skipping a whole interval.
            if (_manager.IsRenewAllRunning) { nextRun = DateTimeOffset.UtcNow + BusyRetry; continue; }

            var retry = interval;
            try
            {
                var prefs = await _manager.GetPreferencesAsync();
                interval = retry = TimeSpan.FromMinutes(Math.Clamp(prefs.RenewalCheckIntervalMinutes, 5, 1440));
                var results = await _manager.PerformRenewAllAsync(false, stoppingToken);
                if (results.Count > 0)
                    _logger.LogInformation("Renewal run complete: {Ok} succeeded, {Failed} failed",
                        results.Count(r => r.IsSuccess), results.Count(r => !r.IsSuccess));
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                // e.g. the database was briefly locked: try again soon rather than after a full interval.
                _logger.LogError(ex, "Renewal run failed; retrying in {Minutes} minutes", ErrorRetry.TotalMinutes);
                retry = ErrorRetry;
            }

            nextRun = NextRunTime(DateTimeOffset.UtcNow, retry, await GetWakeTimeAsync());
        }
    }

    private async Task<DateTimeOffset?> GetWakeTimeAsync()
    {
        try { return await _manager.GetNextRenewalWakeTimeAsync(); }
        catch (Exception ex) { _logger.LogDebug(ex, "Could not compute the next renewal wake time"); return null; }
    }

    /// <summary>The next check: after <paramref name="interval"/>, or earlier when a back-off ends or an ARI time arrives first (at least a minute from now).</summary>
    internal static DateTimeOffset NextRunTime(DateTimeOffset now, TimeSpan interval, DateTimeOffset? wake)
    {
        var next = now + interval;
        if (wake < next) next = wake.Value < now + MinGap ? now + MinGap : wake.Value;
        return next;
    }

    /// <summary>
    /// Waits until <paramref name="due"/> by the wall clock, in steps of at most a minute. One long Task.Delay does not count
    /// time the machine spent asleep or a VM spent paused, which could push a renewal check back by hours or days. A clock
    /// set backwards never stretches the wait beyond <paramref name="maxWait"/>.
    /// </summary>
    internal static async Task WaitUntilAsync(DateTimeOffset due, TimeSpan maxWait, CancellationToken ct, TimeSpan? step = null)
    {
        var maxStep = step ?? MinGap;
        while (true)
        {
            var now = DateTimeOffset.UtcNow;
            if (due - now > maxWait) due = now + maxWait;
            var left = due - now;
            if (left <= TimeSpan.Zero) return;
            await Task.Delay(left < maxStep ? left : maxStep, ct);
        }
    }
}
