using CertMaster.Core;

namespace CertMaster.Server.Core;

/// <summary>Periodically renews certificates that are due (equivalent of the agent's scheduled renewal task).</summary>
public class RenewalBackgroundService : BackgroundService
{
    private readonly CertManager _manager;
    private readonly ILogger<RenewalBackgroundService> _logger;

    public RenewalBackgroundService(CertManager manager, ILogger<RenewalBackgroundService> logger)
    {
        _manager = manager;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            var interval = TimeSpan.FromMinutes(60);
            try
            {
                var prefs = await _manager.GetPreferencesAsync();
                interval = TimeSpan.FromMinutes(Math.Max(5, prefs.RenewalCheckIntervalMinutes));
                var results = await _manager.PerformRenewAllAsync(false, stoppingToken);
                if (results.Count > 0)
                    _logger.LogInformation("Renewal run complete: {Ok} succeeded, {Failed} failed",
                        results.Count(r => r.IsSuccess), results.Count(r => !r.IsSuccess));
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "Renewal run failed"); }

            try { await Task.Delay(interval, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}
