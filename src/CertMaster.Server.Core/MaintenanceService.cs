using CertMaster.Core.Storage;

namespace CertMaster.Server.Core;

/// <summary>Daily housekeeping: database backup (keeps 14), and trimming of oversized per-item request logs.</summary>
public class MaintenanceService : BackgroundService
{
    private const long MaxItemLogBytes = 2 * 1024 * 1024;
    private readonly DocumentStore _store;
    private readonly DataPaths _paths;
    private readonly ILogger<MaintenanceService> _logger;

    public MaintenanceService(DocumentStore store, DataPaths paths, ILogger<MaintenanceService> logger)
    {
        _store = store; _paths = paths; _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            var retry = TimeSpan.FromHours(24);
            try
            {
                var file = await _store.BackupAsync(_paths.Combine("backups"));
                _logger.LogInformation("Database backup written to {File}", file);
            }
            catch (Exception ex)
            {
                // e.g. disk full; try again sooner than tomorrow so a transient problem doesn't cost a day of backups.
                _logger.LogWarning(ex, "Database backup failed; retrying in 1 hour");
                retry = TimeSpan.FromHours(1);
            }
            try
            {
                foreach (var name in ItemLog.TrimLargeLogs(_paths, MaxItemLogBytes)) _logger.LogInformation("Trimmed request log {File}", name);
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Request log trimming failed"); }
            try { await Task.Delay(retry, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}
