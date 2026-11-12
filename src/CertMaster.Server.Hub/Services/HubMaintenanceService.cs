using CertMaster.Core.Storage;

namespace CertMaster.Server.Hub.Services;

/// <summary>Daily backup of the hub database (users, joined instances, joining keys); keeps the newest 14.</summary>
public class HubMaintenanceService : BackgroundService
{
    private readonly DocumentStore _store;
    private readonly DataPaths _paths;
    private readonly ILogger<HubMaintenanceService> _logger;

    public HubMaintenanceService(DocumentStore store, DataPaths paths, ILogger<HubMaintenanceService> logger)
    {
        _store = store; _paths = paths; _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            var next = TimeSpan.FromHours(24);
            try
            {
                var file = await _store.BackupAsync(_paths.Combine("backups"));
                _logger.LogInformation("Hub database backup written to {File}", file);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Hub database backup failed; retrying in 1 hour");
                next = TimeSpan.FromHours(1);
            }
            try { await Task.Delay(next, stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}
