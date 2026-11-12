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
            try
            {
                var file = await _store.BackupAsync(_paths.Combine("backups"));
                _logger.LogInformation("Database backup written to {File}", file);
                TrimItemLogs();
            }
            catch (Exception ex) { _logger.LogWarning(ex, "Maintenance run failed"); }
            try { await Task.Delay(TimeSpan.FromHours(24), stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }

    private void TrimItemLogs()
    {
        foreach (var f in new DirectoryInfo(_paths.Logs).GetFiles("item_*.log").Where(f => f.Length > MaxItemLogBytes))
        {
            try
            {
                var lines = File.ReadAllLines(f.FullName);
                File.WriteAllLines(f.FullName, lines.Skip(lines.Length / 2));
                _logger.LogInformation("Trimmed request log {File}", f.Name);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "Could not trim {File}", f.Name); }
        }
    }
}
