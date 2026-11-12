using CertMaster.Core.Updates;

namespace CertMaster.Server.Core;

/// <summary>Scheduled update checks (and optional automatic installs) for the agent. See <see cref="UpdateManager"/>.</summary>
public class UpdateBackgroundService : BackgroundService
{
    private readonly UpdateManager _updates;

    public UpdateBackgroundService(UpdateManager updates) => _updates = updates;

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        _updates.RunScheduleAsync(TimeSpan.FromMinutes(10), stoppingToken);
}
