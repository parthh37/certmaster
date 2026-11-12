using CertMaster.Models;

namespace CertMaster.Core;

/// <summary>Receives live progress and item change notifications (SignalR in the agent, forwarded to the hub).</summary>
public interface IProgressReporter
{
    Task ReportProgressAsync(RequestProgressState state);
    Task ManagedCertificateUpdatedAsync(ManagedCertificate item);
}

public class NullProgressReporter : IProgressReporter
{
    public Task ReportProgressAsync(RequestProgressState state) => Task.CompletedTask;
    public Task ManagedCertificateUpdatedAsync(ManagedCertificate item) => Task.CompletedTask;
}
