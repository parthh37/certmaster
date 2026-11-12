using CertMaster.Core;
using CertMaster.Models;
using Microsoft.AspNetCore.SignalR;

namespace CertMaster.Server.Core;

/// <summary>SignalR hub that pushes request progress to local UI clients.</summary>
public class StatusHub : Hub
{
    public const string Path = "/api/status";
    public const string ProgressEvent = "RequestProgressStateUpdated";
    public const string ItemUpdatedEvent = "ManagedCertificateUpdated";
}

/// <summary>Sends engine progress to local SignalR clients and (if joined) to the management hub.</summary>
public class SignalRProgressReporter : IProgressReporter
{
    private readonly IHubContext<StatusHub> _hub;
    private readonly HubClientService _hubClient;
    private readonly AgentIdentity _identity;

    public SignalRProgressReporter(IHubContext<StatusHub> hub, HubClientService hubClient, AgentIdentity identity)
    {
        _hub = hub; _hubClient = hubClient; _identity = identity;
    }

    public async Task ReportProgressAsync(RequestProgressState state)
    {
        state.InstanceId = _identity.InstanceId;
        await _hub.Clients.All.SendAsync(StatusHub.ProgressEvent, state);
        await _hubClient.ForwardProgressAsync(state);
    }

    public async Task ManagedCertificateUpdatedAsync(ManagedCertificate item)
    {
        await _hub.Clients.All.SendAsync(StatusHub.ItemUpdatedEvent, item);
        await _hubClient.ForwardItemUpdatedAsync(item);
    }
}
