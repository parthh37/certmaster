using System.Collections.Concurrent;
using CertMaster.Core.Storage;
using CertMaster.Models;
using CertMaster.Models.Hub;
using Microsoft.AspNetCore.SignalR;

namespace CertMaster.Server.Hub.Services;

internal class StoredInstance
{
    public string InstanceId { get; set; } = "";
    public string Title { get; set; } = "";
    public string? OS { get; set; }
    public string? ClientVersion { get; set; }
    public string SecretHash { get; set; } = "";
    public string? JoiningKeyId { get; set; }
    public DateTimeOffset DateRegistered { get; set; }
    public DateTimeOffset? DateLastReported { get; set; }
    public ManagedInstanceSummary? Summary { get; set; }
}

internal class StoredJoiningKey
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string KeyHash { get; set; } = "";
    public DateTimeOffset DateCreated { get; set; }
    public DateTimeOffset? DateExpiry { get; set; }
    public bool IsRevoked { get; set; }
}

/// <summary>Tracks joined instances, their live SignalR connections, joining keys and recent progress.</summary>
public class InstanceRegistry
{
    private const string Instances = "instances";
    private const string JoiningKeys = "joiningkeys";
    private readonly DocumentStore _store;
    private readonly ILogger<InstanceRegistry> _logger;
    private readonly ConcurrentDictionary<string, string> _connectionToInstance = new();
    private readonly ConcurrentDictionary<string, string> _instanceToConnection = new();
    private readonly ConcurrentDictionary<string, RequestProgressState> _progress = new();

    public InstanceRegistry(DocumentStore store, ILogger<InstanceRegistry> logger)
    {
        _store = store; _logger = logger;
    }

    // ---- joining keys ----

    public async Task<List<JoiningKey>> GetJoiningKeysAsync() =>
        (await _store.GetAllAsync<StoredJoiningKey>(JoiningKeys))
        .Select(k => new JoiningKey { Id = k.Id, Title = k.Title, DateCreated = k.DateCreated, DateExpiry = k.DateExpiry, IsRevoked = k.IsRevoked }).ToList();

    public async Task<JoiningKey> CreateJoiningKeyAsync(string title, int? expiryDays)
    {
        var key = SecretHash.NewToken("cmjk_");
        var stored = new StoredJoiningKey
        {
            Id = Guid.NewGuid().ToString(), Title = string.IsNullOrWhiteSpace(title) ? "Joining key" : title.Trim(),
            KeyHash = SecretHash.HashToken(key), DateCreated = DateTimeOffset.UtcNow,
            DateExpiry = expiryDays is > 0 ? DateTimeOffset.UtcNow.AddDays(expiryDays.Value) : null,
        };
        await _store.UpsertAsync(JoiningKeys, stored.Id, stored);
        return new JoiningKey { Id = stored.Id, Title = stored.Title, Key = key, DateCreated = stored.DateCreated, DateExpiry = stored.DateExpiry };
    }

    public async Task<bool> RevokeJoiningKeyAsync(string id)
    {
        var k = await _store.GetAsync<StoredJoiningKey>(JoiningKeys, id);
        if (k == null) return false;
        k.IsRevoked = true;
        await _store.UpsertAsync(JoiningKeys, id, k);
        return true;
    }

    // ---- registration ----

    public async Task<InstanceRegistrationResult> RegisterAsync(string connectionId, InstanceRegistration reg)
    {
        if (string.IsNullOrWhiteSpace(reg.InstanceId)) return new() { Message = "Instance id is required" };
        var existing = await _store.GetAsync<StoredInstance>(Instances, reg.InstanceId);
        string? issuedSecret = null;

        if (!string.IsNullOrEmpty(reg.InstanceSecret))
        {
            if (existing == null || !SecretHash.VerifyToken(reg.InstanceSecret, existing.SecretHash))
                return new() { Message = "Instance credentials are not valid. Rejoin with a new joining key." };
        }
        else if (!string.IsNullOrEmpty(reg.JoiningKey))
        {
            var keys = await _store.GetAllAsync<StoredJoiningKey>(JoiningKeys);
            var key = keys.FirstOrDefault(k => SecretHash.VerifyToken(reg.JoiningKey, k.KeyHash));
            if (key == null || key.IsRevoked || (key.DateExpiry != null && key.DateExpiry < DateTimeOffset.UtcNow))
                return new() { Message = "Joining key is invalid, expired or revoked." };
            issuedSecret = SecretHash.NewToken("cmis_");
            existing ??= new StoredInstance { InstanceId = reg.InstanceId, DateRegistered = DateTimeOffset.UtcNow };
            existing.SecretHash = SecretHash.HashToken(issuedSecret);
            existing.JoiningKeyId = key.Id;
            _logger.LogInformation("Instance {Title} ({Id}) joined using key '{Key}'", reg.Title, reg.InstanceId, key.Title);
        }
        else return new() { Message = "A joining key is required." };

        existing.Title = string.IsNullOrWhiteSpace(existing.Title) ? reg.Title : existing.Title;
        existing.OS = reg.OS; existing.ClientVersion = reg.ClientVersion; existing.DateLastReported = DateTimeOffset.UtcNow;
        await _store.UpsertAsync(Instances, existing.InstanceId, existing);

        if (_instanceToConnection.TryGetValue(reg.InstanceId, out var oldConn)) _connectionToInstance.TryRemove(oldConn, out _);
        _connectionToInstance[connectionId] = reg.InstanceId;
        _instanceToConnection[reg.InstanceId] = connectionId;
        return new() { IsAccepted = true, InstanceSecret = issuedSecret, Message = "Registered" };
    }

    public void Disconnected(string connectionId)
    {
        if (_connectionToInstance.TryRemove(connectionId, out var instanceId))
            _instanceToConnection.TryRemove(new KeyValuePair<string, string>(instanceId, connectionId));
    }

    public string? GetInstanceForConnection(string connectionId) => _connectionToInstance.GetValueOrDefault(connectionId);
    public string? GetConnection(string instanceId) => _instanceToConnection.GetValueOrDefault(instanceId);

    public async Task ReportSummaryAsync(string instanceId, ManagedInstanceSummary summary)
    {
        var i = await _store.GetAsync<StoredInstance>(Instances, instanceId);
        if (i == null) return;
        i.Summary = summary; i.DateLastReported = DateTimeOffset.UtcNow;
        await _store.UpsertAsync(Instances, instanceId, i);
    }

    public void ReportProgress(string instanceId, RequestProgressState state)
    {
        state.InstanceId = instanceId;
        _progress[instanceId + "/" + state.ManagedCertificateId] = state;
    }

    public RequestProgressState? GetProgress(string instanceId, string itemId) => _progress.GetValueOrDefault(instanceId + "/" + itemId);

    public async Task<List<ManagedInstanceInfo>> GetInstancesAsync() =>
        (await _store.GetAllAsync<StoredInstance>(Instances)).Select(i => new ManagedInstanceInfo
        {
            InstanceId = i.InstanceId, Title = i.Title, OS = i.OS, ClientVersion = i.ClientVersion,
            DateRegistered = i.DateRegistered, DateLastReported = i.DateLastReported, Summary = i.Summary,
            IsConnected = _instanceToConnection.ContainsKey(i.InstanceId),
        }).OrderBy(i => i.Title).ToList();

    public async Task<bool> UpdateTitleAsync(string instanceId, string title)
    {
        var i = await _store.GetAsync<StoredInstance>(Instances, instanceId);
        if (i == null) return false;
        i.Title = title.Trim();
        await _store.UpsertAsync(Instances, instanceId, i);
        return true;
    }

    public Task<bool> RemoveInstanceAsync(string instanceId) => _store.DeleteAsync(Instances, instanceId);
}

/// <summary>SignalR endpoint agents connect to. Only Register is usable before an instance authenticates.</summary>
public class InstanceHub : Microsoft.AspNetCore.SignalR.Hub
{
    private static readonly ConcurrentDictionary<string, (int count, DateTimeOffset window)> FailedJoins = new();
    private const int MaxFailedJoinsPerMinute = 10;
    private readonly InstanceRegistry _registry;
    public InstanceHub(InstanceRegistry registry) => _registry = registry;

    public async Task<InstanceRegistrationResult> Register(InstanceRegistration reg)
    {
        var ip = Context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var now = DateTimeOffset.UtcNow;
        var entry = FailedJoins.GetValueOrDefault(ip);
        if (entry.window > now.AddMinutes(-1) && entry.count >= MaxFailedJoinsPerMinute)
            return new InstanceRegistrationResult { Message = "Too many failed join attempts. Try again later." };

        var result = await _registry.RegisterAsync(Context.ConnectionId, reg);
        if (!result.IsAccepted)
            FailedJoins[ip] = entry.window > now.AddMinutes(-1) ? (entry.count + 1, entry.window) : (1, now);
        return result;
    }

    public async Task ReportSummary(ManagedInstanceSummary summary)
    {
        var id = _registry.GetInstanceForConnection(Context.ConnectionId);
        if (id != null) await _registry.ReportSummaryAsync(id, summary);
    }

    public Task ReportProgress(RequestProgressState state)
    {
        var id = _registry.GetInstanceForConnection(Context.ConnectionId);
        if (id != null) _registry.ReportProgress(id, state);
        return Task.CompletedTask;
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        _registry.Disconnected(Context.ConnectionId);
        return base.OnDisconnectedAsync(exception);
    }
}

public class InstanceUnavailableException(string message) : Exception(message);

/// <summary>Sends commands to connected agents and awaits their results.</summary>
public class InstanceGateway
{
    private readonly IHubContext<InstanceHub> _hub;
    private readonly InstanceRegistry _registry;

    public InstanceGateway(IHubContext<InstanceHub> hub, InstanceRegistry registry)
    {
        _hub = hub; _registry = registry;
    }

    public async Task<InstanceCommandResult> SendAsync(string instanceId, string commandType, object? payload, TimeSpan? timeout = null)
    {
        var conn = _registry.GetConnection(instanceId) ?? throw new InstanceUnavailableException("Instance is not connected to the hub.");
        using var cts = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(60));
        var cmd = new InstanceCommand { CommandType = commandType, Payload = payload == null ? null : JsonDefaults.Serialize(payload) };
        try
        {
            return await _hub.Clients.Client(conn).InvokeAsync<InstanceCommandResult>("PerformCommand", cmd, cts.Token);
        }
        catch (OperationCanceledException) { throw new InstanceUnavailableException("Instance did not respond in time."); }
    }

    public async Task<T?> SendAsync<T>(string instanceId, string commandType, object? payload, TimeSpan? timeout = null)
    {
        var r = await SendAsync(instanceId, commandType, payload, timeout);
        if (!r.IsSuccess) throw new InvalidOperationException(r.Message ?? "Command failed");
        return JsonDefaults.Deserialize<T>(r.Result);
    }

    /// <summary>Queries every connected instance in parallel and merges their managed certificates.</summary>
    public async Task<List<ManagedCertificate>> GetAllManagedCertificatesAsync(string? search)
    {
        var instances = (await _registry.GetInstancesAsync()).Where(i => i.IsConnected).ToList();
        var tasks = instances.Select(async inst =>
        {
            try
            {
                var items = await SendAsync<List<ManagedCertificate>>(inst.InstanceId, InstanceCommands.GetManagedCertificates, search, TimeSpan.FromSeconds(20)) ?? new();
                foreach (var i in items) { i.InstanceId = inst.InstanceId; i.InstanceTitle = inst.Title; }
                return items;
            }
            catch { return new List<ManagedCertificate>(); }
        });
        return (await Task.WhenAll(tasks)).SelectMany(x => x).OrderBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
