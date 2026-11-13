using System.Security.Cryptography;
using System.Text;
using CertMaster.Core.Storage;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Server.Core;

/// <summary>Instance identity and local API key. The key file is readable only by SYSTEM/Administrators.</summary>
public class AgentIdentity
{
    public const string ApiKeyHeader = "X-Api-Key";
    public string InstanceId { get; }
    public string Title { get; }
    public string ApiKey { get; }
    public string Version { get; } = typeof(AgentIdentity).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    public record IdentityFile(string InstanceId, string Title);

    public AgentIdentity(DataPaths paths)
    {
        var id = LoadOrCreateIdentity(paths.Combine("instance.json"));
        InstanceId = id.InstanceId;
        Title = id.Title;
        ApiKey = LoadOrCreateApiKey(ApiKeyPath(paths));
    }

    public static string ApiKeyPath(DataPaths paths) => paths.Combine("agent-api.key");

    /// <summary>
    /// The instance id is how the hub knows this agent, so it is never replaced just because the file could not be read:
    /// a damaged file is recovered from its backup, and if neither copy is usable startup fails instead of silently
    /// registering as a new instance.
    /// </summary>
    public static IdentityFile LoadOrCreateIdentity(string file)
    {
        static IdentityFile? Parse(string json) =>
            JsonDefaults.Deserialize<IdentityFile>(json) is { InstanceId.Length: > 0 } f ? f : null;

        var id = AtomicFile.Read(file, Parse, out var fromBackup);
        if (id != null)
        {
            if (fromBackup) AtomicFile.WriteAllText(file, JsonDefaults.Serialize(id));
            return id;
        }
        if (AtomicFile.Exists(file))
            throw new InvalidOperationException(
                $"The instance identity file {file} could not be read and has no usable backup. Restore it from a backup to keep this " +
                "agent's identity, or delete it (and any .bak) to start as a new instance (it will need to join the management hub again).");

        id = new IdentityFile(Guid.NewGuid().ToString(), Environment.MachineName);
        AtomicFile.WriteAllText(file, JsonDefaults.Serialize(id));
        return id;
    }

    /// <summary>The local API key; recovered from its backup when damaged, generated only when there is none at all.</summary>
    public static string LoadOrCreateApiKey(string file)
    {
        static string? Parse(string text) => text.Trim() is { Length: >= 32 } k && k.All(char.IsAsciiHexDigit) ? k : null;

        var key = AtomicFile.Read(file, Parse, out var fromBackup);
        if (key != null)
        {
            if (fromBackup) AtomicFile.WriteAllText(file, key);
            return key;
        }
        // Local clients read the key file on start, so a new key only means restarting the desktop app.
        key = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        AtomicFile.WriteAllText(file, key);
        return key;
    }

    /// <summary>
    /// API paths that need no key: the health check, and the read-only status summary when the caller is on this machine
    /// (the tray monitor runs unelevated and can't read the key file). The agent listens on loopback by default; if
    /// Agent:Url opens it to the network, remote callers still need the key for the summary.
    /// </summary>
    public static bool AllowsAnonymous(PathString path, System.Net.IPAddress? remote) =>
        path.StartsWithSegments("/api/system/health")
        || (path.StartsWithSegments("/api/system/summary") && remote != null
            && System.Net.IPAddress.IsLoopback(remote.IsIPv4MappedToIPv6 ? remote.MapToIPv4() : remote));

    public bool IsValidKey(string? candidate) =>
        candidate != null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(candidate), Encoding.UTF8.GetBytes(ApiKey));

    public SystemVersion GetVersion() => new()
    {
        Version = Version,
        InstanceId = InstanceId,
        Hostname = Environment.MachineName,
        OS = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
    };
}
