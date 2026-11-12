using System.Security.Cryptography;
using System.Text;
using CertMaster.Core.Storage;
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

    private record IdentityFile(string InstanceId, string Title);

    public AgentIdentity(DataPaths paths)
    {
        var idFile = paths.Combine("instance.json");
        var id = File.Exists(idFile) ? JsonDefaults.Deserialize<IdentityFile>(File.ReadAllText(idFile)) : null;
        if (id == null)
        {
            id = new IdentityFile(Guid.NewGuid().ToString(), Environment.MachineName);
            File.WriteAllText(idFile, JsonDefaults.Serialize(id));
        }
        InstanceId = id.InstanceId;
        Title = id.Title;

        var keyFile = ApiKeyPath(paths);
        if (!File.Exists(keyFile)) File.WriteAllText(keyFile, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        ApiKey = File.ReadAllText(keyFile).Trim();
    }

    public static string ApiKeyPath(DataPaths paths) => paths.Combine("agent-api.key");

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
