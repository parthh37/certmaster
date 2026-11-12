using System.Reflection;
using CertMaster.Core.Providers.Deployment;
using CertMaster.Core.Providers.Dns;
using CertMaster.Models;

namespace CertMaster.Core.Providers;

/// <summary>Supplies extra credential types (e.g. SSH, Windows, cloud service principals) beyond those implied by provider parameters.</summary>
public interface ICredentialTypeSource
{
    IEnumerable<CredentialTypeDefinition> GetCredentialTypes();
}

/// <summary>Optional source of additional DNS providers created at runtime (e.g. script-based plugin catalogs).</summary>
public interface IDnsProviderSource
{
    IEnumerable<IDnsProvider> GetProviders();
}

/// <summary>
/// Plugin catalog: DNS challenge providers, deployment tasks and credential types. Providers are discovered by reflection
/// (any public non-abstract type in this assembly implementing the interface with a parameterless constructor), so adding
/// a provider only requires adding a class.
/// </summary>
public class ProviderRegistry
{
    public IReadOnlyList<IDnsProvider> DnsProviders { get; }
    public IReadOnlyList<IDeploymentTaskProvider> DeploymentProviders { get; }
    private readonly List<ICredentialTypeSource> _credentialSources;

    public ProviderRegistry(IEnumerable<IDnsProvider>? dns = null, IEnumerable<IDeploymentTaskProvider>? deploy = null)
    {
        var dnsList = (dns ?? Discover<IDnsProvider>()).ToList();
        foreach (var source in Discover<IDnsProviderSource>())
        {
            try { dnsList.AddRange(source.GetProviders().Where(p => dnsList.All(x => x.Definition.Id != p.Definition.Id))); }
            catch { /* a broken optional source must not stop the agent */ }
        }
        DnsProviders = dnsList.OrderBy(p => p.Definition.Title, StringComparer.OrdinalIgnoreCase).ToList();
        DeploymentProviders = (deploy ?? Discover<IDeploymentTaskProvider>()).OrderBy(p => p.Definition.Title, StringComparer.OrdinalIgnoreCase).ToList();
        _credentialSources = Discover<ICredentialTypeSource>().ToList();
    }

    private static IEnumerable<T> Discover<T>() where T : class =>
        typeof(ProviderRegistry).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false, IsPublic: true } && typeof(T).IsAssignableFrom(t) && t.GetConstructor(Type.EmptyTypes) != null)
            .Select(t => { try { return (T?)Activator.CreateInstance(t); } catch { return null; } })
            .Where(x => x != null)!;

    public const string HttpBuiltInProviderId = "HTTP01.BuiltIn";

    public List<ChallengeProviderDefinition> GetChallengeProviders()
    {
        var list = new List<ChallengeProviderDefinition>
        {
            new()
            {
                Id = HttpBuiltInProviderId, Title = "HTTP Validation (built-in)", ChallengeType = ChallengeTypes.Http01,
                Description = "Answers http-01 challenges on port 80 using the built-in challenge server, and/or writes files to a web root.",
                PropagationDelaySeconds = 0,
                ProviderParameters =
                {
                    new ProviderParameter { Key = "webroot", Name = "Web root path (optional)", Description = "If set, challenge files are also written here." },
                }
            }
        };
        list.AddRange(DnsProviders.Select(p => p.Definition));
        return list;
    }

    public List<DeploymentProviderDefinition> GetDeploymentProviders() => DeploymentProviders.Select(p => p.Definition).ToList();

    public IDnsProvider? GetDnsProvider(string? id) => DnsProviders.FirstOrDefault(p => p.Definition.Id == id);
    public IDeploymentTaskProvider? GetDeploymentProvider(string? id) => DeploymentProviders.FirstOrDefault(p => p.Definition.Id == id);

    public List<CredentialTypeDefinition> GetCredentialTypes()
    {
        var types = new List<CredentialTypeDefinition>();
        void Add(CredentialTypeDefinition t) { if (types.All(x => x.ProviderType != t.ProviderType)) types.Add(t); }

        foreach (var source in _credentialSources)
            foreach (var t in source.GetCredentialTypes()) Add(t);

        foreach (var def in DnsProviders.Select(p => (ProviderDefinition)p.Definition).Concat(DeploymentProviders.Select(p => p.Definition)))
        {
            if (def.CredentialType == null) continue;
            var fields = def.ProviderParameters.Where(p => p.IsCredential).ToList();
            if (fields.Count > 0) Add(new CredentialTypeDefinition { ProviderType = def.CredentialType, Title = def.Title, Fields = fields });
        }
        return types.OrderBy(t => t.Title, StringComparer.OrdinalIgnoreCase).ToList();
    }
}

/// <summary>Credential types shared by many providers.</summary>
public class StandardCredentialTypes : ICredentialTypeSource
{
    public const string Password = "Password";
    public const string Windows = "Windows";
    public const string SSH = "SSH";
    public const string ApiToken = "ApiToken";

    public IEnumerable<CredentialTypeDefinition> GetCredentialTypes() => new[]
    {
        new CredentialTypeDefinition
        {
            ProviderType = Password, Title = "Password (e.g. PFX password)",
            Fields = { new ProviderParameter { Key = "password", Name = "Password", Type = OptionType.Password, IsRequired = true, IsCredential = true } }
        },
        new CredentialTypeDefinition
        {
            ProviderType = Windows, Title = "Windows Credentials (network share / run as user)",
            Fields =
            {
                new ProviderParameter { Key = "username", Name = "Username", IsRequired = true, IsCredential = true },
                new ProviderParameter { Key = "password", Name = "Password", Type = OptionType.Password, IsRequired = true, IsCredential = true },
                new ProviderParameter { Key = "domain", Name = "Domain (optional)", IsCredential = true },
            }
        },
        new CredentialTypeDefinition
        {
            ProviderType = SSH, Title = "SSH Credentials (password or private key)",
            Fields =
            {
                new ProviderParameter { Key = "username", Name = "Username", IsRequired = true, IsCredential = true },
                new ProviderParameter { Key = "password", Name = "Password (optional if using key)", Type = OptionType.Password, IsCredential = true },
                new ProviderParameter { Key = "privatekey", Name = "Private key file path (optional)", IsCredential = true },
                new ProviderParameter { Key = "key_passphrase", Name = "Private key passphrase (optional)", Type = OptionType.Password, IsCredential = true },
            }
        },
        new CredentialTypeDefinition
        {
            ProviderType = ApiToken, Title = "API Token",
            Fields = { new ProviderParameter { Key = "api_token", Name = "API Token", Type = OptionType.Password, IsRequired = true, IsCredential = true } }
        },
    };
}
