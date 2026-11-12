namespace CertMaster.Models;

public enum OptionType { String, Boolean, Select, MultiLineText, Password, Number }

/// <summary>Describes one configurable field of a provider so UIs can render dynamic forms.</summary>
public class ProviderParameter
{
    public string Key { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public OptionType Type { get; set; } = OptionType.String;
    public bool IsRequired { get; set; }
    /// <summary>When true the value is stored in the provider credential rather than in the task/challenge config.</summary>
    public bool IsCredential { get; set; }
    public string? Value { get; set; }
    /// <summary>For Select: "value=Display;value2=Display 2".</summary>
    public string? OptionsList { get; set; }

    public IEnumerable<KeyValuePair<string, string>> GetOptions() =>
        (OptionsList ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(o => o.Split('=', 2))
            .Select(p => new KeyValuePair<string, string>(p[0].Trim(), (p.Length > 1 ? p[1] : p[0]).Trim()));
}

public abstract class ProviderDefinition
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public string? HelpUrl { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool IsExperimental { get; set; }
    /// <summary>Credential provider type this provider needs (matches StoredCredential.ProviderType). Null = none.</summary>
    public string? CredentialType { get; set; }
    public List<ProviderParameter> ProviderParameters { get; set; } = new();
}

public class ChallengeProviderDefinition : ProviderDefinition
{
    public string ChallengeType { get; set; } = ChallengeTypes.Dns01;
    public int PropagationDelaySeconds { get; set; } = 60;
}

public enum DeploymentContextType { LocalAsService, LocalAsUser, WindowsNetwork, SSH }

public class DeploymentProviderDefinition : ProviderDefinition
{
    public string DefaultTitle { get; set; } = "";
    public bool SupportsRemoteTarget { get; set; }
    public bool IsPreRequestCapable { get; set; }
    /// <summary>Targets this task can run against. LocalAsService is always first/default.</summary>
    public List<DeploymentContextType> SupportedTargets { get; set; } = new() { DeploymentContextType.LocalAsService };
    /// <summary>Optional note shown in the UI, e.g. "Experimental" or prerequisites.</summary>
    public string? UsageNote { get; set; }
}

/// <summary>Describes the credential fields needed for a credential provider type.</summary>
public class CredentialTypeDefinition
{
    public string ProviderType { get; set; } = "";
    public string Title { get; set; } = "";
    public List<ProviderParameter> Fields { get; set; } = new();
}
