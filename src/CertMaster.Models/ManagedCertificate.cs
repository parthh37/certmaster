namespace CertMaster.Models;

public enum ManagedCertificateType { SSL_ACME, SSL_Manual, SSL_ExternallyManaged }

public enum ManagedCertificateHealth { Unknown, OK, AwaitingUser, Warning, Error }

public enum RequestState { NotRunning, Queued, Running, Success, Error, Warning, Paused }

public static class ChallengeTypes
{
    public const string Http01 = "http-01";
    public const string Dns01 = "dns-01";
}

/// <summary>A certificate that CertMaster requests, renews and deploys.</summary>
public class ManagedCertificate
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Name { get; set; } = "";
    public string? Comments { get; set; }
    public ManagedCertificateType ItemType { get; set; } = ManagedCertificateType.SSL_ACME;

    /// <summary>Which hub-managed instance owns this item (set by the hub when aggregating).</summary>
    public string? InstanceId { get; set; }
    public string? InstanceTitle { get; set; }

    /// <summary>Web server site this certificate is associated with (e.g. IIS site id), used by SingleSite deployment.</summary>
    public string? ServerSiteId { get; set; }

    public string? CertificateAuthorityId { get; set; } = "letsencrypt.org";
    public bool UseStagingMode { get; set; }
    public bool IncludeInAutoRenew { get; set; } = true;

    public CertRequestConfig RequestConfig { get; set; } = new();
    public List<DeploymentTaskConfig> PreRequestTasks { get; set; } = new();
    public List<DeploymentTaskConfig> PostRequestTasks { get; set; } = new();

    // Status
    public DateTimeOffset? DateStart { get; set; }
    public DateTimeOffset? DateExpiry { get; set; }
    public DateTimeOffset? DateRenewed { get; set; }
    public DateTimeOffset? DateLastRenewalAttempt { get; set; }
    public DateTimeOffset? DateNextScheduledRenewalAttempt { get; set; }
    public RequestState LastRenewalStatus { get; set; } = RequestState.NotRunning;
    public int RenewalFailureCount { get; set; }
    public string? RenewalFailureMessage { get; set; }
    public ManagedCertificateHealth Health { get; set; } = ManagedCertificateHealth.Unknown;

    // Certificate details
    public string? CertificatePath { get; set; }
    public string? CertificateThumbprintHash { get; set; }
    public string? CertificatePreviousThumbprintHash { get; set; }
    public string? CertificateIssuer { get; set; }
    public string? CertificateKeyType { get; set; }
    public string? CertificatePasswordCredentialId { get; set; }
    public bool CertificateRevoked { get; set; }
    public string? CurrentOrderUri { get; set; }
    /// <summary>ACME Renewal Information (RFC 9773) certificate id.</summary>
    public string? ARICertificateId { get; set; }
    public string? LastAttemptedCA { get; set; }

    /// <summary>Custom renewal: renew when this many days remain before expiry (null = use global preference).</summary>
    public int? CustomRenewalDaysBeforeExpiry { get; set; }

    public IEnumerable<string> GetAllDomains()
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(RequestConfig.PrimaryDomain)) list.Add(RequestConfig.PrimaryDomain.Trim());
        foreach (var d in RequestConfig.SubjectAlternativeNames)
            if (!string.IsNullOrWhiteSpace(d) && !list.Contains(d.Trim(), StringComparer.OrdinalIgnoreCase)) list.Add(d.Trim());
        return list;
    }
}

public class CertRequestConfig
{
    public string PrimaryDomain { get; set; } = "";
    public List<string> SubjectAlternativeNames { get; set; } = new();
    public List<string> SubjectIPAddresses { get; set; } = new();

    /// <summary>Web root used for http-01 file based validation when the built-in HTTP challenge server is not used.</summary>
    public string? WebsiteRootPath { get; set; }
    public bool PerformChallengeFileCopy { get; set; } = true;

    public List<CertRequestChallengeConfig> Challenges { get; set; } = new() { new CertRequestChallengeConfig() };

    /// <summary>RS256 (RSA 2048), RS256-3072, RS256-4096, ES256, ES384. Blank = the instance default (Preferences.DefaultKeyType).</summary>
    public string CSRKeyAlg { get; set; } = "";
    public bool ReusePrivateKey { get; set; }
    public string? PreferredChain { get; set; }
    public string? AcmeProfile { get; set; }

    // ---- Deployment (web server bindings, e.g. IIS) ----
    public DeploymentOption DeploymentSiteOption { get; set; } = DeploymentOption.Auto;
    public DeploymentBindingOption DeploymentBindingOption { get; set; } = DeploymentBindingOption.AddOrUpdate;
    /// <summary>Update existing https bindings whose hostname matches one of the certificate domains.</summary>
    public bool DeploymentBindingMatchHostname { get; set; } = true;
    /// <summary>Update existing https bindings with no hostname (IP only / All Unassigned).</summary>
    public bool DeploymentBindingBlankHostname { get; set; }
    /// <summary>Update existing https bindings that use the previous version of this certificate.</summary>
    public bool DeploymentBindingReplacePrevious { get; set; }
    /// <summary>False = auto create/update bindings using SNI; true = use the specific IP/port below.</summary>
    public bool UseSpecificBindingIPPort { get; set; }
    public string BindingIPAddress { get; set; } = "*";
    public int BindingPort { get; set; } = 443;
    public bool BindingUseSNI { get; set; } = true;

    public string? WebhookTrigger { get; set; } // none | on_success | on_error | always
    public string? WebhookMethod { get; set; } = "POST";
    public string? WebhookUrl { get; set; }
    public string? WebhookContentType { get; set; } = "application/json";
    public string? WebhookContentBody { get; set; }

    /// <summary>Send this item's failures to the instance notification webhook (Preferences.NotificationWebhookUrl).</summary>
    public bool EnableFailureNotifications { get; set; } = true;
}

public class CertRequestChallengeConfig
{
    public string ChallengeType { get; set; } = ChallengeTypes.Http01;
    /// <summary>Optional list of domains (comma/semicolon separated, wildcards ok) this config applies to. Blank = all.</summary>
    public string? DomainMatch { get; set; }
    /// <summary>Provider id, e.g. DNS01.API.Cloudflare. For http-01 blank = built-in HTTP challenge server.</summary>
    public string? ChallengeProvider { get; set; }
    public string? ChallengeCredentialKey { get; set; }
    public string? ZoneId { get; set; }
    /// <summary>e.g. "*.example.com:*.auth.example.net" (CNAME delegation of _acme-challenge).</summary>
    public string? ChallengeDelegationRule { get; set; }
    public int? PropagationDelaySeconds { get; set; }
    public List<ProviderParameterSetting> Parameters { get; set; } = new();
}

public enum TaskTriggerType { NOT_ENABLED, ANY_STATUS, ON_SUCCESS, ON_ERROR, MANUAL }

public class DeploymentTaskConfig
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string TaskTypeId { get; set; } = "";
    public string TaskName { get; set; } = "";
    public string? Description { get; set; }
    public bool IsFatalOnError { get; set; } = true;
    public int RetriesAllowed { get; set; }
    public int RetryDelaySeconds { get; set; } = 10;
    /// <summary>Stored credential for the task: provider credential (API token etc.) or the target credential (Windows/SSH).</summary>
    public string? ChallengeCredentialKey { get; set; }
    /// <summary>Where the task runs: on this machine, a Windows network share, or a remote host over SSH.</summary>
    public DeploymentContextType TargetType { get; set; } = DeploymentContextType.LocalAsService;
    /// <summary>Remote host name for SSH targets (host or host:port).</summary>
    public string? TargetHost { get; set; }
    public TaskTriggerType TaskTrigger { get; set; } = TaskTriggerType.ON_SUCCESS;
    public bool RunIfLastStepFailed { get; set; }
    public List<ProviderParameterSetting> Parameters { get; set; } = new();
    public DateTimeOffset? DateLastExecuted { get; set; }
    public RequestState LastRunStatus { get; set; } = RequestState.NotRunning;
    public string? LastResult { get; set; }
}

public class ProviderParameterSetting
{
    public ProviderParameterSetting() { }
    public ProviderParameterSetting(string key, string? value) { Key = key; Value = value; }
    public string Key { get; set; } = "";
    public string? Value { get; set; }
}
