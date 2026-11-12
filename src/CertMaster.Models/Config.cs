namespace CertMaster.Models;

public class CertificateAuthority
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string? Description { get; set; }
    public string? WebsiteUrl { get; set; }
    public string? TermsAndConditionsUrl { get; set; }
    public string ProductionAPIEndpoint { get; set; } = "";
    public string? StagingAPIEndpoint { get; set; }
    public bool RequiresEmailAddress { get; set; } = true;
    public bool RequiresExternalAccountBinding { get; set; }
    public string? EabInstructions { get; set; }
    public int SANLimit { get; set; } = 100;
    public int StandardExpiryDays { get; set; } = 90;
    public bool SupportsWildcards { get; set; } = true;
    public bool IsEnabled { get; set; } = true;
    public bool IsCustom { get; set; }
    public string? DefaultPreferredChain { get; set; }
    /// <summary>Skip TLS validation of the ACME endpoint (custom/test CAs such as Pebble or an internal step-ca only).</summary>
    public bool AllowUntrustedTls { get; set; }
}

/// <summary>An ACME account registered with a certificate authority.</summary>
public class AccountDetails
{
    public string StorageKey { get; set; } = Guid.NewGuid().ToString();
    public string? Title { get; set; }
    public string CertificateAuthorityId { get; set; } = "letsencrypt.org";
    public bool IsStagingAccount { get; set; }
    public string Email { get; set; } = "";
    public string? AccountURI { get; set; }
    /// <summary>PEM private key (never returned by the API).</summary>
    public string? AccountKey { get; set; }
    public string? EabKeyId { get; set; }
    public string? EabKey { get; set; }
    public string? EabKeyAlg { get; set; }
    public string? PreferredChain { get; set; }
    public DateTimeOffset DateCreated { get; set; } = DateTimeOffset.UtcNow;
}

public class NewAccountRequest
{
    public string CertificateAuthorityId { get; set; } = "letsencrypt.org";
    public string Email { get; set; } = "";
    public bool AgreedToTermsAndConditions { get; set; }
    public bool IsStaging { get; set; }
    public string? EabKeyId { get; set; }
    public string? EabKey { get; set; }
    public string? EabKeyAlg { get; set; } = "HS256";
    /// <summary>Optional: import an existing account key (PEM) instead of generating one.</summary>
    public string? ImportedAccountKey { get; set; }
}

/// <summary>A secret (API token, password etc.) used by challenge or deployment providers. Secret is encrypted at rest.</summary>
public class StoredCredential
{
    public string StorageKey { get; set; } = Guid.NewGuid().ToString();
    public string ProviderType { get; set; } = "";
    public string Title { get; set; } = "";
    public DateTimeOffset DateCreated { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? DateExpiry { get; set; }
    /// <summary>JSON dictionary of credential values. Only populated on write, never returned by the API.</summary>
    public string? Secret { get; set; }
}

public static class RenewalIntervalModes
{
    /// <summary>Renew when RenewalIntervalDays remain (short-lived certificates renew at one third of their lifetime).</summary>
    public const string DaysBeforeExpiry = "DaysBeforeExpiry";
    /// <summary>Renew once RenewalLifetimePercentage of the certificate lifetime has passed.</summary>
    public const string PercentageOfLifetime = "PercentageOfLifetime";
}

public class Preferences
{
    public int RenewalIntervalDays { get; set; } = 30;
    /// <summary>One of <see cref="RenewalIntervalModes"/>.</summary>
    public string RenewalIntervalMode { get; set; } = RenewalIntervalModes.DaysBeforeExpiry;
    /// <summary>PercentageOfLifetime mode: renew once this much of the lifetime has passed (clamped to 1-99).</summary>
    public int RenewalLifetimePercentage { get; set; } = 75;
    public int MaxRenewalRequests { get; set; } = 0;
    public int RenewalCheckIntervalMinutes { get; set; } = 60;
    public bool EnableHttpChallengeServer { get; set; } = true;
    public string HttpChallengeServerPrefix { get; set; } = "http://+:80/.well-known/acme-challenge/";
    public string DefaultCertificateAuthority { get; set; } = "letsencrypt.org";
    public string? DefaultKeyType { get; set; } = "RS256";
    /// <summary>After the DNS propagation delay, wait up to this long for TXT records to appear on the authoritative name servers (0 = skip the check).</summary>
    public int DnsPropagationCheckSeconds { get; set; } = 300;
    /// <summary>When set, request failures, deployment task failures and recoveries are POSTed here as JSON (with a Slack-compatible "text" field).</summary>
    public string? NotificationWebhookUrl { get; set; }
    public string CertificateStorePath { get; set; } = "";
}

public class HubConnectionSettings
{
    public string? HubUrl { get; set; }
    public string? JoiningKey { get; set; }
    public string? InstanceSecret { get; set; }
    public bool IsJoined { get; set; }
}

public class JoinHubRequest
{
    public string HubUrl { get; set; } = "";
    public string JoiningKey { get; set; } = "";
}

public class ManagedInstanceInfo
{
    public string InstanceId { get; set; } = "";
    public string Title { get; set; } = "";
    public string? OS { get; set; }
    public string? ClientName { get; set; } = "CertMaster";
    public string? ClientVersion { get; set; }
    public DateTimeOffset? DateRegistered { get; set; }
    public DateTimeOffset? DateLastReported { get; set; }
    public bool IsConnected { get; set; }
    public ManagedInstanceSummary? Summary { get; set; }
}

public class ManagedInstanceSummary
{
    public int Total { get; set; }
    public int Healthy { get; set; }
    public int Warning { get; set; }
    public int Error { get; set; }
    public int AwaitingUser { get; set; }
    public int ExpiringSoon { get; set; }

    public static ManagedInstanceSummary From(IEnumerable<ManagedCertificate> items)
    {
        var list = items.ToList();
        var soon = DateTimeOffset.UtcNow.AddDays(14);
        return new ManagedInstanceSummary
        {
            Total = list.Count,
            Healthy = list.Count(i => i.Health == ManagedCertificateHealth.OK),
            Warning = list.Count(i => i.Health == ManagedCertificateHealth.Warning),
            Error = list.Count(i => i.Health == ManagedCertificateHealth.Error),
            AwaitingUser = list.Count(i => i.Health == ManagedCertificateHealth.AwaitingUser || i.Health == ManagedCertificateHealth.Unknown),
            ExpiringSoon = list.Count(i => i.DateExpiry != null && i.DateExpiry < soon),
        };
    }
}
