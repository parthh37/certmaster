namespace CertMaster.Models;

/// <summary>
/// Read-only health snapshot of a local agent, served without the API key to loopback callers so the tray monitor can
/// run in a normal (non-elevated) user session. It holds certificate names and dates only: no domains, paths,
/// error messages or settings.
/// </summary>
public class AgentStatusSummary
{
    /// <summary>How close to expiry a certificate must be to count as expiring soon.</summary>
    public static readonly TimeSpan ExpiringSoonWindow = TimeSpan.FromDays(14);
    public const int MaxAttentionItems = 25;

    public string Version { get; set; } = "";
    public DateTimeOffset GeneratedAt { get; set; }
    public ManagedInstanceSummary Certificates { get; set; } = new();
    /// <summary>Number of certificate requests running right now.</summary>
    public int RequestsInProgress { get; set; }
    /// <summary>Failed, warning and soon-expiring certificates, worst first.</summary>
    public List<CertificateAttentionItem> Attention { get; set; } = new();

    public static AgentStatusSummary From(IEnumerable<ManagedCertificate> items, string version, int requestsInProgress, DateTimeOffset now)
    {
        var list = items.ToList();
        var soon = now.Add(ExpiringSoonWindow);
        return new AgentStatusSummary
        {
            Version = version,
            GeneratedAt = now,
            Certificates = ManagedInstanceSummary.From(list),
            RequestsInProgress = requestsInProgress,
            Attention = list
                .Where(i => i.Health is ManagedCertificateHealth.Error or ManagedCertificateHealth.Warning
                            || (i.DateExpiry != null && i.DateExpiry < soon))
                .OrderBy(i => i.Health == ManagedCertificateHealth.Error ? 0 : 1)
                .ThenBy(i => i.DateExpiry ?? DateTimeOffset.MaxValue)
                .Take(MaxAttentionItems)
                .Select(i => new CertificateAttentionItem
                {
                    Id = i.Id,
                    Name = i.Name,
                    Health = i.Health,
                    DateExpiry = i.DateExpiry,
                    LastRenewalStatus = i.LastRenewalStatus,
                    DateNextRenewalAttempt = i.DateNextScheduledRenewalAttempt,
                })
                .ToList(),
        };
    }
}

public class CertificateAttentionItem
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public ManagedCertificateHealth Health { get; set; }
    public DateTimeOffset? DateExpiry { get; set; }
    public RequestState LastRenewalStatus { get; set; }
    public DateTimeOffset? DateNextRenewalAttempt { get; set; }
}
