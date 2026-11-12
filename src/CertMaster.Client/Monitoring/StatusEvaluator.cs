using CertMaster.Models;

namespace CertMaster.Client.Monitoring;

/// <summary>State of a Windows service as the tray monitor sees it.</summary>
public enum ServiceState { NotInstalled, Stopped, Starting, Stopping, Running, Paused, Disabled, Unknown }

/// <summary>Overall level shown by the tray icon.</summary>
public enum MonitorLevel { Ok, Warning, Error, Offline }

/// <summary>One poll of the local services and agent.</summary>
/// <param name="Agent">The agent service state.</param>
/// <param name="Hub">The hub service state, or null when the hub isn't installed on this machine.</param>
/// <param name="Summary">The agent's status summary, or null when the agent didn't answer.</param>
public sealed record MonitorSnapshot(ServiceState Agent, ServiceState? Hub, AgentStatusSummary? Summary, DateTimeOffset Time);

public sealed record MonitorStatus(MonitorLevel Level, string Headline, IReadOnlyList<string> Details, string Tooltip);

public sealed record MonitorNotification(MonitorLevel Level, string Title, string Text);

/// <summary>
/// Turns polls into what the tray shows (icon level, tooltip, menu lines) and which balloon notifications to raise.
/// Pure functions, so the rules are unit tested without a tray or services.
/// </summary>
public static class StatusEvaluator
{
    /// <summary>Windows limits a tray tooltip to 127 characters.</summary>
    public const int MaxTooltipLength = 127;
    public const int MaxAttentionLines = 5;

    public static MonitorStatus Evaluate(MonitorSnapshot s)
    {
        var details = new List<string>();
        MonitorLevel level;
        string headline;

        switch (s.Agent)
        {
            case ServiceState.NotInstalled:
                level = MonitorLevel.Offline;
                headline = "CertMaster Agent service is not installed";
                break;
            case ServiceState.Disabled:
                level = MonitorLevel.Error;
                headline = "CertMaster Agent service is disabled";
                details.Add("Certificates will not renew until the service is enabled.");
                break;
            case ServiceState.Stopped:
            case ServiceState.Paused:
                level = MonitorLevel.Error;
                headline = "CertMaster Agent service is stopped";
                details.Add("Certificates will not renew until the service is started.");
                break;
            case ServiceState.Starting:
                level = MonitorLevel.Offline;
                headline = "CertMaster Agent service is starting";
                break;
            case ServiceState.Stopping:
                level = MonitorLevel.Offline;
                headline = "CertMaster Agent service is stopping";
                break;
            case ServiceState.Running when s.Summary == null:
                level = MonitorLevel.Offline;
                headline = "CertMaster Agent is not responding";
                details.Add("The service is running but its local API did not answer.");
                break;
            case ServiceState.Running or ServiceState.Unknown when s.Summary != null:
                (level, headline) = Describe(s.Summary!.Certificates);
                AddCertificateDetails(details, s.Summary!, s.Time);
                break;
            default:
                level = MonitorLevel.Offline;
                headline = "CertMaster Agent status is unknown";
                break;
        }

        if (s.Hub is { } hub) details.Add("Management Hub service: " + Describe(hub));

        return new MonitorStatus(level, headline, details, Tooltip(headline));
    }

    /// <summary>Notifications for what changed between two polls. <paramref name="previous"/> is null on the first poll.</summary>
    /// <remarks>
    /// Certificate changes compare against the last poll that had a summary, so a brief "not responding" gap (the agent
    /// restarting) doesn't re-announce every failure: callers pass the previous snapshot with its last known summary.
    /// </remarks>
    public static IReadOnlyList<MonitorNotification> Diff(MonitorSnapshot? previous, MonitorSnapshot current)
    {
        var list = new List<MonitorNotification>();

        // ---- services ----
        if (previous == null)
        {
            if (current.Agent is ServiceState.Stopped or ServiceState.Disabled or ServiceState.Paused)
                list.Add(new(MonitorLevel.Error, "CertMaster Agent is not running", "Certificates will not renew until the CertMaster Agent service is started."));
        }
        else
        {
            if (previous.Agent == ServiceState.Running && current.Agent is ServiceState.Stopped or ServiceState.Disabled or ServiceState.Paused)
                list.Add(new(MonitorLevel.Error, "CertMaster Agent service stopped", "Certificates will not renew until the service is started again."));
            else if (previous.Agent is ServiceState.Stopped or ServiceState.Disabled or ServiceState.Paused && current.Agent == ServiceState.Running)
                list.Add(new(MonitorLevel.Ok, "CertMaster Agent service is running", "Automatic renewal has resumed."));

            if (previous.Hub == ServiceState.Running && current.Hub is ServiceState.Stopped or ServiceState.Disabled or ServiceState.Paused)
                list.Add(new(MonitorLevel.Error, "Management Hub service stopped", "Managed servers can't report to the hub until it is started again."));
            else if (previous.Hub is ServiceState.Stopped or ServiceState.Disabled or ServiceState.Paused && current.Hub == ServiceState.Running)
                list.Add(new(MonitorLevel.Ok, "Management Hub service is running", "The Management Hub is available again."));
        }

        // ---- certificates ----
        var cur = current.Summary;
        if (cur == null) return list;
        var prev = previous?.Summary;

        if (prev == null)
        {
            // First answer from the agent (sign-in, or the tray started): one summary of what needs attention.
            var c = cur.Certificates;
            if (c.Error > 0)
            {
                var first = FirstName(cur, ManagedCertificateHealth.Error);
                list.Add(new(MonitorLevel.Error, "Certificates need attention",
                    c.Error == 1 && first != null ? first + " failed to renew."
                    : Plural(c.Error, "certificate") + " failed to renew" + (first != null ? ", including " + first + "." : ".")));
            }
            else if (ExpiringSoon(cur, current.Time).Count is var e and > 0)
                list.Add(new(MonitorLevel.Warning, "Certificates expire soon", Plural(e, "certificate") + (e == 1 ? " expires" : " expire") + " within " +
                                                                              (int)AgentStatusSummary.ExpiringSoonWindow.TotalDays + " days."));
            return list;
        }

        var prevErrors = Ids(prev, ManagedCertificateHealth.Error);
        var newErrors = cur.Attention.Where(i => i.Health == ManagedCertificateHealth.Error && !prevErrors.Contains(i.Id)).ToList();
        if (newErrors.Count == 1)
            list.Add(new(MonitorLevel.Error, "Certificate renewal failed", newErrors[0].Name + " could not be renewed. Open CertMaster to see the request log."));
        else if (newErrors.Count > 1)
            list.Add(new(MonitorLevel.Error, "Certificate renewals failed", Plural(newErrors.Count, "certificate") + " could not be renewed, including " + newErrors[0].Name + "."));
        else if (prev.Certificates.Error > 0 && cur.Certificates.Error == 0)
            list.Add(new(MonitorLevel.Ok, "Certificates are healthy again", "No certificate is failing to renew."));

        var prevExpiring = ExpiringSoon(prev, previous!.Time).Select(i => i.Id).ToHashSet();
        var newExpiring = ExpiringSoon(cur, current.Time)
            .Where(i => i.Health != ManagedCertificateHealth.Error && !prevExpiring.Contains(i.Id)).ToList();
        if (newExpiring.Count == 1)
            list.Add(new(MonitorLevel.Warning, "Certificate expires soon", newExpiring[0].Name + " " + ExpiryText(newExpiring[0].DateExpiry!.Value, current.Time) + "."));
        else if (newExpiring.Count > 1)
            list.Add(new(MonitorLevel.Warning, "Certificates expire soon", Plural(newExpiring.Count, "certificate") + " expire within " +
                                                                          (int)AgentStatusSummary.ExpiringSoonWindow.TotalDays + " days."));
        return list;
    }

    public static string ExpiryText(DateTimeOffset expiry, DateTimeOffset now)
    {
        var left = expiry - now;
        if (left <= TimeSpan.Zero) return "has expired";
        var days = (int)Math.Ceiling(left.TotalDays);
        return days <= 1 ? "expires within a day" : $"expires in {days} days";
    }

    // ---------- helpers ----------

    private static (MonitorLevel, string) Describe(ManagedInstanceSummary c)
    {
        if (c.Error > 0) return (MonitorLevel.Error, Plural(c.Error, "certificate") + " failed to renew");
        if (c.ExpiringSoon > 0) return (MonitorLevel.Warning, Plural(c.ExpiringSoon, "certificate") + " expiring soon");
        if (c.Warning > 0) return (MonitorLevel.Warning, Plural(c.Warning, "certificate") + " need" + (c.Warning == 1 ? "s" : "") + " attention");
        if (c.Total == 0) return (MonitorLevel.Ok, "No certificates yet");
        return (MonitorLevel.Ok, c.Total == 1 ? "1 certificate, healthy" : $"All {c.Total} certificates healthy");
    }

    private static string Describe(ServiceState s) => s switch
    {
        ServiceState.Running => "running",
        ServiceState.Stopped => "stopped",
        ServiceState.Starting => "starting",
        ServiceState.Stopping => "stopping",
        ServiceState.Paused => "paused",
        ServiceState.Disabled => "disabled",
        ServiceState.NotInstalled => "not installed",
        _ => "unknown",
    };

    private static void AddCertificateDetails(List<string> details, AgentStatusSummary s, DateTimeOffset now)
    {
        var c = s.Certificates;
        if (c.Total > 0)
        {
            var parts = new List<string> { $"{c.Healthy} OK" };
            if (c.Error > 0) parts.Add($"{c.Error} failed");
            if (c.Warning > 0) parts.Add($"{c.Warning} warning");
            if (c.ExpiringSoon > 0) parts.Add($"{c.ExpiringSoon} expiring soon");
            if (c.AwaitingUser > 0) parts.Add($"{c.AwaitingUser} not yet requested");
            details.Add(Plural(c.Total, "certificate") + ": " + string.Join(", ", parts));
        }
        if (s.RequestsInProgress > 0) details.Add("Requesting " + Plural(s.RequestsInProgress, "certificate") + " now");

        foreach (var i in s.Attention.Take(MaxAttentionLines))
        {
            var what = i.Health == ManagedCertificateHealth.Error ? "renewal failed"
                : i.DateExpiry is { } exp && exp < now.Add(AgentStatusSummary.ExpiringSoonWindow) ? ExpiryText(exp, now)
                : "needs attention";
            details.Add($"{i.Name}: {what}");
        }
        if (s.Attention.Count > MaxAttentionLines) details.Add($"and {s.Attention.Count - MaxAttentionLines} more");
    }

    private static string Tooltip(string headline)
    {
        var text = "CertMaster: " + headline;
        return text.Length <= MaxTooltipLength ? text : text[..(MaxTooltipLength - 3)] + "...";
    }

    private static HashSet<string> Ids(AgentStatusSummary s, ManagedCertificateHealth health) =>
        s.Attention.Where(i => i.Health == health).Select(i => i.Id).ToHashSet();

    private static List<CertificateAttentionItem> ExpiringSoon(AgentStatusSummary s, DateTimeOffset now) =>
        s.Attention.Where(i => i.DateExpiry is { } e && e < now.Add(AgentStatusSummary.ExpiringSoonWindow)).ToList();

    private static string? FirstName(AgentStatusSummary s, ManagedCertificateHealth health) =>
        s.Attention.FirstOrDefault(i => i.Health == health)?.Name;

    private static string Plural(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n} {noun}s";
}
