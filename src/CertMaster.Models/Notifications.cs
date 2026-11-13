namespace CertMaster.Models;

public static class NotificationEvents
{
    /// <summary>The certificate request failed (no new certificate was issued or it could not be deployed).</summary>
    public const string RequestFailed = "certificate_request_failed";
    /// <summary>The certificate was issued but one or more deployment tasks failed.</summary>
    public const string DeploymentTasksFailed = "deployment_tasks_failed";
    /// <summary>A request succeeded after the previous attempt failed.</summary>
    public const string Recovered = "certificate_request_recovered";
    /// <summary>The certificate expires soon (or has expired) and has not been renewed yet. Sent at most once a day.</summary>
    public const string CertificateExpiring = "certificate_expiring";
    /// <summary>Sent by the Settings "Send test notification" button.</summary>
    public const string Test = "test";
}

/// <summary>JSON body POSTed to Preferences.NotificationWebhookUrl. "text" makes it readable by Slack-style incoming webhooks.</summary>
public class NotificationMessage
{
    public string Event { get; set; } = "";
    public string Text { get; set; } = "";
    public string Instance { get; set; } = Environment.MachineName;
    public DateTimeOffset Timestamp { get; set; } = DateTimeOffset.UtcNow;
    public string? ManagedCertificateId { get; set; }
    public string? Name { get; set; }
    public string? PrimaryDomain { get; set; }
    public List<string> Domains { get; set; } = new();
    public string? Message { get; set; }
    public int FailureCount { get; set; }
    public DateTimeOffset? DateExpiry { get; set; }
    public DateTimeOffset? DateNextAttempt { get; set; }
}

public class TestNotificationRequest
{
    /// <summary>Webhook URL to test. Blank = the saved Preferences.NotificationWebhookUrl.</summary>
    public string? Url { get; set; }
}
