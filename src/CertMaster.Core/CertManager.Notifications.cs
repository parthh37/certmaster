using System.Text;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core;

/// <summary>Instance-wide failure notifications: one JSON POST to Preferences.NotificationWebhookUrl per failed or recovered request.</summary>
public partial class CertManager
{
    /// <summary>
    /// Which notification (if any) a finished request should send. Failures notify every attempt (the retry back-off keeps
    /// this to a few a day); a success only notifies when it follows a failure.
    /// </summary>
    public static string? GetNotificationEvent(RequestState previous, RequestState current, bool cancelled) => current switch
    {
        _ when cancelled => null,
        RequestState.Error => NotificationEvents.RequestFailed,
        RequestState.Warning => NotificationEvents.DeploymentTasksFailed,
        RequestState.Success when previous is RequestState.Error or RequestState.Warning => NotificationEvents.Recovered,
        _ => null,
    };

    public static NotificationMessage BuildNotification(string evt, ManagedCertificate item, string? message)
    {
        var name = string.IsNullOrWhiteSpace(item.Name) ? item.RequestConfig.PrimaryDomain : item.Name;
        var host = Environment.MachineName;
        var text = evt switch
        {
            NotificationEvents.RequestFailed => $"CertMaster on {host}: certificate request for {name} failed (attempt {item.RenewalFailureCount}): {message}",
            NotificationEvents.DeploymentTasksFailed => $"CertMaster on {host}: certificate for {name} was issued but deployment tasks failed: {message}",
            NotificationEvents.Recovered => $"CertMaster on {host}: certificate request for {name} succeeded after earlier failures. {message}",
            _ => $"CertMaster on {host}: {message}",
        };
        return new NotificationMessage
        {
            Event = evt, Text = text, Instance = host,
            ManagedCertificateId = item.Id, Name = name, PrimaryDomain = item.RequestConfig.PrimaryDomain,
            Domains = item.GetAllDomains().Concat(item.RequestConfig.SubjectIPAddresses).ToList(),
            Message = message, FailureCount = item.RenewalFailureCount,
            DateExpiry = item.DateExpiry, DateNextAttempt = item.DateNextScheduledRenewalAttempt,
        };
    }

    private async Task SendNotificationAsync(ManagedCertificate item, RequestState previous, bool cancelled, string? message, ItemLog log)
    {
        if (!item.RequestConfig.EnableFailureNotifications) return;
        var evt = GetNotificationEvent(previous, item.LastRenewalStatus, cancelled);
        if (evt == null) return;
        var url = (await GetPreferencesAsync()).NotificationWebhookUrl;
        if (string.IsNullOrWhiteSpace(url)) return;

        var r = await PostNotificationAsync(url, BuildNotification(evt, item, message));
        if (r.IsSuccess) log.Info($"Notification ({evt}) sent: {r.Message}");
        else log.Warn($"Notification ({evt}) failed: {r.Message}");
    }

    /// <summary>Send a test message to <paramref name="url"/>, or to the saved webhook URL when blank.</summary>
    public async Task<ActionResult> SendTestNotificationAsync(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) url = (await GetPreferencesAsync()).NotificationWebhookUrl;
        if (string.IsNullOrWhiteSpace(url)) return ActionResult.Fail("No notification webhook URL is set.");
        return await PostNotificationAsync(url, new NotificationMessage
        {
            Event = NotificationEvents.Test,
            Text = $"CertMaster on {Environment.MachineName}: test notification. Failure alerts will be sent to this webhook.",
            Message = "Test notification",
        });
    }

    private async Task<ActionResult> PostNotificationAsync(string url, NotificationMessage msg)
    {
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return ActionResult.Fail("The notification webhook URL must be an absolute http(s) URL.");
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var req = new HttpRequestMessage(HttpMethod.Post, uri)
            { Content = new StringContent(JsonDefaults.Serialize(msg), Encoding.UTF8, "application/json") };
            using var resp = await _http.SendAsync(req, cts.Token);
            return resp.IsSuccessStatusCode
                ? ActionResult.Ok($"{uri.Host} returned {(int)resp.StatusCode}")
                : ActionResult.Fail($"{uri.Host} returned {(int)resp.StatusCode} {resp.ReasonPhrase}");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Notification webhook failed");
            return ActionResult.Fail(ex is OperationCanceledException ? $"{uri.Host} did not respond within 30 seconds" : ex.Message);
        }
    }
}
