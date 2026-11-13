using System.Net;
using CertMaster.Client.Monitoring;
using CertMaster.Models;
using CertMaster.Server.Core;
using Microsoft.AspNetCore.Http;

namespace CertMaster.Tests.Monitoring;

public class TrayMonitorTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 12, 12, 0, 0, TimeSpan.Zero);

    private static ManagedCertificate Cert(string id, ManagedCertificateHealth health, int daysLeft, RequestState last = RequestState.Success) => new()
    {
        Id = id,
        Name = id + ".example.com",
        Health = health,
        DateExpiry = Now.AddDays(daysLeft),
        LastRenewalStatus = last,
    };

    private static AgentStatusSummary Summary(params ManagedCertificate[] items) => AgentStatusSummary.From(items, "1.0.0", 0, Now);

    private static MonitorSnapshot Snap(AgentStatusSummary? summary, ServiceState agent = ServiceState.Running, ServiceState? hub = null) =>
        new(agent, hub, summary, Now);

    // ---------- summary served by the agent ----------

    [Fact]
    public void Summary_lists_failed_then_expiring_and_skips_healthy()
    {
        var s = Summary(
            Cert("ok", ManagedCertificateHealth.OK, 60),
            Cert("soon", ManagedCertificateHealth.Warning, 5),
            Cert("failed", ManagedCertificateHealth.Error, 40, RequestState.Error));

        Assert.Equal(3, s.Certificates.Total);
        Assert.Equal(new[] { "failed", "soon" }, s.Attention.Select(a => a.Id));
    }

    [Fact]
    public void Summary_caps_attention_items()
    {
        var items = Enumerable.Range(0, 40).Select(i => Cert("e" + i, ManagedCertificateHealth.Error, 30, RequestState.Error)).ToArray();
        Assert.Equal(AgentStatusSummary.MaxAttentionItems, Summary(items).Attention.Count);
    }

    [Theory]
    [InlineData("/api/system/health", "203.0.113.5", true)]
    [InlineData("/api/system/summary", "127.0.0.1", true)]
    [InlineData("/api/system/summary", "::1", true)]
    [InlineData("/api/system/summary", "::ffff:127.0.0.1", true)]
    [InlineData("/api/system/summary", "203.0.113.5", false)]
    [InlineData("/api/managedcertificates", "127.0.0.1", false)]
    [InlineData("/api/system/version", "127.0.0.1", false)]
    public void Only_health_and_loopback_summary_skip_the_api_key(string path, string ip, bool anonymous) =>
        Assert.Equal(anonymous, AgentIdentity.AllowsAnonymous(new PathString(path), IPAddress.Parse(ip)));

    [Fact]
    public void Summary_needs_a_key_when_the_caller_is_unknown() =>
        Assert.False(AgentIdentity.AllowsAnonymous(new PathString("/api/system/summary"), null));

    // ---------- tray status ----------

    [Fact]
    public void Stopped_agent_is_an_error()
    {
        var s = StatusEvaluator.Evaluate(Snap(null, ServiceState.Stopped));
        Assert.Equal(MonitorLevel.Error, s.Level);
        Assert.Contains("stopped", s.Headline);
    }

    [Fact]
    public void Running_agent_without_an_answer_is_offline()
    {
        Assert.Equal(MonitorLevel.Offline, StatusEvaluator.Evaluate(Snap(null)).Level);
    }

    [Fact]
    public void Failed_certificates_win_over_expiring_ones()
    {
        var s = StatusEvaluator.Evaluate(Snap(Summary(
            Cert("a", ManagedCertificateHealth.Error, 40, RequestState.Error),
            Cert("b", ManagedCertificateHealth.Warning, 3))));
        Assert.Equal(MonitorLevel.Error, s.Level);
        Assert.Equal("1 certificate failed to renew", s.Headline);
        Assert.Contains(s.Details, d => d == "b.example.com: expires in 3 days");
    }

    [Fact]
    public void All_healthy_is_ok_and_hub_state_is_listed()
    {
        var s = StatusEvaluator.Evaluate(Snap(Summary(Cert("a", ManagedCertificateHealth.OK, 60), Cert("b", ManagedCertificateHealth.OK, 70)),
            hub: ServiceState.Running));
        Assert.Equal(MonitorLevel.Ok, s.Level);
        Assert.Equal("All 2 certificates healthy", s.Headline);
        Assert.Contains("Management Hub service: running", s.Details);
    }

    [Fact]
    public void Tooltip_fits_the_shell_limit()
    {
        var items = Enumerable.Range(0, 3).Select(i => Cert(new string('x', 200) + i, ManagedCertificateHealth.Error, 30, RequestState.Error)).ToArray();
        var s = StatusEvaluator.Evaluate(Snap(Summary(items)));
        Assert.True(s.Tooltip.Length <= StatusEvaluator.MaxTooltipLength);
    }

    // ---------- notifications ----------

    [Fact]
    public void First_poll_summarises_failures_once()
    {
        var n = StatusEvaluator.Diff(null, Snap(Summary(
            Cert("a", ManagedCertificateHealth.Error, 40, RequestState.Error),
            Cert("b", ManagedCertificateHealth.Error, 40, RequestState.Error))));
        var only = Assert.Single(n);
        Assert.Equal(MonitorLevel.Error, only.Level);
        Assert.Equal("2 certificates failed to renew, including a.example.com.", only.Text);

        var single = Assert.Single(StatusEvaluator.Diff(null, Snap(Summary(Cert("a", ManagedCertificateHealth.Error, 40, RequestState.Error)))));
        Assert.Equal("a.example.com failed to renew.", single.Text);
    }

    [Fact]
    public void First_poll_with_healthy_certificates_is_quiet()
    {
        Assert.Empty(StatusEvaluator.Diff(null, Snap(Summary(Cert("a", ManagedCertificateHealth.OK, 60)))));
    }

    [Fact]
    public void Service_stopping_and_starting_are_announced()
    {
        var running = Snap(Summary(Cert("a", ManagedCertificateHealth.OK, 60)));
        var stopped = Snap(running.Summary, ServiceState.Stopped);

        Assert.Contains(StatusEvaluator.Diff(running, stopped), n => n.Level == MonitorLevel.Error && n.Title.Contains("stopped"));
        Assert.Contains(StatusEvaluator.Diff(stopped, running), n => n.Level == MonitorLevel.Ok && n.Title.Contains("running"));
    }

    [Fact]
    public void A_new_failure_is_announced_by_name_and_not_repeated()
    {
        var before = Snap(Summary(Cert("a", ManagedCertificateHealth.OK, 60)));
        var after = Snap(Summary(Cert("a", ManagedCertificateHealth.Error, 60, RequestState.Error)));

        var n = Assert.Single(StatusEvaluator.Diff(before, after));
        Assert.Equal("Certificate renewal failed", n.Title);
        Assert.Contains("a.example.com", n.Text);
        Assert.Empty(StatusEvaluator.Diff(after, after));
    }

    [Fact]
    public void Recovery_is_announced()
    {
        var failing = Snap(Summary(Cert("a", ManagedCertificateHealth.Error, 60, RequestState.Error)));
        var fixedUp = Snap(Summary(Cert("a", ManagedCertificateHealth.OK, 90)));
        var n = Assert.Single(StatusEvaluator.Diff(failing, fixedUp));
        Assert.Equal(MonitorLevel.Ok, n.Level);
    }

    [Fact]
    public void Entering_the_expiry_window_is_announced()
    {
        var before = Snap(Summary(Cert("a", ManagedCertificateHealth.OK, 20)));
        var after = Snap(Summary(Cert("a", ManagedCertificateHealth.Warning, 10)));
        var n = Assert.Single(StatusEvaluator.Diff(before, after));
        Assert.Equal(MonitorLevel.Warning, n.Level);
        Assert.Equal("a.example.com expires in 10 days.", n.Text);
    }

    [Theory]
    [InlineData(-1, "has expired")]
    [InlineData(0.5, "expires within a day")]
    [InlineData(2.2, "expires in 3 days")]
    public void Expiry_wording(double days, string expected) =>
        Assert.Equal(expected, StatusEvaluator.ExpiryText(Now.AddDays(days), Now));

    // ---------- local addresses ----------

    [Fact]
    public void Agent_url_defaults_and_follows_settings_order()
    {
        Assert.Equal("http://127.0.0.1:9696", LocalEndpoints.AgentUrl(null, null, null));
        Assert.Equal("http://127.0.0.1:9800", LocalEndpoints.AgentUrl(
            """{ "Agent": { "Url": "http://127.0.0.1:9700" } }""",
            null,
            """{ /* admin override */ "Agent": { "Url": "http://*:9800" }, }"""));
    }

    [Fact]
    public void Hub_url_prefers_kestrel_https_endpoint()
    {
        var installer = """{ "Hub": { "Url": "http://*:9697" } }""";
        var production = """{ "Kestrel": { "Endpoints": { "Http": { "Url": "http://*:80" }, "Https": { "Url": "https://*:9697" } } } }""";
        Assert.Equal("http://localhost:9697", LocalEndpoints.HubUrl(null, installer, null));
        Assert.Equal("https://localhost:9697", LocalEndpoints.HubUrl(null, installer, production));
    }

    [Theory]
    [InlineData("http://+:5000", "http://localhost:5000")]
    [InlineData("http://[::]:5000", "http://localhost:5000")]
    [InlineData("http://0.0.0.0:5000;https://hub.example.com:443", "https://hub.example.com:443")]
    [InlineData("http://hub.example.com", "http://hub.example.com")]
    [InlineData("not a url", null)]
    public void Wildcard_hosts_become_local(string input, string? expected) =>
        Assert.Equal(expected, LocalEndpoints.FirstUsable(input, preferHttps: true, localHost: "localhost"));

    [Fact]
    public void Broken_or_odd_settings_fall_back_to_defaults()
    {
        Assert.Equal(LocalEndpoints.DefaultHubUrl, LocalEndpoints.HubUrl("{ not json", """{ "Hub": "oops" }""", """{ "Kestrel": { "Endpoints": 5 } }"""));
    }
}
