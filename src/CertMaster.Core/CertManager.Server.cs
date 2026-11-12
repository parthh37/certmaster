using CertMaster.Core.Iis;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core;

// Web server (IIS) integration: site discovery, binding deployment and preview.
// CONTRACT used by the agent API, desktop UI and hub.
public partial class CertManager
{
    private IWebServerProvider? _webServer;

    /// <summary>The local web server integration (IIS by default). Replaceable for tests or other hosts.</summary>
    public IWebServerProvider WebServer
    {
        get => _webServer ??= new IisServerProvider();
        set => _webServer = value;
    }

    /// <summary>Whether a supported local web server (IIS) is available.</summary>
    public async Task<ServerStatus> GetServerStatusAsync()
    {
        try { return await WebServer.GetStatusAsync(); }
        catch (Exception ex) { return new ServerStatus { IsIisAvailable = false, Message = "Could not determine web server status: " + ex.Message }; }
    }

    /// <summary>Sites on the local web server.</summary>
    public async Task<List<SiteInfo>> GetSitesAsync()
    {
        var status = await GetServerStatusAsync();
        if (!status.IsIisAvailable) return new List<SiteInfo>();
        try { return await WebServer.GetSitesAsync(); }
        catch (WebServerAccessException ex)
        {
            _logger.LogWarning(ex, "Could not list IIS sites: {Message}", ex.Message);
            return new List<SiteInfo>();
        }
    }

    /// <summary>Hostnames from a site's bindings, offered as domains for a new certificate.</summary>
    public async Task<List<DomainOption>> GetDomainOptionsFromSiteAsync(string siteId)
    {
        var site = await GetSiteSnapshotAsync(siteId);
        if (site == null) return new List<DomainOption>();
        return DomainOptionBuilder.FromHosts(site.Bindings.Where(b => b.IsHttp || b.IsHttps).Select(b => b.Host));
    }

    /// <summary>
    /// Physical path of a site's root application, for use as the http-01 web root when none is configured.
    /// Null when IIS or the site is unavailable.
    /// </summary>
    internal async Task<string?> GetSiteWebRootAsync(string siteId)
    {
        var site = await GetSiteSnapshotAsync(siteId);
        return string.IsNullOrWhiteSpace(site?.PhysicalPath) ? null : site.PhysicalPath;
    }

    private async Task<ServerSiteSnapshot?> GetSiteSnapshotAsync(string? siteId)
    {
        if (string.IsNullOrWhiteSpace(siteId)) return null;
        var status = await GetServerStatusAsync();
        if (!status.IsIisAvailable) return null;
        try { return (await WebServer.GetSiteSnapshotsAsync()).FirstOrDefault(s => s.Id == siteId); }
        catch (WebServerAccessException ex)
        {
            _logger.LogWarning(ex, "Could not read IIS site {SiteId}: {Message}", siteId, ex.Message);
            return null;
        }
    }

    // ---------- Preview ----------

    /// <summary>Describes what a request for this item would do: authorizations, CA, deployment bindings and tasks.</summary>
    public async Task<List<ActionStep>> GeneratePreviewAsync(ManagedCertificate item)
    {
        var steps = new List<ActionStep>
        {
            await DescribeCertificateRequestAsync(item),
            await DescribeAuthorizationAsync(item),
            // A new request produces a new certificate: the current one becomes the "previous" certificate.
            await DescribeDeploymentAsync(item, null, item.CertificateThumbprintHash),
            DescribeTasks("Pre-request tasks", item.PreRequestTasks, preRequest: true),
            DescribeTasks("Deployment tasks", item.PostRequestTasks, preRequest: false),
        };

        var checks = new ActionStep("Checks") { Category = "Checks" };
        try
        {
            foreach (var s in await TestConfigurationAsync(item)) { s.Category ??= "Checks"; checks.Substeps.Add(s); }
        }
        catch (Exception ex) { checks.Substeps.Add(new ActionStep("Configuration test", "Could not test the configuration: " + ex.Message, true) { Category = "Checks" }); }
        var problems = checks.Substeps.Count(s => s.HasError);
        checks.HasError = problems > 0;
        checks.HasWarning = checks.Substeps.Any(s => s.HasWarning);
        checks.Description = problems == 0 ? "All configuration checks passed." : $"{problems} problem(s) found.";
        steps.Add(checks);
        return steps;
    }

    private async Task<ActionStep> DescribeCertificateRequestAsync(ManagedCertificate item)
    {
        const string group = "Certificate Request";
        var rc = item.RequestConfig;
        var caId = item.CertificateAuthorityId ?? "letsencrypt.org";
        string caTitle = caId;
        try { caTitle = (await _acme.GetCertificateAuthorityAsync(caId))?.Title ?? caId; }
        catch (Exception ex) { _logger.LogDebug(ex, "CA lookup failed"); }

        var domains = item.GetAllDomains().ToList();
        var identifiers = domains.Concat(rc.SubjectIPAddresses).ToList();
        var step = new ActionStep(group,
            $"Request a certificate from {caTitle}{(item.UseStagingMode ? " (staging)" : "")} for: {(identifiers.Count == 0 ? "(no domains)" : string.Join(", ", identifiers))}")
        { Category = group };
        void Add(string title, string? desc, bool err = false, bool warn = false) =>
            step.Substeps.Add(new ActionStep(title, desc, err) { Category = group, HasWarning = warn });

        Add("Certificate Authority", $"{caTitle}{(item.UseStagingMode ? " - staging environment (test certificate, not trusted by browsers)" : "")}", warn: item.UseStagingMode);
        Add("Domains", domains.Count == 0 ? "None" : string.Join(", ", domains) + (string.IsNullOrEmpty(rc.PrimaryDomain) ? "" : $" (primary: {rc.PrimaryDomain})"),
            err: domains.Count == 0 && rc.SubjectIPAddresses.Count == 0);
        if (rc.SubjectIPAddresses.Count > 0) Add("IP addresses", string.Join(", ", rc.SubjectIPAddresses));
        Add("Key type", KeyTypeLabel(rc.CSRKeyAlg) + (rc.ReusePrivateKey ? ", reusing the existing private key" : ", new private key"));
        if (!string.IsNullOrWhiteSpace(rc.PreferredChain)) Add("Preferred chain", rc.PreferredChain);
        if (!string.IsNullOrWhiteSpace(rc.AcmeProfile)) Add("ACME profile", rc.AcmeProfile);
        if (!string.IsNullOrWhiteSpace(item.ARICertificateId) && !item.CertificateRevoked) Add("Renewal", "Replacement (ARI) order for the current certificate");
        return step;
    }

    internal async Task<ActionStep> DescribeAuthorizationAsync(ManagedCertificate item)
    {
        const string group = "Authorization";
        var step = new ActionStep(group) { Category = group };
        var identifiers = item.GetAllDomains().Concat(item.RequestConfig.SubjectIPAddresses).ToList();
        if (item.RequestConfig.Challenges.Count == 0)
        {
            step.Description = "No authorization (challenge) configuration.";
            step.HasError = true;
            return step;
        }

        string? siteRoot = null;
        var siteRootLoaded = false;
        foreach (var id in identifiers)
        {
            var cfg = SelectChallengeConfig(item, id);
            var sub = new ActionStep(id) { Category = group };
            if (cfg.ChallengeType == ChallengeTypes.Dns01)
            {
                var provider = _providers.GetDnsProvider(cfg.ChallengeProvider);
                var record = GetDnsRecordName(id, cfg.ChallengeDelegationRule);
                sub.Description = provider == null
                    ? $"dns-01: no DNS provider selected. Record: TXT {record}"
                    : $"dns-01 via {provider.Definition.Title}: create TXT {record}"
                      + (cfg.PropagationDelaySeconds is { } d ? $", wait {d}s for propagation" : "");
                sub.HasError = provider == null;
            }
            else if (cfg.ChallengeType == ChallengeTypes.Http01)
            {
                var webroot = cfg.Parameters.FirstOrDefault(p => p.Key == "webroot")?.Value ?? item.RequestConfig.WebsiteRootPath;
                var fromSite = false;
                if (string.IsNullOrWhiteSpace(webroot) && !string.IsNullOrWhiteSpace(item.ServerSiteId))
                {
                    if (!siteRootLoaded) { siteRoot = await GetSiteWebRootAsync(item.ServerSiteId); siteRootLoaded = true; }
                    webroot = siteRoot; fromSite = webroot != null;
                }
                var served = new List<string> { "built-in HTTP challenge server (when enabled)" };
                if (!string.IsNullOrWhiteSpace(webroot) && item.RequestConfig.PerformChallengeFileCopy)
                    served.Add($"challenge file in {webroot}{(fromSite ? " (IIS site root)" : "")}");
                sub.Description = $"http-01 via {string.Join(" and ", served)}: http://{id}/.well-known/acme-challenge/<token>";
                if (id.StartsWith("*.")) { sub.HasError = true; sub.Description = "Wildcard domains require dns-01 validation."; }
            }
            else
            {
                sub.Description = $"{cfg.ChallengeType}: not supported.";
                sub.HasError = true;
            }
            step.Substeps.Add(sub);
        }
        step.HasError = step.Substeps.Any(s => s.HasError);
        step.Description = identifiers.Count == 0 ? "Nothing to authorize." : $"{identifiers.Count} identifier(s) to authorize.";
        return step;
    }

    private ActionStep DescribeTasks(string group, List<DeploymentTaskConfig> tasks, bool preRequest)
    {
        var step = new ActionStep(group) { Category = group };
        if (tasks.Count == 0) { step.Description = "No tasks configured."; return step; }
        step.Description = $"{tasks.Count} task(s), run in order.";
        foreach (var t in tasks)
        {
            var provider = _providers.GetDeploymentProvider(t.TaskTypeId);
            var trigger = t.TaskTrigger switch
            {
                TaskTriggerType.ANY_STATUS => "always",
                TaskTriggerType.ON_SUCCESS => preRequest ? "before every request" : "on success",
                TaskTriggerType.ON_ERROR => preRequest ? "on error (never runs before a request)" : "on error",
                TaskTriggerType.MANUAL => "manual only",
                _ => "disabled",
            };
            var extras = new List<string>();
            if (t.IsFatalOnError) extras.Add(preRequest ? "failure stops the request" : "failure stops later tasks");
            if (t.RetriesAllowed > 0) extras.Add($"{t.RetriesAllowed} retr{(t.RetriesAllowed == 1 ? "y" : "ies")}");
            if (t.RunIfLastStepFailed) extras.Add("runs even if the previous task failed");
            if (t.TargetType != DeploymentContextType.LocalAsService) extras.Add($"target: {t.TargetType}{(string.IsNullOrEmpty(t.TargetHost) ? "" : " " + t.TargetHost)}");
            step.Substeps.Add(new ActionStep(string.IsNullOrWhiteSpace(t.TaskName) ? provider?.Definition.Title ?? t.TaskTypeId : t.TaskName,
                $"{provider?.Definition.Title ?? $"Unknown task type '{t.TaskTypeId}'"} - trigger: {trigger}{(extras.Count > 0 ? " (" + string.Join(", ", extras) + ")" : "")}",
                provider == null)
            { Category = group, HasWarning = t.TaskTrigger == TaskTriggerType.NOT_ENABLED });
        }
        step.HasError = step.Substeps.Any(s => s.HasError);
        return step;
    }

    private static string KeyTypeLabel(string? alg) => (alg ?? "RS256").ToUpperInvariant() switch
    {
        "ES256" => "ECDSA P-256",
        "ES384" => "ECDSA P-384",
        "RS256-3072" => "RSA 3072",
        "RS256-4096" => "RSA 4096",
        _ => "RSA 2048",
    };

    private static string DeploymentModeLabel(DeploymentOption mode) => mode switch
    {
        DeploymentOption.Auto => "Auto: update matching https bindings on any site; add bindings only to the selected site",
        DeploymentOption.SingleSite => "Single site: update and add https bindings on the selected site only",
        DeploymentOption.AllSites => "All sites: update matching https bindings on every site",
        DeploymentOption.CertificateStoreOnly => "Certificate store only: no binding changes",
        _ => "No deployment",
    };

    private async Task<ActionStep> DescribeDeploymentAsync(ManagedCertificate item, string? newThumbprint, string? previousThumbprint) =>
        (await PlanDeploymentAsync(item, newThumbprint, previousThumbprint)).Step;

    /// <summary>Describes the deployment step; also returns the plan when one could be made (IIS available and readable).</summary>
    private async Task<(ActionStep Step, BindingPlan? Plan, ServerStatus? Status)> PlanDeploymentAsync(ManagedCertificate item, string? newThumbprint, string? previousThumbprint)
    {
        const string group = "Deployment";
        var rc = item.RequestConfig;
        var mode = rc.DeploymentSiteOption;
        var step = new ActionStep(group) { Category = group };
        void Add(string title, string? desc, bool err = false, bool warn = false) =>
            step.Substeps.Add(new ActionStep(title, desc, err) { Category = group, HasWarning = warn });

        if (mode == DeploymentOption.NoDeployment)
        {
            step.Description = "No deployment: the certificate is not applied to the web server (deployment tasks still run).";
            return (step, null, null);
        }
        if (mode == DeploymentOption.CertificateStoreOnly)
        {
            step.Description = $"Store only: import the certificate into LocalMachine\\{IisServerProvider.CertificateStoreName}; no binding changes.";
            if (!OperatingSystem.IsWindows()) { step.HasError = true; Add("Certificate store", "The Windows certificate store is only available on Windows.", err: true); }
            return (step, null, null);
        }

        var status = await GetServerStatusAsync();
        if (!status.IsIisAvailable)
        {
            var fatal = mode is DeploymentOption.SingleSite or DeploymentOption.AllSites;
            step.Description = fatal
                ? $"IIS not available: deployment ({mode}) would fail. {status.Message}"
                : $"IIS not available; the certificate will only be stored. {status.Message}";
            step.HasError = fatal;
            step.HasWarning = !fatal;
            return (step, null, status);
        }

        Add("Mode", DeploymentModeLabel(mode) + (rc.DeploymentBindingOption == DeploymentBindingOption.UpdateOnly ? " (update existing bindings only)" : " (add or update bindings)"));
        Add("Certificate store", $"Import the certificate into LocalMachine\\{IisServerProvider.CertificateStoreName}");

        List<ServerSiteSnapshot> sites;
        try { sites = await WebServer.GetSiteSnapshotsAsync(); }
        catch (WebServerAccessException ex)
        {
            step.Description = "Could not read the IIS configuration: " + ex.Message;
            step.HasError = true;
            return (step, null, status);
        }

        var plan = BindingPlanner.Plan(sites, BindingPlanRequest.FromItem(item, newThumbprint, previousThumbprint));
        if (plan.Error != null)
        {
            step.Description = plan.Error;
            step.HasError = true;
            return (step, plan, status);
        }
        foreach (var a in plan.Actions) Add(a.IsNewBinding ? "Add binding" : "Update binding", a.Description);
        foreach (var w in plan.Warnings) Add("Warning", w, warn: true);
        foreach (var n in plan.Notes) Add("Note", n);
        step.HasWarning = plan.Warnings.Count > 0;
        var adds = plan.Additions.Count();
        var updates = plan.Updates.Count();
        step.Description = plan.Actions.Count == 0
            ? $"IIS {status.IisVersion}: no bindings would be changed{(plan.UpToDateCount > 0 ? $" ({plan.UpToDateCount} already up to date)" : "")}."
            : $"IIS {status.IisVersion}: update {updates} and add {adds} https binding(s).";
        return (step, plan, status);
    }

    // ---------- Deployment ----------

    /// <summary>
    /// Applies the issued certificate to the local web server according to RequestConfig.DeploymentSiteOption.
    /// Called after a successful request and before post-request tasks. Must not throw for "nothing to do".
    /// </summary>
    internal async Task<ActionResult> DeployToServerAsync(ManagedCertificate item, string pfxPath, string? pfxPassword, ItemLog log, bool isPreview, CancellationToken ct)
    {
        var mode = item.RequestConfig.DeploymentSiteOption;
        if (mode == DeploymentOption.NoDeployment)
            return ActionResult.Ok("Automatic deployment is disabled for this certificate.");

        if (isPreview)
        {
            var (step, _, _) = await PlanDeploymentAsync(item, item.CertificateThumbprintHash, item.CertificatePreviousThumbprintHash);
            var preview = new ActionResult(!step.HasError, "Preview: " + step.Description);
            preview.Actions.Add(step);
            return preview;
        }

        var status = await GetServerStatusAsync();
        if (!status.IsIisAvailable && mode is DeploymentOption.SingleSite or DeploymentOption.AllSites)
            return ActionResult.Fail($"IIS is not available ({status.Message}); cannot deploy to {(mode == DeploymentOption.SingleSite ? "the selected site" : "all sites")}.");
        if (!OperatingSystem.IsWindows())
            return mode == DeploymentOption.Auto
                ? ActionResult.Ok("IIS not available; certificate stored as files only.")
                : ActionResult.Fail("The Windows certificate store is only available on Windows.");
        if (!File.Exists(pfxPath)) return ActionResult.Fail($"Certificate file not found: {pfxPath}");

        // 1. Machine certificate store
        var friendly = string.IsNullOrWhiteSpace(item.Name) ? item.RequestConfig.PrimaryDomain : item.Name;
        var import = await WebServer.ImportCertificateAsync(pfxPath, pfxPassword, friendly, ct);
        if (!import.IsSuccess || string.IsNullOrEmpty(import.Result))
        {
            if (mode == DeploymentOption.Auto && !status.IsIisAvailable)
            {
                log.Warn(import.Message ?? "Certificate store import failed");
                return ActionResult.Ok("IIS not available; certificate files saved but not added to the machine certificate store: " + import.Message);
            }
            log.Error(import.Message ?? "Certificate store import failed");
            return ActionResult.Fail(import.Message ?? "Certificate store import failed");
        }
        var thumbprint = import.Result;
        log.Info(import.Message ?? $"Imported {thumbprint} into LocalMachine\\{IisServerProvider.CertificateStoreName}");

        if (mode == DeploymentOption.CertificateStoreOnly)
            return ActionResult.Ok($"Certificate stored in LocalMachine\\{IisServerProvider.CertificateStoreName} (no binding changes).");
        if (!status.IsIisAvailable)
        {
            log.Info("IIS not available: " + status.Message);
            return ActionResult.Ok($"IIS not available; certificate stored in LocalMachine\\{IisServerProvider.CertificateStoreName}.");
        }

        // 2. Bindings
        List<ServerSiteSnapshot> sites;
        try { sites = await WebServer.GetSiteSnapshotsAsync(); }
        catch (WebServerAccessException ex) { log.Error(ex.Message); return ActionResult.Fail(ex.Message); }

        var previous = BindingPlanner.NormalizeThumbprint(item.CertificatePreviousThumbprintHash);
        var plan = BindingPlanner.Plan(sites, BindingPlanRequest.FromItem(item, thumbprint, previous));
        if (plan.Error != null) { log.Error(plan.Error); return ActionResult.Fail(plan.Error); }
        foreach (var w in plan.Warnings) log.Warn(w);
        foreach (var n in plan.Notes) log.Info(n);

        var result = new ActionResult(true, null);
        if (plan.Actions.Count == 0)
        {
            result.Message = $"Certificate stored; no IIS bindings needed changes{(plan.UpToDateCount > 0 ? $" ({plan.UpToDateCount} already up to date)" : "")}.";
            return result;
        }

        foreach (var a in plan.Actions)
        {
            log.Info(a.Description);
            result.Actions.Add(new ActionStep(a.IsNewBinding ? "Add binding" : "Update binding", a.Description) { Category = "Deployment" });
        }
        ActionResult applied;
        try { applied = await WebServer.ApplyBindingActionsAsync(plan.Actions, thumbprint, IisServerProvider.CertificateStoreName, ct); }
        catch (WebServerAccessException ex) { applied = ActionResult.Fail(ex.Message); }
        if (!applied.IsSuccess)
        {
            log.Error("IIS binding update failed: " + applied.Message);
            return ActionResult.Fail("IIS binding update failed: " + applied.Message);
        }

        var updates = plan.Updates.Count();
        var adds = plan.Additions.Count();
        result.Message = $"IIS: updated {updates} and added {adds} https binding(s)"
                         + (plan.Warnings.Count > 0 ? $"; {plan.Warnings.Count} warning(s), see log" : "") + ".";
        return result;
    }
}
