using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Certes;
using Certes.Acme;
using AuthorizationStatus = Certes.Acme.Resource.AuthorizationStatus;
using Identifier = Certes.Acme.Resource.Identifier;
using IdentifierType = Certes.Acme.Resource.IdentifierType;
using RevocationReason = Certes.Acme.Resource.RevocationReason;
using ChallengeTypes = CertMaster.Models.ChallengeTypes;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Providers;
using CertMaster.Core.Providers.Deployment;
using CertMaster.Core.Providers.Dns;
using CertMaster.Core.Storage;
using CertMaster.Models;
using Microsoft.Extensions.Logging;

namespace CertMaster.Core;

/// <summary>
/// The certificate management engine: stores managed certificates, performs ACME requests (validation, issue,
/// deployment tasks), renewals, revocation and configuration tests.
/// </summary>
public partial class CertManager
{
    private const string ItemsCollection = "managedcertificates";
    private const string PreferencesKey = "preferences";

    private readonly DocumentStore _store;
    private readonly CredentialsManager _credentials;
    private readonly AcmeService _acme;
    private readonly ProviderRegistry _providers;
    private readonly HttpChallengeServer _httpChallenge;
    private readonly DataPaths _paths;
    private readonly ILogger<CertManager> _logger;
    private readonly HttpClient _http;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _running = new();
    private readonly SemaphoreSlim _renewAllLock = new(1, 1);

    public IProgressReporter ProgressReporter { get; set; } = new NullProgressReporter();

    public CertManager(DocumentStore store, CredentialsManager credentials, AcmeService acme, ProviderRegistry providers,
        HttpChallengeServer httpChallenge, DataPaths paths, ILogger<CertManager> logger, HttpClient? http = null)
    {
        _store = store; _credentials = credentials; _acme = acme; _providers = providers;
        _httpChallenge = httpChallenge; _paths = paths; _logger = logger;
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
    }

    public CredentialsManager Credentials => _credentials;
    public AcmeService Acme => _acme;
    public ProviderRegistry Providers => _providers;
    public DataPaths Paths => _paths;

    // ---------- Preferences ----------

    public async Task<Preferences> GetPreferencesAsync()
    {
        var p = await _store.GetSettingAsync<Preferences>(PreferencesKey);
        if (string.IsNullOrEmpty(p.CertificateStorePath)) p.CertificateStorePath = _paths.Certificates;
        return p;
    }

    public Task SetPreferencesAsync(Preferences prefs) => _store.SetSettingAsync(PreferencesKey, prefs);

    // ---------- Managed certificates ----------

    public async Task<List<ManagedCertificate>> GetManagedCertificatesAsync(string? search = null)
    {
        var items = await _store.GetAllAsync<ManagedCertificate>(ItemsCollection);
        foreach (var i in items) RefreshHealth(i);
        if (!string.IsNullOrWhiteSpace(search))
            items = items.Where(i => i.Name.Contains(search, StringComparison.OrdinalIgnoreCase)
                                     || i.GetAllDomains().Any(d => d.Contains(search, StringComparison.OrdinalIgnoreCase))).ToList();
        return items.OrderBy(i => i.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<ManagedCertificate?> GetManagedCertificateAsync(string id)
    {
        var item = await _store.GetAsync<ManagedCertificate>(ItemsCollection, id);
        if (item != null) RefreshHealth(item);
        return item;
    }

    public async Task<ActionResult<ManagedCertificate>> UpdateManagedCertificateAsync(ManagedCertificate item)
    {
        item.RequestConfig.PrimaryDomain = item.RequestConfig.PrimaryDomain?.Trim().ToLowerInvariant() ?? "";
        item.RequestConfig.SubjectAlternativeNames = item.RequestConfig.SubjectAlternativeNames
            .Select(d => d.Trim().ToLowerInvariant()).Where(d => d.Length > 0).Distinct().ToList();
        if (string.IsNullOrEmpty(item.RequestConfig.PrimaryDomain) && item.RequestConfig.SubjectAlternativeNames.Count > 0)
            item.RequestConfig.PrimaryDomain = item.RequestConfig.SubjectAlternativeNames[0];
        if (string.IsNullOrWhiteSpace(item.Name)) item.Name = item.RequestConfig.PrimaryDomain;
        if (string.IsNullOrWhiteSpace(item.Id)) item.Id = Guid.NewGuid().ToString();

        var errors = Validate(item);
        if (errors.Count > 0) return new ActionResult<ManagedCertificate> { Message = string.Join(" ", errors) };
        // The running request saves its own copy of the item when it finishes, which would overwrite these changes.
        if (IsRequestInProgress(item.Id)) return new ActionResult<ManagedCertificate> { Message = RequestInProgressMessage("saved") };

        // Preserve status fields owned by the engine.
        var existing = await _store.GetAsync<ManagedCertificate>(ItemsCollection, item.Id);
        if (existing != null)
        {
            item.DateStart = existing.DateStart; item.DateExpiry = existing.DateExpiry; item.DateRenewed = existing.DateRenewed;
            item.CertificatePath = existing.CertificatePath; item.CertificateThumbprintHash = existing.CertificateThumbprintHash;
            item.CertificatePreviousThumbprintHash = existing.CertificatePreviousThumbprintHash;
            item.CertificateIssuer = existing.CertificateIssuer; item.ARICertificateId = existing.ARICertificateId;
            item.LastRenewalStatus = existing.LastRenewalStatus; item.RenewalFailureCount = existing.RenewalFailureCount;
            item.RenewalFailureMessage = existing.RenewalFailureMessage; item.DateLastRenewalAttempt = existing.DateLastRenewalAttempt;
            item.CertificateRevoked = existing.CertificateRevoked; item.CertificateKeyType = existing.CertificateKeyType;
            item.LastAttemptedCA = existing.LastAttemptedCA; item.CurrentOrderUri = existing.CurrentOrderUri;
            // configuration changed: allow an immediate retry
            item.DateNextScheduledRenewalAttempt = null;
        }
        RefreshHealth(item);
        await _store.UpsertAsync(ItemsCollection, item.Id, item);
        await ProgressReporter.ManagedCertificateUpdatedAsync(item);
        return new ActionResult<ManagedCertificate> { IsSuccess = true, Message = "Saved", Result = item };
    }

    /// <summary>Deletes an item. Throws while a request for it is running, because the request would save the item again when it finishes.</summary>
    public async Task<bool> DeleteManagedCertificateAsync(string id)
    {
        if (IsRequestInProgress(id)) throw new InvalidOperationException(RequestInProgressMessage("deleted"));
        var deleted = await _store.DeleteAsync(ItemsCollection, id);
        return deleted;
    }

    internal static string RequestInProgressMessage(string what) =>
        $"A certificate request is in progress for this certificate, so it can't be {what} now: the request would overwrite the change when it finishes. Try again once the request has completed.";

    private static List<string> Validate(ManagedCertificate item)
    {
        var errors = new List<string>();
        var domains = item.GetAllDomains().ToList();
        if (domains.Count == 0 && item.RequestConfig.SubjectIPAddresses.Count == 0) errors.Add("At least one domain or IP address is required.");
        foreach (var d in domains)
        {
            var check = d.StartsWith("*.") ? d[2..] : d;
            if (Uri.CheckHostName(check) != UriHostNameType.Dns) errors.Add($"'{d}' is not a valid domain name.");
        }
        if (item.RequestConfig.Challenges.Count == 0) errors.Add("At least one authorization (challenge) configuration is required.");
        foreach (var d in domains.Where(d => d.StartsWith("*.")))
        {
            var cfg = SelectChallengeConfig(item, d);
            if (cfg.ChallengeType != ChallengeTypes.Dns01) errors.Add($"Wildcard domain {d} requires dns-01 validation.");
        }
        return errors;
    }


    /// <summary>Expiry warning window: 7 days, or 20% of the lifetime for short-lived certificates.</summary>
    private static TimeSpan WarningWindow(ManagedCertificate item)
    {
        var week = TimeSpan.FromDays(7);
        if (item.DateStart == null || item.DateExpiry == null) return week;
        var fifth = TimeSpan.FromTicks((item.DateExpiry.Value - item.DateStart.Value).Ticks / 5);
        return fifth < week ? fifth : week;
    }
    private static void RefreshHealth(ManagedCertificate item)
    {
        if (item.DateExpiry == null)
            item.Health = item.LastRenewalStatus == RequestState.Error ? ManagedCertificateHealth.Error : ManagedCertificateHealth.AwaitingUser;
        else if (item.LastRenewalStatus == RequestState.Error)
            item.Health = ManagedCertificateHealth.Error;
        else if (item.CertificateRevoked || item.DateExpiry < DateTimeOffset.UtcNow.Add(WarningWindow(item)))
            item.Health = ManagedCertificateHealth.Warning;
        else
            item.Health = ManagedCertificateHealth.OK;
    }

    public List<LogEntry> GetItemLog(string id, int limit = 1000) => ItemLog.Read(_paths, id, limit);

    public bool IsRequestInProgress(string id) => _running.ContainsKey(id);
    /// <summary>Number of certificate requests running now (an update install waits until this is zero).</summary>
    public int RunningRequestCount => _running.Count;

    // ---------- Challenge selection helpers ----------

    public static CertRequestChallengeConfig SelectChallengeConfig(ManagedCertificate item, string domain)
    {
        var configs = item.RequestConfig.Challenges;
        foreach (var c in configs.Where(c => !string.IsNullOrWhiteSpace(c.DomainMatch)))
        {
            var patterns = c.DomainMatch!.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var p in patterns.Select(p => p.Trim().ToLowerInvariant()))
            {
                if (p == domain) return c;
                if (p.StartsWith("*.") && (domain.EndsWith(p[1..]) || domain == p)) return c;
                if (!p.StartsWith("*.") && domain.EndsWith("." + p)) return c;
            }
        }
        return configs.FirstOrDefault(c => string.IsNullOrWhiteSpace(c.DomainMatch)) ?? configs.First();
    }

    public static string GetDnsRecordName(string domain, string? delegationRule)
    {
        var record = "_acme-challenge." + (domain.StartsWith("*.") ? domain[2..] : domain);
        if (string.IsNullOrWhiteSpace(delegationRule)) return record;
        foreach (var rule in delegationRule.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = rule.Split(':');
            if (parts.Length != 2) continue;
            var src = parts[0].Trim().TrimStart('*', '.');
            var dst = parts[1].Trim().TrimStart('*', '.');
            if (record.EndsWith("." + src, StringComparison.OrdinalIgnoreCase))
                return record[..^src.Length] + dst;
        }
        return record;
    }


    /// <summary>Provider default values overlaid with the configured values (blank values fall back to defaults).</summary>
    public static Dictionary<string, string> MergeParameters(ProviderDefinition? def, IEnumerable<ProviderParameterSetting> settings)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (def != null)
            foreach (var p in def.ProviderParameters.Where(p => !p.IsCredential && !string.IsNullOrEmpty(p.Value)))
                result[p.Key] = p.Value!;
        foreach (var s in settings.Where(s => !string.IsNullOrEmpty(s.Value)))
            result[s.Key] = s.Value!;
        return result;
    }
    private async Task<DnsProviderContext> CreateDnsContextAsync(CertRequestChallengeConfig cfg, ItemLog? log) => new()
    {
        Credentials = await _credentials.GetUnlockedCredentialsDictionaryAsync(cfg.ChallengeCredentialKey),
        Parameters = MergeParameters(_providers.GetDnsProvider(cfg.ChallengeProvider)?.Definition, cfg.Parameters),
        Http = _http, Paths = _paths, Log = log, ZoneId = cfg.ZoneId,
    };

    // ---------- Certificate request ----------

    private async Task Report(ManagedCertificate item, RequestState state, string message, ItemLog log, bool final = false)
    {
        if (!final) { if (state == RequestState.Error) log.Error(message); else log.Info(message); }
        try
        {
            await ProgressReporter.ReportProgressAsync(new RequestProgressState
            { ManagedCertificateId = item.Id, CurrentState = state, Message = message, IsFinal = final });
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Progress report failed"); }
    }

    /// <summary>Request (or renew) the certificate for a managed item.</summary>
    public async Task<CertificateRequestResult> PerformCertificateRequestAsync(string id, CancellationToken ct = default)
    {
        var item = await _store.GetAsync<ManagedCertificate>(ItemsCollection, id);
        if (item == null) return new CertificateRequestResult { Message = "Managed certificate not found" };

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (!_running.TryAdd(id, cts)) return new CertificateRequestResult { Message = "A request is already in progress for this item.", ManagedItem = item };

        var log = new ItemLog(_paths, item.Id, _logger);
        var result = new CertificateRequestResult { ManagedItem = item };
        var previousStatus = item.LastRenewalStatus;
        var cancelled = false;
        var taskWarning = false;
        var tasksFailed = false;
        try
        {
            await Report(item, RequestState.Running, $"Beginning certificate request for {item.Name}", log);
            item.DateLastRenewalAttempt = DateTimeOffset.UtcNow;

            // Pre-request tasks
            var pre = await RunTasksAsync(item, item.PreRequestTasks, null, null, log, false, cts.Token);
            if (pre == TaskListOutcome.Failed) throw new InvalidOperationException("A pre-request task failed.");
            taskWarning = pre == TaskListOutcome.Warning;

            var chain = await PerformAcmeOrderAsync(item, log, cts.Token);
            await SaveCertificateAsync(item, chain.cert, chain.key, chain.chain, chain.ariId, log);

            // Apply to local web server bindings (IIS) according to the deployment mode.
            var deployPrefs = await GetPreferencesAsync();
            var deployFiles = GetFiles(item, deployPrefs, await GetPfxPasswordAsync(item));
            var deploy = await DeployToServerAsync(item, deployFiles.Pfx, deployFiles.PfxPassword, log, false, cts.Token);
            if (!deploy.IsSuccess) throw new InvalidOperationException("Certificate issued but deployment failed: " + deploy.Message);
            if (!string.IsNullOrEmpty(deploy.Message)) await Report(item, RequestState.Running, deploy.Message, log);

            item.LastRenewalStatus = RequestState.Success;
            item.RenewalFailureCount = 0;
            item.RenewalFailureMessage = null;
            item.DateNextScheduledRenewalAttempt = null;
            item.DateRenewed = DateTimeOffset.UtcNow;
            result.IsSuccess = true;
            result.Message = $"Certificate issued, expires {item.DateExpiry:yyyy-MM-dd}";
            await Report(item, RequestState.Running, result.Message, log);
        }
        catch (Exception ex)
        {
            var msg = ex is AcmeRequestException are ? $"ACME error: {are.Error?.Detail ?? are.Message}" : ex.Message;
            if (ex is OperationCanceledException) { msg = "Request cancelled."; cancelled = true; }
            if (ex.ToString().Contains("accountDoesNotExist", StringComparison.Ordinal))
                msg = "The ACME account no longer exists at the CA (it was deactivated, or the CA was reset). Register the account again in Settings > Certificate Authorities.";
            else if (ex is AggregateException agg && agg.InnerException != null && msg.StartsWith("One or more errors"))
                msg = agg.InnerException is AcmeRequestException inner ? $"ACME error: {inner.Error?.Detail ?? inner.Message}" : agg.InnerException.Message;
            item.LastRenewalStatus = RequestState.Error;
            item.RenewalFailureCount++;
            item.RenewalFailureMessage = msg;
            var backoffHours = Math.Min(Math.Pow(2, item.RenewalFailureCount - 1), 24);
            item.DateNextScheduledRenewalAttempt = DateTimeOffset.UtcNow.AddHours(backoffHours);
            result.IsSuccess = false;
            result.Message = msg;
            _logger.LogWarning(ex, "Certificate request failed for {Name}", item.Name);
            await Report(item, RequestState.Error, "Request failed: " + msg, log);
        }

        try
        {
            // Post-request tasks run according to their triggers
            var post = await RunTasksAsync(item, item.PostRequestTasks, result.IsSuccess, result.Message, log, false, cts.Token);
            if (post == TaskListOutcome.Failed && result.IsSuccess)
            {
                tasksFailed = true;
                item.LastRenewalStatus = RequestState.Warning;
                result.Message += " (one or more deployment tasks failed)";
            }
            else if ((taskWarning || post == TaskListOutcome.Warning) && result.IsSuccess)
            {
                item.LastRenewalStatus = RequestState.Warning;
                result.Message += " (one or more deployment tasks reported a warning)";
            }
            await SendWebhookAsync(item, result, log);
        }
        catch (Exception ex) { log.Error("Post-request processing failed: " + ex.Message); }
        finally
        {
            try { await SendNotificationAsync(item, previousStatus, cancelled, tasksFailed, result.Message, log); }
            catch (Exception ex) { log.Warn("Notification failed: " + ex.Message); }

            RefreshHealth(item);
            await _store.UpsertAsync(ItemsCollection, item.Id, item);
            _running.TryRemove(id, out _);
            cts.Dispose();
            await Report(item, item.LastRenewalStatus == RequestState.Error ? RequestState.Error : RequestState.Success, result.Message ?? "", log, final: true);
            await ProgressReporter.ManagedCertificateUpdatedAsync(item);
        }
        result.ManagedItem = item;
        return result;
    }

    public bool CancelRequest(string id)
    {
        if (_running.TryGetValue(id, out var cts)) { cts.Cancel(); return true; }
        return false;
    }

    /// <summary>The item's key type, or the instance default (Preferences.DefaultKeyType) when the item leaves it blank.</summary>
    public static string ResolveKeyAlg(string? itemAlg, Preferences prefs) =>
        !string.IsNullOrWhiteSpace(itemAlg) ? itemAlg.Trim()
        : !string.IsNullOrWhiteSpace(prefs.DefaultKeyType) ? prefs.DefaultKeyType.Trim()
        : "RS256";

    private static IKey CreateKey(string? alg) => (alg ?? "RS256").ToUpperInvariant() switch
    {
        "ES256" => KeyFactory.NewKey(KeyAlgorithm.ES256),
        "ES384" => KeyFactory.NewKey(KeyAlgorithm.ES384),
        "RS256-3072" => KeyFactory.NewKey(KeyAlgorithm.RS256, 3072),
        "RS256-4096" => KeyFactory.NewKey(KeyAlgorithm.RS256, 4096),
        _ => KeyFactory.NewKey(KeyAlgorithm.RS256, 2048),
    };



    /// <summary>http-01 web root: the challenge config's webroot, else the item's website root, else the selected IIS site's physical path.</summary>
    private async Task<string?> ResolveWebRootAsync(ManagedCertificate item, CertRequestChallengeConfig cfg)
    {
        var explicitRoot = cfg.Parameters.FirstOrDefault(p => p.Key == "webroot")?.Value;
        if (!string.IsNullOrWhiteSpace(explicitRoot)) return explicitRoot;
        if (!string.IsNullOrWhiteSpace(item.RequestConfig.WebsiteRootPath)) return item.RequestConfig.WebsiteRootPath;
        if (string.IsNullOrWhiteSpace(item.ServerSiteId)) return null;
        try { return await GetSiteWebRootAsync(item.ServerSiteId); }
        catch { return null; }
    }
    internal async Task<string?> GetPfxPasswordAsync(ManagedCertificate item) =>
        item.CertificatePasswordCredentialId == null ? null
            : (await _credentials.GetUnlockedCredentialsDictionaryAsync(item.CertificatePasswordCredentialId)).GetValueOrDefault("password");

    internal CertificateFiles GetCertificateFiles(ManagedCertificate item, Preferences prefs, string? pfxPassword) => GetFiles(item, prefs, pfxPassword);
    private CertificateFiles GetFiles(ManagedCertificate item, Preferences prefs, string? pfxPassword = null) =>
        new() { Folder = Path.Combine(string.IsNullOrEmpty(prefs.CertificateStorePath) ? _paths.Certificates : prefs.CertificateStorePath, item.Id), PfxPassword = pfxPassword };

    private async Task<(string cert, IKey key, List<string> chain, string? ariId)> PerformAcmeOrderAsync(ManagedCertificate item, ItemLog log, CancellationToken ct)
    {
        var prefs = await GetPreferencesAsync();
        var (acme, account, ca) = await _acme.GetContextAsync(item.CertificateAuthorityId, item.UseStagingMode);
        item.LastAttemptedCA = ca.Id;
        log.Info($"Using {ca.Title}{(item.UseStagingMode ? " (staging)" : "")} account {account.AccountURI}");

        var identifiers = item.GetAllDomains().Select(d => new Identifier { Type = IdentifierType.Dns, Value = d })
            .Concat(item.RequestConfig.SubjectIPAddresses.Select(ip => new Identifier { Type = IdentifierType.Ip, Value = ip })).ToList();
        log.Info("Identifiers: " + string.Join(", ", identifiers.Select(i => i.Value)));

        IOrderContext order;
        try
        {
            if (!string.IsNullOrEmpty(item.RequestConfig.AcmeProfile))
                order = await acme.NewOrderWithProfile(identifiers, item.RequestConfig.AcmeProfile, null, null, item.ARICertificateId, false);
            else if (!string.IsNullOrEmpty(item.ARICertificateId) && !item.CertificateRevoked)
                order = await acme.NewReplacementOrder(identifiers, item.ARICertificateId, null, null);
            else
                order = await acme.NewOrder(identifiers, null, null);
        }
        catch (AcmeRequestException ex) when (!string.IsNullOrEmpty(item.ARICertificateId))
        {
            log.Warn($"Replacement (ARI) order not accepted ({ex.Error?.Detail}), creating a standard order.");
            order = await acme.NewOrder(identifiers, null, null);
        }
        item.CurrentOrderUri = order.Location?.ToString();
        await Report(item, RequestState.Running, "Order created, completing authorizations", log);

        var pending = new List<(IChallengeContext challenge, Func<Task> cleanup, string identifier)>();
        var httpStarted = false;
        try
        {
            var maxPropagation = 0;
            var dnsRecords = new List<(string record, string value)>();
            foreach (var authz in await order.Authorizations())
            {
                ct.ThrowIfCancellationRequested();
                var res = await authz.Resource();
                var domain = (res.Wildcard == true ? "*." : "") + res.Identifier.Value;
                if (res.Status == AuthorizationStatus.Valid) { log.Info($"{domain}: authorization already valid (cached)"); continue; }

                var cfg = SelectChallengeConfig(item, domain);
                if (cfg.ChallengeType == ChallengeTypes.Dns01)
                {
                    var provider = _providers.GetDnsProvider(cfg.ChallengeProvider) ?? throw new InvalidOperationException($"DNS provider '{cfg.ChallengeProvider}' not found for {domain}.");
                    var challenge = await authz.Dns() ?? throw new InvalidOperationException($"CA did not offer dns-01 for {domain}.");
                    var txt = acme.AccountKey.DnsTxt(challenge.Token);
                    var record = GetDnsRecordName(domain, cfg.ChallengeDelegationRule);
                    var dctx = await CreateDnsContextAsync(cfg, log);
                    log.Info($"{domain}: creating TXT {record} via {provider.Definition.Title}");
                    var created = await provider.CreateRecordAsync(dctx, record, txt);
                    if (!created.IsSuccess) throw new InvalidOperationException(created.Message);
                    log.Info(created.Message ?? "");
                    pending.Add((challenge, async () =>
                    {
                        var del = await provider.DeleteRecordAsync(dctx, record, txt);
                        log.Info($"Cleanup {record}: {del.Message}");
                    }, domain));
                    var delay = cfg.PropagationDelaySeconds
                                ?? (int.TryParse(dctx.Param("propagationdelay"), out var pd) ? pd : provider.Definition.PropagationDelaySeconds);
                    maxPropagation = Math.Max(maxPropagation, delay);
                    dnsRecords.Add((record, txt));
                }
                else if (cfg.ChallengeType == ChallengeTypes.Http01)
                {
                    var challenge = await authz.Http() ?? throw new InvalidOperationException($"CA did not offer http-01 for {domain}.");
                    var keyAuthz = challenge.KeyAuthz;
                    var webroot = await ResolveWebRootAsync(item, cfg);
                    var served = false;
                    if (prefs.EnableHttpChallengeServer)
                    {
                        if (!httpStarted)
                        {
                            httpStarted = _httpChallenge.Start(prefs.HttpChallengeServerPrefix, out var err);
                            if (!httpStarted) log.Warn("Built-in HTTP challenge server unavailable: " + err);
                        }
                        if (httpStarted) { _httpChallenge.AddResponse(challenge.Token, keyAuthz); served = true; }
                    }
                    string? file = null;
                    if (!string.IsNullOrWhiteSpace(webroot) && item.RequestConfig.PerformChallengeFileCopy)
                    {
                        file = HttpChallengeServer.WriteChallengeFile(webroot, challenge.Token, keyAuthz);
                        log.Info($"{domain}: wrote challenge file {file}");
                        served = true;
                    }
                    if (!served) throw new InvalidOperationException($"No way to serve http-01 for {domain}: built-in server unavailable and no web root configured.");
                    var token = challenge.Token;
                    pending.Add((challenge, () =>
                    {
                        _httpChallenge.RemoveResponse(token);
                        if (file != null) try { File.Delete(file); } catch { /* ignore */ }
                        return Task.CompletedTask;
                    }, domain));
                }
                else throw new NotSupportedException($"Challenge type {cfg.ChallengeType} is not supported yet.");
            }

            if (maxPropagation > 0)
            {
                await Report(item, RequestState.Running, $"Waiting {maxPropagation}s for DNS propagation", log);
                await Task.Delay(TimeSpan.FromSeconds(maxPropagation), ct);
            }

            if (dnsRecords.Count > 0 && prefs.DnsPropagationCheckSeconds > 0)
            {
                await Report(item, RequestState.Running, $"Checking {dnsRecords.Count} TXT record(s) on authoritative name servers", log);
                foreach (var (record, value) in dnsRecords.Distinct())
                {
                    var check = await DnsPropagationChecker.WaitForTxtAsync(record, value, TimeSpan.FromSeconds(prefs.DnsPropagationCheckSeconds), log, ct);
                    if (check.IsVisible) log.Info($"{record}: visible on authoritative name servers after {check.Elapsed.TotalSeconds:0}s");
                    else log.Warn($"{record}: not confirmed on all authoritative name servers ({check.Message}). Continuing; the CA may still see it.");
                }
            }

            foreach (var (challenge, _, identifier) in pending)
            {
                await Report(item, RequestState.Running, $"Requesting validation for {identifier}", log);
                await challenge.Validate();
            }

            // Poll authorizations until valid/invalid
            var deadline = DateTime.UtcNow.AddMinutes(3);
            foreach (var authz in await order.Authorizations())
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    var res = await authz.Resource();
                    var name = (res.Wildcard == true ? "*." : "") + res.Identifier.Value;
                    if (res.Status == AuthorizationStatus.Valid) { log.Info($"{name}: validated"); break; }
                    if (res.Status is AuthorizationStatus.Invalid or AuthorizationStatus.Revoked or AuthorizationStatus.Expired or AuthorizationStatus.Deactivated)
                    {
                        var err = res.Challenges?.FirstOrDefault(c => c.Error != null)?.Error;
                        throw new InvalidOperationException($"Validation failed for {name}: {err?.Detail ?? res.Status.ToString()}");
                    }
                    if (DateTime.UtcNow > deadline) throw new TimeoutException($"Timed out waiting for validation of {name}");
                    await Task.Delay(2000, ct);
                }
            }
        }
        finally
        {
            foreach (var (_, cleanup, _) in pending)
                try { await cleanup(); } catch (Exception ex) { log.Warn("Challenge cleanup failed: " + ex.Message); }
            if (httpStarted) _httpChallenge.Stop();
        }

        await Report(item, RequestState.Running, "Authorizations complete, finalizing order", log);
        var files = GetFiles(item, prefs);
        IKey certKey = item.RequestConfig.ReusePrivateKey && File.Exists(files.KeyPem)
            ? KeyFactory.FromPem(await File.ReadAllTextAsync(files.KeyPem, ct))
            : CreateKey(ResolveKeyAlg(item.RequestConfig.CSRKeyAlg, prefs));

        var csr = new CsrInfo();
        var primary = item.RequestConfig.PrimaryDomain;
        if (!string.IsNullOrEmpty(primary) && primary.Length <= 64) csr.CommonName = primary;
        var chain = await order.Generate(csr, certKey, item.RequestConfig.PreferredChain ?? account.PreferredChain, 10);
        var certPem = chain.Certificate.ToPem();
        var issuers = chain.Issuers.Select(i => i.ToPem()).ToList();
        string? ariId = null;
        try { ariId = chain.GetRenewalInfoCertificateId(); } catch { /* CA cert without AKI */ }
        return (certPem, certKey, issuers, ariId);
    }

    private async Task SaveCertificateAsync(ManagedCertificate item, string certPem, IKey key, List<string> issuers, string? ariId, ItemLog log)
    {
        var prefs = await GetPreferencesAsync();
        var pfxPassword = item.CertificatePasswordCredentialId != null
            ? (await _credentials.GetUnlockedCredentialsDictionaryAsync(item.CertificatePasswordCredentialId)).GetValueOrDefault("password")
            : null;
        var files = GetFiles(item, prefs, pfxPassword);
        Directory.CreateDirectory(files.Folder);

        var keyPem = key.ToPem();
        var chainPem = string.Concat(issuers);
        await File.WriteAllTextAsync(files.CertPem, certPem);
        await File.WriteAllTextAsync(files.ChainPem, chainPem);
        await File.WriteAllTextAsync(files.FullChainPem, certPem + chainPem);
        await File.WriteAllTextAsync(files.KeyPem, keyPem);

        using var leaf = X509Certificate2.CreateFromPem(certPem, keyPem);
        var collection = new X509Certificate2Collection(leaf);
        foreach (var pem in issuers) collection.Add(X509Certificate2.CreateFromPem(pem));
        await File.WriteAllBytesAsync(files.Pfx, collection.Export(X509ContentType.Pkcs12, pfxPassword)!);

        if (item.CertificateThumbprintHash != leaf.Thumbprint) item.CertificatePreviousThumbprintHash = item.CertificateThumbprintHash;
        item.CertificateThumbprintHash = leaf.Thumbprint;
        item.CertificatePath = files.Pfx;
        item.DateStart = leaf.NotBefore.ToUniversalTime();
        item.DateExpiry = leaf.NotAfter.ToUniversalTime();
        item.CertificateIssuer = leaf.Issuer;
        item.CertificateKeyType = leaf.GetRSAPublicKey() is { } rsa ? $"RSA {rsa.KeySize}" : leaf.GetECDsaPublicKey() is { } ec ? $"ECDSA P-{ec.KeySize}" : key.Algorithm.ToString();
        item.CertificateRevoked = false;
        item.ARICertificateId = ariId;
        log.Info($"Certificate saved to {files.Folder}. Thumbprint {leaf.Thumbprint}, expires {leaf.NotAfter:u}");
    }

    /// <summary>Overall outcome of a task list: all OK, completed with at least one warning, or at least one failure.</summary>
    internal enum TaskListOutcome { Ok, Warning, Failed }

    private async Task<TaskListOutcome> RunTasksAsync(ManagedCertificate item, List<DeploymentTaskConfig> tasks, bool? requestOk, string? message,
        ItemLog log, bool previewOnly, CancellationToken ct, string? onlyTaskId = null)
    {
        var allOk = true;
        var anyWarning = false;
        var prefs = await GetPreferencesAsync();
        var pfxPassword = item.CertificatePasswordCredentialId != null
            ? (await _credentials.GetUnlockedCredentialsDictionaryAsync(item.CertificatePasswordCredentialId)).GetValueOrDefault("password") : null;
        var files = GetFiles(item, prefs, pfxPassword);
        var previousFailed = false;

        foreach (var task in tasks)
        {
            if (onlyTaskId != null && task.Id != onlyTaskId) continue;
            if (onlyTaskId == null)
            {
                var shouldRun = task.TaskTrigger switch
                {
                    TaskTriggerType.ANY_STATUS => true,
                    TaskTriggerType.ON_SUCCESS => requestOk != false,
                    TaskTriggerType.ON_ERROR => requestOk == false,
                    _ => false,
                };
                if (!shouldRun) continue;
                if (previousFailed && !task.RunIfLastStepFailed) { log.Warn($"Skipping task {task.TaskName}: previous task failed"); continue; }
            }

            var provider = _providers.GetDeploymentProvider(task.TaskTypeId);
            if (provider == null) { log.Error($"Unknown task type {task.TaskTypeId}"); allOk = false; previousFailed = true; continue; }

            var ctx = new DeploymentContext
            {
                Item = item, Task = task, Files = files, Log = log, Http = _http, IsPreviewOnly = previewOnly,
                RequestSucceeded = requestOk, RequestMessage = message,
                Parameters = MergeParameters(provider.Definition, task.Parameters),
                Credentials = await _credentials.GetUnlockedCredentialsDictionaryAsync(task.ChallengeCredentialKey),
                UnlockCredentialAsync = _credentials.GetUnlockedCredentialsDictionaryAsync,
            };

            var validation = await provider.ValidateAsync(ctx);
            ActionResult r;
            if (validation.Any(v => v.HasError)) r = ActionResult.Fail("Invalid task configuration: " + string.Join("; ", validation.Select(v => v.Title)));
            else
            {
                r = ActionResult.Fail("Not run");
                for (var attempt = 0; attempt <= task.RetriesAllowed; attempt++)
                {
                    try { r = await provider.ExecuteAsync(ctx, ct); }
                    catch (Exception ex) { r = ActionResult.Fail(ex.Message); }
                    if (r.IsSuccess || attempt == task.RetriesAllowed) break;
                    log.Warn($"Task {task.TaskName} failed ({r.Message}), retrying in {task.RetryDelaySeconds}s");
                    await Task.Delay(TimeSpan.FromSeconds(task.RetryDelaySeconds), ct);
                }
            }

            var warning = r.IsSuccess && r.IsWarning;
            if (!previewOnly)
            {
                task.DateLastExecuted = DateTimeOffset.UtcNow;
                task.LastRunStatus = !r.IsSuccess ? RequestState.Error : warning ? RequestState.Warning : RequestState.Success;
                task.LastResult = r.Message;
            }
            await Report(item, r.IsSuccess ? RequestState.Running : RequestState.Error,
                $"Task '{task.TaskName}'{(warning ? " completed with a warning" : "")}: {r.Message}", log);
            if (warning) anyWarning = true;
            if (!r.IsSuccess)
            {
                allOk = false; previousFailed = true;
                if (task.IsFatalOnError && onlyTaskId == null) { log.Error($"Task {task.TaskName} is fatal on error; stopping task list."); break; }
            }
        }
        return !allOk ? TaskListOutcome.Failed : anyWarning ? TaskListOutcome.Warning : TaskListOutcome.Ok;
    }

    private async Task SendWebhookAsync(ManagedCertificate item, CertificateRequestResult result, ItemLog log)
    {
        var rc = item.RequestConfig;
        if (string.IsNullOrWhiteSpace(rc.WebhookUrl) || rc.WebhookTrigger is null or "none") return;
        if (rc.WebhookTrigger == "on_success" && !result.IsSuccess) return;
        if (rc.WebhookTrigger == "on_error" && result.IsSuccess) return;
        try
        {
            var body = (rc.WebhookContentBody ?? "{\"name\":\"{Name}\",\"success\":{IsSuccess},\"message\":\"{Message}\"}")
                .Replace("{Name}", item.Name).Replace("{ManagedItemId}", item.Id)
                .Replace("{IsSuccess}", result.IsSuccess.ToString().ToLowerInvariant()).Replace("{Message}", result.Message?.Replace("\"", "'") ?? "");
            var req = new HttpRequestMessage(new HttpMethod(rc.WebhookMethod ?? "POST"), rc.WebhookUrl)
            { Content = new StringContent(body, Encoding.UTF8, rc.WebhookContentType ?? "application/json") };
            using var resp = await _http.SendAsync(req);
            log.Info($"Webhook {rc.WebhookUrl} returned {(int)resp.StatusCode}");
        }
        catch (Exception ex) { log.Warn("Webhook failed: " + ex.Message); }
    }

    /// <summary>Manually run a single deployment task (pre or post) for an item.</summary>
    public async Task<ActionResult> PerformDeploymentTaskAsync(string id, string taskId, bool previewOnly)
    {
        var item = await _store.GetAsync<ManagedCertificate>(ItemsCollection, id);
        if (item == null) return ActionResult.Fail("Managed certificate not found");
        if (!previewOnly && IsRequestInProgress(id)) return ActionResult.Fail(RequestInProgressMessage("updated by running a task"));
        var log = new ItemLog(_paths, id, _logger);
        var tasks = item.PreRequestTasks.Concat(item.PostRequestTasks).ToList();
        if (tasks.All(t => t.Id != taskId)) return ActionResult.Fail("Task not found");
        var outcome = await RunTasksAsync(item, tasks, null, null, log, previewOnly, CancellationToken.None, taskId);
        if (!previewOnly) await _store.UpsertAsync(ItemsCollection, item.Id, item);
        var task = tasks.First(t => t.Id == taskId);
        var ok = outcome != TaskListOutcome.Failed;
        var fallback = outcome switch { TaskListOutcome.Ok => "Task completed", TaskListOutcome.Warning => "Task completed with a warning", _ => "Task failed" };
        return new ActionResult(ok, task.LastResult ?? fallback) { IsWarning = outcome == TaskListOutcome.Warning };
    }

    // ---------- Test configuration ----------

    public async Task<List<ActionStep>> TestConfigurationAsync(ManagedCertificate item)
    {
        var steps = new List<ActionStep>();
        foreach (var e in Validate(item)) steps.Add(new ActionStep("Configuration", e, true));
        var prefs = await GetPreferencesAsync();

        try
        {
            var (_, account, ca) = await _acme.GetContextAsync(item.CertificateAuthorityId, item.UseStagingMode);
            steps.Add(new ActionStep("ACME Account", $"Using {ca.Title} account {account.Email}"));
        }
        catch (Exception ex) { steps.Add(new ActionStep("ACME Account", ex.Message, true)); }

        foreach (var domain in item.GetAllDomains())
        {
            var cfg = SelectChallengeConfig(item, domain);
            if (cfg.ChallengeType == ChallengeTypes.Dns01)
            {
                var provider = _providers.GetDnsProvider(cfg.ChallengeProvider);
                if (provider == null) { steps.Add(new ActionStep($"dns-01: {domain}", "No DNS provider selected", true)); continue; }
                var r = await provider.TestAsync(await CreateDnsContextAsync(cfg, null));
                steps.Add(new ActionStep($"dns-01: {domain}", $"{provider.Definition.Title}: {r.Message}. Record: {GetDnsRecordName(domain, cfg.ChallengeDelegationRule)}", !r.IsSuccess));
            }
            else
            {
                steps.Add(await TestHttpChallengeAsync(item, cfg, domain, prefs));
            }
        }

        foreach (var task in item.PreRequestTasks.Concat(item.PostRequestTasks))
        {
            var p = _providers.GetDeploymentProvider(task.TaskTypeId);
            if (p == null) { steps.Add(new ActionStep($"Task: {task.TaskName}", "Unknown task type", true)); continue; }
            var ctx = new DeploymentContext
            {
                Item = item, Task = task, Files = GetFiles(item, prefs), Log = new ItemLog(_paths, item.Id, _logger), Http = _http, IsPreviewOnly = true,
                Parameters = MergeParameters(p.Definition, task.Parameters),
                Credentials = await _credentials.GetUnlockedCredentialsDictionaryAsync(task.ChallengeCredentialKey),
                UnlockCredentialAsync = _credentials.GetUnlockedCredentialsDictionaryAsync,
            };
            var v = await p.ValidateAsync(ctx);
            steps.Add(v.Count == 0 ? new ActionStep($"Task: {task.TaskName}", "Configuration OK") : new ActionStep($"Task: {task.TaskName}", string.Join("; ", v.Select(x => x.Title)), true));
        }
        return steps;
    }

    private async Task<ActionStep> TestHttpChallengeAsync(ManagedCertificate item, CertRequestChallengeConfig cfg, string domain, Preferences prefs)
    {
        var token = "certmaster-test-" + Guid.NewGuid().ToString("N")[..12];
        var value = "certmaster-" + Guid.NewGuid().ToString("N");
        var started = false;
        string? file = null;
        try
        {
            if (prefs.EnableHttpChallengeServer)
            {
                started = _httpChallenge.Start(prefs.HttpChallengeServerPrefix, out var err);
                if (started) _httpChallenge.AddResponse(token, value);
                else if (string.IsNullOrWhiteSpace(item.RequestConfig.WebsiteRootPath))
                    return new ActionStep($"http-01: {domain}", "Built-in HTTP challenge server could not start: " + err, true);
            }
            var webroot = await ResolveWebRootAsync(item, cfg);
            if (!string.IsNullOrWhiteSpace(webroot)) file = HttpChallengeServer.WriteChallengeFile(webroot, token, value);

            var url = $"http://{domain}/.well-known/acme-challenge/{token}";
            try
            {
                var resp = await _http.GetStringAsync(url);
                return resp.Trim() == value
                    ? new ActionStep($"http-01: {domain}", $"OK - {url} returned the expected response")
                    : new ActionStep($"http-01: {domain}", $"{url} returned unexpected content", true) { HasWarning = true };
            }
            catch (Exception ex)
            {
                return new ActionStep($"http-01: {domain}", $"Could not fetch {url}: {ex.Message}. The CA must reach this URL from the internet.", true);
            }
        }
        finally
        {
            _httpChallenge.RemoveResponse(token);
            if (started) _httpChallenge.Stop();
            if (file != null) try { File.Delete(file); } catch { /* ignore */ }
        }
    }

    // ---------- Revoke / download ----------

    public async Task<ActionResult> RevokeCertificateAsync(string id)
    {
        var item = await _store.GetAsync<ManagedCertificate>(ItemsCollection, id);
        if (item == null) return ActionResult.Fail("Managed certificate not found");
        var prefs = await GetPreferencesAsync();
        var files = GetFiles(item, prefs);
        if (!File.Exists(files.CertPem)) return ActionResult.Fail("No certificate to revoke");
        var log = new ItemLog(_paths, id, _logger);
        try
        {
            var (acme, _, _) = await _acme.GetContextAsync(item.LastAttemptedCA ?? item.CertificateAuthorityId, item.UseStagingMode);
            using var cert = X509Certificate2.CreateFromPem(await File.ReadAllTextAsync(files.CertPem));
            await acme.RevokeCertificate(cert.RawData, RevocationReason.Unspecified, null);
            item.CertificateRevoked = true;
            RefreshHealth(item);
            await _store.UpsertAsync(ItemsCollection, id, item);
            log.Warn("Certificate revoked");
            await ProgressReporter.ManagedCertificateUpdatedAsync(item);
            return ActionResult.Ok("Certificate revoked");
        }
        catch (Exception ex)
        {
            log.Error("Revoke failed: " + ex.Message);
            return ActionResult.Fail("Revoke failed: " + (ex is AcmeRequestException a ? a.Error?.Detail : ex.Message));
        }
    }

    public async Task<(byte[] data, string fileName, string contentType)?> GetCertificateFileAsync(string id, CertificateDownloadFormat format)
    {
        var item = await _store.GetAsync<ManagedCertificate>(ItemsCollection, id);
        if (item == null) return null;
        var files = GetFiles(item, await GetPreferencesAsync());
        if (!files.Exists) return null;
        var safe = string.Concat(item.Name.Select(c => Path.GetInvalidFileNameChars().Contains(c) || c == '*' ? '_' : c));
        return format switch
        {
            CertificateDownloadFormat.pfx => (await File.ReadAllBytesAsync(files.Pfx), safe + ".pfx", "application/x-pkcs12"),
            CertificateDownloadFormat.pem_crt => (await File.ReadAllBytesAsync(files.CertPem), safe + ".crt.pem", "application/x-pem-file"),
            CertificateDownloadFormat.pem_chain => (await File.ReadAllBytesAsync(files.FullChainPem), safe + ".fullchain.pem", "application/x-pem-file"),
            CertificateDownloadFormat.pem_key => (await File.ReadAllBytesAsync(files.KeyPem), safe + ".key.pem", "application/x-pem-file"),
            _ => (Encoding.ASCII.GetBytes(await File.ReadAllTextAsync(files.FullChainPem) + await File.ReadAllTextAsync(files.KeyPem)), safe + ".pem", "application/x-pem-file"),
        };
    }

    // ---------- Renewal ----------

    public static bool IsRenewalDue(ManagedCertificate item, Preferences prefs, DateTimeOffset now, out string reason)
    {
        reason = "";
        if (item.ItemType != ManagedCertificateType.SSL_ACME || !item.IncludeInAutoRenew) { reason = "auto-renew disabled"; return false; }
        if (item.DateNextScheduledRenewalAttempt != null && item.DateNextScheduledRenewalAttempt > now) { reason = "waiting for retry back-off"; return false; }
        if (item.DateExpiry == null) { reason = "no certificate yet"; return true; }
        if (item.CertificateRevoked) { reason = "certificate revoked"; return true; }

        double? lifetime = item.DateStart != null ? (item.DateExpiry.Value - item.DateStart.Value).TotalDays : null;
        double days;
        if (item.CustomRenewalDaysBeforeExpiry == null && lifetime != null
            && string.Equals(prefs.RenewalIntervalMode, RenewalIntervalModes.PercentageOfLifetime, StringComparison.OrdinalIgnoreCase))
        {
            // Renew once the configured share of the lifetime has passed, i.e. when (100 - pct)% remains.
            var pct = Math.Clamp(prefs.RenewalLifetimePercentage, 1, 99);
            days = lifetime.Value * (100 - pct) / 100.0;
        }
        else
        {
            days = item.CustomRenewalDaysBeforeExpiry ?? prefs.RenewalIntervalDays;
            if (lifetime != null) days = Math.Min(days, lifetime.Value / 3.0);
        }
        var remaining = (item.DateExpiry.Value - now).TotalDays;
        if (remaining <= days) { reason = $"{remaining:0.#} days remaining (threshold {days:0.#})"; return true; }
        reason = "not due";
        return false;
    }

    /// <summary>Renew all items that are due. Returns the results for items attempted.</summary>
    public async Task<List<CertificateRequestResult>> PerformRenewAllAsync(bool forceAll = false, CancellationToken ct = default)
    {
        var results = new List<CertificateRequestResult>();
        if (!await _renewAllLock.WaitAsync(0, ct)) return results;
        try
        {
            var prefs = await GetPreferencesAsync();
            var items = await GetManagedCertificatesAsync();
            var due = items.Where(i => forceAll ? i.IncludeInAutoRenew : IsRenewalDue(i, prefs, DateTimeOffset.UtcNow, out _)).ToList();
            if (prefs.MaxRenewalRequests > 0) due = due.Take(prefs.MaxRenewalRequests).ToList();
            if (due.Count > 0) _logger.LogInformation("Renewal: {Count} item(s) due", due.Count);
            foreach (var item in due)
            {
                ct.ThrowIfCancellationRequested();
                if (IsRequestInProgress(item.Id)) continue;
                results.Add(await PerformCertificateRequestAsync(item.Id, ct));
            }
        }
        finally { _renewAllLock.Release(); }
        return results;
    }
}
