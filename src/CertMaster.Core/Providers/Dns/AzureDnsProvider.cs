using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;
using Azure.ResourceManager.Resources;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Azure DNS (public zones). Values are added to / removed from the TXT record set with ETag concurrency checks.</summary>
public class AzureDnsProvider : DnsProviderBase
{
    private const string Name = "Azure DNS";

    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.API.Azure",
        Title = "Azure DNS API",
        Description = "Validates via Azure DNS using a service principal (tenant id, client id, client secret) or a managed identity. The identity needs the 'DNS Zone Contributor' role on the zone or resource group.",
        HelpUrl = "https://learn.microsoft.com/azure/dns/dns-protect-zones-recordsets",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 30,
        CredentialType = "AzureDns",
        ProviderParameters =
        {
            new ProviderParameter { Key = "tenant_id", Name = "Tenant (Directory) ID", IsCredential = true },
            new ProviderParameter { Key = "client_id", Name = "Client (Application) ID", IsCredential = true, Description = "For a user-assigned managed identity, its client id." },
            new ProviderParameter { Key = "client_secret", Name = "Client Secret", Type = OptionType.Password, IsCredential = true },
            new ProviderParameter { Key = "subscription_id", Name = "Subscription ID", IsRequired = true },
            new ProviderParameter { Key = "resource_group", Name = "Resource Group (optional)", Description = "Limit zone lookup to this resource group." },
            new ProviderParameter { Key = "use_managed_identity", Name = "Use Managed Identity", Type = OptionType.Boolean, Value = "false", Description = "Authenticate with the machine's managed identity instead of a client secret." },
            new ProviderParameter { Key = "cloud", Name = "Azure Cloud", Type = OptionType.Select, Value = "AzureCloud", OptionsList = "AzureCloud=Azure (public);AzureUSGovernment=Azure US Government;AzureChinaCloud=Azure China" },
        }
    };

    // ---------- pure helpers (unit tested) ----------

    /// <summary>
    /// TXT records of a record set (each record is a list of character strings) with <paramref name="value"/> added as a
    /// new record unless already present. Existing records are preserved unchanged.
    /// </summary>
    public static List<List<string>> AddTxtValue(IEnumerable<IReadOnlyList<string>>? records, string value)
    {
        var list = (records ?? Enumerable.Empty<IReadOnlyList<string>>()).Select(r => r.ToList()).ToList();
        if (!list.Any(r => string.Concat(r) == value)) list.Add(SplitValue(value));
        return list;
    }

    /// <summary>TXT records without the one(s) whose joined strings equal <paramref name="value"/>.</summary>
    public static List<List<string>> RemoveTxtValue(IEnumerable<IReadOnlyList<string>>? records, string value) =>
        (records ?? Enumerable.Empty<IReadOnlyList<string>>()).Where(r => string.Concat(r) != value).Select(r => r.ToList()).ToList();

    /// <summary>TXT character strings are limited to 255 characters.</summary>
    private static List<string> SplitValue(string value)
    {
        var parts = new List<string>();
        for (var i = 0; i < value.Length; i += 255) parts.Add(value.Substring(i, Math.Min(255, value.Length - i)));
        if (parts.Count == 0) parts.Add("");
        return parts;
    }

    // ---------- client ----------

    private static ArmClient CreateClient(DnsProviderContext ctx)
    {
        var subscription = ctx.Require("subscription_id", "Subscription ID", Name);
        var (env, authority) = (ctx.Param("cloud") ?? "AzureCloud") switch
        {
            "AzureUSGovernment" => (ArmEnvironment.AzureGovernment, AzureAuthorityHosts.AzureGovernment),
            "AzureChinaCloud" => (ArmEnvironment.AzureChina, AzureAuthorityHosts.AzureChina),
            _ => (ArmEnvironment.AzurePublicCloud, AzureAuthorityHosts.AzurePublicCloud),
        };
        TokenCredential credential;
        if (ctx.Flag("use_managed_identity"))
        {
            var clientId = ctx.Cred("client_id");
            credential = clientId != null
                ? new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(clientId))
                : new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned);
        }
        else
        {
            var tenant = ctx.Require("tenant_id", "Tenant ID", Name);
            var client = ctx.Require("client_id", "Client ID", Name);
            var secret = ctx.Require("client_secret", "Client Secret", Name);
            credential = new ClientSecretCredential(tenant, client, secret, new ClientSecretCredentialOptions { AuthorityHost = authority });
        }
        return new ArmClient(credential, subscription, new ArmClientOptions { Environment = env });
    }

    private static async Task<T> Call<T>(Func<Task<T>> f)
    {
        try { return await f(); }
        catch (Exception ex) when (ex is AuthenticationFailedException or RequestFailedException) { throw Translate(ex); }
    }

    private static Exception Translate(Exception ex)
    {
        if (ex is AuthenticationFailedException)
            return new DnsProviderException($"Azure DNS: authentication failed ({FirstLine(ex.Message)}). Check the tenant id, client id and secret (or that a managed identity is assigned to this machine).", ex);
        if (ex is RequestFailedException r)
        {
            var hint = r.Status switch
            {
                401 => " Check the service principal credentials.",
                403 => " Grant the identity the 'DNS Zone Contributor' role on the DNS zone or its resource group.",
                404 => " Check the subscription id, resource group and zone.",
                412 => " The record set changed while it was being updated; retry.",
                429 => " Azure is throttling requests; retry shortly.",
                _ => "",
            };
            return new DnsProviderException($"Azure DNS error {r.Status} {r.ErrorCode}: {FirstLine(r.Message)}.{hint}", ex);
        }
        return ex;
    }

    private static string FirstLine(string s) => s.Split('\n')[0].Trim();

    public override async Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx)
    {
        var arm = CreateClient(ctx);
        var sub = arm.GetSubscriptionResource(SubscriptionResource.CreateResourceIdentifier(ctx.Require("subscription_id", "Subscription ID", Name)));
        return await Call(async () =>
        {
            var zones = new List<DnsZone>();
            IAsyncEnumerable<DnsZoneResource> source = ctx.Param("resource_group") is { } rg
                ? (await sub.GetResourceGroupAsync(rg)).Value.GetDnsZones().GetAllAsync()
                : sub.GetDnsZonesAsync();
            await foreach (var z in source) zones.Add(new DnsZone(z.Id.ToString(), z.Data.Name));
            return zones;
        });
    }

    protected override async Task<DnsZone?> GetZoneByIdAsync(DnsProviderContext ctx, string zoneId)
    {
        if (!zoneId.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase)) return await base.GetZoneByIdAsync(ctx, zoneId);
        var arm = CreateClient(ctx);
        var zone = await Call(() => arm.GetDnsZoneResource(new ResourceIdentifier(zoneId)).GetAsync());
        return new DnsZone(zone.Value.Id.ToString(), zone.Value.Data.Name);
    }

    private static async Task<DnsTxtRecordResource?> GetSetAsync(DnsTxtRecordCollection coll, string rel)
    {
        try { return (await coll.GetAsync(rel)).Value; }
        catch (RequestFailedException ex) when (ex.Status == 404) { return null; }
    }

    private static DnsTxtRecordData BuildData(DnsTxtRecordResource? existing, IEnumerable<List<string>> records)
    {
        var data = new DnsTxtRecordData { TtlInSeconds = existing?.Data.TtlInSeconds ?? 60 };
        if (existing != null) foreach (var kv in existing.Data.Metadata) data.Metadata[kv.Key] = kv.Value;
        foreach (var r in records)
        {
            var info = new DnsTxtRecordInfo();
            foreach (var s in r) info.Values.Add(s);
            data.DnsTxtRecords.Add(info);
        }
        return data;
    }

    private static List<IReadOnlyList<string>> Current(DnsTxtRecordResource? set) =>
        set?.Data.DnsTxtRecords.Select(r => (IReadOnlyList<string>)r.Values.ToList()).ToList() ?? new List<IReadOnlyList<string>>();

    private static DnsTxtRecordCollection GetCollection(DnsProviderContext ctx, DnsZone zone)
    {
        var arm = CreateClient(ctx);
        return arm.GetDnsZoneResource(new ResourceIdentifier(zone.ZoneId)).GetDnsTxtRecords();
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var coll = GetCollection(ctx, zone);
        for (var attempt = 1; ; attempt++)
        {
            var existing = await Call(() => GetSetAsync(coll, rel));
            var current = Current(existing);
            if (current.Any(r => string.Concat(r) == value))
                return ActionResult.Ok($"TXT {rel} in {zone.Name} already has this value");
            var data = BuildData(existing, AddTxtValue(current, value));
            try
            {
                // ETag guards against overwriting a concurrent change; If-None-Match:* when creating the set.
                await coll.CreateOrUpdateAsync(WaitUntil.Completed, rel, data, existing?.Data.ETag, existing == null ? "*" : null);
                return ActionResult.Ok($"Added TXT value to {rel} in {zone.Name}");
            }
            catch (RequestFailedException ex) when (ex.Status == 412 && attempt < 4) { await Task.Delay(500 * attempt); }
            catch (Exception ex) when (ex is RequestFailedException or AuthenticationFailedException) { throw Translate(ex); }
        }
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        var zone = await RequireZoneAsync(ctx, recordName);
        var rel = RelativeName(recordName, zone.Name);
        var coll = GetCollection(ctx, zone);
        for (var attempt = 1; ; attempt++)
        {
            var existing = await Call(() => GetSetAsync(coll, rel));
            var current = Current(existing);
            if (existing == null || !current.Any(r => string.Concat(r) == value))
                return ActionResult.Ok($"TXT {rel} in {zone.Name} with this value was already absent");
            var remaining = RemoveTxtValue(current, value);
            try
            {
                if (remaining.Count == 0) await existing.DeleteAsync(WaitUntil.Completed, existing.Data.ETag);
                else await coll.CreateOrUpdateAsync(WaitUntil.Completed, rel, BuildData(existing, remaining), existing.Data.ETag);
                return ActionResult.Ok($"Removed TXT value from {rel} in {zone.Name}");
            }
            catch (RequestFailedException ex) when (ex.Status == 412 && attempt < 4) { await Task.Delay(500 * attempt); }
            catch (Exception ex) when (ex is RequestFailedException or AuthenticationFailedException) { throw Translate(ex); }
        }
    });
}
