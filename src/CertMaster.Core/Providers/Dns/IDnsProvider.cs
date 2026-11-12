using System.Runtime.CompilerServices;
using CertMaster.Core.Storage;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

public record DnsZone(string ZoneId, string Name);

public class DnsProviderContext
{
    public required Dictionary<string, string> Credentials { get; init; }
    public required Dictionary<string, string> Parameters { get; init; }
    public required HttpClient Http { get; init; }
    public required DataPaths Paths { get; init; }
    public ItemLog? Log { get; init; }
    /// <summary>Optional explicit zone id from the challenge config.</summary>
    public string? ZoneId { get; init; }

    public string? Cred(string key) => Credentials.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;
    public string? Param(string key) => Parameters.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;

    /// <summary>Credential value, falling back to a parameter with the same key.</summary>
    public string? CredOrParam(string key) => Cred(key) ?? Param(key);

    /// <summary>Boolean parameter ("true", "1", "yes", "on"); <paramref name="fallback"/> when blank.</summary>
    public bool Flag(string key, bool fallback = false)
    {
        var v = CredOrParam(key);
        if (v == null) return fallback;
        return v.Trim().ToLowerInvariant() is "true" or "1" or "yes" or "on" or "y";
    }

    /// <summary>Integer parameter; <paramref name="fallback"/> when blank or not a number.</summary>
    public int Int(string key, int fallback) => int.TryParse(CredOrParam(key), out var v) ? v : fallback;

    /// <summary>A required credential (or parameter) value, with an actionable error when it is missing.</summary>
    public string Require(string key, string displayName, string provider) =>
        CredOrParam(key) ?? throw new DnsProviderException($"{provider}: '{displayName}' is not set. Edit the stored credential / challenge settings and provide it.");
}

/// <summary>A dns-01 challenge provider: creates and deletes the _acme-challenge TXT record.</summary>
/// <remarks>
/// Apex and wildcard identifiers of the same name share one record name with two different values, so
/// <see cref="CreateRecordAsync"/> must ADD a value (never replace the existing set) and
/// <see cref="DeleteRecordAsync"/> must remove only the given value.
/// </remarks>
public interface IDnsProvider
{
    ChallengeProviderDefinition Definition { get; }
    Task<ActionResult> TestAsync(DnsProviderContext ctx);
    Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value);
    Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value);
    Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx);
}

public abstract class DnsProviderBase : IDnsProvider
{
    private sealed class ZoneCache
    {
        public List<DnsZone>? Zones;
        public DateTimeOffset Loaded;
    }

    // Zone lists are cached per context (one context is used for create + delete of a record).
    private static readonly ConditionalWeakTable<DnsProviderContext, ZoneCache> ZoneCaches = new();

    public abstract ChallengeProviderDefinition Definition { get; }
    public abstract Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value);
    public abstract Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value);
    public virtual Task<List<DnsZone>> GetZonesAsync(DnsProviderContext ctx) => Task.FromResult(new List<DnsZone>());

    public virtual async Task<ActionResult> TestAsync(DnsProviderContext ctx)
    {
        try
        {
            var zones = await GetZonesAsync(ctx);
            return zones.Count > 0
                ? ActionResult.Ok($"Connected. {zones.Count} zone(s) available: {string.Join(", ", zones.Take(10).Select(z => z.Name))}{(zones.Count > 10 ? ", ..." : "")}")
                : ActionResult.Fail("Connected, but no DNS zones were returned for these credentials. Check the account/permissions the credentials belong to.");
        }
        catch (Exception ex) { return ActionResult.Fail(DescribeError(ex)); }
    }

    /// <summary>Zone list for this context, cached for a few minutes so create + delete do not re-list every zone.</summary>
    protected async Task<List<DnsZone>> GetZonesCachedAsync(DnsProviderContext ctx)
    {
        var cache = ZoneCaches.GetOrCreateValue(ctx);
        if (cache.Zones != null && DateTimeOffset.UtcNow - cache.Loaded < TimeSpan.FromMinutes(10)) return cache.Zones;
        cache.Zones = await GetZonesAsync(ctx);
        cache.Loaded = DateTimeOffset.UtcNow;
        return cache.Zones;
    }

    /// <summary>
    /// Look up a zone by the explicit zone id from the challenge config. The default implementation matches the id
    /// (or zone name) against <see cref="GetZonesAsync"/>; providers that can fetch a zone directly override this.
    /// </summary>
    protected virtual async Task<DnsZone?> GetZoneByIdAsync(DnsProviderContext ctx, string zoneId) =>
        DnsNames.FindZoneById(await GetZonesCachedAsync(ctx), zoneId);

    /// <summary>
    /// Find the zone that best matches (longest suffix) a record name. When the challenge config has an explicit
    /// zone id it is used (and must contain the record). Returns null when nothing matches.
    /// </summary>
    protected virtual async Task<DnsZone?> ResolveZoneAsync(DnsProviderContext ctx, string recordName)
    {
        if (!string.IsNullOrWhiteSpace(ctx.ZoneId))
        {
            var byId = await GetZoneByIdAsync(ctx, ctx.ZoneId.Trim());
            if (byId == null) return null;
            if (!DnsNames.IsInZone(recordName, byId.Name))
                throw new DnsProviderException($"{Definition.Title}: the configured zone id '{ctx.ZoneId}' is zone '{byId.Name}', which does not contain {recordName}. Clear the zone id to auto-detect, or pick the correct zone.");
            return byId;
        }
        return DnsNames.FindBestZone(await GetZonesCachedAsync(ctx), recordName);
    }

    /// <summary>Like <see cref="ResolveZoneAsync"/> but throws an actionable error when no zone matches.</summary>
    protected async Task<DnsZone> RequireZoneAsync(DnsProviderContext ctx, string recordName)
    {
        var zone = await ResolveZoneAsync(ctx, recordName);
        if (zone != null) return zone;
        if (!string.IsNullOrWhiteSpace(ctx.ZoneId))
            throw new DnsProviderException($"{Definition.Title}: zone id '{ctx.ZoneId}' was not found for these credentials. Check the zone id, or clear it to auto-detect the zone.");
        throw new DnsProviderException($"{Definition.Title}: no DNS zone managed by these credentials matches {recordName}. Check that the domain is hosted at this provider and the credentials have access to it (or use a CNAME delegation rule).");
    }

    /// <summary>Record name relative to the zone, e.g. "_acme-challenge.www" for zone example.com ("@" for the apex).</summary>
    protected static string RelativeName(string recordName, string zone) => DnsNames.RelativeName(recordName, zone);

    /// <summary>Runs a provider operation, converting exceptions into a failed <see cref="ActionResult"/> with an actionable message.</summary>
    protected async Task<ActionResult> Guard(Func<Task<ActionResult>> operation)
    {
        try { return await operation(); }
        catch (Exception ex) { return ActionResult.Fail(DescribeError(ex)); }
    }

    protected string DescribeError(Exception ex) => ex switch
    {
        DnsProviderException => ex.Message,
        HttpRequestException h => $"{Definition.Title}: could not reach the provider API ({h.Message}). Check network connectivity, proxy and firewall settings.",
        TaskCanceledException => $"{Definition.Title}: the provider API did not respond in time. Try again later.",
        _ => $"{Definition.Title}: {ex.Message}",
    };
}
