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
}

/// <summary>A dns-01 challenge provider: creates and deletes the _acme-challenge TXT record.</summary>
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
                ? ActionResult.Ok($"Connected. {zones.Count} zone(s) available: {string.Join(", ", zones.Take(10).Select(z => z.Name))}")
                : ActionResult.Fail("Connected, but no DNS zones were returned for these credentials.");
        }
        catch (Exception ex) { return ActionResult.Fail($"Provider test failed: {ex.Message}"); }
    }

    /// <summary>Find the zone that best matches (longest suffix) a record name.</summary>
    protected async Task<DnsZone?> ResolveZoneAsync(DnsProviderContext ctx, string recordName)
    {
        var zones = await GetZonesAsync(ctx);
        if (!string.IsNullOrEmpty(ctx.ZoneId))
        {
            var byId = zones.FirstOrDefault(z => z.ZoneId == ctx.ZoneId);
            if (byId != null) return byId;
        }
        var name = recordName.TrimEnd('.').ToLowerInvariant();
        return zones
            .Where(z => name == z.Name.ToLowerInvariant() || name.EndsWith("." + z.Name.ToLowerInvariant()))
            .OrderByDescending(z => z.Name.Length)
            .FirstOrDefault();
    }

    /// <summary>Record name relative to the zone, e.g. "_acme-challenge.www" for zone example.com.</summary>
    protected static string RelativeName(string recordName, string zone)
    {
        var name = recordName.TrimEnd('.');
        if (name.Equals(zone, StringComparison.OrdinalIgnoreCase)) return "@";
        return name[..^(zone.Length + 1)];
    }
}
