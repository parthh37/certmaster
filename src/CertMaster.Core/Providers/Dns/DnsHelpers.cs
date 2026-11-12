using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace CertMaster.Core.Providers.Dns;

/// <summary>A provider error whose message is already user facing (says what failed and what to check).</summary>
public class DnsProviderException : Exception
{
    public DnsProviderException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Pure helpers for DNS names and zone matching.</summary>
public static class DnsNames
{
    /// <summary>Lower case, trimmed, no trailing dot.</summary>
    public static string Normalize(string? name) => (name ?? "").Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>True when <paramref name="recordName"/> equals <paramref name="zone"/> or is below it.</summary>
    public static bool IsInZone(string recordName, string zone)
    {
        var n = Normalize(recordName);
        var z = Normalize(zone);
        return z.Length > 0 && (n == z || n.EndsWith("." + z, StringComparison.Ordinal));
    }

    /// <summary>
    /// Candidate zone names for a record, longest first, e.g. "_acme-challenge.www.example.co.uk" gives
    /// "_acme-challenge.www.example.co.uk", "www.example.co.uk", "example.co.uk", "co.uk". Single labels (TLDs) are excluded.
    /// </summary>
    public static List<string> CandidateZones(string recordName, bool includeSelf = true)
    {
        var labels = Normalize(recordName).Split('.', StringSplitOptions.RemoveEmptyEntries);
        var result = new List<string>();
        for (var i = includeSelf ? 0 : 1; i < labels.Length - 1; i++)
            result.Add(string.Join('.', labels.Skip(i)));
        return result;
    }

    /// <summary>Longest-suffix match of a record name against a zone list. Returns null when no zone contains the record.</summary>
    public static DnsZone? FindBestZone(IEnumerable<DnsZone> zones, string recordName) =>
        zones.Where(z => IsInZone(recordName, z.Name))
             .OrderByDescending(z => Normalize(z.Name).Length)
             .FirstOrDefault();

    /// <summary>
    /// Longest-suffix match, honouring an explicit zone id (matched against the zone id or the zone name) when given.
    /// An explicit zone that does not contain the record yields null.
    /// </summary>
    public static DnsZone? FindBestZone(IEnumerable<DnsZone> zones, string recordName, string? explicitZoneId)
    {
        var list = zones as IReadOnlyCollection<DnsZone> ?? zones.ToList();
        if (string.IsNullOrWhiteSpace(explicitZoneId)) return FindBestZone(list, recordName);
        var z = FindZoneById(list, explicitZoneId);
        return z != null && IsInZone(recordName, z.Name) ? z : null;
    }

    /// <summary>Zone whose id (case-insensitive) or name equals <paramref name="zoneIdOrName"/>.</summary>
    public static DnsZone? FindZoneById(IEnumerable<DnsZone> zones, string zoneIdOrName)
    {
        var list = zones as IReadOnlyCollection<DnsZone> ?? zones.ToList();
        var id = zoneIdOrName.Trim();
        return list.FirstOrDefault(z => string.Equals(z.ZoneId, id, StringComparison.OrdinalIgnoreCase))
               ?? list.FirstOrDefault(z => Normalize(z.Name) == Normalize(id));
    }

    /// <summary>Record name relative to the zone ("@" or <paramref name="apex"/> for the zone apex).</summary>
    public static string RelativeName(string recordName, string zone, string apex = "@")
    {
        var n = recordName.Trim().TrimEnd('.');
        var z = zone.Trim().TrimEnd('.');
        if (n.Equals(z, StringComparison.OrdinalIgnoreCase)) return apex;
        if (!n.EndsWith("." + z, StringComparison.OrdinalIgnoreCase))
            throw new DnsProviderException($"Record {recordName} is not inside zone {zone}.");
        return n[..^(z.Length + 1)];
    }

    /// <summary>Second-level name and TLD of a zone, e.g. "example.co.uk" gives ("example", "co.uk").</summary>
    public static (string Sld, string Tld) SplitZone(string zone)
    {
        var z = Normalize(zone);
        var dot = z.IndexOf('.');
        if (dot <= 0) throw new DnsProviderException($"'{zone}' is not a registrable domain name.");
        return (z[..dot], z[(dot + 1)..]);
    }
}

/// <summary>Pure helpers for TXT values held as provider-specific strings (quoted or not).</summary>
public static class TxtValues
{
    /// <summary>
    /// Value of a TXT record as presentation text: surrounding quotes are removed and multiple quoted strings
    /// (<c>"abc" "def"</c>) are joined. Unquoted input is returned trimmed.
    /// </summary>
    public static string Unquote(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length < 2 || v[0] != '"') return v;
        var sb = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < v.Length; i++)
        {
            var c = v[i];
            if (c == '\\' && inQuotes && i + 1 < v.Length) { sb.Append(v[++i]); continue; }
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (inQuotes) sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Quoted TXT value, escaping quotes and backslashes.</summary>
    public static string Quote(string value) => "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    public static bool Matches(string? stored, string value) => Unquote(stored) == value;

    public static bool Contains(IEnumerable<string?> stored, string value) => stored.Any(s => Matches(s, value));

    /// <summary>The stored values plus <paramref name="value"/> (formatted by <paramref name="format"/>) unless it is already present. Existing values are kept as they are.</summary>
    public static List<string> Add(IEnumerable<string>? stored, string value, Func<string, string>? format = null)
    {
        var list = (stored ?? Enumerable.Empty<string>()).ToList();
        if (!Contains(list, value)) list.Add(format != null ? format(value) : value);
        return list;
    }

    /// <summary>The stored values without <paramref name="value"/> (all other values are kept as they are).</summary>
    public static List<string> Remove(IEnumerable<string>? stored, string value) =>
        (stored ?? Enumerable.Empty<string>()).Where(s => !Matches(s, value)).ToList();
}

/// <summary>Small HttpClient helpers shared by the REST providers.</summary>
public static class DnsHttp
{
    private static readonly JsonSerializerOptions ExactNames = new() { PropertyNamingPolicy = null };

    /// <summary>JSON body serialized with the property names exactly as given.</summary>
    public static StringContent Json(object body) => new(JsonSerializer.Serialize(body, ExactNames), Encoding.UTF8, "application/json");

    public static string Serialize(object body) => JsonSerializer.Serialize(body, ExactNames);

    /// <summary>Sends the request and returns the body; non-success responses throw a <see cref="DnsProviderException"/> with a hint.</summary>
    public static async Task<string> SendAsync(HttpClient http, HttpRequestMessage request, string provider, CancellationToken ct = default)
    {
        using (request)
        {
            if (!request.Headers.UserAgent.Any()) request.Headers.UserAgent.Add(new ProductInfoHeaderValue("CertMaster", "1.0"));
            using var resp = await http.SendAsync(request, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode) throw new DnsProviderException(Describe(provider, resp.StatusCode, body));
            return body;
        }
    }

    public static async Task<JsonElement> SendJsonAsync(HttpClient http, HttpRequestMessage request, string provider, CancellationToken ct = default) =>
        ParseJson(await SendAsync(http, request, provider, ct), provider);

    public static JsonElement ParseJson(string body, string provider)
    {
        if (string.IsNullOrWhiteSpace(body)) return default;
        try { return JsonDocument.Parse(body).RootElement.Clone(); }
        catch (JsonException) { throw new DnsProviderException($"{provider}: the API returned an unexpected (non-JSON) response: {Truncate(body, 300)}"); }
    }

    public static string Describe(string provider, HttpStatusCode code, string body)
    {
        var hint = (int)code switch
        {
            400 or 422 => " The request was rejected; check the record name, zone and parameter values.",
            401 => " Check that the API credentials are correct, complete and not expired.",
            403 => " The credentials are valid but not allowed to do this; check API token scopes/permissions, IP allow-lists and that the zone belongs to this account.",
            404 => " The zone or record was not found; check that the domain is managed by this account (or clear the explicit zone id).",
            409 => " The provider reported a conflict; the record may already exist or be changing. Retry the request.",
            429 => " The provider is rate limiting requests; wait a few minutes and retry.",
            >= 500 => " The provider API had an internal error; try again later.",
            _ => "",
        };
        return $"{provider} API error {(int)code} ({code}): {Truncate(body, 500)}.{hint}";
    }

    public static string Truncate(string? s, int max)
    {
        s = (s ?? "").Trim();
        return s.Length <= max ? s : s[..max] + "...";
    }

    /// <summary>Safe property access helpers for JsonElement trees.</summary>
    public static string? Str(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var p)
            ? p.ValueKind switch { JsonValueKind.String => p.GetString(), JsonValueKind.Number => p.GetRawText(), JsonValueKind.True => "true", JsonValueKind.False => "false", _ => null }
            : null;

    public static JsonElement Prop(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var p) ? p : default;

    public static IEnumerable<JsonElement> Items(this JsonElement e) =>
        e.ValueKind == JsonValueKind.Array ? e.EnumerateArray() : Enumerable.Empty<JsonElement>();
}
