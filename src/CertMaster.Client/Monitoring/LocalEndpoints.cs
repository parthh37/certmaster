using System.Text.Json;
using System.Text.Json.Nodes;

namespace CertMaster.Client.Monitoring;

/// <summary>
/// Works out the local agent and hub addresses from their appsettings files, the same way the services read them
/// (appsettings.json, then appsettings.Installer.json, then appsettings.Production.json; later files win).
/// </summary>
public static class LocalEndpoints
{
    public const string DefaultAgentUrl = AgentClient.DefaultUrl;
    public const string DefaultHubUrl = "http://localhost:9697";
    public static readonly string[] SettingsFiles = { "appsettings.json", "appsettings.Installer.json", "appsettings.Production.json" };

    private static readonly JsonDocumentOptions Lenient = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    /// <summary>The address to reach the agent at from this machine, from settings texts in load order (nulls are skipped).</summary>
    public static string AgentUrl(params string?[] settingsInLoadOrder)
    {
        var url = LastValue(settingsInLoadOrder, "Agent", "Url");
        return FirstUsable(url, preferHttps: false, localHost: "127.0.0.1") ?? DefaultAgentUrl;
    }

    /// <summary>
    /// The address to open the hub at from this machine. Kestrel endpoints win over Hub:Url (as in Kestrel itself), and an
    /// https endpoint is preferred.
    /// </summary>
    public static string HubUrl(params string?[] settingsInLoadOrder)
    {
        var kestrel = new List<string>();
        foreach (var text in settingsInLoadOrder)
        {
            if (Obj(Obj(Parse(text), "Kestrel"), "Endpoints") is { } endpoints)
            {
                kestrel.Clear();
                foreach (var (_, ep) in endpoints)
                    if (Str(ep, "Url") is { } u) kestrel.Add(u);
            }
        }
        if (FirstUsable(string.Join(';', kestrel), preferHttps: true, localHost: "localhost") is { } k) return k;
        return FirstUsable(LastValue(settingsInLoadOrder, "Hub", "Url"), preferHttps: true, localHost: "localhost") ?? DefaultHubUrl;
    }

    /// <summary>Reads the settings files next to a service executable, in load order. Missing or unreadable files are null.</summary>
    public static string?[] ReadSettings(string serviceDirectory) =>
        SettingsFiles.Select(f =>
        {
            try { return File.ReadAllText(Path.Combine(serviceDirectory, f)); }
            catch { return null; }
        }).ToArray();

    /// <summary>
    /// Picks one URL from a ';'-separated list and rewrites wildcard hosts (*, +, 0.0.0.0, [::]) to a host that works locally.
    /// </summary>
    public static string? FirstUsable(string? urls, bool preferHttps, string localHost)
    {
        if (string.IsNullOrWhiteSpace(urls)) return null;
        var list = urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(u => Normalize(u, localHost)).Where(u => u != null).Select(u => u!).ToList();
        if (list.Count == 0) return null;
        return (preferHttps ? list.FirstOrDefault(u => u.StartsWith("https:", StringComparison.OrdinalIgnoreCase)) : null)
               ?? list.FirstOrDefault(u => u.StartsWith("http:", StringComparison.OrdinalIgnoreCase))
               ?? list[0];
    }

    private static string? Normalize(string url, string localHost)
    {
        var schemeEnd = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd <= 0) return null;
        var scheme = url[..schemeEnd].ToLowerInvariant();
        if (scheme is not ("http" or "https")) return null;
        var rest = url[(schemeEnd + 3)..];
        var pathStart = rest.IndexOf('/');
        var authority = pathStart >= 0 ? rest[..pathStart] : rest;

        string host, port;
        if (authority.StartsWith('['))
        {
            var close = authority.IndexOf(']');
            if (close < 0) return null;
            host = authority[..(close + 1)];
            port = authority[(close + 1)..].TrimStart(':');
        }
        else
        {
            var colon = authority.LastIndexOf(':');
            host = colon >= 0 ? authority[..colon] : authority;
            port = colon >= 0 ? authority[(colon + 1)..] : "";
        }
        if (host is "*" or "+" or "0.0.0.0" or "[::]" or "") host = localHost;
        var result = scheme + "://" + host + (port.Length > 0 ? ":" + port : "");
        return Uri.TryCreate(result, UriKind.Absolute, out _) ? result : null;
    }

    private static string? LastValue(string?[] texts, string section, string key)
    {
        string? value = null;
        foreach (var text in texts)
            if (Str(Obj(Parse(text), section), key) is { } s) value = s;
        return value;
    }

    private static JsonObject? Obj(JsonNode? node, string name) => node is JsonObject o && o[name] is JsonObject child ? child : null;

    private static string? Str(JsonNode? node, string name) =>
        node is JsonObject o && o[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 ? s : null;

    private static JsonObject? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return JsonNode.Parse(text, documentOptions: Lenient) as JsonObject; }
        catch (JsonException) { return null; }
    }
}
