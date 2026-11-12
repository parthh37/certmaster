using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Finds a PowerShell executable: pwsh (PowerShell 7+) when installed, otherwise Windows PowerShell 5.1.</summary>
public static class PowerShellLocator
{
    private static readonly Lazy<string?> Cached = new(Locate);

    /// <summary>Full path of pwsh/powershell, or null when none is installed. CERTMASTER_POWERSHELL overrides the search.</summary>
    public static string? Find() => Cached.Value;

    private static string? Locate()
    {
        try
        {
            var overridePath = Environment.GetEnvironmentVariable("CERTMASTER_POWERSHELL");
            if (!string.IsNullOrWhiteSpace(overridePath) && File.Exists(overridePath)) return overridePath;

            var pwshName = OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh";
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(dir.Trim().Trim('"'), pwshName);
                    if (File.Exists(candidate)) return candidate;
                }
                catch { /* invalid PATH entry */ }
            }

            var known = new List<string>();
            if (OperatingSystem.IsWindows())
            {
                var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                known.Add(Path.Combine(pf, "PowerShell", "7", "pwsh.exe"));
                known.Add(Path.Combine(pf, "PowerShell", "7-preview", "pwsh.exe"));
                known.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"));
            }
            else
            {
                known.AddRange(new[] { "/usr/bin/pwsh", "/usr/local/bin/pwsh", "/opt/microsoft/powershell/7/pwsh", "/snap/bin/pwsh" });
            }
            return known.FirstOrDefault(File.Exists);
        }
        catch { return null; }
    }
}

/// <summary>Maps one provider field to the plugin parameter it feeds.</summary>
public sealed record PoshAcmeField(string Key, string ParameterName, string Kind, string? Part, string? DefaultValue);

/// <summary>
/// A DNS provider backed by one bundled Posh-ACME plugin. Runs Scripts/PoshAcme/Invoke-PoshAcmePlugin.ps1 with the
/// request (including secrets) in a short-lived JSON file that the wrapper deletes as soon as it has read it.
/// </summary>
public class PoshAcmeDnsProvider : DnsProviderBase
{
    public const string IdPrefix = "DNS01.PoshAcme.";
    public const string CredentialTypePrefix = "PoshAcme.";

    private readonly string _scriptsRoot;
    private readonly List<PoshAcmeField> _fields;

    public PoshAcmeDnsProvider(PoshAcmePluginInfo plugin, string scriptsRoot, string? moduleVersion = null, bool bouncyCastleAvailable = false)
    {
        Plugin = plugin;
        _scriptsRoot = scriptsRoot;
        (Definition, _fields) = BuildDefinition(plugin, moduleVersion, bouncyCastleAvailable);
    }

    public PoshAcmePluginInfo Plugin { get; }
    public override ChallengeProviderDefinition Definition { get; }
    public IReadOnlyList<PoshAcmeField> Fields => _fields;

    private static readonly Regex SecretName = new("token|key|secret|pass", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex PathLike = new("(file|path|url|uri)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>Builds the provider definition (form fields) from a parsed plugin.</summary>
    public static (ChallengeProviderDefinition Definition, List<PoshAcmeField> Fields) BuildDefinition(PoshAcmePluginInfo plugin, string? moduleVersion, bool bouncyCastleAvailable)
    {
        var activeSets = plugin.ActiveParameterSets;
        var parameters = new List<ProviderParameter>();
        var fields = new List<PoshAcmeField>();

        foreach (var p in PoshAcmePluginParser.UserParameters(plugin))
        {
            var sets = p.SetNames.Where(s => !PoshAcmePluginInfo.IsDeprecatedSet(s)).ToList();
            var mandatoryActive = p.Usages.Any(u => u.Mandatory && !PoshAcmePluginInfo.IsDeprecatedSet(u.SetName));
            var required = p.MandatoryInAllSets || (activeSets.Count <= 1 && mandatoryActive);
            var setNote = !p.InAllSets && activeSets.Count > 1 && sets.Count > 0
                ? $" Used with: {string.Join(", ", sets)}{(mandatoryActive ? " (required there)" : "")}."
                : "";
            var help = (p.Help ?? "").Trim();
            var isSecretType = p.Type is "securestring" or "pscredential";
            var isFlag = p.Type is "switch" or "bool";
            var credential = isSecretType || (!isFlag && SecretName.IsMatch(p.Name));
            var password = isSecretType || (credential && !PathLike.IsMatch(p.Name));

            if (p.Type == "pscredential")
            {
                parameters.Add(new ProviderParameter { Key = p.Name + "_User", Name = p.Name + " (username)", Description = (help + setNote).Trim(), IsRequired = required, IsCredential = true });
                parameters.Add(new ProviderParameter { Key = p.Name + "_Password", Name = p.Name + " (password)", Type = OptionType.Password, IsRequired = required, IsCredential = true });
                fields.Add(new PoshAcmeField(p.Name + "_User", p.Name, "pscredential", "User", null));
                fields.Add(new PoshAcmeField(p.Name + "_Password", p.Name, "pscredential", "Password", null));
                continue;
            }

            var pp = new ProviderParameter { Key = p.Name, Name = p.Name, IsRequired = required, IsCredential = credential };
            string kind;
            switch (p.Type)
            {
                case "securestring": kind = "securestring"; pp.Type = OptionType.Password; break;
                case "switch": kind = "switch"; pp.Type = OptionType.Boolean; pp.IsRequired = false; break;
                case "bool": kind = "bool"; pp.Type = OptionType.Boolean; break;
                case "int": kind = "int"; pp.Type = OptionType.Number; break;
                case "double": kind = "double"; pp.Type = OptionType.Number; break;
                case "hashtable": kind = "hashtable"; pp.Type = OptionType.MultiLineText; help += " JSON object, e.g. {\"name\":\"value\"}."; break;
                case "string[]": kind = "stringarray"; help += " Comma-separated list."; break;
                default: kind = "string"; if (password) pp.Type = OptionType.Password; break;
            }
            if (p.ValidateSet.Count > 0 && kind == "string" && !credential)
            {
                pp.Type = OptionType.Select;
                pp.OptionsList = string.Join(";", p.ValidateSet.Select(v => $"{v}={v}"));
            }
            if (p.DefaultValue != null && !credential) pp.Value = p.DefaultValue;
            pp.Description = (help + setNote).Trim() is { Length: > 0 } d ? d : null;
            parameters.Add(pp);
            fields.Add(new PoshAcmeField(p.Name, p.Name, kind, null, p.DefaultValue));
        }

        var bcMissing = plugin.RequiresBouncyCastle && !bouncyCastleAvailable;
        var desc = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(plugin.Synopsis)) desc.Append(plugin.Synopsis!.Trim().TrimEnd('.')).Append(". ");
        desc.Append($"Runs the bundled Posh-ACME{(moduleVersion != null ? " " + moduleVersion : "")} '{plugin.Name}' plugin in PowerShell.");
        if (activeSets.Count > 1) desc.Append($" Supports several authentication methods ({string.Join(", ", activeSets)}): fill in the fields for one of them.");
        if (bcMissing) desc.Append(" Requires the BouncyCastle library from the Posh-ACME release (lib folder), which is not bundled.");

        var def = new ChallengeProviderDefinition
        {
            Id = IdPrefix + plugin.Name,
            Title = $"{plugin.Name} (via Posh-ACME)",
            Description = desc.ToString(),
            HelpUrl = $"https://poshac.me/docs/latest/Plugins/{plugin.Name}/",
            ChallengeType = ChallengeTypes.Dns01,
            PropagationDelaySeconds = 120,
            IsExperimental = bcMissing,
            CredentialType = parameters.Any(x => x.IsCredential) ? CredentialTypePrefix + plugin.Name : null,
            ProviderParameters = parameters,
        };
        return (def, fields);
    }

    /// <summary>
    /// Plugin arguments for the wrapper, keyed by plugin parameter name: {"Type": kind, "Value": ...} (pscredential: "User"/"Password").
    /// Blank values, switches that are off and values equal to the plugin's own default are left out so PowerShell can pick the parameter set.
    /// </summary>
    public static Dictionary<string, Dictionary<string, object?>> BuildArguments(IEnumerable<PoshAcmeField> fields, Func<string, string?> lookup)
    {
        var args = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in fields.GroupBy(f => f.ParameterName, StringComparer.OrdinalIgnoreCase))
        {
            var first = group.First();
            if (first.Kind == "pscredential")
            {
                var user = lookup(group.First(f => f.Part == "User").Key);
                var pass = lookup(group.First(f => f.Part == "Password").Key);
                if (string.IsNullOrEmpty(user) && string.IsNullOrEmpty(pass)) continue;
                if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(pass))
                    throw new DnsProviderException($"Posh-ACME: {first.ParameterName} needs both a username and a password.");
                args[first.ParameterName] = new() { ["Type"] = "pscredential", ["User"] = user, ["Password"] = pass };
                continue;
            }

            var raw = lookup(first.Key);
            if (string.IsNullOrWhiteSpace(raw)) continue;
            if (first.DefaultValue != null && string.Equals(raw.Trim(), first.DefaultValue, StringComparison.OrdinalIgnoreCase)) continue;
            object? value;
            switch (first.Kind)
            {
                case "switch":
                case "bool":
                    var b = raw.Trim().ToLowerInvariant() is "true" or "1" or "yes" or "on" or "y";
                    if (first.Kind == "switch" && !b) continue;
                    value = b;
                    break;
                case "int":
                    value = long.TryParse(raw.Trim(), out var l) ? l : throw new DnsProviderException($"Posh-ACME: {first.ParameterName} must be a whole number.");
                    break;
                case "double":
                    value = double.TryParse(raw.Trim(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) ? d
                        : throw new DnsProviderException($"Posh-ACME: {first.ParameterName} must be a number.");
                    break;
                case "stringarray":
                    value = raw.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    break;
                case "hashtable":
                    try
                    {
                        var el = JsonDocument.Parse(raw).RootElement.Clone();
                        if (el.ValueKind != JsonValueKind.Object) throw new JsonException();
                        value = el;
                    }
                    catch (JsonException) { throw new DnsProviderException($"Posh-ACME: {first.ParameterName} must be a JSON object, e.g. {{\"name\":\"value\"}}."); }
                    break;
                default:
                    value = raw;
                    break;
            }
            args[first.ParameterName] = new() { ["Type"] = first.Kind, ["Value"] = value };
        }
        return args;
    }

    private string? Lookup(DnsProviderContext ctx, string key)
    {
        var def = Definition.ProviderParameters.FirstOrDefault(p => p.Key == key);
        return def?.IsCredential == true ? ctx.Cred(key) ?? ctx.Param(key) : ctx.Param(key) ?? ctx.Cred(key);
    }

    private List<string> MissingRequired(DnsProviderContext ctx) =>
        Definition.ProviderParameters.Where(p => p.IsRequired && string.IsNullOrWhiteSpace(Lookup(ctx, p.Key))).Select(p => p.Name).ToList();

    private async Task<string> RunAsync(DnsProviderContext ctx, string action, string recordName, string value)
    {
        var ps = PowerShellLocator.Find()
                 ?? throw new DnsProviderException("Posh-ACME: PowerShell was not found. Install PowerShell 7 (pwsh) or enable Windows PowerShell 5.1.");
        var wrapper = Path.Combine(_scriptsRoot, "Invoke-PoshAcmePlugin.ps1");
        if (!File.Exists(wrapper)) throw new DnsProviderException($"Posh-ACME: bridge script not found at {wrapper}. Reinstall the agent.");
        var missing = MissingRequired(ctx);
        if (missing.Count > 0) throw new DnsProviderException($"{Definition.Title}: required field(s) not set: {string.Join(", ", missing)}.");

        var args = BuildArguments(_fields, k => Lookup(ctx, k));
        var home = ctx.Paths.Combine("poshacme");
        var requests = Path.Combine(home, "requests");
        Directory.CreateDirectory(requests);
        var file = Path.Combine(requests, Guid.NewGuid().ToString("N") + ".json");
        var payload = new Dictionary<string, object?>
        {
            ["Action"] = action,
            ["Plugin"] = Plugin.Name,
            ["RecordName"] = DnsNames.Normalize(recordName),
            ["TxtValue"] = value,
            ["PoshAcmeHome"] = home,
            ["Verbose"] = true,
            ["Args"] = args,
        };
        var secrets = Definition.ProviderParameters.Where(p => p.IsCredential).Select(p => Lookup(ctx, p.Key)).Where(v => v is { Length: >= 4 }).Cast<string>().ToList();
        try
        {
            await File.WriteAllTextAsync(file, JsonSerializer.Serialize(payload), new UTF8Encoding(false));
            var env = new Dictionary<string, string> { ["POSHACME_PLUGINS"] = "" };
            var r = await ProcessRunner.RunAsync(ps, new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper, "-ParamFile", file }, env, TimeSpan.FromMinutes(10));
            var output = Mask(r.Output, secrets);
            foreach (var line in output.Split('\n').Select(l => l.TrimEnd()).Where(l => l.Length > 0 && !l.StartsWith("POSHACME-RESULT", StringComparison.Ordinal)).Take(60))
                ctx.Log?.Info($"[Posh-ACME {Plugin.Name}] {line}");
            if (r.ExitCode != 0)
            {
                var err = Mask(string.IsNullOrWhiteSpace(r.Error) ? output : r.Error, secrets).Trim();
                var hint = r.ExitCode == 3 ? " The bundled Posh-ACME module could not be loaded." : "";
                throw new DnsProviderException($"{Definition.Title} {action} failed (exit {r.ExitCode}): {DnsHttp.Truncate(err, 800)}{hint}");
            }
            return output;
        }
        finally
        {
            try { if (File.Exists(file)) File.Delete(file); } catch { /* wrapper normally deletes it first */ }
        }
    }

    private static string Mask(string text, List<string> secrets)
    {
        foreach (var s in secrets) text = text.Replace(s, "********");
        return text;
    }

    public override async Task<ActionResult> TestAsync(DnsProviderContext ctx)
    {
        try
        {
            await RunAsync(ctx, "Test", "_acme-challenge.example.com", "test");
            return ActionResult.Ok($"PowerShell and the Posh-ACME '{Plugin.Name}' plugin loaded. Credentials are only verified when a record is created.");
        }
        catch (Exception ex) { return ActionResult.Fail(DescribeError(ex)); }
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        await RunAsync(ctx, "Add", recordName, value);
        return ActionResult.Ok($"Posh-ACME {Plugin.Name}: added TXT {recordName}");
    });

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) => Guard(async () =>
    {
        await RunAsync(ctx, "Remove", recordName, value);
        return ActionResult.Ok($"Posh-ACME {Plugin.Name}: removed TXT {recordName}");
    });
}

/// <summary>
/// Contributes one DNS provider per bundled Posh-ACME plugin (Scripts/PoshAcme/Posh-ACME/Plugins/*.ps1). Returns no
/// providers when the folder or PowerShell is missing; never throws.
/// </summary>
public class PoshAcmeProviderSource : IDnsProviderSource
{
    /// <summary>Plugins with a native CertMaster provider; skipped unless <see cref="IncludeNativelyCovered"/> is set.</summary>
    public static readonly HashSet<string> NativelyCoveredPlugins = new(StringComparer.OrdinalIgnoreCase)
    {
        "AcmeDns", "Aliyun", "Azure", "Cloudflare", "DMEasy", "DOcean", "GoDaddy", "Hetzner", "HetznerCloud", "IONOS",
        "Linode", "Namecheap", "OVH", "Route53", "SimpleDNSPlus", "TransIP", "Windows",
    };

    /// <summary>Plugins that cannot run unattended.</summary>
    public static readonly HashSet<string> UnsupportedPlugins = new(StringComparer.OrdinalIgnoreCase) { "Manual" };

    private static readonly ConcurrentDictionary<string, IReadOnlyList<PoshAcmePluginInfo>> Cache = new(StringComparer.OrdinalIgnoreCase);

    private readonly string _root;
    private readonly bool _requirePowerShell;

    public PoshAcmeProviderSource() : this(DefaultRoot) { }

    public PoshAcmeProviderSource(string scriptsRoot, bool requirePowerShell = true, bool includeNativelyCovered = false)
    {
        _root = scriptsRoot;
        _requirePowerShell = requirePowerShell;
        IncludeNativelyCovered = includeNativelyCovered;
    }

    public bool IncludeNativelyCovered { get; set; }

    /// <summary>AppContext.BaseDirectory/Scripts/PoshAcme.</summary>
    public static string DefaultRoot => Path.Combine(AppContext.BaseDirectory, "Scripts", "PoshAcme");

    public static string ModuleDir(string root) => Path.Combine(root, "Posh-ACME");

    public IEnumerable<IDnsProvider> GetProviders()
    {
        try
        {
            if (!Directory.Exists(Path.Combine(ModuleDir(_root), "Plugins")) || !File.Exists(Path.Combine(_root, "Invoke-PoshAcmePlugin.ps1")))
                return Array.Empty<IDnsProvider>();
            if (_requirePowerShell && PowerShellLocator.Find() == null) return Array.Empty<IDnsProvider>();
            var version = ReadModuleVersion(_root);
            var bc = BouncyCastleAvailable(_root);
            return LoadPlugins(_root)
                .Where(p => IncludeNativelyCovered || !NativelyCoveredPlugins.Contains(p.Name))
                .Select(p => (IDnsProvider)new PoshAcmeDnsProvider(p, _root, version, bc))
                .ToList();
        }
        catch
        {
            return Array.Empty<IDnsProvider>();
        }
    }

    /// <summary>Parsed dns-01 plugins (cached per folder). Plugins that fail to parse are skipped.</summary>
    public static IReadOnlyList<PoshAcmePluginInfo> LoadPlugins(string scriptsRoot) => Cache.GetOrAdd(Path.GetFullPath(scriptsRoot), root =>
    {
        var list = new List<PoshAcmePluginInfo>();
        var dir = Path.Combine(ModuleDir(root), "Plugins");
        if (!Directory.Exists(dir)) return list;
        foreach (var file in Directory.GetFiles(dir, "*.ps1").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            var name = Path.GetFileNameWithoutExtension(file);
            if (name.StartsWith('_') || UnsupportedPlugins.Contains(name)) continue;
            try
            {
                var info = PoshAcmePluginParser.Parse(name, File.ReadAllText(file));
                if (info is { ChallengeType: "dns-01", HasRemoveDnsTxt: true }) list.Add(info);
            }
            catch { /* skip unparseable plugin */ }
        }
        return list;
    });

    /// <summary>ModuleVersion from Posh-ACME.psd1, or null.</summary>
    public static string? ReadModuleVersion(string scriptsRoot)
    {
        try
        {
            var psd1 = Path.Combine(ModuleDir(scriptsRoot), "Posh-ACME.psd1");
            if (!File.Exists(psd1)) return null;
            var m = Regex.Match(File.ReadAllText(psd1), @"ModuleVersion\s*=\s*['""]([^'""]+)['""]");
            return m.Success ? m.Groups[1].Value : null;
        }
        catch { return null; }
    }

    private static bool BouncyCastleAvailable(string root)
    {
        var lib = Path.Combine(ModuleDir(root), "lib");
        return Directory.Exists(lib) && Directory.GetFiles(lib, "*.dll").Length > 0;
    }
}
