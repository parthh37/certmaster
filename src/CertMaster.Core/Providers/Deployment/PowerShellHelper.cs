using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using CertMaster.Core.Util;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Runs the PowerShell helper scripts bundled under Scripts\Deploy.</summary>
public static partial class PowerShellHelper
{
    public static string ScriptsFolder => Path.Combine(AppContext.BaseDirectory, "Scripts", "Deploy");
    public static string GetScriptPath(string name) => Path.Combine(ScriptsFolder, name);

    /// <summary>Windows PowerShell by full System32 path on Windows (never resolved via the search path); pwsh elsewhere.</summary>
    public static string PowerShellExe => ProcessRunner.PowerShellExe;

    /// <summary>
    /// Runs a bundled script with named parameters. Values are passed as separate process arguments (never concatenated
    /// into a -Command string), and switches are only added when true. Secrets should be passed via <paramref name="env"/>.
    /// </summary>
    public static async Task<ProcessResult> RunBundledScriptAsync(string scriptName, IEnumerable<(string Name, string Value)> parameters,
        IEnumerable<string>? switches, IDictionary<string, string>? env, TimeSpan timeout, CancellationToken ct, IRemoteCommandRunner? runner = null)
    {
        var path = GetScriptPath(scriptName);
        if (!File.Exists(path)) throw new FileNotFoundException($"Helper script {scriptName} is missing from {ScriptsFolder}. Reinstall the agent.", path);
        var args = new List<string> { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path };
        foreach (var (name, value) in parameters)
        {
            if (value.StartsWith('-')) throw new ArgumentException($"Value for -{name} must not start with '-'");
            args.Add("-" + name);
            args.Add(value);
        }
        if (switches != null) args.AddRange(switches.Select(s => "-" + s));
        var spec = new CommandSpec(PowerShellExe) { Arguments = args, Environment = env, Timeout = timeout };
        return runner != null ? await runner.RunAsync(spec, ct) : await ProcessRunner.RunAsync(spec, ct);
    }

    /// <summary>Combines stdout/stderr into a single trimmed message for logs and results.</summary>
    public static string Summarize(ProcessResult r, int max = 2000)
    {
        var text = string.Join(" ", new[] { r.Output, r.Error }.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()));
        text = Regex.Replace(text, @"\s+", " ");
        return text.Length > max ? text[..max] + "…" : text;
    }

    [GeneratedRegex("^[0-9A-Fa-f]{40}$")]
    private static partial Regex ThumbprintRegex();

    public static bool IsThumbprint(string? value) => value != null && ThumbprintRegex().IsMatch(value);

    /// <summary>True when the certificate with this thumbprint is in LocalMachine\{storeName}.</summary>
    public static bool IsInMachineStore(string thumbprint, string storeName = "My")
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var store = new X509Store(storeName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        // Both the store snapshot and the Find result hold native certificate contexts; release them deterministically.
        var all = store.Certificates;
        X509Certificate2Collection? found = null;
        try
        {
            found = all.Find(X509FindType.FindByThumbprint, thumbprint, false);
            return found.Count > 0;
        }
        finally
        {
            if (found != null) foreach (var c in found) c.Dispose();
            foreach (var c in all) c.Dispose();
        }
    }
}
