using System.Management;
using System.Net;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>
/// Base for Windows role deployments done by a bundled PowerShell helper script against the certificate already stored in
/// LocalMachine\My (looked up by thumbprint).
/// </summary>
public abstract class PowerShellRoleTaskBase : DeploymentTaskProviderBase
{
    protected abstract string ScriptName { get; }
    /// <summary>What the script does, for preview/log messages.</summary>
    protected abstract string Describe(DeploymentContext ctx);
    protected virtual bool RequiresCertificateInStore => true;
    protected virtual TimeSpan Timeout => TimeSpan.FromMinutes(5);

    /// <summary>Extra named parameters for the script (thumbprint is always passed as -Thumbprint).</summary>
    protected virtual IEnumerable<(string Name, string Value)> GetParameters(DeploymentContext ctx) => Array.Empty<(string, string)>();
    protected virtual IEnumerable<string> GetSwitches(DeploymentContext ctx) => Array.Empty<string>();
    protected virtual IDictionary<string, string>? GetEnvironment(DeploymentContext ctx) => null;

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (!OperatingSystem.IsWindows()) errors.Add(Error($"{Definition.Title} is only available on Windows."));
        if (ctx.Item.CertificateThumbprintHash is { } t && !PowerShellHelper.IsThumbprint(t)) errors.Add(Error($"Invalid certificate thumbprint '{t}'"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var thumbprint = ctx.Item.CertificateThumbprintHash;
        if (ctx.IsPreviewOnly) return Preview(ctx, Describe(ctx) + (thumbprint != null ? $" using certificate {thumbprint}" : " (no certificate issued yet)"));
        if (!OperatingSystem.IsWindows()) return Fail(ctx, $"{Definition.Title} is only available on Windows.");
        if (thumbprint == null || !PowerShellHelper.IsThumbprint(thumbprint)) return Fail(ctx, "No certificate has been issued yet (thumbprint unknown). Request the certificate first.");
        if (RequiresCertificateInStore && !PowerShellHelper.IsInMachineStore(thumbprint))
            return Fail(ctx, $"Certificate {thumbprint} is not in the LocalMachine\\My store. Add a 'Deploy to Certificate Store (Local Machine)' task before this one.");

        return await Guard(ctx, Definition.Title, async () =>
        {
            ctx.Log.Info(Describe(ctx) + $" using certificate {thumbprint}");
            var r = await PowerShellHelper.RunBundledScriptAsync(ScriptName, new[] { ("Thumbprint", thumbprint) }.Concat(GetParameters(ctx)),
                GetSwitches(ctx), GetEnvironment(ctx), Timeout, ct);
            if (!string.IsNullOrWhiteSpace(r.Output)) ctx.Log.Info(r.Output.Trim());
            return r.ExitCode == 0
                ? Ok(ctx, $"{Definition.Title}: completed for certificate {thumbprint}")
                : Fail(ctx, $"{Definition.Title} failed (exit code {r.ExitCode}): {PowerShellHelper.Summarize(r)}");
        }, ct);
    }

    protected static ProviderParameter RestartParam(string key, string name, bool defaultValue) =>
        new() { Key = key, Name = name, Type = OptionType.Boolean, Value = defaultValue ? "true" : "false" };
}

/// <summary>Active Directory Federation Services: SSL and service-communications certificate.</summary>
public class AdfsDeploymentTask : PowerShellRoleTaskBase
{
    protected override string ScriptName => "Deploy-Adfs.ps1";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.ADFS",
        Title = "Deploy to ADFS",
        DefaultTitle = "Deploy to ADFS",
        Description = "Set the certificate as the AD FS SSL certificate (Set-AdfsSslCertificate) and service-communications certificate (Set-AdfsCertificate) on this AD FS server, optionally restarting the AD FS service.",
        UsageNote = "Run on the primary AD FS server. The AD FS service account needs read access to the private key (see 'Set Certificate Key Permissions').",
        ProviderParameters =
        {
            RestartParam("servicecomms", "Also set the service-communications certificate", true),
            RestartParam("restart", "Restart the AD FS service (adfssrv)", true),
        }
    };

    protected override string Describe(DeploymentContext ctx) =>
        "Set the AD FS SSL certificate" + (ctx.ParamBool("servicecomms", true) ? " and service-communications certificate" : "") + (ctx.ParamBool("restart", true) ? ", then restart adfssrv" : "");

    protected override IEnumerable<string> GetSwitches(DeploymentContext ctx)
    {
        if (ctx.ParamBool("servicecomms", true)) yield return "ServiceCommunications";
        if (ctx.ParamBool("restart", true)) yield return "RestartService";
    }
}

/// <summary>Microsoft Exchange 2013 and later.</summary>
public partial class ExchangeDeploymentTask : PowerShellRoleTaskBase
{
    public static readonly string[] KnownServices = { "IIS", "SMTP", "POP", "IMAP", "UM", "UMCallRouter", "Federation", "None" };

    protected override string ScriptName => "Deploy-Exchange.ps1";
    protected override bool RequiresCertificateInStore => false; // the script imports the PFX itself
    protected override TimeSpan Timeout => TimeSpan.FromMinutes(10);

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Exchange",
        Title = "Deploy to Microsoft Exchange (2013+)",
        DefaultTitle = "Deploy to Exchange",
        Description = "Import the certificate into Exchange (Import-ExchangeCertificate) and enable it for the selected services (Enable-ExchangeCertificate) using the Exchange Management Shell on this server.",
        UsageNote = "Requires the Exchange management tools on this server and an agent service account with Exchange Organization Management rights.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "services", Name = "Services", Value = "POP,IMAP,SMTP,IIS", Description = "Comma separated: IIS, SMTP, POP, IMAP, UM, UMCallRouter, Federation" },
            RestartParam("donotrequiressl", "Do not require SSL (DoNotRequireSsl)", false),
        }
    };

    private static List<string> Services(DeploymentContext ctx) =>
        (ctx.Param("services") ?? "POP,IMAP,SMTP,IIS").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        base.ValidateTask(ctx, errors);
        var services = Services(ctx);
        if (services.Count == 0) errors.Add(Error("Select at least one Exchange service"));
        foreach (var s in services.Where(s => !KnownServices.Contains(s, StringComparer.OrdinalIgnoreCase)))
            errors.Add(Error($"Unknown Exchange service '{s}'. Valid: {string.Join(", ", KnownServices)}"));
    }

    protected override string Describe(DeploymentContext ctx) =>
        $"Import the certificate into Exchange and enable it for {string.Join(",", Services(ctx))}" + (ctx.ParamBool("donotrequiressl") ? " (DoNotRequireSsl)" : "");

    protected override IEnumerable<(string Name, string Value)> GetParameters(DeploymentContext ctx)
    {
        yield return ("PfxPath", ctx.Files.Pfx);
        yield return ("Services", string.Join(",", Services(ctx).Select(s => KnownServices.First(k => k.Equals(s, StringComparison.OrdinalIgnoreCase)))));
    }

    protected override IEnumerable<string> GetSwitches(DeploymentContext ctx)
    {
        if (ctx.ParamBool("donotrequiressl")) yield return "DoNotRequireSsl";
    }

    // the PFX password is passed in the environment so it never appears on a command line
    protected override IDictionary<string, string>? GetEnvironment(DeploymentContext ctx) =>
        new Dictionary<string, string> { ["CERTMASTER_PFX_PASSWORD"] = ctx.Files.PfxPassword ?? "" };

    public override Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct) =>
        !ctx.IsPreviewOnly && RequireCertificateFiles(ctx) is { } missing ? Task.FromResult(missing) : base.ExecuteAsync(ctx, ct);
}

/// <summary>Remote Access (DirectAccess, VPN, SSTP).</summary>
public class RasDeploymentTask : PowerShellRoleTaskBase
{
    protected override string ScriptName => "Deploy-RemoteAccess.ps1";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.RAS",
        Title = "Deploy to RAS (DirectAccess, VPN, SSTP)",
        DefaultTitle = "Deploy to Remote Access",
        Description = "Set the certificate as the Remote Access IP-HTTPS / SSTP certificate (Set-RemoteAccess -SslCertificate) and optionally restart the RemoteAccess service.",
        UsageNote = "Requires the RemoteAccess PowerShell module (Remote Access role).",
        ProviderParameters = { RestartParam("restart", "Restart the RemoteAccess service", true) }
    };

    protected override string Describe(DeploymentContext ctx) => "Set the Remote Access SSL certificate" + (ctx.ParamBool("restart", true) ? " and restart RemoteAccess" : "");
    protected override IEnumerable<string> GetSwitches(DeploymentContext ctx) { if (ctx.ParamBool("restart", true)) yield return "RestartService"; }
}

/// <summary>Remote Desktop Gateway.</summary>
public class RdpGatewayDeploymentTask : PowerShellRoleTaskBase
{
    protected override string ScriptName => "Deploy-RdGateway.ps1";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.RDPGateway",
        Title = "Deploy to RDP Gateway Service",
        DefaultTitle = "Deploy to RD Gateway",
        Description = "Set the certificate used by the Remote Desktop Gateway (RDS:\\GatewayServer\\SSLCertificate\\Thumbprint) and optionally restart the TSGateway service.",
        UsageNote = "Requires the RemoteDesktopServices PowerShell module (RD Gateway role). Restarting disconnects active gateway sessions.",
        ProviderParameters = { RestartParam("restart", "Restart the TSGateway service", true) }
    };

    protected override string Describe(DeploymentContext ctx) => "Set the RD Gateway SSL certificate" + (ctx.ParamBool("restart", true) ? " and restart TSGateway" : "");
    protected override IEnumerable<string> GetSwitches(DeploymentContext ctx) { if (ctx.ParamBool("restart", true)) yield return "RestartService"; }
}

/// <summary>Remote Desktop (RDP-Tcp) listener certificate via WMI.</summary>
public partial class RdpListenerDeploymentTask : DeploymentTaskProviderBase
{
    public const string NetworkServiceAccount = @"NT AUTHORITY\NETWORK SERVICE";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.RDPListener",
        Title = "Deploy to RDP Listener Service",
        DefaultTitle = "Deploy to RDP Listener",
        Description = "Set the certificate used by the Remote Desktop listener (Win32_TSGeneralSetting.SSLCertificateSHA1Hash) so RDP clients see a trusted certificate. Takes effect for new connections.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "terminalname", Name = "Listener name", Value = "RDP-Tcp" },
            new ProviderParameter { Key = "grantnetworkservice", Name = "Grant NETWORK SERVICE read access to the private key", Type = OptionType.Boolean, Value = "true",
                Description = "The Remote Desktop service needs to read the key." },
        }
    };

    [GeneratedRegex(@"^[A-Za-z0-9#_\-]{1,64}$")] private static partial Regex ListenerRegex();

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (!OperatingSystem.IsWindows()) errors.Add(Error("RDP listener configuration is only available on Windows."));
        if (ctx.Param("terminalname") is { } n && !ListenerRegex().IsMatch(n)) errors.Add(Error($"Invalid listener name '{n}'"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var listener = ctx.Param("terminalname") ?? "RDP-Tcp";
        var thumbprint = ctx.Item.CertificateThumbprintHash;
        var grant = ctx.ParamBool("grantnetworkservice", true);
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would set the {listener} listener certificate to {thumbprint ?? "(not issued yet)"}" + (grant ? " and grant NETWORK SERVICE read access to its private key" : ""));
        if (!OperatingSystem.IsWindows()) return Fail(ctx, "RDP listener configuration is only available on Windows.");
        if (thumbprint == null || !PowerShellHelper.IsThumbprint(thumbprint)) return Fail(ctx, "No certificate has been issued yet. Request the certificate first.");
        if (!PowerShellHelper.IsInMachineStore(thumbprint))
            return Fail(ctx, $"Certificate {thumbprint} is not in LocalMachine\\My. Add a 'Deploy to Certificate Store (Local Machine)' task before this one.");

        return await Guard(ctx, "RDP listener update", () => Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            if (grant)
            {
                var r = KeyPermissionsTask.Grant(thumbprint, NetworkServiceAccount, FileSystemRights.Read, previewOnly: false);
                ctx.Log.Info(r);
            }
            using var searcher = new ManagementObjectSearcher(new ManagementScope(@"\\.\root\cimv2\TerminalServices"),
                new ObjectQuery($"SELECT * FROM Win32_TSGeneralSetting WHERE TerminalName = '{listener}'"));
            var updated = 0;
            foreach (ManagementObject setting in searcher.Get())
            {
                using (setting)
                {
                    setting["SSLCertificateSHA1Hash"] = thumbprint;
                    setting.Put();
                    updated++;
                }
            }
            return updated == 0
                ? Fail(ctx, $"RDP listener '{listener}' was not found (Win32_TSGeneralSetting). Check the listener name.")
                : Ok(ctx, $"RDP listener {listener} now uses certificate {thumbprint}");
        }, ct), ct);
    }
}

/// <summary>Grant an account access to the private key of the stored certificate.</summary>
public class KeyPermissionsTask : DeploymentTaskProviderBase
{
    public const string DefaultAccount = @"NT AUTHORITY\LOCAL SERVICE";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.KeyPermissions",
        Title = "Set Certificate Key Permissions",
        DefaultTitle = "Set Private Key Permissions",
        Description = "Give a Windows account (service or app pool identity) read or full control access to the private key of the certificate stored in LocalMachine\\My or WebHosting, so that service can use the certificate.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "account", Name = "Account", Value = DefaultAccount, IsRequired = true, Description = @"e.g. NT AUTHORITY\NETWORK SERVICE, IIS AppPool\DefaultAppPool, DOMAIN\svc-app" },
            new ProviderParameter { Key = "permission", Name = "Permission", Type = OptionType.Select, Value = "read", OptionsList = "read=Read;fullcontrol=Full control" },
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (!OperatingSystem.IsWindows()) { errors.Add(Error("Key permissions can only be set on Windows.")); return; }
        if (ctx.Param("permission") is { } p && p is not ("read" or "fullcontrol")) errors.Add(Error($"Unknown permission '{p}'. Use read or fullcontrol."));
        if (ctx.Param("account") is { } a)
        {
            try { FileAcl.ResolveAccount(a); }
            catch (InvalidOperationException ex) { errors.Add(Error(ex.Message)); }
        }
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var account = ctx.Param("account") ?? DefaultAccount;
        var thumbprint = ctx.Item.CertificateThumbprintHash;
        if (!OperatingSystem.IsWindows()) return Fail(ctx, "Key permissions can only be set on Windows.");
        var rights = ctx.Param("permission") == "fullcontrol" ? FileSystemRights.FullControl : FileSystemRights.Read;
        if (thumbprint == null)
            return ctx.IsPreviewOnly ? Preview(ctx, $"Would grant {account} {rights} on the certificate's private key (no certificate issued yet)")
                                     : Fail(ctx, "No certificate has been issued yet. Request the certificate first.");
        if (ctx.IsPreviewOnly)
        {
            string detail;
            try { detail = Grant(thumbprint, account, rights, previewOnly: true); }
            catch (Exception ex) { detail = $"Would grant {account} {rights} on the private key of {thumbprint} (currently: {ex.Message})"; }
            return Preview(ctx, detail);
        }
        return await Guard(ctx, "Key permissions", () => Task.Run(() => OperatingSystem.IsWindows()
            ? Ok(ctx, Grant(thumbprint, account, rights, previewOnly: false))
            : throw new PlatformNotSupportedException(), ct), ct);
    }

    /// <summary>Finds the certificate's private key file and grants the account access. Returns a description of what was (or would be) done.</summary>
    [SupportedOSPlatform("windows")]
    public static string Grant(string thumbprint, string account, FileSystemRights rights, bool previewOnly)
    {
        var sid = FileAcl.ResolveAccount(account);
        using var cert = FindStoredCertificate(thumbprint)
                         ?? throw new InvalidOperationException($"Certificate {thumbprint} was not found in LocalMachine\\My or LocalMachine\\WebHosting.");
        if (!cert.HasPrivateKey) throw new InvalidOperationException($"Certificate {thumbprint} has no private key in the machine store.");
        var keyFile = FindPrivateKeyFile(cert);
        if (previewOnly) return $"Would grant {account} {rights} on private key file {keyFile}";
        var added = FileAcl.Grant(keyFile, sid, rights);
        return added ? $"Granted {account} {rights} on private key of {thumbprint} ({keyFile})" : $"{account} already has {rights} on private key of {thumbprint}";
    }

    [SupportedOSPlatform("windows")]
    private static X509Certificate2? FindStoredCertificate(string thumbprint)
    {
        foreach (var storeName in new[] { "My", "WebHosting" })
        {
            try
            {
                using var store = new X509Store(storeName, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                var found = CertificateStoreHelper.Find(store, thumbprint);
                for (var i = 1; i < found.Count; i++) found[i].Dispose();
                if (found.Count > 0) return found[0];
            }
            catch (CryptographicException) { /* store does not exist */ }
        }
        return null;
    }

    /// <summary>Locates the key file: CNG keys under ProgramData\Microsoft\Crypto\Keys, legacy CryptoAPI keys under Crypto\RSA\MachineKeys.</summary>
    [SupportedOSPlatform("windows")]
    public static string FindPrivateKeyFile(X509Certificate2 cert)
    {
        string? uniqueName;
        using (var rsa = cert.GetRSAPrivateKey())
        using (var ecdsa = rsa == null ? cert.GetECDsaPrivateKey() : null)
        {
            AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)rsa ?? ecdsa;
            uniqueName = key switch
            {
                RSACng c => c.Key.UniqueName,
                ECDsaCng e => e.Key.UniqueName,
                RSACryptoServiceProvider csp => csp.CspKeyContainerInfo.UniqueKeyContainerName,
                _ => null,
            };
        }
        if (string.IsNullOrEmpty(uniqueName)) throw new InvalidOperationException("Could not determine the private key container (unsupported key storage provider, e.g. a hardware/TPM key).");

        var crypto = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Crypto");
        var candidates = new[]
        {
            Path.Combine(crypto, "Keys", uniqueName),
            Path.Combine(crypto, "RSA", "MachineKeys", uniqueName),
            Path.Combine(crypto, "SystemKeys", uniqueName),
        };
        return candidates.FirstOrDefault(File.Exists)
               ?? throw new FileNotFoundException($"Private key file '{uniqueName}' not found (searched {string.Join(", ", candidates.Select(Path.GetDirectoryName).Distinct())}). The key may be stored in a user profile; re-import it into the machine store.");
    }
}

/// <summary>HTTP.sys SSL binding for an IP:port via netsh (for self-hosted services that are not IIS sites).</summary>
public class PortBindingTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.PortBinding",
        Title = "Update Port Binding (experimental)",
        DefaultTitle = "Update HTTP.sys Port Binding",
        Description = "Point the HTTP.sys SSL certificate binding for an IP:port at the new certificate (netsh http update sslcert, or add when there is no binding yet) so self-hosted HTTPS services use it.",
        IsExperimental = true,
        UsageNote = "Experimental. Binding options other than the certificate, app id and store (client certificate negotiation etc.) may be reset to their defaults.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "ipport", Name = "IP:Port", Value = "0.0.0.0:443", IsRequired = true, Description = "e.g. 0.0.0.0:443, 10.0.0.5:8443 or [::]:443" },
            new ProviderParameter { Key = "appid", Name = "Application ID (GUID, optional)", Description = "Blank = keep the existing binding's application ID (a new GUID when there is no binding)" },
        }
    };

    /// <summary>An existing HTTP.sys binding as reported by "netsh http show sslcert".</summary>
    public sealed record SslCertBinding(string CertificateHash, Guid? AppId, string? CertStoreName);

    public static string[] ShowArgs(string ipport) => new[] { "http", "show", "sslcert", $"ipport={ipport}" };
    public static string[] DeleteArgs(string ipport) => new[] { "http", "delete", "sslcert", $"ipport={ipport}" };

    /// <summary>Arguments for "netsh http add|update sslcert".</summary>
    public static string[] SetArgs(string verb, string ipport, string certHash, Guid appId, string? certStoreName = null) => new[]
    {
        "http", verb, "sslcert", $"ipport={ipport}", $"certhash={certHash}", $"appid={{{appId}}}", $"certstorename={(string.IsNullOrWhiteSpace(certStoreName) ? "MY" : certStoreName.Trim())}",
    };

    private static readonly Regex HashValue = new(@"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex GuidValue = new(@"^\{[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$", RegexOptions.CultureInvariant);

    /// <summary>
    /// Parses "netsh http show sslcert" output. Uses the English labels when present and otherwise the value shapes (a hex hash,
    /// a {GUID}), so localized Windows works too. Returns null when the output shows no binding.
    /// </summary>
    public static SslCertBinding? ParseShowSslCert(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return null;
        string? hash = null, labelledHash = null, store = null;
        Guid? appId = null, labelledAppId = null;
        foreach (var raw in output.Split('\n'))
        {
            var sep = raw.IndexOf(" : ", StringComparison.Ordinal);
            if (sep < 0) continue;
            var label = raw[..sep].Trim();
            var value = raw[(sep + 3)..].Trim();
            if (label.Equals("Certificate Hash", StringComparison.OrdinalIgnoreCase) && HashValue.IsMatch(value)) labelledHash = value;
            else if (label.Equals("Application ID", StringComparison.OrdinalIgnoreCase) && Guid.TryParse(value, out var a)) labelledAppId = a;
            else if (label.Equals("Certificate Store Name", StringComparison.OrdinalIgnoreCase) && value.Length > 0 && !value.Equals("(null)", StringComparison.OrdinalIgnoreCase)) store = value;
            if (hash == null && HashValue.IsMatch(value)) hash = value;
            if (appId == null && GuidValue.IsMatch(value) && Guid.TryParse(value, out var g)) appId = g;
        }
        hash = labelledHash ?? hash;
        return hash == null ? null : new SslCertBinding(hash.ToUpperInvariant(), labelledAppId ?? appId, store);
    }

    /// <summary>
    /// Points the binding at the certificate: "update" when a binding exists (keeping its app id unless one is configured),
    /// otherwise "add". If update fails the binding is replaced (delete + add), and when that add fails the previous certificate
    /// is bound again so the endpoint is never left without one.
    /// </summary>
    internal static async Task<ActionResult> ApplyBindingAsync(DeploymentContext ctx, Func<string[], CancellationToken, Task<ProcessResult>> netsh,
        string ipport, string thumbprint, Guid? configuredAppId, CancellationToken ct)
    {
        const string elevated = "The agent must run elevated.";
        var existing = ParseShowSslCert((await netsh(ShowArgs(ipport), ct)).Output);
        var appId = configuredAppId ?? existing?.AppId ?? Guid.NewGuid();
        if (existing == null)
        {
            var add = await netsh(SetArgs("add", ipport, thumbprint, appId), ct);
            return add.ExitCode == 0
                ? Ok(ctx, $"Bound {ipport} to certificate {thumbprint} (appid {{{appId}}})")
                : Fail(ctx, $"netsh http add sslcert failed (exit code {add.ExitCode}): {PowerShellHelper.Summarize(add)}. {elevated}");
        }
        if (string.Equals(existing.CertificateHash, thumbprint, StringComparison.OrdinalIgnoreCase) && existing.AppId == appId)
            return Ok(ctx, $"{ipport} is already bound to certificate {thumbprint} (appid {{{appId}}})");

        ctx.Log.Info($"Existing binding for {ipport}: certificate {existing.CertificateHash}" + (existing.AppId is { } old ? $", appid {{{old}}}" : ""));
        var update = await netsh(SetArgs("update", ipport, thumbprint, appId), ct);
        if (update.ExitCode == 0)
            return Ok(ctx, $"Updated {ipport} from certificate {existing.CertificateHash} to {thumbprint} (appid {{{appId}}})");

        ctx.Log.Warn($"netsh http update sslcert failed (exit code {update.ExitCode}): {PowerShellHelper.Summarize(update)}. Replacing the binding instead.");
        var del = await netsh(DeleteArgs(ipport), ct);
        if (del.ExitCode != 0)
            return Fail(ctx, $"Could not update or remove the binding for {ipport} (exit code {del.ExitCode}): {PowerShellHelper.Summarize(del)}. It still uses certificate {existing.CertificateHash}. {elevated}");

        // From here the endpoint has no certificate: finish (or roll back) even if the task is being cancelled.
        var readd = await netsh(SetArgs("add", ipport, thumbprint, appId), CancellationToken.None);
        if (readd.ExitCode == 0)
            return Ok(ctx, $"Replaced the binding for {ipport}: certificate {thumbprint} (appid {{{appId}}})");
        var restore = await netsh(SetArgs("add", ipport, existing.CertificateHash, existing.AppId ?? appId, existing.CertStoreName), CancellationToken.None);
        return Fail(ctx, $"netsh http add sslcert failed (exit code {readd.ExitCode}): {PowerShellHelper.Summarize(readd)}. " +
                         (restore.ExitCode == 0
                             ? $"The previous binding (certificate {existing.CertificateHash}) was restored."
                             : $"Restoring the previous binding (certificate {existing.CertificateHash}) also failed: {PowerShellHelper.Summarize(restore)}. {ipport} has no certificate binding now. {elevated}"));
    }

    /// <summary>Normalizes and validates an ip:port for netsh. Returns null when invalid.</summary>
    public static string? NormalizeIpPort(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim();
        var colon = v.LastIndexOf(':');
        if (colon <= 0 || colon == v.Length - 1) return null; // a port is required
        if (!IPEndPoint.TryParse(v, out var ep) || ep.Port == 0) return null;
        return ep.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{ep.Address}]:{ep.Port}" : $"{ep.Address}:{ep.Port}";
    }

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (!OperatingSystem.IsWindows()) errors.Add(Error("HTTP.sys bindings are only available on Windows."));
        if (ctx.Param("ipport") is { } ip && NormalizeIpPort(ip) == null) errors.Add(Error($"Invalid IP:Port '{ip}'. Use e.g. 0.0.0.0:443 or [::]:443"));
        if (ctx.Param("appid") is { } a && !Guid.TryParse(a, out _)) errors.Add(Error($"Application ID must be a GUID (got {a})"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var ipport = NormalizeIpPort(ctx.Param("ipport") ?? "0.0.0.0:443")!;
        Guid? appId = ctx.Param("appid") is { } a ? Guid.Parse(a) : null;
        var thumbprint = ctx.Item.CertificateThumbprintHash;
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would bind {ipport} to certificate {thumbprint ?? "(not issued yet)"} " +
                                (appId is { } id ? $"(appid {{{id}}})" : "(keeping the existing binding's appid)") + " with netsh http");
        if (!OperatingSystem.IsWindows()) return Fail(ctx, "HTTP.sys bindings are only available on Windows.");
        if (thumbprint == null || !PowerShellHelper.IsThumbprint(thumbprint)) return Fail(ctx, "No certificate has been issued yet. Request the certificate first.");
        if (!PowerShellHelper.IsInMachineStore(thumbprint))
            return Fail(ctx, $"Certificate {thumbprint} is not in LocalMachine\\My. Add a 'Deploy to Certificate Store (Local Machine)' task before this one.");

        return await Guard(ctx, "Port binding", () => ApplyBindingAsync(ctx,
            (args, token) => ProcessRunner.RunAsync("netsh.exe", args, null, TimeSpan.FromMinutes(1), token),
            ipport, thumbprint, appId, ct), ct);
    }
}
