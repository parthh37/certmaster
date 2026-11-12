using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
using System.Security.Principal;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Export the certificate in one of several PFX/PEM formats to a local, UNC or SSH path.</summary>
public class CertificateExportTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.CertificateExport",
        Title = "Export Certificate",
        DefaultTitle = "Export Certificate",
        Description = "Write the certificate as a single PFX or PEM file (choice of chain/key combinations) to a folder on this machine, a network share, or a remote host over SSH.",
        SupportsRemoteTarget = true,
        SupportedTargets = new(DeploymentTargets.AllTargets),
        ProviderParameters =
        {
            new ProviderParameter { Key = "path", Name = "Destination File Path", IsRequired = true, Description = "Full file path including the file name, e.g. C:\\certs\\site.pfx, \\\\server\\share\\site.pem or /etc/ssl/site.pem" },
            new ProviderParameter { Key = "type", Name = "Export As", Type = OptionType.Select, Value = ExportFormats.PfxFull, IsRequired = true, OptionsList = ExportFormats.OptionsList },
            new ProviderParameter { Key = "pfxpasswordcredential", Name = "New PFX password (stored credential key, optional)", Description = "Stored 'Password' credential used to protect the exported PFX. Blank = keep the certificate's current PFX password." },
            DeploymentTargets.LogonTypeParameter(),
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        var type = ctx.Param("type") ?? ExportFormats.PfxFull;
        if (!ExportFormats.IsKnown(type)) errors.Add(Error($"Unknown export format '{type}'. Valid: {string.Join(", ", ExportFormats.All)}"));
        if (DeploymentTargets.ValidatePath(ctx, "Destination File Path", ctx.Param("path")) is { } e) errors.Add(Error(e));
    }

    /// <summary>Resolves the password for exported PFX files: an optional stored credential, else the current PFX password.</summary>
    internal static async Task<(string? password, string? error)> ResolvePfxPasswordAsync(DeploymentContext ctx, string paramKey = "pfxpasswordcredential")
    {
        var key = ctx.Param(paramKey);
        if (key == null) return (ctx.Files.PfxPassword, null);
        var values = await ctx.UnlockCredentialAsync(key);
        return values.TryGetValue("password", out var pwd) && !string.IsNullOrEmpty(pwd)
            ? (pwd, null)
            : (null, $"Stored credential '{key}' was not found or has no 'password' value. Create a Password credential and use its key.");
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var dest = ctx.Expand(ctx.Param("path")!);
        var type = ctx.Param("type") ?? ExportFormats.PfxFull;
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would export the certificate as {type} to {dest} on {DeploymentTargets.Describe(ctx)}" +
                                (ctx.Param("pfxpasswordcredential") != null ? " protected with the selected PFX password" : ""));
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "Export", async () =>
        {
            var (password, pwdError) = await ResolvePfxPasswordAsync(ctx);
            if (pwdError != null) return Fail(ctx, pwdError);
            byte[] content;
            using (var material = CertificateMaterial.Load(ctx.Files)) content = material.Export(type, password);

            using var fs = DeploymentTargets.CreateFileSystem(ctx);
            if (await fs.IsDirectoryAsync(dest, ct))
                return Fail(ctx, $"Destination {dest} is a folder. Include a file name, e.g. {dest.TrimEnd('\\', '/')}{(ctx.TargetType == DeploymentContextType.SSH ? "/" : "\\")}{SafeName(ctx)}{(type == ExportFormats.PfxFull ? ".pfx" : ".pem")}");
            await fs.WriteAllBytesAsync(dest, content, ExportFormats.IncludesPrivateKey(type), ct);
            return Ok(ctx, $"Exported certificate ({type}, {content.Length} bytes) to {dest} via {fs.Description}");
        }, ct);
    }

    internal static string SafeName(DeploymentContext ctx) =>
        string.Concat((ctx.Item.RequestConfig.PrimaryDomain is { Length: > 0 } d ? d : ctx.Item.Name).Select(c => c == '*' ? '_' : Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
}

/// <summary>Import the certificate into the Windows certificate store (LocalMachine).</summary>
public class WindowsCertificateStoreTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.CertificateStore",
        Title = "Deploy to Certificate Store (Local Machine)",
        DefaultTitle = "Store in Local Machine Certificate Store",
        Description = "Import the certificate and private key into a Local Machine certificate store (Personal or Web Hosting).",
        UsageNote = "Usually not needed: certificates are stored in the Local Machine store automatically after each request. Use this to target a different store or to remove the previous certificate.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "store", Name = "Store", Type = OptionType.Select, Value = "My", OptionsList = "My=Personal (My);WebHosting=Web Hosting" },
            new ProviderParameter { Key = "removeprevious", Name = "Remove previous certificate", Type = OptionType.Boolean, Value = "false" },
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (ctx.Param("store") is { } s && s is not ("My" or "WebHosting")) errors.Add(Error($"Unsupported store '{s}'. Use My or WebHosting."));
        if (!OperatingSystem.IsWindows()) errors.Add(Error("The Windows certificate store is only available on Windows."));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Fail(ctx, "The Windows certificate store is only available on Windows.");
        var storeName = ctx.Param("store") ?? "My";
        var removePrevious = ctx.ParamBool("removeprevious");
        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would import the certificate into LocalMachine\\{storeName}" + (removePrevious ? " and remove the previous certificate" : ""));
        if (RequireCertificateFiles(ctx) is { } missing) return missing;

        return await Guard(ctx, "Certificate store import", () =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            // Read the PFX without persisting its key first: importing again would create another key container in MachineKeys
            // and drop the ACL granted on the current one (e.g. NETWORK SERVICE for RDP).
            string thumbprint, friendlyName;
            using (var probe = X509CertificateLoader.LoadPkcs12FromFile(ctx.Files.Pfx, ctx.Files.PfxPassword, X509KeyStorageFlags.EphemeralKeySet))
            {
                thumbprint = probe.Thumbprint;
                friendlyName = $"{ctx.Item.Name} [CertMaster] {probe.NotBefore:yyyyMMdd} to {probe.NotAfter:yyyyMMdd}";
            }
            using var store = new X509Store(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            string action;
            if (CertificateStoreHelper.TryUseExisting(store, thumbprint, friendlyName))
                action = $"{thumbprint} is already in LocalMachine\\{storeName} with its private key; kept the existing key";
            else
            {
                using var cert = X509CertificateLoader.LoadPkcs12FromFile(ctx.Files.Pfx, ctx.Files.PfxPassword,
                    X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                cert.FriendlyName = friendlyName;
                store.Add(cert);
                action = $"Imported {thumbprint} into LocalMachine\\{storeName}";
            }
            var removed = 0;
            if (removePrevious && !string.IsNullOrEmpty(ctx.Item.CertificatePreviousThumbprintHash))
            {
                var previous = CertificateStoreHelper.Find(store, ctx.Item.CertificatePreviousThumbprintHash);
                try
                {
                    foreach (var old in previous)
                        if (!string.Equals(old.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase)) { store.Remove(old); removed++; }
                }
                finally { CertificateStoreHelper.DisposeAll(previous); }
            }
            return Task.FromResult(Ok(ctx, action + (removed > 0 ? $"; removed {removed} previous certificate(s)" : "")));
        }, ct);
    }
}

/// <summary>Certificate store lookups that dispose the certificate objects they create.</summary>
internal static class CertificateStoreHelper
{
    /// <summary>Certificates in the open store with the thumbprint. The caller disposes them (<see cref="DisposeAll"/>).</summary>
    public static X509Certificate2Collection Find(X509Store store, string thumbprint)
    {
        var all = store.Certificates; // a fresh copy of every certificate in the store
        try { return all.Find(X509FindType.FindByThumbprint, thumbprint, false); }
        finally { DisposeAll(all); }
    }

    public static void DisposeAll(X509Certificate2Collection certificates)
    {
        foreach (var c in certificates) c.Dispose();
    }

    /// <summary>
    /// True when the open store already holds the certificate with a usable private key; its friendly name is updated if it
    /// differs. False when it is missing, or present without a (working) private key, so the caller imports the PFX.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static bool TryUseExisting(X509Store store, string thumbprint, string friendlyName)
    {
        var found = Find(store, thumbprint);
        try
        {
            foreach (var c in found)
            {
                if (!c.HasPrivateKey || !PrivateKeyOpens(c)) continue;
                if (c.FriendlyName != friendlyName)
                {
                    try { c.FriendlyName = friendlyName; } // updates the store entry
                    catch (CryptographicException) { /* cosmetic */ }
                }
                return true;
            }
            return false;
        }
        finally { DisposeAll(found); }
    }

    /// <summary>HasPrivateKey only means the store entry links to a key; this checks the key container still exists.</summary>
    private static bool PrivateKeyOpens(X509Certificate2 c)
    {
        try
        {
            using AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)c.GetRSAPrivateKey() ?? (AsymmetricAlgorithm?)c.GetECDsaPrivateKey() ?? c.GetDSAPrivateKey();
            return key != null;
        }
        catch (CryptographicException) { return false; }
    }
}

/// <summary>Run a PowerShell script (or other script type) with the certificate details.</summary>
public class ScriptTask : DeploymentTaskProviderBase
{
    public const string WrapperScript = "Invoke-DeploymentScript.ps1";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.PowershellScript",
        Title = "Run PowerShell Script",
        DefaultTitle = "Run PowerShell Script",
        Description = "Run your own PowerShell script after (or before) a request. Arguments are given as name=value;name2=value2 and passed as named parameters; " +
                      "the request result can be passed as the first argument. Certificate details are also available as CERT_* environment variables. " +
                      ".bat/.cmd/.py/.sh scripts are supported too.",
        IsPreRequestCapable = true,
        SupportedTargets = new() { DeploymentContextType.LocalAsService, DeploymentContextType.LocalAsUser },
        ProviderParameters =
        {
            new ProviderParameter { Key = "scriptpath", Name = "Script Path", IsRequired = true, Description = "Full path to the .ps1 script, e.g. C:\\scripts\\deploy.ps1" },
            new ProviderParameter { Key = "args", Name = "Arguments (optional)", Description = "name=value;name2=value2 (escape ; and = as \\; and \\=). Supports {PrimaryDomain}, {Thumbprint} and other placeholders." },
            new ProviderParameter { Key = "passresult", Name = "Pass result as first argument", Type = OptionType.Boolean, Value = "false",
                Description = "PowerShell scripts receive the result object (ManagedItem, IsSuccess, Message) as their first parameter; other scripts receive the path of a JSON file." },
            new ProviderParameter { Key = "timeout", Name = "Timeout (minutes)", Type = OptionType.Number, Value = "5", Description = "1 to 120 minutes" },
            DeploymentTargets.LogonTypeParameter(),
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        var script = ctx.Param("scriptpath");
        if (script != null)
        {
            if (!Path.IsPathFullyQualified(script)) errors.Add(Error($"Script Path must be a full path: {script}"));
            else if (!File.Exists(script)) errors.Add(Error($"Script not found: {script}"));
        }
        if (ctx.Param("timeout") is { } t && (!int.TryParse(t, out var m) || m < 1 || m > 120))
            errors.Add(Error("Timeout must be a whole number of minutes between 1 and 120"));
        try { if (ScriptArguments.UsesNamedSyntax(ctx.Param("args"))) ScriptArguments.Parse(ctx.Param("args")); }
        catch (FormatException ex) { errors.Add(Error("Arguments: " + ex.Message)); }
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var script = ctx.Param("scriptpath")!;
        var timeout = TimeSpan.FromMinutes(Math.Clamp(ctx.ParamInt("timeout") ?? 5, 1, 120));
        var passResult = ctx.ParamBool("passresult");
        var rawArgs = ctx.Param("args") is { } a ? ctx.Expand(a) : null;
        var named = ScriptArguments.UsesNamedSyntax(rawArgs);
        var args = named ? ScriptArguments.Parse(rawArgs)
            : (rawArgs ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(v => new ScriptArgument(null, v)).ToList();

        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would run {script} on {DeploymentTargets.Describe(ctx)} with {args.Count} argument(s)" + (passResult ? ", passing the result as the first argument" : "") + $", timeout {timeout.TotalMinutes:0} min");
        if (!File.Exists(script)) return Fail(ctx, $"Script not found: {script}");

        var id = Guid.NewGuid().ToString("N");
        string resultJson = "", argsJson = "";
        return await Guard(ctx, "Script", async () =>
        {
            try
            {
                // Not the shared system temp folder (C:\Windows\Temp for SYSTEM), where any local user could pre-create the
                // folder and read or swap the files.
                var tempDir = PrivateTempFolder.Ensure(ctx.ScriptTempFolder ?? DeploymentContext.DefaultScriptTempFolder());
                resultJson = Path.Combine(tempDir, $"result_{id}.json");
                argsJson = Path.Combine(tempDir, $"args_{id}.json");
                await PrivateTempFolder.WriteNewFileAsync(resultJson, JsonDefaults.Serialize(new { ManagedItem = ctx.Item, IsSuccess = ctx.RequestSucceeded ?? true, Message = ctx.RequestMessage }), ct);
                var env = BuildEnvironment(ctx, resultJson);

                CommandSpec spec;
                if (Path.GetExtension(script).Equals(".ps1", StringComparison.OrdinalIgnoreCase))
                {
                    var payload = new
                    {
                        named = args.Where(x => x.Name != null).ToDictionary(x => x.Name!.TrimStart('-'), x => x.Value),
                        positional = args.Where(x => x.Name == null).Select(x => x.Value).ToList(),
                    };
                    await PrivateTempFolder.WriteNewFileAsync(argsJson, JsonSerializer.Serialize(payload), ct);
                    var wrapper = PowerShellHelper.GetScriptPath(WrapperScript);
                    if (!File.Exists(wrapper)) return Fail(ctx, $"Helper script {wrapper} is missing. Reinstall the agent.");
                    var list = new List<string> { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper,
                        "-ScriptPath", script, "-ResultJsonPath", resultJson, "-ArgumentsJsonPath", argsJson };
                    if (passResult) list.Add("-PassResult");
                    spec = new CommandSpec(PowerShellHelper.PowerShellExe) { Arguments = list, Environment = env, Timeout = timeout, WorkingDirectory = Path.GetDirectoryName(script) };
                }
                else
                {
                    var list = ScriptArguments.ToArgumentList(args);
                    if (passResult) list.Insert(0, resultJson);
                    spec = ProcessRunner.ResolveInterpreter(new CommandSpec(script) { Arguments = list, Environment = env, Timeout = timeout, WorkingDirectory = Path.GetDirectoryName(script) });
                }

                if (ctx.TargetType == DeploymentContextType.LocalAsUser && OperatingSystem.IsWindows())
                    GrantTempFileAccess(ctx, resultJson, argsJson);

                using var runner = DeploymentTargets.CreateCommandRunner(ctx);
                ctx.Log.Info($"Running script {script} ({runner.Description}), timeout {timeout.TotalMinutes:0} min");
                var r = await runner.RunAsync(spec, ct);
                if (!string.IsNullOrWhiteSpace(r.Output)) ctx.Log.Info("Script output: " + r.Output.Trim());
                if (r.ExitCode == 0)
                {
                    if (!string.IsNullOrWhiteSpace(r.Error)) ctx.Log.Warn("Script error output: " + r.Error.Trim());
                    return Ok(ctx, "Script completed");
                }
                return Fail(ctx, $"Script failed with exit code {r.ExitCode}. {PowerShellHelper.Summarize(r with { Output = "" })}".Trim());
            }
            finally
            {
                foreach (var f in new[] { resultJson, argsJson }.Where(f => f.Length > 0))
                {
                    try { File.Delete(f); } catch { /* ignore */ }
                }
            }
        }, ct);
    }

    [SupportedOSPlatform("windows")]
    private static void GrantTempFileAccess(DeploymentContext ctx, params string[] files)
    {
        var account = WindowsCredential.FromDictionary(ctx.Credentials)?.AccountName;
        if (account == null) return;
        foreach (var f in files.Where(File.Exists))
        {
            try { FileAcl.Grant(f, account, FileSystemRights.Read); }
            catch (Exception ex) { ctx.Log.Warn($"Could not grant {account} read access to {f}: {ex.Message}"); }
        }
    }

    internal static Dictionary<string, string> BuildEnvironment(DeploymentContext ctx, string resultJson) => new()
    {
        ["CERT_ID"] = ctx.Item.Id, ["CERT_NAME"] = ctx.Item.Name,
        ["CERT_PRIMARY_DOMAIN"] = ctx.Item.RequestConfig.PrimaryDomain,
        ["CERT_DOMAINS"] = string.Join(",", ctx.Item.GetAllDomains()),
        ["CERT_THUMBPRINT"] = ctx.Item.CertificateThumbprintHash ?? "",
        ["CERT_PFX_PATH"] = ctx.Files.Pfx, ["CERT_FULLCHAIN_PEM"] = ctx.Files.FullChainPem,
        ["CERT_PEM"] = ctx.Files.CertPem, ["CERT_KEY_PEM"] = ctx.Files.KeyPem, ["CERT_CHAIN_PEM"] = ctx.Files.ChainPem,
        ["CERT_REQUEST_SUCCESS"] = (ctx.RequestSucceeded ?? true).ToString().ToLowerInvariant(),
        ["CERT_RESULT_JSON"] = resultJson,
    };
}

/// <summary>
/// Agent-private folder for short-lived files handed to scripts. Created (or re-secured) with a protected ACL for SYSTEM,
/// Administrators and the agent account only (0700 elsewhere); an existing folder owned by anyone else is refused.
/// </summary>
internal static class PrivateTempFolder
{
    public static string Ensure(string folder)
    {
        folder = Path.GetFullPath(folder);
        if (OperatingSystem.IsWindows()) EnsureWindows(folder);
        else
        {
            const UnixFileMode ownerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Directory.CreateDirectory(folder, ownerOnly);
            File.SetUnixFileMode(folder, ownerOnly);
        }
        return folder;
    }

    /// <summary>Writes a new file (fails if the name already exists, so a pre-planted file or link is never reused).</summary>
    public static async Task WriteNewFileAsync(string path, string content, CancellationToken ct)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, Options = FileOptions.Asynchronous };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var fs = new FileStream(path, options);
        await fs.WriteAsync(new UTF8Encoding(false).GetBytes(content), ct);
    }

    [SupportedOSPlatform("windows")]
    private static void EnsureWindows(string folder)
    {
        var parent = Path.GetDirectoryName(folder);
        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
        var trusted = TrustedSids();
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in trusted)
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

        var dir = new DirectoryInfo(folder);
        if (!dir.Exists)
        {
            dir.Create(security);
            return;
        }
        if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException($"The script temp folder {folder} is a link. Delete it so the agent can recreate it.");
        var owner = dir.GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner == null || !trusted.Contains(owner))
            throw new InvalidOperationException($"The script temp folder {folder} is owned by {owner?.Value ?? "an unknown account"}, not by SYSTEM, Administrators or the agent account. Delete it so the agent can recreate it.");
        dir.SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    private static List<SecurityIdentifier> TrustedSids()
    {
        var sids = new List<SecurityIdentifier>
        {
            new(WellKnownSidType.LocalSystemSid, null),
            new(WellKnownSidType.BuiltinAdministratorsSid, null),
        };
        using (var current = WindowsIdentity.GetCurrent()) if (current.User != null && !sids.Contains(current.User)) sids.Add(current.User);
        return sids;
    }
}

/// <summary>Call a webhook (HTTP) with a templated body.</summary>
public class WebhookTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Webhook",
        Title = "Webhook",
        DefaultTitle = "Call Webhook",
        Description = "Send an HTTP request. URL and body support {ManagedItemId} {Name} {PrimaryDomain} {Thumbprint} {DateExpiry} {IsSuccess} {Message}.",
        IsPreRequestCapable = true,
        ProviderParameters =
        {
            new ProviderParameter { Key = "url", Name = "URL", IsRequired = true },
            new ProviderParameter { Key = "method", Name = "Method", Type = OptionType.Select, Value = "POST", OptionsList = "POST;PUT;GET" },
            new ProviderParameter { Key = "contenttype", Name = "Content Type", Value = "application/json" },
            new ProviderParameter { Key = "body", Name = "Body", Type = OptionType.MultiLineText,
                Value = "{\"id\":\"{ManagedItemId}\",\"name\":\"{Name}\",\"success\":{IsSuccess},\"message\":\"{Message}\"}" },
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (ctx.Param("url") is { } u && (!Uri.TryCreate(ExpandUrl(ctx, u), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")))
            errors.Add(Error($"URL must be an absolute http(s) address: {u}"));
        if (ctx.Param("method") is { } m && m.ToUpperInvariant() is not ("POST" or "PUT" or "GET"))
            errors.Add(Error($"Unsupported method {m}"));
    }

    /// <summary>Placeholders in the URL are percent-encoded.</summary>
    internal static string ExpandUrl(DeploymentContext ctx, string url) => ctx.Expand(url, Uri.EscapeDataString);

    /// <summary>
    /// Placeholders in the body are escaped for the content type: JSON string escaping for JSON bodies (so a failure message
    /// with quotes or newlines still yields valid JSON), percent-encoding for form bodies, raw otherwise.
    /// </summary>
    internal static string ExpandBody(DeploymentContext ctx, string body, string contentType)
    {
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase)) return ctx.Expand(body, DeploymentContext.JsonStringEncoder);
        if (contentType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) return ctx.Expand(body, Uri.EscapeDataString);
        return ctx.Expand(body);
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var url = ExpandUrl(ctx, ctx.Param("url")!);
        var method = (ctx.Param("method") ?? "POST").ToUpperInvariant();
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would send {method} {url}");
        return await Guard(ctx, "Webhook", async () =>
        {
            using var req = new HttpRequestMessage(new HttpMethod(method), url);
            var contentType = ctx.Param("contenttype") ?? "application/json";
            if (req.Method != HttpMethod.Get)
                req.Content = new StringContent(ExpandBody(ctx, ctx.Param("body") ?? "", contentType), Encoding.UTF8, contentType);
            using var resp = await ctx.Http.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return Ok(ctx, $"Webhook returned {(int)resp.StatusCode}");
            var body = await resp.Content.ReadAsStringAsync(ct);
            return Fail(ctx, $"Webhook returned {(int)resp.StatusCode} {resp.ReasonPhrase}" + (body.Length > 0 ? ": " + (body.Length > 300 ? body[..300] : body) : ""));
        }, ct);
    }
}

/// <summary>Start, stop or restart a Windows service.</summary>
public class ServiceManagerTask : DeploymentTaskProviderBase
{
    /// <summary>The agent's own service, which a task must never stop (it would kill the running request).</summary>
    public const string AgentServiceName = "CertMaster Agent";

    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.ServiceManager",
        Title = "Restart a Service",
        DefaultTitle = "Restart Service",
        Description = "Start, stop or restart a local Windows service, e.g. one that only loads its certificate at startup.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "servicename", Name = "Service Name", IsRequired = true, Description = "Service name or display name" },
            new ProviderParameter { Key = "action", Name = "Action", Type = OptionType.Select, Value = "restart", OptionsList = "restart=Restart;stop=Stop;start=Start" },
            new ProviderParameter { Key = "maxwait", Name = "Max wait (seconds)", Type = OptionType.Number, Value = "60" },
        }
    };

    public static bool IsAgentService(string name) => string.Equals(name.Trim(), AgentServiceName, StringComparison.OrdinalIgnoreCase);

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        var action = ctx.Param("action") ?? "restart";
        if (action is not ("restart" or "stop" or "start")) errors.Add(Error($"Unknown action '{action}'. Use start, stop or restart."));
        if (ctx.Param("maxwait") is { } w && (!int.TryParse(w, out var s) || s < 1 || s > 3600)) errors.Add(Error("Max wait must be between 1 and 3600 seconds"));
        if (!OperatingSystem.IsWindows()) errors.Add(Error("Service control is only implemented on Windows."));
    }

    /// <summary>
    /// Stopping the agent's own service would end the certificate request before its result is saved, so the request would
    /// run again on every start. The stop is skipped and the task completes with this warning instead.
    /// </summary>
    public static string SkippedAgentStopMessage(string action) =>
        $"Skipped: did not {action} the {AgentServiceName} service, because it is running this certificate request and stopping it would end the request before its result is saved. Restart it manually if needed.";

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Fail(ctx, "Service control is only implemented on Windows.");
        var name = ctx.Param("servicename")!.Trim();
        var action = ctx.Param("action") ?? "restart";
        var stops = action != "start";
        if (stops && IsAgentService(name))
            return ctx.IsPreviewOnly ? Preview(ctx, SkippedAgentStopMessage(action)) : Warn(ctx, SkippedAgentStopMessage(action));
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would {action} service '{name}'");
        var wait = TimeSpan.FromSeconds(Math.Clamp(ctx.ParamInt("maxwait") ?? 60, 1, 3600));
        try
        {
            var (status, skipped) = await Task.Run(() => OperatingSystem.IsWindows() ? Control(ctx, name, action, wait, ct) : throw new PlatformNotSupportedException(), ct);
            return skipped ? Warn(ctx, SkippedAgentStopMessage(action)) : Ok(ctx, $"Service {name}: {action} completed ({status})");
        }
        catch (InvalidOperationException ex) { return Fail(ctx, $"Could not {action} service '{name}': {ex.InnerException?.Message ?? ex.Message}"); }
        catch (System.ServiceProcess.TimeoutException ex) { return Fail(ctx, ex.Message); }
    }

    [SupportedOSPlatform("windows")]
    private static (string Status, bool SkippedAgentStop) Control(DeploymentContext ctx, string name, string action, TimeSpan wait, CancellationToken ct)
    {
        using var sc = new ServiceController(name);
        _ = sc.Status; // throws InvalidOperationException when the service does not exist
        // The name given may be a display name or differ in case from the agent's; check the resolved service too.
        if (action != "start" && IsAgent(sc))
            return (sc.Status.ToString(), true);

        // Stopping a service also stops the services that depend on it (stopping WAS stops W3SVC), but starting it starts only
        // that service. Remember the running dependents so a restart brings them back too.
        var dependents = new List<ServiceController>();
        try
        {
            if (action is "stop" or "restart" && sc.Status != ServiceControllerStatus.Stopped)
            {
                dependents = ActiveDependents(sc);
                if (dependents.Any(IsAgent)) return (sc.Status.ToString(), true);
                for (var i = dependents.Count - 1; i >= 0; i--) StopAndWait(ctx, dependents[i], wait, ct); // deepest dependents first
                StopAndWait(ctx, sc, wait, ct);
            }
            if (action is "start" or "restart")
            {
                StartAndWait(ctx, sc, wait, ct);
                var failed = new List<string>();
                foreach (var d in dependents) // each one's dependencies come before it
                {
                    try { StartAndWait(ctx, d, wait, ct); }
                    catch (Exception ex) when (ex is InvalidOperationException or System.ServiceProcess.TimeoutException)
                    {
                        failed.Add($"{d.ServiceName} ({ex.InnerException?.Message ?? ex.Message})");
                    }
                }
                if (failed.Count > 0)
                    throw new InvalidOperationException($"{sc.ServiceName} is running again, but these dependent services did not start: {string.Join("; ", failed)}");
                if (dependents.Count > 0) ctx.Log.Info($"Started dependent service(s) again: {string.Join(", ", dependents.Select(d => d.ServiceName))}");
            }
            sc.Refresh();
            return (sc.Status.ToString(), false);
        }
        finally
        {
            foreach (var d in dependents) d.Dispose();
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsAgent(ServiceController sc) => IsAgentService(sc.ServiceName) || IsAgentService(sc.DisplayName);

    [SupportedOSPlatform("windows")]
    private static bool IsActive(ServiceController sc) => sc.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending);

    /// <summary>All services (recursively) that depend on <paramref name="root"/> and are not stopped, in start order.</summary>
    [SupportedOSPlatform("windows")]
    private static List<ServiceController> ActiveDependents(ServiceController root)
    {
        var controllers = new Dictionary<string, ServiceController>(StringComparer.OrdinalIgnoreCase);
        List<string> Children(string serviceName)
        {
            var parent = string.Equals(serviceName, root.ServiceName, StringComparison.OrdinalIgnoreCase) ? root : controllers[serviceName];
            var names = new List<string>();
            foreach (var d in parent.DependentServices)
            {
                if (controllers.ContainsKey(d.ServiceName)) names.Add(d.ServiceName); // reached through another path
                else if (IsActive(d))
                {
                    controllers[d.ServiceName] = d;
                    names.Add(d.ServiceName);
                    continue;
                }
                d.Dispose();
            }
            return names;
        }
        try
        {
            return DependentStartOrder(root.ServiceName, Children).Select(n => controllers[n]).ToList();
        }
        catch
        {
            foreach (var c in controllers.Values) c.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Orders the services that (transitively) depend on <paramref name="root"/> so that each comes after every service in the
    /// set it depends on: by the longest dependency path from the root. Reverse the list to stop them.
    /// </summary>
    /// <param name="activeDependents">Direct, running dependents of a service (by service name).</param>
    internal static List<string> DependentStartOrder(string root, Func<string, IEnumerable<string>> activeDependents)
    {
        var children = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var depth = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase) { [root] = 0 };
        var queue = new Queue<string>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var name = queue.Dequeue();
            var d = depth[name];
            if (d > 64) throw new InvalidOperationException($"The dependency chain of service {root} is too deep (circular dependency?).");
            if (!children.TryGetValue(name, out var kids)) children[name] = kids = activeDependents(name).ToList();
            foreach (var kid in kids)
            {
                if (string.Equals(kid, root, StringComparison.OrdinalIgnoreCase)) continue;
                if (!depth.TryGetValue(kid, out var current) || current < d + 1)
                {
                    depth[kid] = d + 1;
                    queue.Enqueue(kid);
                }
            }
        }
        return depth.Where(kv => !string.Equals(kv.Key, root, StringComparison.OrdinalIgnoreCase))
            .OrderBy(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Select(kv => kv.Key).ToList();
    }

    [SupportedOSPlatform("windows")]
    private static void StopAndWait(DeploymentContext ctx, ServiceController sc, TimeSpan wait, CancellationToken ct)
    {
        sc.Refresh();
        if (sc.Status == ServiceControllerStatus.Stopped) return;
        if (sc.Status != ServiceControllerStatus.StopPending)
        {
            ctx.Log.Info($"Stopping service {sc.ServiceName}");
            sc.Stop();
        }
        WaitForStatus(sc, ServiceControllerStatus.Stopped, wait, ct);
    }

    [SupportedOSPlatform("windows")]
    private static void StartAndWait(DeploymentContext ctx, ServiceController sc, TimeSpan wait, CancellationToken ct)
    {
        sc.Refresh();
        if (sc.Status == ServiceControllerStatus.Running) return;
        if (sc.Status == ServiceControllerStatus.StopPending) WaitForStatus(sc, ServiceControllerStatus.Stopped, wait, ct);
        if (sc.Status != ServiceControllerStatus.StartPending)
        {
            ctx.Log.Info($"Starting service {sc.ServiceName}");
            sc.Start();
        }
        WaitForStatus(sc, ServiceControllerStatus.Running, wait, ct);
    }

    /// <summary>Waits for the status in short slices so cancellation is noticed within about a second.</summary>
    [SupportedOSPlatform("windows")]
    private static void WaitForStatus(ServiceController sc, ServiceControllerStatus status, TimeSpan timeout, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                sc.Refresh();
                if (sc.Status == status) return;
                throw new System.ServiceProcess.TimeoutException($"Service '{sc.ServiceName}' did not reach {status} within {timeout.TotalSeconds:0}s (currently {sc.Status})");
            }
            try
            {
                sc.WaitForStatus(status, remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1));
                return;
            }
            catch (System.ServiceProcess.TimeoutException) { /* keep waiting */ }
            if (status == ServiceControllerStatus.Running && sc.Status == ServiceControllerStatus.Stopped)
                throw new InvalidOperationException($"Service '{sc.ServiceName}' stopped while starting. Check the System event log.");
        }
    }
}

/// <summary>Pause between tasks.</summary>
public class WaitTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.Wait",
        Title = "Wait For N Seconds",
        DefaultTitle = "Wait",
        Description = "Pause for a number of seconds before the next task, e.g. to let a service finish restarting.",
        IsPreRequestCapable = true,
        ProviderParameters = { new ProviderParameter { Key = "duration", Name = "Seconds", Type = OptionType.Number, Value = "10", IsRequired = true } }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        if (ctx.Param("duration") is { } d && (!int.TryParse(d, out var s) || s < 0 || s > 3600)) errors.Add(Error("Seconds must be a whole number between 0 and 3600"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var secs = Math.Clamp(ctx.ParamInt("duration") ?? 10, 0, 3600);
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would wait {secs}s");
        ctx.Log.Info($"Waiting {secs}s");
        await Task.Delay(TimeSpan.FromSeconds(secs), ct);
        return ActionResult.Ok($"Waited {secs}s");
    }
}
