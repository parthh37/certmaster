using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.Json;
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
            var cert = X509CertificateLoader.LoadPkcs12FromFile(ctx.Files.Pfx, ctx.Files.PfxPassword,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            cert.FriendlyName = $"{ctx.Item.Name} [CertMaster] {cert.NotBefore:yyyyMMdd} to {cert.NotAfter:yyyyMMdd}";
            using var store = new X509Store(storeName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            var removed = 0;
            if (removePrevious && !string.IsNullOrEmpty(ctx.Item.CertificatePreviousThumbprintHash))
            {
                foreach (var old in store.Certificates.Find(X509FindType.FindByThumbprint, ctx.Item.CertificatePreviousThumbprintHash, false))
                    if (old.Thumbprint != cert.Thumbprint) { store.Remove(old); removed++; }
            }
            return Task.FromResult(Ok(ctx, $"Imported {cert.Thumbprint} into LocalMachine\\{storeName}" + (removed > 0 ? $"; removed {removed} previous certificate(s)" : "")));
        }, ct);
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

        var tempDir = Path.Combine(Path.GetTempPath(), "CertMaster");
        Directory.CreateDirectory(tempDir);
        var id = Guid.NewGuid().ToString("N")[..12];
        var resultJson = Path.Combine(tempDir, $"result_{id}.json");
        var argsJson = Path.Combine(tempDir, $"args_{id}.json");
        return await Guard(ctx, "Script", async () =>
        {
            try
            {
                await File.WriteAllTextAsync(resultJson, JsonDefaults.Serialize(new { ManagedItem = ctx.Item, IsSuccess = ctx.RequestSucceeded ?? true, Message = ctx.RequestMessage }), ct);
                var env = BuildEnvironment(ctx, resultJson);

                CommandSpec spec;
                if (Path.GetExtension(script).Equals(".ps1", StringComparison.OrdinalIgnoreCase))
                {
                    var payload = new
                    {
                        named = args.Where(x => x.Name != null).ToDictionary(x => x.Name!.TrimStart('-'), x => x.Value),
                        positional = args.Where(x => x.Name == null).Select(x => x.Value).ToList(),
                    };
                    await File.WriteAllTextAsync(argsJson, JsonSerializer.Serialize(payload), ct);
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
                try { File.Delete(resultJson); } catch { /* ignore */ }
                try { File.Delete(argsJson); } catch { /* ignore */ }
            }
        }, ct);
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
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
        if (ctx.Param("url") is { } u && (!Uri.TryCreate(ctx.Expand(u), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")))
            errors.Add(Error($"URL must be an absolute http(s) address: {u}"));
        if (ctx.Param("method") is { } m && m.ToUpperInvariant() is not ("POST" or "PUT" or "GET"))
            errors.Add(Error($"Unsupported method {m}"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var url = ctx.Expand(ctx.Param("url")!);
        var method = (ctx.Param("method") ?? "POST").ToUpperInvariant();
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would send {method} {url}");
        return await Guard(ctx, "Webhook", async () =>
        {
            using var req = new HttpRequestMessage(new HttpMethod(method), url);
            if (req.Method != HttpMethod.Get)
                req.Content = new StringContent(ctx.Expand(ctx.Param("body") ?? ""), Encoding.UTF8, ctx.Param("contenttype") ?? "application/json");
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
        if (ctx.Param("servicename") is { } n && IsAgentService(n) && action != "start")
            errors.Add(Error($"Refusing to {action} the {AgentServiceName} service: it is running this task."));
        if (!OperatingSystem.IsWindows()) errors.Add(Error("Service control is only implemented on Windows."));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Fail(ctx, "Service control is only implemented on Windows.");
        var name = ctx.Param("servicename")!.Trim();
        var action = ctx.Param("action") ?? "restart";
        if (ctx.IsPreviewOnly) return Preview(ctx, $"Would {action} service '{name}'");
        var wait = TimeSpan.FromSeconds(Math.Clamp(ctx.ParamInt("maxwait") ?? 60, 1, 3600));
        try
        {
            var status = await Task.Run(() => OperatingSystem.IsWindows() ? Control(ctx, name, action, wait) : throw new PlatformNotSupportedException(), ct);
            return Ok(ctx, $"Service {name}: {action} completed ({status})");
        }
        catch (InvalidOperationException ex) { return Fail(ctx, $"Could not {action} service '{name}': {ex.InnerException?.Message ?? ex.Message}"); }
        catch (System.ServiceProcess.TimeoutException) { return Fail(ctx, $"Service '{name}' did not reach the expected state within {wait.TotalSeconds:0}s"); }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string Control(DeploymentContext ctx, string name, string action, TimeSpan wait)
    {
        using var sc = new ServiceController(name);
        _ = sc.Status; // throws InvalidOperationException when the service does not exist
        if (action != "start" && (IsAgentService(sc.ServiceName) || IsAgentService(sc.DisplayName)))
            throw new InvalidOperationException($"Refusing to {action} the {AgentServiceName} service: it is running this task.");
        if (action is "stop" or "restart" && sc.Status != ServiceControllerStatus.Stopped)
        {
            ctx.Log.Info($"Stopping service {sc.ServiceName}");
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, wait);
        }
        if (action is "start" or "restart")
        {
            sc.Refresh();
            if (sc.Status != ServiceControllerStatus.Running)
            {
                ctx.Log.Info($"Starting service {sc.ServiceName}");
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, wait);
            }
        }
        sc.Refresh();
        return sc.Status.ToString();
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
