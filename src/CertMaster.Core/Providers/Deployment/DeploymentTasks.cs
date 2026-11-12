using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Export the certificate to a file in various formats (local or UNC path).</summary>
public class CertificateExportTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.CertificateExport",
        Title = "Export Certificate",
        DefaultTitle = "Export Certificate",
        Description = "Copy the certificate to a file path as PFX or PEM (local folder or UNC share).",
        ProviderParameters =
        {
            new ProviderParameter { Key = "path", Name = "Destination File Path", IsRequired = true, Description = "e.g. C:\\certs\\site.pfx or \\\\server\\share\\site.pem" },
            new ProviderParameter { Key = "type", Name = "Export As", Type = OptionType.Select, Value = "pfxfull", IsRequired = true,
                OptionsList = "pfxfull=PFX (with chain);pemfull=PEM - Full Chain + Key;pemcrt=PEM - Certificate Only;pemchain=PEM - Full Chain (no key);pemkey=PEM - Private Key Only" },
        }
    };

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var dest = ctx.Param("path")!;
        var type = ctx.Param("type") ?? "pfxfull";
        if (ctx.IsPreviewOnly) return ActionResult.Ok($"Would export {type} to {dest}");
        if (!ctx.Files.Exists) return ActionResult.Fail("Certificate files not found. Request the certificate first.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(dest))!);
        switch (type)
        {
            case "pfxfull": File.Copy(ctx.Files.Pfx, dest, true); break;
            case "pemfull":
                await File.WriteAllTextAsync(dest, await File.ReadAllTextAsync(ctx.Files.FullChainPem, ct) + await File.ReadAllTextAsync(ctx.Files.KeyPem, ct), ct); break;
            case "pemcrt": File.Copy(ctx.Files.CertPem, dest, true); break;
            case "pemchain": File.Copy(ctx.Files.FullChainPem, dest, true); break;
            case "pemkey": File.Copy(ctx.Files.KeyPem, dest, true); break;
            default: return ActionResult.Fail($"Unknown export type {type}");
        }
        return ActionResult.Ok($"Exported {type} to {dest}");
    }
}

/// <summary>Import the certificate into the Windows certificate store (LocalMachine).</summary>
public class WindowsCertificateStoreTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.CertificateStore",
        Title = "Windows Certificate Store",
        DefaultTitle = "Store in Windows Certificate Store",
        Description = "Import the certificate into the Local Machine certificate store (for IIS, RDP, Exchange, SQL Server etc).",
        ProviderParameters =
        {
            new ProviderParameter { Key = "store", Name = "Store", Type = OptionType.Select, Value = "My", OptionsList = "My=Personal (My);WebHosting=Web Hosting" },
            new ProviderParameter { Key = "removeprevious", Name = "Remove previous certificate", Type = OptionType.Boolean, Value = "false" },
        }
    };

    public override Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(ActionResult.Fail("Windows certificate store is only available on Windows."));
        var storeName = ctx.Param("store") ?? "My";
        if (ctx.IsPreviewOnly) return Task.FromResult(ActionResult.Ok($"Would import certificate into LocalMachine\\{storeName}"));
        if (!ctx.Files.Exists) return Task.FromResult(ActionResult.Fail("Certificate files not found."));

        var cert = X509CertificateLoader.LoadPkcs12FromFile(ctx.Files.Pfx, ctx.Files.PfxPassword,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        cert.FriendlyName = $"{ctx.Item.Name} [CertMaster] {cert.NotBefore:yyyyMMdd} to {cert.NotAfter:yyyyMMdd}";
        using var store = new X509Store(storeName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert);
        if (ctx.Param("removeprevious") == "true" && !string.IsNullOrEmpty(ctx.Item.CertificatePreviousThumbprintHash))
        {
            foreach (var old in store.Certificates.Find(X509FindType.FindByThumbprint, ctx.Item.CertificatePreviousThumbprintHash, false))
                if (old.Thumbprint != cert.Thumbprint) store.Remove(old);
        }
        return Task.FromResult(ActionResult.Ok($"Imported {cert.Thumbprint} into LocalMachine\\{storeName}"));
    }
}

/// <summary>Run a PowerShell / batch / shell script with certificate details passed as environment variables.</summary>
public class ScriptTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.PowershellScript",
        Title = "Run Script",
        DefaultTitle = "Run Script",
        Description = "Run a .ps1/.bat/.cmd/.sh/.py script. Certificate details are passed as CERT_* environment variables and a JSON file path (CERT_RESULT_JSON).",
        IsPreRequestCapable = true,
        ProviderParameters =
        {
            new ProviderParameter { Key = "scriptpath", Name = "Script Path", IsRequired = true },
            new ProviderParameter { Key = "args", Name = "Arguments (optional, supports {placeholders})" },
            new ProviderParameter { Key = "timeout", Name = "Timeout (minutes)", Type = OptionType.Number, Value = "5" },
        }
    };

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var script = ctx.Param("scriptpath")!;
        if (!File.Exists(script)) return ActionResult.Fail($"Script not found: {script}");
        if (ctx.IsPreviewOnly) return ActionResult.Ok($"Would run {script}");

        var resultJson = Path.Combine(Path.GetTempPath(), $"certmaster_{ctx.Item.Id}.json");
        await File.WriteAllTextAsync(resultJson, JsonDefaults.Serialize(new { ctx.Item, IsSuccess = ctx.RequestSucceeded, Message = ctx.RequestMessage }), ct);
        var env = new Dictionary<string, string>
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
        var args = (ctx.Param("args") is { } a ? ctx.Expand(a) : "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var timeout = TimeSpan.FromMinutes(double.TryParse(ctx.Param("timeout"), out var m) ? m : 5);
        try
        {
            var r = await ProcessRunner.RunScriptAsync(script, args, env, timeout, ct);
            if (!string.IsNullOrWhiteSpace(r.Output)) ctx.Log.Info("Script output: " + r.Output.Trim());
            return r.ExitCode == 0 ? ActionResult.Ok("Script completed") : ActionResult.Fail($"Script exit code {r.ExitCode}. {r.Error.Trim()}");
        }
        finally { try { File.Delete(resultJson); } catch { /* ignore */ } }
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
        Description = "Send an HTTP request. Body supports {ManagedItemId} {Name} {PrimaryDomain} {Thumbprint} {DateExpiry} {IsSuccess} {Message}.",
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

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var url = ctx.Expand(ctx.Param("url")!);
        if (ctx.IsPreviewOnly) return ActionResult.Ok($"Would call {url}");
        var req = new HttpRequestMessage(new HttpMethod(ctx.Param("method") ?? "POST"), url);
        if (req.Method != HttpMethod.Get)
            req.Content = new StringContent(ctx.Expand(ctx.Param("body") ?? ""), Encoding.UTF8, ctx.Param("contenttype") ?? "application/json");
        using var resp = await ctx.Http.SendAsync(req, ct);
        return resp.IsSuccessStatusCode ? ActionResult.Ok($"Webhook returned {(int)resp.StatusCode}") : ActionResult.Fail($"Webhook returned {(int)resp.StatusCode}");
    }
}

/// <summary>Start, stop or restart a Windows service.</summary>
public class ServiceManagerTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.ServiceManager",
        Title = "Stop, Start or Restart a Service",
        DefaultTitle = "Restart Service",
        Description = "Control a local Windows service, e.g. restart a service that loads the certificate at startup.",
        ProviderParameters =
        {
            new ProviderParameter { Key = "servicename", Name = "Service Name", IsRequired = true },
            new ProviderParameter { Key = "action", Name = "Action", Type = OptionType.Select, Value = "restart", OptionsList = "restart=Restart;stop=Stop;start=Start" },
            new ProviderParameter { Key = "maxwait", Name = "Max wait (seconds)", Type = OptionType.Number, Value = "60" },
        }
    };

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return ActionResult.Fail("Service control is only implemented on Windows.");
        var name = ctx.Param("servicename")!;
        var action = ctx.Param("action") ?? "restart";
        if (ctx.IsPreviewOnly) return ActionResult.Ok($"Would {action} service {name}");
        var wait = TimeSpan.FromSeconds(int.TryParse(ctx.Param("maxwait"), out var s) ? s : 60);
        var status = await Task.Run(() => Control(name, action, wait), ct);
        return ActionResult.Ok($"Service {name}: {action} completed ({status})");
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string Control(string name, string action, TimeSpan wait)
    {
        using var sc = new ServiceController(name);
        if ((action is "stop" or "restart") && sc.Status != ServiceControllerStatus.Stopped)
        { sc.Stop(); sc.WaitForStatus(ServiceControllerStatus.Stopped, wait); }
        if (action is "start" or "restart")
        { sc.Start(); sc.WaitForStatus(ServiceControllerStatus.Running, wait); }
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
        Title = "Wait",
        DefaultTitle = "Wait",
        Description = "Wait for a number of seconds before continuing.",
        IsPreRequestCapable = true,
        ProviderParameters = { new ProviderParameter { Key = "duration", Name = "Seconds", Type = OptionType.Number, Value = "10", IsRequired = true } }
    };

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var secs = int.TryParse(ctx.Param("duration"), out var s) ? s : 10;
        if (!ctx.IsPreviewOnly) await Task.Delay(TimeSpan.FromSeconds(secs), ct);
        return ActionResult.Ok($"Waited {secs}s");
    }
}
