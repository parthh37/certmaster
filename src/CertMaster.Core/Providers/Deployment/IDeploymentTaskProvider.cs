using CertMaster.Core.Storage;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Files produced for a managed certificate after a successful request.</summary>
public class CertificateFiles
{
    public required string Folder { get; init; }
    public string Pfx => Path.Combine(Folder, "certificate.pfx");
    public string FullChainPem => Path.Combine(Folder, "fullchain.pem");
    public string CertPem => Path.Combine(Folder, "cert.pem");
    public string ChainPem => Path.Combine(Folder, "chain.pem");
    public string KeyPem => Path.Combine(Folder, "privkey.pem");
    public string? PfxPassword { get; init; }
    public bool Exists => File.Exists(Pfx);
}

public class DeploymentContext
{
    public required ManagedCertificate Item { get; init; }
    public required DeploymentTaskConfig Task { get; init; }
    public required CertificateFiles Files { get; init; }
    public required Dictionary<string, string> Parameters { get; init; }
    /// <summary>Unlocked values of the task's stored credential (DeploymentTaskConfig.ChallengeCredentialKey): API credential or target (Windows/SSH) credential.</summary>
    public required Dictionary<string, string> Credentials { get; init; }
    public required ItemLog Log { get; init; }
    public required HttpClient Http { get; init; }
    public bool IsPreviewOnly { get; init; }
    /// <summary>Outcome of the certificate request that triggered this task (null for manual runs).</summary>
    public bool? RequestSucceeded { get; init; }
    public string? RequestMessage { get; init; }

    /// <summary>Where the task runs (from the task config).</summary>
    public DeploymentContextType TargetType => Task.TargetType;
    /// <summary>Remote host for SSH targets, host or host:port (from the task config).</summary>
    public string? TargetHost => Task.TargetHost;

    /// <summary>
    /// Unlocks another stored credential by storage key, for tasks that need a second secret (e.g. a new PFX password).
    /// Returns an empty dictionary when the key is blank or not found.
    /// </summary>
    public Func<string?, Task<Dictionary<string, string>>> UnlockCredentialAsync { get; init; } = _ => System.Threading.Tasks.Task.FromResult(new Dictionary<string, string>());

    public string? Param(string key) => Parameters.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;

    public bool ParamBool(string key, bool defaultValue = false) =>
        Param(key) is { } v ? v.Trim().ToLowerInvariant() is "true" or "1" or "yes" or "on" : defaultValue;

    public int? ParamInt(string key) => int.TryParse(Param(key), out var i) ? i : null;

    /// <summary>
    /// Private folder for temporary files handed to scripts (result/argument JSON). Null = <see cref="DefaultScriptTempFolder"/>
    /// (temp under the agent data folder). The folder is restricted to SYSTEM, Administrators and the agent account before use.
    /// </summary>
    public string? ScriptTempFolder { get; init; }

    /// <summary>The agent data folder's "temp" subfolder (CERTMASTER_DATA, else %ProgramData%\CertMaster), never the shared system temp folder.</summary>
    public static string DefaultScriptTempFolder()
    {
        var root = Environment.GetEnvironmentVariable("CERTMASTER_DATA") is { Length: > 0 } data ? data
            : OperatingSystem.IsWindows() ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CertMaster")
            : "/var/lib/certmaster";
        return Path.Combine(root, "temp");
    }

    /// <summary>Replaces {placeholders} with certificate values.</summary>
    public string Expand(string text) => Expand(text, static v => v);

    /// <summary>
    /// Replaces {placeholders} with certificate values passed through <paramref name="encode"/>, e.g. JSON string escaping for a
    /// JSON body (see <see cref="JsonStringEncoder"/>) or <see cref="Uri.EscapeDataString(string)"/> for a URL, so values with quotes,
    /// backslashes, newlines or reserved characters can't break the surrounding syntax.
    /// </summary>
    public string Expand(string text, Func<string, string> encode) => text
        .Replace("{ManagedItemId}", encode(Item.Id)).Replace("{Name}", encode(Item.Name))
        .Replace("{PrimaryDomain}", encode(Item.RequestConfig.PrimaryDomain))
        .Replace("{Thumbprint}", encode(Item.CertificateThumbprintHash ?? ""))
        .Replace("{CertificatePath}", encode(Item.CertificatePath ?? ""))
        .Replace("{DateExpiry}", encode(Item.DateExpiry?.ToString("O") ?? ""))
        .Replace("{IsSuccess}", encode((RequestSucceeded ?? true).ToString().ToLowerInvariant()))
        .Replace("{Message}", encode(RequestMessage ?? ""));

    /// <summary>Escapes a value for use inside a JSON string literal (no surrounding quotes are added).</summary>
    public static string JsonStringEncoder(string value) =>
        System.Text.Json.JsonEncodedText.Encode(value, System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString();
}

public interface IDeploymentTaskProvider
{
    DeploymentProviderDefinition Definition { get; }
    Task<List<ActionStep>> ValidateAsync(DeploymentContext ctx);
    Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct);
}

public abstract class DeploymentTaskProviderBase : IDeploymentTaskProvider
{
    public abstract DeploymentProviderDefinition Definition { get; }
    public abstract Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct);

    /// <summary>
    /// Checks required parameters, the stored credential (when the definition names a credential type), the selected
    /// target (type/host/credentials) and then task-specific rules from <see cref="ValidateTask"/>.
    /// </summary>
    public virtual Task<List<ActionStep>> ValidateAsync(DeploymentContext ctx)
    {
        var errors = Definition.ProviderParameters
            .Where(p => p.IsRequired && !p.IsCredential && ctx.Param(p.Key) == null)
            .Select(p => new ActionStep($"{p.Name} is required", hasError: true)).ToList();
        if (Definition.CredentialType != null && ctx.Credentials.Count == 0)
            errors.Add(new ActionStep("A stored credential is required for this task", hasError: true));
        errors.AddRange(DeploymentTargets.Validate(Definition, ctx));
        try { ValidateTask(ctx, errors); }
        catch (Exception ex) { errors.Add(new ActionStep("Validation failed: " + ex.Message, hasError: true)); }
        return Task.FromResult(errors);
    }

    /// <summary>Task-specific validation; add <see cref="ActionStep"/>s with HasError for invalid settings.</summary>
    protected virtual void ValidateTask(DeploymentContext ctx, List<ActionStep> errors) { }

    protected static ActionStep Error(string message) => new(message, hasError: true);

    /// <summary>Logs and returns a preview (no changes made) result.</summary>
    protected static ActionResult Preview(DeploymentContext ctx, string message)
    {
        ctx.Log.Info("[Preview] " + message);
        return ActionResult.Ok("Preview: " + message);
    }

    /// <summary>Logs and returns a failure.</summary>
    protected static ActionResult Fail(DeploymentContext ctx, string message)
    {
        ctx.Log.Error(message);
        return ActionResult.Fail(message);
    }

    /// <summary>Logs and returns a success.</summary>
    protected static ActionResult Ok(DeploymentContext ctx, string message)
    {
        ctx.Log.Info(message);
        return ActionResult.Ok(message);
    }

    /// <summary>Logs and returns a completed-with-warning result (the task did not fail, but needs attention).</summary>
    protected static ActionResult Warn(DeploymentContext ctx, string message)
    {
        ctx.Log.Warn(message);
        return ActionResult.Warn(message);
    }

    /// <summary>
    /// Runs the task body, turning expected failures (I/O, access denied, SSH/network, crypto, cloud API errors) into a
    /// failed <see cref="ActionResult"/> with a readable message instead of an exception. Cancellation is rethrown.
    /// </summary>
    protected static async Task<ActionResult> Guard(DeploymentContext ctx, string action, Func<Task<ActionResult>> body, CancellationToken ct)
    {
        try { return await body(); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return Fail(ctx, $"{action} failed: {DescribeError(ex)}"); }
    }

    /// <summary>Maps common exceptions to actionable messages.</summary>
    public static string DescribeError(Exception ex) => ex switch
    {
        Renci.SshNet.Common.SshAuthenticationException => "SSH authentication failed. Check the username, password or private key in the stored credential.",
        Renci.SshNet.Common.SshConnectionException e => $"SSH connection error: {e.Message}",
        Renci.SshNet.Common.SftpPermissionDeniedException e => $"Permission denied on the remote host ({e.Message}). Check the SSH user's rights on the destination folder.",
        Renci.SshNet.Common.SftpPathNotFoundException e => $"Remote path not found ({e.Message}).",
        Renci.SshNet.Common.SshOperationTimeoutException => "The SSH operation timed out.",
        System.Net.Sockets.SocketException e => $"Could not connect to the target host: {e.Message}",
        UnauthorizedAccessException e => $"Access denied: {e.Message} Check that the account used has write permission.",
        System.ComponentModel.Win32Exception e => e.Message,
        HttpRequestException e => $"HTTP request failed: {e.Message}",
        TaskCanceledException => "The operation timed out.",
        Azure.Identity.AuthenticationFailedException e => $"Azure authentication failed (check tenant id, client id and client secret): {FirstLine(e.Message)}",
        Azure.RequestFailedException e => $"Azure returned {e.Status} {e.ErrorCode}: {FirstLine(e.Message)}",
        AggregateException { InnerException: { } inner } => DescribeError(inner),
        _ => ex.Message,
    };

    private static string FirstLine(string s) => s.Split('\n', 2)[0].Trim();

    /// <summary>Fails when no certificate has been issued yet (the files do not exist).</summary>
    protected static ActionResult? RequireCertificateFiles(DeploymentContext ctx) =>
        ctx.Files.Exists ? null : Fail(ctx, $"Certificate files not found in {ctx.Files.Folder}. Request the certificate before running this task.");
}
