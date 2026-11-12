using CertMaster.Core;
using CertMaster.Core.Updates;
using CertMaster.Models;
using CertMaster.Models.Hub;

namespace CertMaster.Server.Core;

/// <summary>Executes commands sent by the management hub against the local engine.</summary>
public class InstanceCommandHandler
{
    private readonly CertManager _m;
    private readonly AgentIdentity _identity;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly ILogger<InstanceCommandHandler> _logger;
    private readonly UpdateManager _updates;

    public InstanceCommandHandler(CertManager m, AgentIdentity identity, IHostApplicationLifetime lifetime, ILogger<InstanceCommandHandler> logger, UpdateManager updates)
    {
        _m = m; _identity = identity; _lifetime = lifetime; _logger = logger; _updates = updates;
    }

    private record IdArg(string Id);
    private record TaskArg(string Id, string TaskId, bool Preview);
    private record DownloadArg(string Id, CertificateDownloadFormat Format);
    private record DownloadResult(string FileName, string ContentType, string Base64);

    public async Task<InstanceCommandResult> HandleAsync(InstanceCommand cmd)
    {
        _logger.LogInformation("Hub command {Command}", cmd.CommandType);
        try
        {
            object? result = cmd.CommandType switch
            {
                InstanceCommands.GetManagedCertificates => await _m.GetManagedCertificatesAsync(Arg<string>(cmd)),
                InstanceCommands.GetManagedCertificate => await _m.GetManagedCertificateAsync(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.UpdateManagedCertificate => await _m.UpdateManagedCertificateAsync(Arg<ManagedCertificate>(cmd)!),
                InstanceCommands.DeleteManagedCertificate => await _m.DeleteManagedCertificateAsync(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.PerformRequest => StartRequest(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.TestConfiguration => await _m.TestConfigurationAsync(Arg<ManagedCertificate>(cmd)!),
                InstanceCommands.RevokeCertificate => await _m.RevokeCertificateAsync(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.GetItemLog => _m.GetItemLog(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.DownloadCertificate => await Download(Arg<DownloadArg>(cmd)!),
                InstanceCommands.GetChallengeProviders => _m.Providers.GetChallengeProviders(),
                InstanceCommands.GetDeploymentProviders => _m.Providers.GetDeploymentProviders(),
                InstanceCommands.GetCredentialTypes => _m.Providers.GetCredentialTypes(),
                InstanceCommands.GetCredentials => await _m.Credentials.GetCredentialsAsync(),
                InstanceCommands.UpdateCredential => await _m.Credentials.UpdateAsync(Arg<StoredCredential>(cmd)!),
                InstanceCommands.DeleteCredential => await _m.Credentials.DeleteAsync(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.GetAccounts => await _m.Acme.GetAccountsAsync(),
                InstanceCommands.AddAccount => await _m.Acme.AddAccountAsync(Arg<NewAccountRequest>(cmd)!),
                InstanceCommands.RemoveAccount => await _m.Acme.RemoveAccountAsync(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.GetCertificateAuthorities => await _m.Acme.GetCertificateAuthoritiesAsync(),
                InstanceCommands.PerformRenewAll => StartRenewAll(),
                InstanceCommands.GetSystemVersion => _identity.GetVersion(),
                InstanceCommands.GeneratePreview => await _m.GeneratePreviewAsync(Arg<ManagedCertificate>(cmd)!),
                InstanceCommands.GetServerStatus => await _m.GetServerStatusAsync(),
                InstanceCommands.GetSites => await _m.GetSitesAsync(),
                InstanceCommands.GetSiteDomains => await _m.GetDomainOptionsFromSiteAsync(Arg<IdArg>(cmd)!.Id),
                InstanceCommands.PerformDeploymentTask => await RunTask(Arg<TaskArg>(cmd)!),
                InstanceCommands.GetUpdateStatus => _updates.GetStatus(),
                InstanceCommands.CheckForUpdates => await _updates.CheckAsync(_lifetime.ApplicationStopping),
                InstanceCommands.InstallUpdate => await _updates.BeginInstallAsync(_lifetime.ApplicationStopping),
                InstanceCommands.GetUpdateSettings => await _updates.GetSettingsAsync(),
                InstanceCommands.SetUpdateSettings => await _updates.SetSettingsAsync(Arg<UpdateSettings>(cmd)!),
                _ => throw new NotSupportedException($"Unknown command {cmd.CommandType}"),
            };
            return new InstanceCommandResult { CommandId = cmd.CommandId, IsSuccess = true, Result = JsonDefaults.Serialize(result) };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Hub command {Command} failed", cmd.CommandType);
            return new InstanceCommandResult { CommandId = cmd.CommandId, IsSuccess = false, Message = ex.Message };
        }
    }

    private static T? Arg<T>(InstanceCommand cmd) => JsonDefaults.Deserialize<T>(cmd.Payload);

    private ActionResult StartRequest(string id)
    {
        if (_m.IsRequestInProgress(id)) return ActionResult.Fail("A request is already in progress");
        _ = Task.Run(() => _m.PerformCertificateRequestAsync(id, _lifetime.ApplicationStopping));
        return ActionResult.Ok("Request started");
    }

    private Task<ActionResult> RunTask(TaskArg a) => _m.PerformDeploymentTaskAsync(a.Id, a.TaskId, a.Preview);

    private ActionResult StartRenewAll()
    {
        _ = Task.Run(() => _m.PerformRenewAllAsync(false, _lifetime.ApplicationStopping));
        return ActionResult.Ok("Renewal of due certificates started");
    }

    private async Task<DownloadResult?> Download(DownloadArg arg)
    {
        var f = await _m.GetCertificateFileAsync(arg.Id, arg.Format);
        return f == null ? null : new DownloadResult(f.Value.fileName, f.Value.contentType, Convert.ToBase64String(f.Value.data));
    }
}
