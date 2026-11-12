using CertMaster.Core;
using CertMaster.Core.Acme;
using CertMaster.Core.Challenges;
using CertMaster.Core.Providers;
using CertMaster.Core.Storage;
using CertMaster.Core.Util;
using CertMaster.Models;
using CertMaster.Server.Core;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace CertMaster.Tests.Core;

/// <summary>Saves, deletes and task results around a running certificate request.</summary>
public sealed class RequestSafetyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"));
    private readonly CertManager _manager;

    public RequestSafetyTests()
    {
        var paths = new DataPaths(_root);
        var store = new DocumentStore(paths.Database);
        _manager = new CertManager(store, new CredentialsManager(store, new SecretProtector(paths)),
            new AcmeService(store, NullLogger<AcmeService>.Instance), new ProviderRegistry(),
            new HttpChallengeServer(NullLogger<HttpChallengeServer>.Instance), paths, NullLogger<CertManager>.Instance);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_root, true); } catch { /* best effort */ }
    }

    private static DeploymentTaskConfig Task(string type, string name, params (string Key, string Value)[] parameters) => new()
    {
        TaskTypeId = type, TaskName = name, TaskTrigger = TaskTriggerType.ON_SUCCESS,
        Parameters = parameters.Select(p => new ProviderParameterSetting(p.Key, p.Value)).ToList(),
    };

    private async Task<ManagedCertificate> SaveAsync(ManagedCertificate item)
    {
        var r = await _manager.UpdateManagedCertificateAsync(item);
        Assert.True(r.IsSuccess, r.Message);
        return r.Result!;
    }

    [Fact]
    public async Task Save_delete_and_task_runs_are_refused_while_a_request_is_running()
    {
        // A long pre-request wait keeps the request running without contacting a CA.
        var item = await SaveAsync(new ManagedCertificate
        {
            Name = "busy", RequestConfig = { PrimaryDomain = "busy.example.test" },
            PreRequestTasks = { Task("CertMaster.Deploy.Wait", "Wait", ("duration", "60")) },
        });

        using var cts = new CancellationTokenSource();
        var request = _manager.PerformCertificateRequestAsync(item.Id, cts.Token);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!_manager.IsRequestInProgress(item.Id) && DateTime.UtcNow < deadline) await System.Threading.Tasks.Task.Delay(20);
        Assert.True(_manager.IsRequestInProgress(item.Id));

        item.Comments = "edited during the request";
        var save = await _manager.UpdateManagedCertificateAsync(item);
        Assert.False(save.IsSuccess);
        Assert.Contains("in progress", save.Message);

        var delete = await Assert.ThrowsAsync<InvalidOperationException>(() => _manager.DeleteManagedCertificateAsync(item.Id));
        Assert.Contains("in progress", delete.Message);

        var run = await _manager.PerformDeploymentTaskAsync(item.Id, item.PreRequestTasks[0].Id, previewOnly: false);
        Assert.False(run.IsSuccess);
        Assert.Contains("in progress", run.Message);

        cts.Cancel();
        await request;
        Assert.False(_manager.IsRequestInProgress(item.Id));

        // Once the request has finished, the same save goes through.
        var after = await _manager.UpdateManagedCertificateAsync(item);
        Assert.True(after.IsSuccess, after.Message);
        Assert.Equal("edited during the request", (await _manager.GetManagedCertificateAsync(item.Id))!.Comments);
    }

    [Fact]
    public async Task A_task_warning_is_recorded_as_a_warning()
    {
        if (!OperatingSystem.IsWindows()) return;
        var item = await SaveAsync(new ManagedCertificate
        {
            Name = "warn", RequestConfig = { PrimaryDomain = "warn.example.test" },
            PostRequestTasks = { Task("CertMaster.Deploy.ServiceManager", "Restart agent", ("servicename", ServiceManagerTaskName), ("action", "restart")) },
        });
        var taskId = item.PostRequestTasks[0].Id;

        var r = await _manager.PerformDeploymentTaskAsync(item.Id, taskId, previewOnly: false);
        Assert.True(r.IsSuccess);
        Assert.True(r.IsWarning);
        Assert.Contains("Skipped", r.Message);

        var stored = (await _manager.GetManagedCertificateAsync(item.Id))!.PostRequestTasks.Single();
        Assert.Equal(RequestState.Warning, stored.LastRunStatus);
    }

    private const string ServiceManagerTaskName = CertMaster.Core.Providers.Deployment.ServiceManagerTask.AgentServiceName;
}

/// <summary>Crash-safe settings files: the instance id, local API key and the files behind them.</summary>
public sealed class SettingsFileTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "certmaster-tests-" + Guid.NewGuid().ToString("N"));

    public SettingsFileTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { /* best effort */ } }

    private string F(string name) => Path.Combine(_dir, name);

    [Fact]
    public void Write_keeps_the_previous_version_as_backup_and_leaves_no_temp_file()
    {
        var file = F("s.json");
        AtomicFile.WriteAllText(file, "one");
        AtomicFile.WriteAllText(file, "two");
        Assert.Equal("two", File.ReadAllText(file));
        Assert.Equal("one", File.ReadAllText(AtomicFile.BackupPath(file)));
        Assert.False(File.Exists(file + ".tmp"));
    }

    [Fact]
    public void Read_falls_back_to_the_backup_when_the_file_is_empty_or_damaged()
    {
        var file = F("s.json");
        AtomicFile.WriteAllText(file, "good");
        AtomicFile.WriteAllText(file, "good2");
        File.WriteAllText(file, "");
        Assert.Equal("good", AtomicFile.Read(file, s => s, out var fromBackup));
        Assert.True(fromBackup);

        File.WriteAllText(file, "garbage");
        Assert.Equal("good", AtomicFile.Read(file, s => s == "garbage" ? null : s, out _));
    }

    [Fact]
    public void Instance_id_is_created_once_and_kept()
    {
        var file = F("instance.json");
        var first = AgentIdentity.LoadOrCreateIdentity(file);
        Assert.Equal(first.InstanceId, AgentIdentity.LoadOrCreateIdentity(file).InstanceId);
    }

    [Fact]
    public void Empty_instance_file_is_recovered_from_backup_not_replaced()
    {
        var file = F("instance.json");
        var original = AgentIdentity.LoadOrCreateIdentity(file);
        AtomicFile.WriteAllText(file, JsonDefaults.Serialize(original)); // creates the .bak
        File.WriteAllText(file, ""); // e.g. truncated by a crash

        Assert.Equal(original.InstanceId, AgentIdentity.LoadOrCreateIdentity(file).InstanceId);
        Assert.Contains(original.InstanceId, File.ReadAllText(file)); // repaired
    }

    [Fact]
    public void Unreadable_instance_file_without_backup_stops_startup_and_is_left_alone()
    {
        var file = F("instance.json");
        File.WriteAllText(file, "");
        var ex = Assert.Throws<InvalidOperationException>(() => AgentIdentity.LoadOrCreateIdentity(file));
        Assert.Contains("could not be read", ex.Message);
        Assert.Equal("", File.ReadAllText(file));

        File.WriteAllText(file, "{ not json");
        Assert.Throws<InvalidOperationException>(() => AgentIdentity.LoadOrCreateIdentity(file));
        Assert.Equal("{ not json", File.ReadAllText(file));
    }

    [Fact]
    public void Api_key_is_kept_and_recovered_from_backup()
    {
        var file = F("agent-api.key");
        var key = AgentIdentity.LoadOrCreateApiKey(file);
        Assert.Equal(64, key.Length);
        Assert.Equal(key, AgentIdentity.LoadOrCreateApiKey(file));

        AtomicFile.WriteAllText(file, key); // creates the .bak
        File.WriteAllText(file, "");
        Assert.Equal(key, AgentIdentity.LoadOrCreateApiKey(file));
    }
}
