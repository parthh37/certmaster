using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Dns;

/// <summary>Runs user supplied create/delete scripts. Arguments: {recordName} {value} {zoneId} {domain}.</summary>
public class ScriptDnsProvider : DnsProviderBase
{
    public override ChallengeProviderDefinition Definition { get; } = new()
    {
        Id = "DNS01.Scripting",
        Title = "(Use Custom Script)",
        Description = "Run your own script (.ps1, .bat, .cmd, .sh, .py) to create and delete the TXT record.",
        ChallengeType = ChallengeTypes.Dns01,
        PropagationDelaySeconds = 60,
        ProviderParameters =
        {
            new ProviderParameter { Key = "createscript", Name = "Create Script Path", IsRequired = true, Description = "Receives args: recordName value zoneId domain" },
            new ProviderParameter { Key = "deletescript", Name = "Delete Script Path" },
            new ProviderParameter { Key = "propagationdelay", Name = "Propagation Delay (seconds)", Type = OptionType.Number, Value = "60" },
        }
    };

    private static string? ScriptPath(DnsProviderContext ctx, string key) =>
        ctx.Param(key)?.Trim().Trim('"') is { Length: > 0 } p ? p : null;

    public override Task<ActionResult> TestAsync(DnsProviderContext ctx)
    {
        var s = ScriptPath(ctx, "createscript");
        if (s == null) return Task.FromResult(ActionResult.Fail("Create script path is not set."));
        if (!File.Exists(s)) return Task.FromResult(ActionResult.Fail($"Create script not found: {s}. Check the path exists on the agent machine and is readable by the service account."));
        var d = ScriptPath(ctx, "deletescript");
        if (d != null && !File.Exists(d)) return Task.FromResult(ActionResult.Fail($"Delete script not found: {d}."));
        return Task.FromResult(ActionResult.Ok($"Create script found: {s}"));
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) =>
        Run(ctx, ScriptPath(ctx, "createscript"), recordName, value);

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) =>
        ScriptPath(ctx, "deletescript") is { } d ? Run(ctx, d, recordName, value) : Task.FromResult(ActionResult.Ok("No delete script configured"));

    private Task<ActionResult> Run(DnsProviderContext ctx, string? script, string recordName, string value) => Guard(async () =>
    {
        if (script == null) return ActionResult.Fail("Script path not set");
        if (!File.Exists(script)) return ActionResult.Fail($"Script not found: {script}");
        var name = DnsNames.Normalize(recordName);
        // Only strip the leading label; "_acme-challenge." elsewhere in the name is part of the domain.
        var domain = name.StartsWith("_acme-challenge.", StringComparison.Ordinal) ? name["_acme-challenge.".Length..] : name;
        var r = await ProcessRunner.RunScriptAsync(script, new[] { name, value, ctx.ZoneId ?? "", domain }, null, TimeSpan.FromMinutes(5));
        if (!string.IsNullOrWhiteSpace(r.Output)) ctx.Log?.Info($"Script output: {r.Output.Trim()}");
        if (r.ExitCode != 0 && !string.IsNullOrWhiteSpace(r.Error)) ctx.Log?.Warn($"Script error output: {r.Error.Trim()}");
        return r.ExitCode == 0
            ? ActionResult.Ok($"Script completed: {Path.GetFileName(script)}")
            : ActionResult.Fail($"Script {Path.GetFileName(script)} exited with code {r.ExitCode}: {DnsHttp.Truncate(r.Error, 500)}");
    });
}
