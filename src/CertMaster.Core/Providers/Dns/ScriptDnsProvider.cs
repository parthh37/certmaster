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

    public override Task<ActionResult> TestAsync(DnsProviderContext ctx)
    {
        var s = ctx.Param("createscript");
        return Task.FromResult(s != null && File.Exists(s) ? ActionResult.Ok($"Create script found: {s}") : ActionResult.Fail($"Create script not found: {s}"));
    }

    public override Task<ActionResult> CreateRecordAsync(DnsProviderContext ctx, string recordName, string value) =>
        Run(ctx, ctx.Param("createscript"), recordName, value);

    public override Task<ActionResult> DeleteRecordAsync(DnsProviderContext ctx, string recordName, string value) =>
        ctx.Param("deletescript") == null ? Task.FromResult(ActionResult.Ok("No delete script configured")) : Run(ctx, ctx.Param("deletescript"), recordName, value);

    private static async Task<ActionResult> Run(DnsProviderContext ctx, string? script, string recordName, string value)
    {
        if (script == null) return ActionResult.Fail("Script path not set");
        var domain = recordName.Replace("_acme-challenge.", "");
        var r = await ProcessRunner.RunScriptAsync(script, new[] { recordName, value, ctx.ZoneId ?? "", domain }, null, TimeSpan.FromMinutes(5));
        ctx.Log?.Info($"Script output: {r.Output.Trim()}");
        return r.ExitCode == 0 ? ActionResult.Ok($"Script completed: {Path.GetFileName(script)}") : ActionResult.Fail($"Script exited with code {r.ExitCode}: {r.Error.Trim()}");
    }
}
