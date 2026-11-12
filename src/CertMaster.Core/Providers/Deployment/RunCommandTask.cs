using CertMaster.Core.Util;
using CertMaster.Models;

namespace CertMaster.Core.Providers.Deployment;

/// <summary>Run a program, batch file or script locally, as another Windows user, or on a remote host over SSH.</summary>
public class RunCommandTask : DeploymentTaskProviderBase
{
    public override DeploymentProviderDefinition Definition { get; } = new()
    {
        Id = "CertMaster.Deploy.RunCommand",
        Title = "Run...",
        DefaultTitle = "Run Program",
        Description = "Run an executable, batch file or script with arguments, on this machine or on a remote host over SSH. " +
                      "Optionally launch it as a separate process without waiting for it to finish.",
        IsPreRequestCapable = true,
        SupportsRemoteTarget = true,
        SupportedTargets = new() { DeploymentContextType.LocalAsService, DeploymentContextType.LocalAsUser, DeploymentContextType.SSH },
        ProviderParameters =
        {
            new ProviderParameter { Key = "path", Name = "Program / Command", IsRequired = true, Description = "e.g. C:\\tools\\reload.bat, notepad.exe, or /usr/sbin/nginx for SSH targets" },
            new ProviderParameter { Key = "args", Name = "Arguments (optional)", Description = "Passed as typed. Supports {PrimaryDomain}, {Thumbprint}, {CertificatePath} and other placeholders." },
            new ProviderParameter { Key = "workingdir", Name = "Working directory (optional)" },
            new ProviderParameter { Key = "launchnew", Name = "Launch as a new process (do not wait)", Type = OptionType.Boolean, Value = "false" },
            new ProviderParameter { Key = "timeout", Name = "Timeout (minutes)", Type = OptionType.Number, Value = "5", Description = "1 to 120 minutes; ignored when launching as a new process" },
            DeploymentTargets.LogonTypeParameter(),
        }
    };

    protected override void ValidateTask(DeploymentContext ctx, List<ActionStep> errors)
    {
        var path = ctx.Param("path");
        if (path != null && ctx.TargetType != DeploymentContextType.SSH && Path.IsPathFullyQualified(path) && !File.Exists(path))
            errors.Add(Error($"Program not found: {path}"));
        if (path != null && path.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0) errors.Add(Error("Program contains invalid characters"));
        if (ctx.Param("args") is { } a && a.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0) errors.Add(Error("Arguments must be on a single line"));
        if (ctx.Param("timeout") is { } t && (!int.TryParse(t, out var m) || m < 1 || m > 120))
            errors.Add(Error("Timeout must be a whole number of minutes between 1 and 120"));
    }

    public override async Task<ActionResult> ExecuteAsync(DeploymentContext ctx, CancellationToken ct)
    {
        var program = ctx.Expand(ctx.Param("path")!);
        var args = ctx.Param("args") is { } a ? ctx.Expand(a) : "";
        var detached = ctx.ParamBool("launchnew");
        var timeout = TimeSpan.FromMinutes(Math.Clamp(ctx.ParamInt("timeout") ?? 5, 1, 120));
        var display = (program + " " + args).Trim();

        if (ctx.IsPreviewOnly)
            return Preview(ctx, $"Would {(detached ? "launch" : "run")} '{display}' on {DeploymentTargets.Describe(ctx)}");

        return await Guard(ctx, "Run", async () =>
        {
            var spec = new CommandSpec(program)
            {
                RawArguments = args, WorkingDirectory = ctx.Param("workingdir"), Timeout = timeout, Detached = detached,
                Environment = ctx.TargetType == DeploymentContextType.SSH ? null : ScriptTask.BuildEnvironment(ctx, ""),
            };
            if (ctx.TargetType != DeploymentContextType.SSH) spec = ProcessRunner.ResolveInterpreter(spec);

            using var runner = DeploymentTargets.CreateCommandRunner(ctx);
            ctx.Log.Info($"{(detached ? "Launching" : "Running")} '{display}' via {runner.Description}");
            var r = await runner.RunAsync(spec, ct);
            if (!string.IsNullOrWhiteSpace(r.Output)) ctx.Log.Info("Output: " + r.Output.Trim());
            if (r.ExitCode == 0)
            {
                if (!string.IsNullOrWhiteSpace(r.Error)) ctx.Log.Warn("Error output: " + r.Error.Trim());
                return Ok(ctx, detached ? $"Launched '{program}'" + (string.IsNullOrWhiteSpace(r.Output) ? "" : $" ({r.Output.Trim()})") : $"'{program}' completed");
            }
            return Fail(ctx, $"'{program}' failed with exit code {r.ExitCode}. {PowerShellHelper.Summarize(r with { Output = "" })}".Trim());
        }, ct);
    }
}
