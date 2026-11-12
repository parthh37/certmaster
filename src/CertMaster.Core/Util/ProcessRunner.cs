using System.Diagnostics;

namespace CertMaster.Core.Util;

public record ProcessResult(int ExitCode, string Output, string Error);

public static class ProcessRunner
{
    /// <summary>Runs a script choosing the interpreter from its extension.</summary>
    public static Task<ProcessResult> RunScriptAsync(string scriptPath, IEnumerable<string> args, IDictionary<string, string>? env, TimeSpan timeout, CancellationToken ct = default)
    {
        var ext = Path.GetExtension(scriptPath).ToLowerInvariant();
        var argList = args.ToList();
        (string file, List<string> a) = ext switch
        {
            ".ps1" => (OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh",
                       new List<string> { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath }.Concat(argList).ToList()),
            ".bat" or ".cmd" => ("cmd.exe", new List<string> { "/c", scriptPath }.Concat(argList).ToList()),
            ".py" => (OperatingSystem.IsWindows() ? "python.exe" : "python3", new List<string> { scriptPath }.Concat(argList).ToList()),
            ".sh" => ("/bin/sh", new List<string> { scriptPath }.Concat(argList).ToList()),
            _ => (scriptPath, argList),
        };
        return RunAsync(file, a, env, timeout, ct);
    }

    public static async Task<ProcessResult> RunAsync(string file, IEnumerable<string> args, IDictionary<string, string>? env, TimeSpan timeout, CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(file)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        if (env != null) foreach (var kv in env) psi.Environment[kv.Key] = kv.Value;

        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}");
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { /* ignore */ }
            return new ProcessResult(-1, await stdout, "Timed out after " + timeout);
        }
        return new ProcessResult(p.ExitCode, await stdout, await stderr);
    }
}
