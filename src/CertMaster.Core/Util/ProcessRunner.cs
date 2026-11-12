using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace CertMaster.Core.Util;

public record ProcessResult(int ExitCode, string Output, string Error);

/// <summary>A program invocation. Use either <see cref="Arguments"/> (each item passed as one argument) or <see cref="RawArguments"/> (passed verbatim).</summary>
public sealed record CommandSpec(string Program)
{
    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();
    /// <summary>When set, used as the literal argument string instead of <see cref="Arguments"/>.</summary>
    public string? RawArguments { get; init; }
    public IDictionary<string, string>? Environment { get; init; }
    public string? WorkingDirectory { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(5);
    /// <summary>Start the process and return immediately without waiting or capturing output.</summary>
    public bool Detached { get; init; }
}

public static class ProcessRunner
{
    /// <summary>Runs a script choosing the interpreter from its extension.</summary>
    public static Task<ProcessResult> RunScriptAsync(string scriptPath, IEnumerable<string> args, IDictionary<string, string>? env, TimeSpan timeout, CancellationToken ct = default)
    {
        var spec = ResolveInterpreter(new CommandSpec(scriptPath) { Arguments = args.ToList(), Environment = env, Timeout = timeout });
        return RunAsync(spec.Program, spec.Arguments, env, timeout, ct);
    }

    /// <summary>
    /// Maps script files to their interpreter (.ps1 → PowerShell, .bat/.cmd → cmd.exe, .py → python, .sh → /bin/sh).
    /// Other programs are returned unchanged. Works with both argument lists and raw argument strings.
    /// </summary>
    public static CommandSpec ResolveInterpreter(CommandSpec spec)
    {
        var ext = Path.GetExtension(spec.Program).ToLowerInvariant();
        string? host;
        string[] prefix;
        switch (ext)
        {
            case ".ps1":
                host = OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh";
                prefix = new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", spec.Program };
                break;
            case ".bat" or ".cmd":
                host = "cmd.exe"; prefix = new[] { "/c", spec.Program }; break;
            case ".py":
                host = OperatingSystem.IsWindows() ? "python.exe" : "python3"; prefix = new[] { spec.Program }; break;
            case ".sh":
                host = "/bin/sh"; prefix = new[] { spec.Program }; break;
            default:
                return spec;
        }
        if (spec.RawArguments != null)
            return spec with { Program = host, RawArguments = BuildCommandLine(prefix) + (spec.RawArguments.Length > 0 ? " " + spec.RawArguments : "") };
        return spec with { Program = host, Arguments = prefix.Concat(spec.Arguments).ToList() };
    }

    public static async Task<ProcessResult> RunAsync(string file, IEnumerable<string> args, IDictionary<string, string>? env, TimeSpan timeout, CancellationToken ct = default)
        => await RunAsync(new CommandSpec(file) { Arguments = args.ToList(), Environment = env, Timeout = timeout }, ct);

    /// <summary>Runs a process as the current account, capturing output (or starting it detached).</summary>
    public static async Task<ProcessResult> RunAsync(CommandSpec spec, CancellationToken ct = default)
    {
        var psi = CreateStartInfo(spec);
        if (spec.Detached)
        {
            using var detached = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {spec.Program}");
            return new ProcessResult(0, $"Started process {detached.Id}", "");
        }
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {spec.Program}");
        return await CollectAsync(p, spec.Timeout, ct);
    }

    /// <summary>
    /// Runs a process as another Windows account. Uses a logon token + CreateProcessWithTokenW (works from the LocalSystem
    /// service), falling back to Process.Start with credentials when the caller lacks SeImpersonatePrivilege.
    /// </summary>
    public static async Task<ProcessResult> RunAsUserAsync(CommandSpec spec, WindowsCredential credential, WindowsLogonType logonType, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Running a process as another user is only supported on Windows.");
        using var token = WindowsLogon.Logon(credential, logonType);
        var commandLine = QuoteWindowsArgument(spec.Program) + (spec.RawArguments != null
            ? (spec.RawArguments.Length > 0 ? " " + spec.RawArguments : "")
            : (spec.Arguments.Count > 0 ? " " + BuildCommandLine(spec.Arguments) : ""));
        try
        {
            return await NativeProcessLauncher.RunAsync(token, commandLine, spec.WorkingDirectory, spec.Environment, spec.Timeout, spec.Detached, ct);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == NativeProcessLauncher.ErrorPrivilegeNotHeld)
        {
            var psi = CreateStartInfo(spec);
            psi.UserName = credential.UserName;
            psi.Domain = credential.Domain;
            psi.PasswordInClearText = credential.Password;
            psi.LoadUserProfile = true;
            using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {spec.Program}");
            if (spec.Detached) return new ProcessResult(0, $"Started process {p.Id}", "");
            return await CollectAsync(p, spec.Timeout, ct);
        }
    }

    private static ProcessStartInfo CreateStartInfo(CommandSpec spec)
    {
        var psi = new ProcessStartInfo(spec.Program)
        {
            RedirectStandardOutput = !spec.Detached,
            RedirectStandardError = !spec.Detached,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (!string.IsNullOrWhiteSpace(spec.WorkingDirectory)) psi.WorkingDirectory = spec.WorkingDirectory;
        if (spec.RawArguments != null) psi.Arguments = spec.RawArguments;
        else foreach (var a in spec.Arguments) psi.ArgumentList.Add(a);
        if (spec.Environment != null) foreach (var kv in spec.Environment) psi.Environment[kv.Key] = kv.Value;
        return psi;
    }

    private static async Task<ProcessResult> CollectAsync(Process p, TimeSpan timeout, CancellationToken ct)
    {
        var stdout = p.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = p.StandardError.ReadToEndAsync(CancellationToken.None);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { /* ignore */ }
            var partial = await Task.WhenAny(stdout, Task.Delay(2000)) == stdout ? stdout.Result : "";
            return new ProcessResult(-1, partial, ct.IsCancellationRequested ? "Cancelled" : "Timed out after " + timeout);
        }
        return new ProcessResult(p.ExitCode, await stdout, await stderr);
    }

    /// <summary>Joins arguments into a Windows command line using the standard (CommandLineToArgvW) quoting rules.</summary>
    public static string BuildCommandLine(IEnumerable<string> args) => string.Join(' ', args.Select(QuoteWindowsArgument));

    /// <summary>Quotes one argument so that CommandLineToArgvW / the MSVC runtime parse it back to exactly the same string.</summary>
    public static string QuoteWindowsArgument(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;
        var sb = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var c in arg)
        {
            if (c == '\\') { backslashes++; continue; }
            if (c == '"') { sb.Append('\\', backslashes * 2 + 1); sb.Append('"'); }
            else { sb.Append('\\', backslashes); sb.Append(c); }
            backslashes = 0;
        }
        sb.Append('\\', backslashes * 2);
        sb.Append('"');
        return sb.ToString();
    }

    /// <summary>Quotes a value for a POSIX shell (single quotes, embedded quotes escaped).</summary>
    public static string QuotePosixArgument(string arg) => "'" + arg.Replace("'", "'\\''") + "'";
}
