using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
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
    /// <summary>
    /// How long to keep reading stdout/stderr after the process has exited (or been killed). A grandchild that inherited
    /// the pipe (e.g. a batch file doing <c>start /b nginx.exe</c>) keeps it open indefinitely, so the readers are abandoned
    /// after this and the output read so far is returned.
    /// </summary>
    internal static readonly TimeSpan OutputDrainGrace = TimeSpan.FromSeconds(5);

    internal const string IncompleteOutputNote =
        "[CertMaster: stopped reading output 5 seconds after the process exited because a process it started is still running and holding the output open; output may be incomplete]";

    /// <summary>Full path of Windows PowerShell (System32) on Windows, so it is never resolved via the search path; <c>pwsh</c> elsewhere.</summary>
    public static string PowerShellExe => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
        : "pwsh";

    /// <summary>Full path of cmd.exe (System32) on Windows, so it is never resolved via the search path.</summary>
    public static string CmdExe => OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "cmd.exe") : "cmd.exe";

    /// <summary>Runs a script choosing the interpreter from its extension.</summary>
    public static Task<ProcessResult> RunScriptAsync(string scriptPath, IEnumerable<string> args, IDictionary<string, string>? env, TimeSpan timeout, CancellationToken ct = default)
        => RunAsync(ResolveInterpreter(new CommandSpec(scriptPath) { Arguments = args.ToList(), Environment = env, Timeout = timeout }), ct);

    /// <summary>
    /// Maps script files to their interpreter (.ps1 → PowerShell, .bat/.cmd → cmd.exe, .py → python, .sh → /bin/sh).
    /// Other programs are returned unchanged. Works with both argument lists and raw argument strings.
    /// Batch files always come back with <see cref="CommandSpec.RawArguments"/> set (cmd.exe has its own quoting rules).
    /// </summary>
    public static CommandSpec ResolveInterpreter(CommandSpec spec)
    {
        var ext = Path.GetExtension(spec.Program).ToLowerInvariant();
        string? host;
        string[] prefix;
        switch (ext)
        {
            case ".ps1":
                host = PowerShellExe;
                prefix = new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", spec.Program };
                break;
            case ".bat" or ".cmd":
            {
                // cmd /c "<line>" strips the first and last quote of the line unless /s is given AND the whole line is
                // wrapped in one extra pair of quotes; only then does `"C:\my scripts\x.bat" "arg one"` survive intact.
                // /d skips any AutoRun command configured in the registry.
                var tail = spec.RawArguments != null
                    ? (spec.RawArguments.Length > 0 ? " " + spec.RawArguments : "")
                    : string.Concat(spec.Arguments.Select(a => " " + QuoteCmdArgument(a)));
                return spec with { Program = CmdExe, Arguments = Array.Empty<string>(), RawArguments = "/d /s /c \"\"" + spec.Program + "\"" + tail + "\"" };
            }
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

    /// <summary>
    /// Runs a process as the current account, capturing output (or starting it detached). On timeout the process tree is
    /// killed and a failed result (exit code -1) is returned; when <paramref name="ct"/> is cancelled the tree is killed and
    /// <see cref="OperationCanceledException"/> is thrown (nothing is started if it is already cancelled).
    /// </summary>
    public static async Task<ProcessResult> RunAsync(CommandSpec spec, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
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
    /// Timeout/cancellation semantics match <see cref="RunAsync(CommandSpec, CancellationToken)"/>.
    /// </summary>
    public static async Task<ProcessResult> RunAsUserAsync(CommandSpec spec, WindowsCredential credential, WindowsLogonType logonType, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Running a process as another user is only supported on Windows.");
        ct.ThrowIfCancellationRequested();
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
            // Process.Start with credentials (CreateProcessWithLogonW) cannot use the elevated linked token, so an
            // administrator account runs UAC-filtered on this path; it is only taken when the agent is not a service.
            Process p;
            try { p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {spec.Program}"); }
            catch (Win32Exception le) when (le.NativeErrorCode == NativeProcessLauncher.ErrorServiceDisabled)
            {
                throw new Win32Exception(le.NativeErrorCode, NativeProcessLauncher.SecondaryLogonDisabledMessage);
            }
            using (p)
            {
                if (spec.Detached) return new ProcessResult(0, $"Started process {p.Id}", "");
                return await CollectAsync(p, spec.Timeout, ct);
            }
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
        var stdout = new OutputCapture(p.StandardOutput, OutputCapture.PipeHandleOf(p.StandardOutput));
        var stderr = new OutputCapture(p.StandardError, OutputCapture.PipeHandleOf(p.StandardError));
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var exited = true;
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { exited = false; }

        if (!exited)
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already gone */ }
            await OutputCapture.DrainAsync(stdout, stderr, OutputDrainGrace);
            if (ct.IsCancellationRequested) throw new OperationCanceledException("The process was cancelled and terminated.", ct);
            return TimedOut(stdout, stderr, timeout);
        }
        var complete = await OutputCapture.DrainAsync(stdout, stderr, OutputDrainGrace);
        return Completed(p.ExitCode, stdout, stderr, complete);
    }

    internal static ProcessResult TimedOut(OutputCapture stdout, OutputCapture stderr, TimeSpan timeout)
    {
        var err = stderr.Text;
        return new ProcessResult(-1, stdout.Text, "Timed out after " + timeout + (string.IsNullOrWhiteSpace(err) ? "" : Environment.NewLine + err));
    }

    internal static ProcessResult Completed(int exitCode, OutputCapture stdout, OutputCapture stderr, bool complete)
    {
        var err = stderr.Text;
        if (!complete) err = string.IsNullOrEmpty(err) ? IncompleteOutputNote : err.TrimEnd() + Environment.NewLine + IncompleteOutputNote;
        return new ProcessResult(exitCode, stdout.Text, err);
    }

    /// <summary>Joins arguments into a Windows command line using the standard (CommandLineToArgvW) quoting rules.</summary>
    public static string BuildCommandLine(IEnumerable<string> args) => string.Join(' ', args.Select(QuoteWindowsArgument));

    private static readonly char[] CmdSpecialChars = { ' ', '\t', '"', '&', '|', '<', '>', '^', '(', ')', ',', ';', '=', '%', '!' };

    /// <summary>
    /// Quotes one argument for a batch file run through <c>cmd /c</c>. Values containing whitespace, cmd operators
    /// (&amp; | &lt; &gt; ^ ( )) or batch delimiters (, ; =) are wrapped in double quotes (embedded quotes are doubled), so
    /// cmd treats the operators literally and the batch file sees one parameter (%~1 removes the quotes).
    /// Limitation: cmd still expands %VAR% references inside quotes; that cannot be escaped reliably on a /c command line.
    /// </summary>
    public static string QuoteCmdArgument(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny(CmdSpecialChars) < 0) return arg;
        return "\"" + arg.Replace("\"", "\"\"") + "\"";
    }

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

/// <summary>
/// Reads a redirected stdout/stderr pipe on a dedicated thread, keeping what has been read so far available at any time.
/// Unlike ReadToEnd this lets the caller give up when the pipe never reaches EOF (a grandchild process inherited the
/// write end) and still return the partial output; on Windows the blocked read is then cancelled so the thread is freed.
/// </summary>
internal sealed class OutputCapture
{
    private readonly StringBuilder _text = new();
    private readonly SafeHandle? _pipe;
    private volatile bool _stopping;

    public OutputCapture(TextReader reader, SafeHandle? pipe)
    {
        _pipe = pipe;
        Completion = Task.Factory.StartNew(() => Pump(reader), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

    /// <summary>Completes (never faults) when the pipe reaches EOF, breaks, or the read is cancelled.</summary>
    public Task Completion { get; }

    public string Text { get { lock (_text) return _text.ToString(); } }

    /// <summary>The pipe handle behind a Process stream. Call before anything reads from the reader.</summary>
    public static SafeHandle? PipeHandleOf(StreamReader reader) =>
        OperatingSystem.IsWindows() && reader.BaseStream is FileStream fs ? fs.SafeFileHandle : null;

    /// <summary>Waits up to <paramref name="grace"/> for both readers to reach EOF. Returns false (and stops them) when they did not.</summary>
    public static async Task<bool> DrainAsync(OutputCapture stdout, OutputCapture stderr, TimeSpan grace)
    {
        var both = Task.WhenAll(stdout.Completion, stderr.Completion);
        if (await Task.WhenAny(both, Task.Delay(grace)) == both) return true;
        await Task.WhenAll(stdout.StopAsync(), stderr.StopAsync());
        return false;
    }

    private void Pump(TextReader reader)
    {
        var buffer = new char[4096];
        try
        {
            int n;
            while (!_stopping && (n = reader.Read(buffer, 0, buffer.Length)) > 0)
                lock (_text) _text.Append(buffer, 0, n);
        }
        catch { /* pipe broken, read cancelled or handle closed: keep what was read */ }
        finally
        {
            try { reader.Dispose(); } catch { /* ignore */ }
        }
    }

    private async Task StopAsync()
    {
        _stopping = true;
        // Retry a few times: a cancel that lands between two reads does not affect the next one.
        for (var i = 0; i < 5 && !Completion.IsCompleted; i++)
        {
            if (_pipe != null && OperatingSystem.IsWindows()) NativeProcessLauncher.CancelPendingIo(_pipe);
            await Task.WhenAny(Completion, Task.Delay(100));
        }
    }
}
