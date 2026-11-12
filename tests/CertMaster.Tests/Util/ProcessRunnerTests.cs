using System.Diagnostics;
using CertMaster.Core.Util;

namespace CertMaster.Tests.Util;

public sealed class ProcessRunnerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cm-procrunner-tests", Guid.NewGuid().ToString("N")[..8], "my scripts (1)");

    public ProcessRunnerTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(Path.GetDirectoryName(_dir)!, true); } catch { /* a stray child may still hold the folder */ }
    }

    private string WriteCmd(string name, params string[] lines)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, string.Join("\r\n", lines) + "\r\n");
        return path;
    }

    [Fact]
    public void Batch_files_get_a_cmd_s_command_line_with_quoted_script_and_arguments()
    {
        var spec = ProcessRunner.ResolveInterpreter(new CommandSpec(@"C:\my scripts\reload.bat") { Arguments = new[] { "arg one", "plain", "a&b", "k=v", "" } });
        Assert.Equal("/d /s /c \"\"C:\\my scripts\\reload.bat\" \"arg one\" plain \"a&b\" \"k=v\" \"\"\"", spec.RawArguments);
        Assert.Empty(spec.Arguments);
        Assert.Equal("cmd.exe", Path.GetFileName(spec.Program), ignoreCase: true);
        if (OperatingSystem.IsWindows()) Assert.True(Path.IsPathFullyQualified(spec.Program));

        var raw = ProcessRunner.ResolveInterpreter(new CommandSpec(@"C:\my scripts\reload.cmd") { RawArguments = "\"arg one\" x" });
        Assert.Equal("/d /s /c \"\"C:\\my scripts\\reload.cmd\" \"arg one\" x\"", raw.RawArguments);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("", "\"\"")]
    [InlineData("two words", "\"two words\"")]
    [InlineData("a|b", "\"a|b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData(@"C:\dir\", @"C:\dir\")] // backslashes are not special to cmd
    [InlineData(@"C:\my dir\", "\"C:\\my dir\\\"")]
    public void Quotes_cmd_arguments(string arg, string expected) => Assert.Equal(expected, ProcessRunner.QuoteCmdArgument(arg));

    [Fact]
    public void PowerShell_is_resolved_by_full_path_on_windows()
    {
        if (!OperatingSystem.IsWindows()) return;
        var ps = ProcessRunner.ResolveInterpreter(new CommandSpec(@"C:\x\deploy.ps1"));
        Assert.True(Path.IsPathFullyQualified(ps.Program));
        Assert.EndsWith(@"WindowsPowerShell\v1.0\powershell.exe", ps.Program, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Runs_batch_file_in_folder_with_spaces_and_quoted_arguments()
    {
        if (!OperatingSystem.IsWindows()) return;
        var script = WriteCmd("show args.cmd", "@echo [%~1]", "@echo [%2]", "@echo [%~3]");
        var r = await ProcessRunner.RunScriptAsync(script, new[] { "arg one", "a&b", "plain" }, null, TimeSpan.FromSeconds(30));
        Assert.True(r.ExitCode == 0, r.Output + r.Error);
        Assert.Contains("[arg one]", r.Output);
        Assert.Contains("[\"a&b\"]", r.Output);
        Assert.Contains("[plain]", r.Output);

        var raw = await ProcessRunner.RunAsync(ProcessRunner.ResolveInterpreter(new CommandSpec(script) { RawArguments = "\"arg one\" x y", Timeout = TimeSpan.FromSeconds(30) }));
        Assert.True(raw.ExitCode == 0, raw.Output + raw.Error);
        Assert.Contains("[arg one]", raw.Output);
        Assert.Contains("[x]", raw.Output);
    }

    [Fact]
    public async Task Grandchild_holding_the_output_pipe_does_not_hang_after_exit()
    {
        if (!OperatingSystem.IsWindows()) return;
        var started = DateTime.Now.AddSeconds(-1);
        // start /b gives ping our stdout/stderr pipe; it keeps it open ~20 s after the batch file has exited.
        var script = WriteCmd("spawn.cmd", "@echo off", "echo hello", "start \"\" /b ping -n 20 127.0.0.1", "exit /b 3");
        try
        {
            var sw = Stopwatch.StartNew();
            var r = await ProcessRunner.RunScriptAsync(script, Array.Empty<string>(), null, TimeSpan.FromSeconds(60));
            sw.Stop();
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(12), $"took {sw.Elapsed}");
            Assert.Equal(3, r.ExitCode);
            Assert.Contains("hello", r.Output);
            Assert.Contains("output may be incomplete", r.Error);
        }
        finally { KillPingsStartedAfter(started); }
    }

    [Fact]
    public async Task Timeout_kills_the_process_and_returns_a_failure()
    {
        if (!OperatingSystem.IsWindows()) return;
        var started = DateTime.Now.AddSeconds(-1);
        var script = WriteCmd("slow.cmd", "@echo before", "@ping -n 30 127.0.0.1 >nul", "@echo after");
        try
        {
            var sw = Stopwatch.StartNew();
            var r = await ProcessRunner.RunScriptAsync(script, Array.Empty<string>(), null, TimeSpan.FromSeconds(1));
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(9), $"took {sw.Elapsed}");
            Assert.Equal(-1, r.ExitCode);
            Assert.StartsWith("Timed out after", r.Error);
            Assert.Contains("before", r.Output);
            Assert.DoesNotContain("after", r.Output);
        }
        finally { KillPingsStartedAfter(started); }
    }

    [Fact]
    public async Task Cancellation_kills_the_process_and_throws()
    {
        if (!OperatingSystem.IsWindows()) return;
        var started = DateTime.Now.AddSeconds(-1);
        var script = WriteCmd("cancel.cmd", "@ping -n 30 127.0.0.1 >nul");
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
            var sw = Stopwatch.StartNew();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProcessRunner.RunScriptAsync(script, Array.Empty<string>(), null, TimeSpan.FromMinutes(1), cts.Token));
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(9), $"took {sw.Elapsed}");
        }
        finally { KillPingsStartedAfter(started); }
    }

    [Fact]
    public async Task Pre_cancelled_token_throws_without_starting_the_process()
    {
        if (!OperatingSystem.IsWindows()) return;
        var marker = Path.Combine(_dir, "ran.txt");
        var script = WriteCmd("marker.cmd", $"@echo x > \"{marker}\"");
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProcessRunner.RunScriptAsync(script, Array.Empty<string>(), null, TimeSpan.FromSeconds(30), cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ProcessRunner.RunAsync(ProcessRunner.ResolveInterpreter(new CommandSpec(script) { Detached = true }), cts.Token));
        await Task.Delay(300);
        Assert.False(File.Exists(marker));
    }

    private static void KillPingsStartedAfter(DateTime since)
    {
        foreach (var p in Process.GetProcessesByName("PING"))
        {
            using (p)
            {
                try { if (p.StartTime >= since) p.Kill(); } catch { /* exited or not ours to inspect */ }
            }
        }
    }
}
