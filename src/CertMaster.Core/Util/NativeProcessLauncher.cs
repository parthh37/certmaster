using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CertMaster.Core.Util;

/// <summary>
/// Starts a process under another Windows account from a logon token (CreateProcessWithTokenW), with redirected
/// stdout/stderr. Unlike Process.Start with a user name (CreateProcessWithLogonW) this also works when the caller runs
/// as LocalSystem, which is the normal case for the agent service. Requires SeImpersonatePrivilege (held by services
/// and elevated administrators).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class NativeProcessLauncher
{
    public const int ErrorPrivilegeNotHeld = 1314;

    private const int LOGON_WITH_PROFILE = 0x1;
    private const int CREATE_NO_WINDOW = 0x08000000;
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const int HANDLE_FLAG_INHERIT = 0x1;
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;

    public static async Task<ProcessResult> RunAsync(SafeAccessTokenHandle logonToken, string commandLine, string? workingDirectory,
        IDictionary<string, string>? environment, TimeSpan timeout, bool detached, CancellationToken ct)
    {
        if (!DuplicateTokenEx(logonToken.DangerousGetHandle(), MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out var primary))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create a primary token for the target account");

        using (primary)
        {
            var envBlock = BuildEnvironmentBlock(primary, environment);
            SafeFileHandle? outRead = null, outWrite = null, errRead = null, errWrite = null, inRead = null, inWrite = null;
            var pi = default(PROCESS_INFORMATION);
            try
            {
                if (!detached)
                {
                    CreateInheritablePipe(out outRead, out outWrite, parentReads: true);
                    CreateInheritablePipe(out errRead, out errWrite, parentReads: true);
                    CreateInheritablePipe(out inRead, out inWrite, parentReads: false);
                }

                var si = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    dwFlags = STARTF_USESHOWWINDOW | (detached ? 0 : STARTF_USESTDHANDLES),
                    wShowWindow = 0, // SW_HIDE
                    hStdInput = inRead?.DangerousGetHandle() ?? IntPtr.Zero,
                    hStdOutput = outWrite?.DangerousGetHandle() ?? IntPtr.Zero,
                    hStdError = errWrite?.DangerousGetHandle() ?? IntPtr.Zero,
                };
                var flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | (detached ? CREATE_NEW_PROCESS_GROUP : 0);
                var cmd = new StringBuilder(commandLine);
                if (!CreateProcessWithTokenW(primary.DangerousGetHandle(), LOGON_WITH_PROFILE, null, cmd, flags, envBlock,
                        string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory, ref si, out pi))
                {
                    var err = Marshal.GetLastWin32Error();
                    throw new Win32Exception(err, err == ErrorPrivilegeNotHeld
                        ? "Starting a process as another user requires SeImpersonatePrivilege (run the agent as a service or elevated)"
                        : $"Could not start process as the target user: {new Win32Exception(err).Message}");
                }

                // The child owns its ends now; close ours so the read side sees EOF when the child exits.
                outWrite?.Dispose(); errWrite?.Dispose(); inRead?.Dispose(); inWrite?.Dispose();
                CloseHandle(pi.hThread); pi.hThread = IntPtr.Zero;

                if (detached)
                    return new ProcessResult(0, $"Started process {pi.dwProcessId}", "");

                var stdout = ReadAllAsync(outRead!);
                var stderr = ReadAllAsync(errRead!);
                var exited = await WaitForExitAsync(pi.hProcess, timeout, ct);
                if (!exited)
                {
                    TerminateProcess(pi.hProcess, 1);
                    var partial = await Task.WhenAny(stdout, Task.Delay(2000)) == stdout ? stdout.Result : "";
                    return new ProcessResult(-1, partial, ct.IsCancellationRequested ? "Cancelled" : "Timed out after " + timeout);
                }
                GetExitCodeProcess(pi.hProcess, out var code);
                return new ProcessResult(code, await stdout, await stderr);
            }
            finally
            {
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                outRead?.Dispose(); outWrite?.Dispose(); errRead?.Dispose(); errWrite?.Dispose(); inRead?.Dispose(); inWrite?.Dispose();
                if (envBlock != IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
            }
        }
    }

    private static Task<bool> WaitForExitAsync(IntPtr hProcess, TimeSpan timeout, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var wait = new ManualResetEvent(false) { SafeWaitHandle = new SafeWaitHandle(hProcess, ownsHandle: false) };
        var registration = ThreadPool.RegisterWaitForSingleObject(wait, (_, timedOut) => tcs.TrySetResult(!timedOut), null, timeout, executeOnlyOnce: true);
        var ctReg = ct.Register(() => tcs.TrySetResult(false));
        return tcs.Task.ContinueWith(t =>
        {
            registration.Unregister(null);
            ctReg.Dispose();
            wait.Dispose();
            return t.Result;
        }, TaskScheduler.Default);
    }

    private static async Task<string> ReadAllAsync(SafeFileHandle handle)
    {
        await using var fs = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
        using var reader = new StreamReader(fs, Encoding.UTF8);
        return await Task.Run(() => reader.ReadToEnd());
    }

    private static void CreateInheritablePipe(out SafeFileHandle read, out SafeFileHandle write, bool parentReads)
    {
        var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(), bInheritHandle = 1 };
        if (!CreatePipe(out read, out write, ref sa, 0)) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe failed");
        // Only the child's end should be inheritable.
        SetHandleInformation(parentReads ? read : write, HANDLE_FLAG_INHERIT, 0);
    }

    private static IntPtr BuildEnvironmentBlock(SafeAccessTokenHandle token, IDictionary<string, string>? extra)
    {
        var vars = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (CreateEnvironmentBlock(out var block, token, false))
        {
            try
            {
                var ptr = block;
                while (true)
                {
                    var entry = Marshal.PtrToStringUni(ptr);
                    if (string.IsNullOrEmpty(entry)) break;
                    var eq = entry.IndexOf('=', 1); // names like "=C:" start with '='
                    if (eq > 0) vars[entry[..eq]] = entry[(eq + 1)..];
                    ptr += (entry.Length + 1) * 2;
                }
            }
            finally { DestroyEnvironmentBlock(block); }
        }
        if (extra != null) foreach (var kv in extra) vars[kv.Key] = kv.Value;
        var sb = new StringBuilder();
        foreach (var kv in vars) sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
        sb.Append('\0');
        return Marshal.StringToHGlobalUni(sb.ToString());
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string? lpApplicationName, StringBuilder lpCommandLine,
        int dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle phNewToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle hReadPipe, out SafeFileHandle hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeHandle hObject, int dwMask, int dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out int lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, int uExitCode);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, SafeAccessTokenHandle hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
}
