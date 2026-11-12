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
    /// <summary>ERROR_SERVICE_DISABLED: CreateProcessWithTokenW/CreateProcessWithLogonW need the Secondary Logon service.</summary>
    public const int ErrorServiceDisabled = 1058;

    public const string SecondaryLogonDisabledMessage =
        "Running a task as another Windows user requires the 'Secondary Logon' (seclogon) service, which is disabled on this computer. " +
        "Set its startup type to Manual or Automatic (services.msc, or: sc.exe config seclogon start= demand) and retry.";

    private const int LOGON_WITH_PROFILE = 0x1;
    private const int CREATE_SUSPENDED = 0x00000004;
    private const int CREATE_NO_WINDOW = 0x08000000;
    private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int STARTF_USESHOWWINDOW = 0x00000001;
    private const int HANDLE_FLAG_INHERIT = 0x1;
    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    /// <summary>
    /// Starts the process (suspended, then placed in a kill-on-close Job Object and resumed so every descendant is tracked)
    /// and collects its output. On timeout the whole job is terminated and a failed result is returned; on cancellation the
    /// job is terminated and <see cref="OperationCanceledException"/> is thrown. On a normal exit, processes the command
    /// deliberately left running (e.g. <c>start nginx</c>) are released from the kill-on-close limit and keep running.
    /// </summary>
    public static async Task<ProcessResult> RunAsync(SafeAccessTokenHandle logonToken, string commandLine, string? workingDirectory,
        IDictionary<string, string>? environment, TimeSpan timeout, bool detached, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!DuplicateTokenEx(logonToken.DangerousGetHandle(), MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out var primary))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create a primary token for the target account");

        using (primary)
        {
            var envBlock = BuildEnvironmentBlock(primary, environment);
            SafeFileHandle? outRead = null, outWrite = null, errRead = null, errWrite = null, inRead = null, inWrite = null;
            var pi = default(PROCESS_INFORMATION);
            var job = IntPtr.Zero;
            var killLeftovers = true; // cleared once the process has exited normally
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
                // Captured runs start suspended so the process can be put in a Job Object before it creates children.
                var flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | (detached ? CREATE_NEW_PROCESS_GROUP : CREATE_SUSPENDED);
                var cmd = new StringBuilder(commandLine);
                if (!CreateProcessWithTokenW(primary.DangerousGetHandle(), LOGON_WITH_PROFILE, null, cmd, flags, envBlock,
                        string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory, ref si, out pi))
                {
                    var err = Marshal.GetLastWin32Error();
                    throw new Win32Exception(err, err switch
                    {
                        ErrorPrivilegeNotHeld => "Starting a process as another user requires SeImpersonatePrivilege (run the agent as a service or elevated)",
                        ErrorServiceDisabled => SecondaryLogonDisabledMessage,
                        _ => $"Could not start process as the target user: {new Win32Exception(err).Message}",
                    });
                }

                // The child owns its ends now; close ours so the read side sees EOF when the child exits.
                outWrite?.Dispose(); errWrite?.Dispose(); inRead?.Dispose(); inWrite?.Dispose();

                if (detached)
                {
                    killLeftovers = false;
                    return new ProcessResult(0, $"Started process {pi.dwProcessId}", "");
                }

                // If the job cannot be set up (e.g. very old OS without nested jobs) fall back to killing just the process.
                job = TryCreateKillOnCloseJob(pi.hProcess);
                if (ResumeThread(pi.hThread) == uint.MaxValue)
                {
                    var err = Marshal.GetLastWin32Error();
                    throw new Win32Exception(err, $"Could not start process as the target user (resume failed): {new Win32Exception(err).Message}");
                }
                CloseHandle(pi.hThread); pi.hThread = IntPtr.Zero;

                var stdout = new OutputCapture(new StreamReader(new FileStream(outRead!, FileAccess.Read, 4096, isAsync: false), Encoding.UTF8), outRead);
                var stderr = new OutputCapture(new StreamReader(new FileStream(errRead!, FileAccess.Read, 4096, isAsync: false), Encoding.UTF8), errRead);
                var exited = await WaitForExitAsync(pi.hProcess, timeout, ct);
                if (!exited)
                {
                    Kill(job, pi.hProcess);
                    await OutputCapture.DrainAsync(stdout, stderr, ProcessRunner.OutputDrainGrace);
                    if (ct.IsCancellationRequested) throw new OperationCanceledException("The process was cancelled and terminated.", ct);
                    return ProcessRunner.TimedOut(stdout, stderr, timeout);
                }
                killLeftovers = false;
                GetExitCodeProcess(pi.hProcess, out var code);
                var complete = await OutputCapture.DrainAsync(stdout, stderr, ProcessRunner.OutputDrainGrace);
                return ProcessRunner.Completed(code, stdout, stderr, complete);
            }
            finally
            {
                if (killLeftovers && pi.hProcess != IntPtr.Zero) Kill(job, pi.hProcess);
                if (job != IntPtr.Zero)
                {
                    // Normal exit: drop the kill-on-close limit so processes the script intentionally left running survive.
                    // Otherwise closing the handle kills anything still in the job.
                    if (!killLeftovers) SetJobLimits(job, 0);
                    CloseHandle(job);
                }
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

    /// <summary>Cancels any blocking read pending on the handle (from any thread). Never throws.</summary>
    internal static void CancelPendingIo(SafeHandle handle)
    {
        try { if (!handle.IsClosed && !handle.IsInvalid) CancelIoEx(handle, IntPtr.Zero); }
        catch { /* handle closed concurrently */ }
    }

    private static IntPtr TryCreateKillOnCloseJob(IntPtr hProcess)
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) return IntPtr.Zero;
        if (SetJobLimits(job, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) && AssignProcessToJobObject(job, hProcess)) return job;
        CloseHandle(job); // no process was assigned, so this kills nothing
        return IntPtr.Zero;
    }

    private static bool SetJobLimits(IntPtr job, uint limitFlags)
    {
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = limitFlags;
        return SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref info, Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>());
    }

    /// <summary>Kills the whole process tree via the job when there is one, and the direct child in any case.</summary>
    private static void Kill(IntPtr job, IntPtr hProcess)
    {
        if (job != IntPtr.Zero) TerminateJobObject(job, 1);
        TerminateProcess(hProcess, 1);
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

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int cbInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(SafeHandle hFile, IntPtr lpOverlapped);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, SafeAccessTokenHandle hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
}
