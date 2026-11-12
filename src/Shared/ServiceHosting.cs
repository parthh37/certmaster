using System.Diagnostics;
using Microsoft.Extensions.Hosting.WindowsServices;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace CertMaster.Hosting;

/// <summary>
/// Shared start-up plumbing for the agent and hub Windows services (linked into both projects). It makes failures visible
/// on an unattended server: everything goes to a size-capped rolling log, warnings and errors also go to the Windows
/// Application event log, and a failed start or a crashed background service ends the process with a non-zero exit code
/// so the service recovery actions (restart) apply.
/// </summary>
internal static class ServiceHosting
{
    public static bool IsWindowsService => OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService();

    public static Logger CreateLogger(string logFile, string eventSource)
    {
        var config = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .WriteTo.File(logFile, rollingInterval: RollingInterval.Day, retainedFileCountLimit: 31,
                fileSizeLimitBytes: 50L * 1024 * 1024, rollOnFileSizeLimit: true);
        if (IsWindowsService) config = config.WriteTo.Sink(new EventLogSink(eventSource), LogEventLevel.Warning);
        return config.CreateLogger();
    }

    /// <summary>Logs crashes on any thread and unobserved task faults, which otherwise vanish without a trace.</summary>
    public static void HookProcessErrors()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            Log.Fatal(e.ExceptionObject as Exception, "Unhandled exception; the process will terminate");
            Log.CloseAndFlush();
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Log.Warning(e.Exception, "Unobserved background task exception");
            e.SetObserved();
        };
    }

    /// <summary>
    /// After the host stops: true when a background service died with an exception. The host then stopped on its own
    /// (BackgroundServiceExceptionBehavior.StopHost), which looks like a clean stop to the service control manager unless
    /// the process exits with an error code.
    /// </summary>
    public static bool AnyBackgroundServiceFaulted(IServiceProvider services)
    {
        var faulted = false;
        foreach (var s in services.GetServices<IHostedService>().OfType<BackgroundService>())
        {
            if (s.ExecuteTask is { IsFaulted: true } t)
            {
                Log.Fatal(t.Exception?.GetBaseException(), "Background service {Service} stopped with an error", s.GetType().Name);
                faulted = true;
            }
        }
        return faulted;
    }

    /// <summary>
    /// Last-resort report for failures before logging is configured (for example the data folder can't be created).
    /// Writes to the Application event log and stderr; never throws.
    /// </summary>
    public static void ReportEarlyFailure(string eventSource, string message, Exception ex)
    {
        var text = message + Environment.NewLine + ex;
        try { Console.Error.WriteLine(text); } catch { /* no console */ }
        EventLogSink.TryWrite(eventSource, text, isError: true);
    }

    /// <summary>Writes warning and error events to the Windows Application event log (for monitoring tools). Never throws.</summary>
    private sealed class EventLogSink(string source) : ILogEventSink
    {
        private const int MaxMessageLength = 30000; // event log limit is 31,839 characters
        private static readonly object SourceLock = new();
        private static readonly HashSet<string> CheckedSources = new();

        public void Emit(LogEvent logEvent)
        {
            var text = logEvent.RenderMessage();
            if (logEvent.Exception != null) text += Environment.NewLine + logEvent.Exception;

            TryWrite(source, text, isError: logEvent.Level >= LogEventLevel.Error);
        }

        public static void TryWrite(string source, string text, bool isError)
        {
            if (!OperatingSystem.IsWindows()) return;
            try
            {
                lock (SourceLock)
                {
                    // Creating a source needs administrator rights (services run as LocalSystem); do it once per process.
                    if (CheckedSources.Add(source) && !EventLog.SourceExists(source)) EventLog.CreateEventSource(source, "Application");
                }
                if (text.Length > MaxMessageLength) text = text[..MaxMessageLength] + " ...";
                EventLog.WriteEntry(source, text, isError ? EventLogEntryType.Error : EventLogEntryType.Warning, isError ? 1000 : 2000);
            }
            catch
            {
                // The event log is best effort: never let it break logging or start-up.
            }
        }
    }
}
