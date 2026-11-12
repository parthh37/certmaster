using System.IO;
using System.ServiceProcess;
using CertMaster.Client;

namespace CertMaster.UI.Desktop;

/// <summary>
/// Makes sure the local CertMaster Agent is running and has written its API key before the app connects. The app runs
/// elevated, so it starts a stopped service itself: after an install whose start step failed, after a reboot before the
/// delayed-auto start, or when someone stopped the service.
/// </summary>
internal static class AgentServiceStarter
{
    public const string ServiceName = "CertMaster Agent";
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);

    /// <summary>Returns once the agent answers; throws <see cref="AgentUnavailableException"/> with a user-facing reason otherwise.</summary>
    /// <param name="showStatus">Called with a progress message when the app has to start or wait for the service.</param>
    public static async Task EnsureRunningAsync(Action<string> showStatus)
    {
        var keyFile = AgentClient.LocalKeyFile();
        if (File.Exists(keyFile) && await AgentClient.IsAgentRespondingAsync()) return;

        using var sc = new ServiceController(ServiceName);
        ServiceControllerStatus state;
        try { state = sc.Status; }
        catch (InvalidOperationException)
        {
            // No service: the agent may still be running as a console app (development); let the normal connect try.
            if (File.Exists(keyFile)) return;
            throw new AgentUnavailableException($"The '{ServiceName}' Windows service is not installed. Reinstall CertMaster to register it.");
        }

        if (state is ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending)
        {
            showStatus($"Starting the {ServiceName} service...");
            try
            {
                if (state == ServiceControllerStatus.StopPending)
                    await Task.Run(() => sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(70)));
                sc.Start();
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ServiceProcess.TimeoutException or System.ComponentModel.Win32Exception)
            {
                throw new AgentUnavailableException($"The '{ServiceName}' service could not be started: {ex.GetBaseException().Message}{LogHint()}");
            }
        }
        else
        {
            showStatus($"Waiting for the {ServiceName} service to start...");
        }

        var deadline = DateTime.UtcNow + StartTimeout;
        while (DateTime.UtcNow < deadline)
        {
            await Task.Delay(PollInterval);
            if (File.Exists(keyFile) && await AgentClient.IsAgentRespondingAsync()) return;

            sc.Refresh();
            if (sc.Status == ServiceControllerStatus.Stopped)
                throw new AgentUnavailableException($"The '{ServiceName}' service started but then stopped.{LogHint()}");
        }
        throw new AgentUnavailableException($"The '{ServiceName}' service did not finish starting within {StartTimeout.TotalSeconds:0} seconds.{LogHint()}");
    }

    private static string LogHint() =>
        $"\n\nCheck {Path.Combine(AgentClient.LocalDataPath(), "logs", "service.log")} and the Windows Application event log for the reason.";
}

internal sealed class AgentUnavailableException(string message) : Exception(message);
