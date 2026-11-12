using System.ComponentModel;
using System.Diagnostics;
using System.ServiceProcess;
using CertMaster.Client.Monitoring;
using Microsoft.Win32;

namespace CertMaster.UI.Tray;

/// <summary>A CertMaster Windows service on this machine.</summary>
public sealed record LocalService(string Key, string ServiceName, string DisplayName)
{
    public static readonly LocalService Agent = new("agent", "CertMaster Agent", "CertMaster Agent");
    public static readonly LocalService Hub = new("hub", "CertMaster Management Hub", "Management Hub");
    public static readonly LocalService[] All = { Agent, Hub };

    public static LocalService? FromKey(string key) => All.FirstOrDefault(s => s.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

    /// <summary>Current state. Any signed-in user may query a service's status, so this needs no elevation.</summary>
    public ServiceState QueryState()
    {
        try
        {
            using var sc = new ServiceController(ServiceName);
            var status = sc.Status; // throws InvalidOperationException when the service doesn't exist
            if (status == ServiceControllerStatus.Stopped && sc.StartType == ServiceStartMode.Disabled) return ServiceState.Disabled;
            return status switch
            {
                ServiceControllerStatus.Running => ServiceState.Running,
                ServiceControllerStatus.Stopped => ServiceState.Stopped,
                ServiceControllerStatus.StartPending or ServiceControllerStatus.ContinuePending => ServiceState.Starting,
                ServiceControllerStatus.StopPending or ServiceControllerStatus.PausePending => ServiceState.Stopping,
                ServiceControllerStatus.Paused => ServiceState.Paused,
                _ => ServiceState.Unknown,
            };
        }
        catch (InvalidOperationException ex) when (ex.InnerException is Win32Exception { NativeErrorCode: 1060 })
        {
            return ServiceState.NotInstalled; // ERROR_SERVICE_DOES_NOT_EXIST
        }
        catch
        {
            return ServiceState.Unknown;
        }
    }

    /// <summary>The folder holding the service executable (from its registered ImagePath), or null.</summary>
    public string? InstallDirectory()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceName);
            if (key?.GetValue("ImagePath") is not string image || image.Length == 0) return null;
            image = Environment.ExpandEnvironmentVariables(image.Trim());
            var exe = image.StartsWith('"') ? image[1..image.IndexOf('"', 1)] : image.Split(' ')[0];
            return Path.GetDirectoryName(exe);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Runs start, stop or restart in an elevated copy of this program (one UAC prompt). Returns false when the user
    /// cancelled the prompt. The elevated copy shows its own error if the operation fails.
    /// </summary>
    public bool RunElevated(string action)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, $"--service {action} {Key}")
            {
                UseShellExecute = true,
                Verb = "runas",
            });
            p?.WaitForExit();
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED: UAC prompt declined
        {
            return false;
        }
    }

    /// <summary>The elevated side of <see cref="RunElevated"/>. Returns a process exit code.</summary>
    public int Control(string action)
    {
        var timeout = TimeSpan.FromMinutes(2); // the agent gives a running request up to 60 s to finish when stopping
        try
        {
            using var sc = new ServiceController(ServiceName);
            if (action is "start" && sc.StartType == ServiceStartMode.Disabled)
                throw new InvalidOperationException($"The {ServiceName} service is disabled. Set its startup type to Automatic in Services (services.msc) first.");

            if (action is "stop" or "restart" && sc.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
                sc.Stop();
            if (action is "stop" or "restart")
                sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);

            if (action is "start" or "restart")
            {
                sc.Refresh();
                if (sc.Status != ServiceControllerStatus.Running && sc.Status != ServiceControllerStatus.StartPending) sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
            }
            return 0;
        }
        catch (Exception ex)
        {
            var detail = ex is System.ServiceProcess.TimeoutException
                ? $"The service did not finish within {timeout.TotalMinutes:0} minutes."
                : (ex.InnerException?.Message ?? ex.Message);
            MessageBox.Show($"Could not {action} the {ServiceName} service.\n\n{detail}\n\nSee the Application event log for details.",
                "CertMaster", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
