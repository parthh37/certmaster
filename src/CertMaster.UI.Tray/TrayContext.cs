using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http.Json;
using CertMaster.Client.Monitoring;
using CertMaster.Models;

namespace CertMaster.UI.Tray;

/// <summary>
/// The notification-area icon. Polls the local services and the agent's status summary, shows the result as icon colour,
/// tooltip and menu lines, and raises a notification when something changes (service stopped, renewal failed,
/// certificate about to expire, recovered).
/// </summary>
public sealed class TrayContext : ApplicationContext
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(20);

    private readonly TrayIcons _icons = new();
    private readonly NotifyIcon _tray;
    private readonly ContextMenuStrip _menu = new();
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = (int)PollInterval.TotalMilliseconds };
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _desktopExe = Path.Combine(AppContext.BaseDirectory, "CertMaster.UI.Desktop.exe");

    private MonitorSnapshot? _baseline; // last poll, carrying the last known summary (see StatusEvaluator.Diff)
    private MonitorSnapshot? _current;
    private bool _polling;
    private bool _serviceActionRunning;

    public TrayContext()
    {
        _tray = new NotifyIcon
        {
            Icon = _icons.For(MonitorLevel.Offline),
            Text = "CertMaster: checking status...",
            ContextMenuStrip = _menu,
            Visible = true,
        };
        _tray.MouseClick += (_, e) => { if (e.Button == MouseButtons.Left) ShowMenu(); };
        _tray.DoubleClick += (_, _) => OpenDesktopApp();
        _tray.BalloonTipClicked += (_, _) => OpenDesktopApp();
        _menu.Opening += (_, _) => BuildMenu();
        _timer.Tick += async (_, _) => await PollAsync();
        BuildMenu();
        _timer.Start();
        _ = PollAsync();
    }

    // ---------- polling ----------

    private async Task PollAsync()
    {
        if (_polling) return;
        _polling = true;
        try
        {
            var snapshot = await Task.Run(TakeSnapshotAsync);
            var status = StatusEvaluator.Evaluate(snapshot);
            _tray.Icon = _icons.For(status.Level);
            _tray.Text = status.Tooltip;

            foreach (var n in StatusEvaluator.Diff(_baseline, snapshot))
                _tray.ShowBalloonTip(10_000, n.Title, n.Text, n.Level switch
                {
                    MonitorLevel.Error => ToolTipIcon.Error,
                    MonitorLevel.Warning => ToolTipIcon.Warning,
                    _ => ToolTipIcon.Info,
                });

            _current = snapshot;
            _baseline = snapshot.Summary != null || _baseline == null ? snapshot : snapshot with { Summary = _baseline.Summary };
        }
        catch (Exception ex)
        {
            Trace.TraceWarning("Tray poll failed: " + ex);
        }
        finally
        {
            _polling = false;
        }
    }

    private async Task<MonitorSnapshot> TakeSnapshotAsync()
    {
        var agent = LocalService.Agent.QueryState();
        var hub = LocalService.Hub.QueryState();
        AgentStatusSummary? summary = null;
        if (agent is ServiceState.Running or ServiceState.Unknown or ServiceState.NotInstalled)
        {
            try { summary = await _http.GetFromJsonAsync<AgentStatusSummary>(AgentUrl() + "/api/system/summary", JsonDefaults.Options); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or NotSupportedException or System.Text.Json.JsonException) { }
        }
        // Without the service installed an agent can still answer (a developer running it from the console).
        if (agent == ServiceState.NotInstalled && summary != null) agent = ServiceState.Unknown;
        return new MonitorSnapshot(agent, hub == ServiceState.NotInstalled ? null : hub, summary, DateTimeOffset.UtcNow);
    }

    private static string AgentUrl()
    {
        if (Environment.GetEnvironmentVariable("CERTMASTER_AGENT_URL") is { Length: > 0 } env) return env.TrimEnd('/');
        var dir = LocalService.Agent.InstallDirectory();
        return (dir == null ? LocalEndpoints.DefaultAgentUrl : LocalEndpoints.AgentUrl(LocalEndpoints.ReadSettings(dir))).TrimEnd('/');
    }

    private static string HubUrl()
    {
        var dir = LocalService.Hub.InstallDirectory();
        return dir == null ? LocalEndpoints.DefaultHubUrl : LocalEndpoints.HubUrl(LocalEndpoints.ReadSettings(dir));
    }

    // ---------- menu ----------

    private void ShowMenu()
    {
        // NotifyIcon only opens the menu on right-click; reuse its private ShowContextMenu so it positions like the shell's.
        typeof(NotifyIcon).GetMethod("ShowContextMenu", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.Invoke(_tray, null);
    }

    private void BuildMenu()
    {
        _menu.Items.Clear();
        var status = _current == null ? null : StatusEvaluator.Evaluate(_current);

        var header = new ToolStripMenuItem(status?.Headline ?? "Checking status...") { Enabled = false, Image = _icons.For(status?.Level ?? MonitorLevel.Offline).ToBitmap() };
        header.Font = new Font(header.Font, FontStyle.Bold);
        _menu.Items.Add(header);
        foreach (var line in status?.Details ?? Array.Empty<string>())
            _menu.Items.Add(new ToolStripMenuItem(line) { Enabled = false });
        _menu.Items.Add(new ToolStripSeparator());

        if (File.Exists(_desktopExe))
        {
            var open = new ToolStripMenuItem("Open CertMaster", null, (_, _) => OpenDesktopApp());
            open.Font = new Font(open.Font, FontStyle.Bold);
            _menu.Items.Add(open);
        }
        if (_current?.Hub != null)
            _menu.Items.Add(new ToolStripMenuItem("Open Management Hub", null, (_, _) => OpenUrl(HubUrl())));

        _menu.Items.Add(ServiceMenu(LocalService.Agent, _current?.Agent ?? ServiceState.Unknown));
        if (_current?.Hub is { } hub) _menu.Items.Add(ServiceMenu(LocalService.Hub, hub));
        _menu.Items.Add(new ToolStripMenuItem("Refresh now", null, async (_, _) => await PollAsync()));

        _menu.Items.Add(new ToolStripSeparator());
        var autoStart = new ToolStripMenuItem("Start when I sign in") { Checked = SafeAutoStartEnabled(), CheckOnClick = true };
        autoStart.CheckedChanged += (_, _) =>
        {
            try { AutoStart.SetEnabled(autoStart.Checked); }
            catch (Exception ex) { MessageBox.Show("Could not change the sign-in setting.\n\n" + ex.Message, "CertMaster", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        };
        _menu.Items.Add(autoStart);
        _menu.Items.Add(new ToolStripMenuItem("Exit tray monitor", null, (_, _) => ExitThread()));
    }

    private ToolStripMenuItem ServiceMenu(LocalService service, ServiceState state)
    {
        var busy = _serviceActionRunning || state is ServiceState.Starting or ServiceState.Stopping;
        var running = state == ServiceState.Running;
        var installed = state != ServiceState.NotInstalled;
        var item = new ToolStripMenuItem($"{service.DisplayName} service") { Enabled = installed };
        item.DropDownItems.Add(new ToolStripMenuItem("Start", null, (_, _) => ControlService(service, "start")) { Enabled = !busy && !running && state != ServiceState.Disabled });
        item.DropDownItems.Add(new ToolStripMenuItem("Stop", null, (_, _) => ControlService(service, "stop")) { Enabled = !busy && running });
        item.DropDownItems.Add(new ToolStripMenuItem("Restart", null, (_, _) => ControlService(service, "restart")) { Enabled = !busy && running });
        item.DropDownItems.Add(new ToolStripSeparator());
        item.DropDownItems.Add(new ToolStripMenuItem("Open Services console", null, (_, _) => Launch("services.msc")));
        item.DropDownItems.Add(new ToolStripMenuItem("Open Event Viewer", null, (_, _) => Launch("eventvwr.msc", "/c:Application")));
        return item;
    }

    private static bool SafeAutoStartEnabled()
    {
        try { return AutoStart.IsEnabled(); } catch { return false; }
    }

    // ---------- actions ----------

    private async void ControlService(LocalService service, string action)
    {
        if (_serviceActionRunning) return;
        _serviceActionRunning = true;
        try
        {
            var verb = action switch { "start" => "Starting", "stop" => "Stopping", _ => "Restarting" };
            _tray.Text = $"CertMaster: {verb} the {service.DisplayName} service...";
            await Task.Run(() => service.RunElevated(action));
        }
        finally
        {
            _serviceActionRunning = false;
            await PollAsync();
        }
    }

    private void OpenDesktopApp()
    {
        if (!File.Exists(_desktopExe))
        {
            if (_current?.Hub != null) OpenUrl(HubUrl());
            return;
        }
        // The desktop app asks for elevation itself (it needs the agent's API key).
        Launch(_desktopExe);
    }

    private static void OpenUrl(string url) => Launch(url);

    private static void Launch(string target, string? args = null)
    {
        try { Process.Start(new ProcessStartInfo(target, args ?? "") { UseShellExecute = true })?.Dispose(); }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { } // UAC prompt declined
        catch (Exception ex) { MessageBox.Show($"Could not open {target}.\n\n{ex.Message}", "CertMaster", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
    }

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _tray.Visible = false;
        base.ExitThreadCore();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _timer.Dispose();
            _tray.Dispose();
            _menu.Dispose();
            _http.Dispose();
            _icons.Dispose();
        }
        base.Dispose(disposing);
    }
}
