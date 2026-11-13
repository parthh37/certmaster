using CertMaster.UI.Tray;

// CertMaster tray monitor.
//   CertMaster.UI.Tray.exe                         show the tray icon (one per signed-in user)
//   CertMaster.UI.Tray.exe --autostart             same, from the Run key at sign-in; exits if this user turned it off
//   CertMaster.UI.Tray.exe --service <start|stop|restart> <agent|hub>
//                                                  elevated helper the tray launches to control a service

ApplicationConfiguration.Initialize();

if (args.Length == 3 && args[0] == "--service")
{
    var service = LocalService.FromKey(args[2]);
    if (service == null || args[1] is not ("start" or "stop" or "restart")) return 2;
    return service.Control(args[1]);
}

if (args.Contains(AutoStart.AutoStartArgument))
{
    try { if (AutoStart.IsOptedOut()) return 0; }
    catch { /* registry unreadable: start anyway */ }
}

// One tray icon per user session.
using var mutex = new Mutex(true, @"Local\CertMaster.UI.Tray", out var first);
if (!first) return 0;

using var context = new TrayContext();
Application.Run(context);
return 0;
