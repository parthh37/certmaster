; CertMaster Certificate Manager: agent Windows service + desktop app.
; Build: build\publish.ps1 (publishes to dist\ and compiles this script with ISCC).
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define ServiceName "CertMaster Agent"
#define AppExe "CertMaster.UI.Desktop.exe"
#define ServiceExe "CertMaster.Server.Core.exe"
#define TrayExe "CertMaster.UI.Tray.exe"
#define TrayRunValue "CertMaster Tray"

[Setup]
AppId={{6C1C8F7E-3E0B-4C2B-9C1E-5D2F0B7A9A11}
AppName=CertMaster Certificate Manager
AppVersion={#AppVersion}
AppVerName=CertMaster Certificate Manager {#AppVersion}
AppPublisher=CertMaster contributors
AppPublisherURL=https://github.com/parthh37/certmaster
AppSupportURL=https://github.com/parthh37/certmaster/issues
VersionInfoVersion={#AppVersion}
VersionInfoProductName=CertMaster
VersionInfoDescription=CertMaster Certificate Manager Setup
DefaultDirName={autopf}\CertMaster
DefaultGroupName=CertMaster
DisableProgramGroupPage=yes
OutputDir=..\dist\installers
OutputBaseFilename=certmaster-windows-x64-{#AppVersion}
SetupIconFile=..\assets\certmaster.ico
UninstallDisplayIcon={app}\Service\{#ServiceExe}
LicenseFile=..\LICENSE
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
PrivilegesRequired=admin
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Types]
Name: "full"; Description: "Agent service and desktop app"
Name: "server"; Description: "Agent service only (headless / managed from a Management Hub)"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "agent"; Description: "CertMaster Agent (Windows service, required)"; Types: full server custom; Flags: fixed
Name: "desktop"; Description: "CertMaster desktop app"; Types: full

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Components: desktop
Name: "trayautostart"; Description: "Start the CertMaster tray monitor when users sign in"; Components: desktop

[Files]
Source: "..\dist\agent\Service\*"; DestDir: "{app}\Service"; Components: agent; Flags: ignoreversion recursesubdirs createallsubdirs
; WPF needs the Desktop Experience: on Server Core only the service is installed.
; UI.Desktop also holds the tray monitor (CertMaster.UI.Tray.exe), which shares the desktop runtime files.
Source: "..\dist\agent\UI.Desktop\*"; DestDir: "{app}\UI.Desktop"; Components: desktop; Check: not IsServerCore; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\CertMaster"; Filename: "{app}\UI.Desktop\{#AppExe}"; Components: desktop; Check: not IsServerCore
Name: "{autoprograms}\CertMaster Tray Monitor"; Filename: "{app}\UI.Desktop\{#TrayExe}"; Components: desktop; Check: not IsServerCore
Name: "{autodesktop}\CertMaster"; Filename: "{app}\UI.Desktop\{#AppExe}"; Tasks: desktopicon; Check: not IsServerCore

[Registry]
; Tray monitor for every user at sign-in (unelevated). Each user can switch it off from the tray menu (stored in HKCU).
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#TrayRunValue}"; \
  ValueData: """{app}\UI.Desktop\{#TrayExe}"" --autostart"; Components: desktop; Tasks: trayautostart; Check: not IsServerCore; Flags: uninsdeletevalue

[Run]
; The service itself is created, configured and started from [Code] (ssPostInstall), so the order is guaranteed and failures are logged.
Filename: "{app}\UI.Desktop\{#AppExe}"; Description: "Launch CertMaster"; Components: desktop; Check: not IsServerCore; Flags: postinstall skipifsilent nowait shellexec
Filename: "{app}\UI.Desktop\{#TrayExe}"; Description: "Show the tray monitor now"; Components: desktop; Tasks: trayautostart; Check: not IsServerCore; Flags: postinstall skipifsilent nowait runasoriginaluser

[Code]
const DataFolder = '{commonappdata}\CertMaster';

function IsServerCore(): Boolean;
var InstallationType: String;
begin
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'InstallationType', InstallationType)
    and (CompareText(InstallationType, 'Server Core') = 0);
end;

function Sc(const Params: String): Integer;
var Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := -1;
  Log('sc ' + Params + ' -> ' + IntToStr(Code));
  Result := Code;
end;

function ServiceExists(): Boolean;
begin
  Result := Sc('query "{#ServiceName}"') = 0;
end;

function ProcessRunning(): Boolean;
var Code: Integer;
begin
  Exec(ExpandConstant('{sys}\cmd.exe'), '/c tasklist /NH /FI "IMAGENAME eq {#ServiceExe}" | find /I "{#ServiceExe}" >nul', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := Code = 0;
end;

{ Stops the service and waits for the process to exit, so files can be replaced. A running renewal gets up to 60 s to
  finish cleanly (the service's shutdown timeout); only then is the process killed. }
procedure StopService();
var I, Code: Integer;
begin
  if ServiceExists() then Sc('stop "{#ServiceName}"');
  for I := 1 to 90 do
  begin
    if not ProcessRunning() then exit;
    Sleep(1000);
  end;
  Log('Service process still running after 90 s; terminating it.');
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM {#ServiceExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(2000);
end;

procedure ConfigureService();
var BinPath: String; Code: Integer;
begin
  BinPath := ExpandConstant('{app}\Service\{#ServiceExe}');
  { Automatic (not delayed) start: renewals run from boot, before and without anyone signing in. Depends on the TCP/IP
    stack and http.sys (used by the http-01 challenge listener); network calls that fail early are retried. }
  if ServiceExists() then
    Code := Sc('config "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= auto depend= Tcpip/HTTP obj= LocalSystem')
  else
    Code := Sc('create "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= auto depend= Tcpip/HTTP obj= LocalSystem DisplayName= "{#ServiceName}"');
  if Code <> 0 then
  begin
    if not WizardSilent() then
      MsgBox('The CertMaster Agent service could not be registered (sc.exe exit code ' + IntToStr(Code) + '). See the setup log for details.', mbError, MB_OK);
    exit;
  end;
  { Earlier versions used delayed start; clear the flag so an upgraded service also starts at boot. }
  RegWriteDWordValue(HKLM, 'SYSTEM\CurrentControlSet\Services\{#ServiceName}', 'DelayedAutostart', 0);
  Sc('description "{#ServiceName}" "Requests, renews and deploys TLS certificates (CertMaster)"');
  { Restart after a crash or a non-zero exit (failureflag 1), at 1 min, 1 min, then every 5 min; the counter resets daily. }
  Sc('failure "{#ServiceName}" reset= 86400 actions= restart/60000/restart/60000/restart/300000');
  Sc('failureflag "{#ServiceName}" 1');
  { Unrestricted service SID so file and certificate ACLs can name "NT SERVICE\CertMaster Agent" if needed. }
  Sc('sidtype "{#ServiceName}" unrestricted');
  Code := Sc('start "{#ServiceName}"');
  { 1056 = already running }
  if (Code <> 0) and (Code <> 1056) and not WizardSilent() then
    MsgBox('The CertMaster Agent service was installed but did not start (sc.exe exit code ' + IntToStr(Code) + ').' + #13#10 +
      'Check ' + ExpandConstant(DataFolder) + '\logs\service.log and the Application event log.', mbError, MB_OK);
end;

{ Closes the desktop app and every user's tray monitor so their files can be replaced or removed. }
procedure CloseDesktopApps();
var Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#TrayExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    StopService();
    CloseDesktopApps();
  end;
  if CurStep = ssPostInstall then
  begin
    ConfigureService();
    { An upgrade where the tray task was unticked: remove the sign-in entry an earlier install created. }
    if not WizardIsTaskSelected('trayautostart') then
      RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', '{#TrayRunValue}');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    { Before files are removed: stop the service, wait for it, then delete it. }
    StopService();
    CloseDesktopApps();
    if ServiceExists() then Sc('delete "{#ServiceName}"');
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    if DirExists(ExpandConstant(DataFolder)) and not UninstallSilent() then
      if MsgBox('Also delete CertMaster data (managed certificates, issued certificate files, ACME accounts and stored credentials) in ' +
                ExpandConstant(DataFolder) + '?' + #13#10#13#10 + 'Choose No to keep it for a future reinstall.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant(DataFolder), True, True, True);
  end;
end;
