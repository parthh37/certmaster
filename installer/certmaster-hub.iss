; CertMaster Management Hub: web UI + API Windows service.
; Build: build\publish.ps1 (publishes to dist\ and compiles this script with ISCC).
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define ServiceName "CertMaster Management Hub"
#define ServiceExe "CertMaster.Server.Hub.exe"
#define FirewallRule "CertMaster Management Hub"

[Setup]
AppId={{9A4E2B61-7C3D-4F8A-B5E2-1D6C0F3A8B22}
AppName=CertMaster Management Hub
AppVersion={#AppVersion}
AppVerName=CertMaster Management Hub {#AppVersion}
AppPublisher=CertMaster contributors
AppPublisherURL=https://github.com/parthh37/certmaster
VersionInfoVersion={#AppVersion}
VersionInfoProductName=CertMaster Management Hub
VersionInfoDescription=CertMaster Management Hub Setup
DefaultDirName={autopf}\CertMasterHub
DisableProgramGroupPage=yes
OutputDir=..\dist\installers
OutputBaseFilename=certmaster-hub-windows-x64-{#AppVersion}
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
SetupLogging=yes

[Tasks]
Name: "firewall"; Description: "Allow inbound connections to the hub port in Windows Firewall"

[Files]
Source: "..\dist\hub\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\CertMaster Management Hub"; Filename: "http://localhost:{code:GetPort}/"; IconFilename: "{app}\Service\{#ServiceExe}"

[Run]
; The service is created, configured and started from [Code] (ssPostInstall), so the order is guaranteed and failures are logged.
Filename: "http://localhost:{code:GetPort}/"; Description: "Open the Management Hub"; Flags: postinstall shellexec skipifsilent nowait

[UninstallDelete]
Type: files; Name: "{app}\Service\appsettings.Installer.json"

[Code]
const DataFolder = '{commonappdata}\CertMasterHub';
var
  NetPage: TInputQueryWizardPage;
  BindPage: TInputOptionWizardPage;

function GetPort(Param: String): String;
begin
  Result := Trim(NetPage.Values[0]);
end;

procedure InitializeWizard();
begin
  NetPage := CreateInputQueryPage(wpSelectTasks, 'Hub network settings', 'Which port should the Management Hub listen on?',
    'Agents and browsers connect to this port. Put the hub behind HTTPS (a reverse proxy such as IIS ARR/nginx, or a Kestrel certificate in appsettings.Production.json) for production use.');
  NetPage.Add('&Port:', False);
  NetPage.Values[0] := GetPreviousData('HubPort', '9697');

  BindPage := CreateInputOptionPage(NetPage.ID, 'Hub network settings', 'Who can reach the hub?', '', True, False);
  BindPage.Add('All network interfaces (agents on other servers can connect)');
  BindPage.Add('This computer only (localhost)');
  BindPage.SelectedValueIndex := StrToIntDef(GetPreviousData('HubBind', '0'), 0);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var P: Integer;
begin
  Result := True;
  if CurPageID = NetPage.ID then
  begin
    P := StrToIntDef(GetPort(''), 0);
    if (P < 1) or (P > 65535) then
    begin
      MsgBox('Enter a port number between 1 and 65535.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(PreviousDataKey, 'HubPort', GetPort(''));
  SetPreviousData(PreviousDataKey, 'HubBind', IntToStr(BindPage.SelectedValueIndex));
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

{ Stops the service and waits for the process to exit so files can be replaced; kills it only as a last resort. }
procedure StopService();
var I, Code: Integer;
begin
  if ServiceExists() then Sc('stop "{#ServiceName}"');
  for I := 1 to 60 do
  begin
    if not ProcessRunning() then exit;
    Sleep(1000);
  end;
  Log('Hub process still running after 60 s; terminating it.');
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM {#ServiceExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(2000);
end;

{ Versions before 1.0.2 wrote the port into appsettings.Production.json, which is the administrator's file (HTTPS and
  Kestrel settings belong there). Remove it only when it holds nothing but that generated Hub:Url line. }
procedure RemoveLegacyGeneratedSettings();
var FileName, S: String; Content: AnsiString;
begin
  FileName := ExpandConstant('{app}\Service\appsettings.Production.json');
  if not LoadStringFromFile(FileName, Content) then exit;
  S := Trim(String(Content));
  if (Pos('"Hub": { "Url": "http://', S) > 0) and (Pos('Kestrel', S) = 0) and (Length(S) < 120) then
  begin
    Log('Removing installer-generated ' + FileName);
    DeleteFile(FileName);
  end;
end;

procedure ConfigureService();
var BinPath, Host, Json: String; Code: Integer;
begin
  RemoveLegacyGeneratedSettings();
  { '*' listens on all IPv4 and IPv6 addresses. }
  if BindPage.SelectedValueIndex = 1 then Host := 'localhost' else Host := '*';
  Json := '{' + #13#10 + '  "Hub": { "Url": "http://' + Host + ':' + GetPort('') + '" }' + #13#10 + '}' + #13#10;
  if not SaveStringToFile(ExpandConstant('{app}\Service\appsettings.Installer.json'), Json, False) then
    Log('Could not write appsettings.Installer.json');

  BinPath := ExpandConstant('{app}\Service\{#ServiceExe}');
  { Automatic (not delayed) start: the hub runs from boot, before and without anyone signing in. It waits for the TCP/IP
    stack; a bind failure (address not assigned yet) exits non-zero and the recovery actions retry it. }
  if ServiceExists() then
    Code := Sc('config "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= auto depend= Tcpip obj= LocalSystem')
  else
    Code := Sc('create "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= auto depend= Tcpip obj= LocalSystem DisplayName= "{#ServiceName}"');
  if Code <> 0 then
  begin
    if not WizardSilent() then
      MsgBox('The Management Hub service could not be registered (sc.exe exit code ' + IntToStr(Code) + '). See the setup log for details.', mbError, MB_OK);
    exit;
  end;
  { Earlier versions used delayed start; clear the flag so an upgraded service also starts at boot. }
  RegWriteDWordValue(HKLM, 'SYSTEM\CurrentControlSet\Services\{#ServiceName}', 'DelayedAutostart', 0);
  Sc('description "{#ServiceName}" "Web UI and API for managing certificates across CertMaster agents"');
  { Restart after a crash or a non-zero exit (failureflag 1), at 1 min, 1 min, then every 5 min; the counter resets daily. }
  Sc('failure "{#ServiceName}" reset= 86400 actions= restart/60000/restart/60000/restart/300000');
  Sc('failureflag "{#ServiceName}" 1');

  { Firewall rule scoped to the hub executable and port. }
  Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="{#FirewallRule}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if WizardIsTaskSelected('firewall') and (BindPage.SelectedValueIndex = 0) then
  begin
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall add rule name="{#FirewallRule}" dir=in action=allow protocol=TCP localport=' + GetPort('') +
      ' program="' + BinPath + '"', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Log('netsh advfirewall add rule -> ' + IntToStr(Code));
  end;

  Code := Sc('start "{#ServiceName}"');
  { 1056 = already running }
  if (Code <> 0) and (Code <> 1056) and not WizardSilent() then
    MsgBox('The Management Hub service was installed but did not start (sc.exe exit code ' + IntToStr(Code) + ').' + #13#10 +
      'Check that port ' + GetPort('') + ' is free, then see ' + ExpandConstant(DataFolder) + '\logs\hub.log and the Application event log.', mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then StopService();
  if CurStep = ssPostInstall then ConfigureService();
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine + 'Hub address:' + NewLine + Space + 'http://localhost:' + GetPort('') + '/' + NewLine + NewLine +
    'First sign-in:' + NewLine + Space + 'user "admin"; the generated password is written to' + NewLine + Space +
    ExpandConstant(DataFolder) + '\initial-admin-password.txt' + NewLine + NewLine + MemoTasksInfo;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Code: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    { Before files are removed: stop the service, wait for it, then delete it and its firewall rule. }
    StopService();
    if ServiceExists() then Sc('delete "{#ServiceName}"');
    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="{#FirewallRule}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
  if CurUninstallStep = usPostUninstall then
    if DirExists(ExpandConstant(DataFolder)) and not UninstallSilent() then
      if MsgBox('Also delete Management Hub data (users, joined instances, settings) in ' + ExpandConstant(DataFolder) + '?',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant(DataFolder), True, True, True);
end;
