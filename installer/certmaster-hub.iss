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
Filename: "{sys}\sc.exe"; Parameters: "description ""{#ServiceName}"" ""Web UI and API for managing certificates across CertMaster agents"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure ""{#ServiceName}"" reset= 86400 actions= restart/60000/restart/60000/restart/300000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start ""{#ServiceName}"""; Flags: runhidden; StatusMsg: "Starting the Management Hub service..."
Filename: "http://localhost:{code:GetPort}/"; Description: "Open the Management Hub"; Flags: postinstall shellexec skipifsilent nowait

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#ServiceName}"""; Flags: runhidden; RunOnceId: "StopHub"
Filename: "{sys}\timeout.exe"; Parameters: "/t 3 /nobreak"; Flags: runhidden; RunOnceId: "WaitHub"
Filename: "{sys}\sc.exe"; Parameters: "delete ""{#ServiceName}"""; Flags: runhidden; RunOnceId: "DeleteHub"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""{#FirewallRule}"""; Flags: runhidden; RunOnceId: "DeleteFirewall"

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
    'Agents and browsers connect to this port. Put the hub behind HTTPS (a reverse proxy such as IIS ARR/nginx, or a Kestrel certificate) for production use.');
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
  Result := Code;
end;

procedure StopService();
var I, Code: Integer;
begin
  if Sc('query "{#ServiceName}"') <> 0 then exit;
  Sc('stop "{#ServiceName}"');
  for I := 1 to 30 do
  begin
    Exec(ExpandConstant('{sys}\cmd.exe'), '/c tasklist /FI "IMAGENAME eq {#ServiceExe}" | find /I "{#ServiceExe}" >nul', '', SW_HIDE, ewWaitUntilTerminated, Code);
    if Code <> 0 then break;
    Sleep(1000);
  end;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#ServiceExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var BinPath, Host, Json: String; Code: Integer;
begin
  if CurStep = ssInstall then StopService();
  if CurStep = ssPostInstall then
  begin
    if BindPage.SelectedValueIndex = 1 then Host := 'localhost' else Host := '0.0.0.0';
    Json := '{' + #13#10 + '  "Hub": { "Url": "http://' + Host + ':' + GetPort('') + '" }' + #13#10 + '}' + #13#10;
    SaveStringToFile(ExpandConstant('{app}\Service\appsettings.Production.json'), Json, False);

    BinPath := ExpandConstant('{app}\Service\{#ServiceExe}');
    if Sc('query "{#ServiceName}"') = 0 then
      Sc('config "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= delayed-auto obj= LocalSystem')
    else
      Sc('create "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= delayed-auto obj= LocalSystem DisplayName= "{#ServiceName}"');

    Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule name="{#FirewallRule}"', '', SW_HIDE, ewWaitUntilTerminated, Code);
    if WizardIsTaskSelected('firewall') and (BindPage.SelectedValueIndex = 0) then
      Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall add rule name="{#FirewallRule}" dir=in action=allow protocol=TCP localport=' + GetPort(''),
        '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine + 'Hub address:' + NewLine + Space + 'http://localhost:' + GetPort('') + '/' + NewLine + NewLine +
    'First sign-in:' + NewLine + Space + 'user "admin"; the generated password is written to' + NewLine + Space +
    ExpandConstant(DataFolder) + '\initial-admin-password.txt' + NewLine + NewLine + MemoTasksInfo;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    if DirExists(ExpandConstant(DataFolder)) and not UninstallSilent() then
      if MsgBox('Also delete Management Hub data (users, joined instances, settings) in ' + ExpandConstant(DataFolder) + '?',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant(DataFolder), True, True, True);
end;
