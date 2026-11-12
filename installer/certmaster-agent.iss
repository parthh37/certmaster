; CertMaster Certificate Manager: agent Windows service + desktop app.
; Build: build\publish.ps1 (publishes to dist\ and compiles this script with ISCC).
#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define ServiceName "CertMaster Agent"
#define AppExe "CertMaster.UI.Desktop.exe"
#define ServiceExe "CertMaster.Server.Core.exe"

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
UninstallDisplayIcon={app}\UI.Desktop\{#AppExe}
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

[Files]
Source: "..\dist\agent\Service\*"; DestDir: "{app}\Service"; Components: agent; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\agent\UI.Desktop\*"; DestDir: "{app}\UI.Desktop"; Components: desktop; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\CertMaster"; Filename: "{app}\UI.Desktop\{#AppExe}"; Components: desktop
Name: "{autodesktop}\CertMaster"; Filename: "{app}\UI.Desktop\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{sys}\sc.exe"; Parameters: "description ""{#ServiceName}"" ""Requests, renews and deploys TLS certificates (CertMaster)"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure ""{#ServiceName}"" reset= 86400 actions= restart/60000/restart/60000/restart/300000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start ""{#ServiceName}"""; Flags: runhidden; StatusMsg: "Starting the CertMaster Agent service..."
Filename: "{app}\UI.Desktop\{#AppExe}"; Description: "Launch CertMaster"; Components: desktop; Flags: postinstall skipifsilent nowait shellexec

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#ServiceName}"""; Flags: runhidden; RunOnceId: "StopAgent"
Filename: "{sys}\timeout.exe"; Parameters: "/t 3 /nobreak"; Flags: runhidden; RunOnceId: "WaitAgent"
Filename: "{sys}\sc.exe"; Parameters: "delete ""{#ServiceName}"""; Flags: runhidden; RunOnceId: "DeleteAgent"

[Code]
const DataFolder = '{commonappdata}\CertMaster';

function Sc(const Params: String): Integer;
var Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := -1;
  Result := Code;
end;

function ServiceExists(): Boolean;
begin
  Result := Sc('query "{#ServiceName}"') = 0;
end;

procedure StopService();
var I, Code: Integer;
begin
  if not ServiceExists() then exit;
  Sc('stop "{#ServiceName}"');
  { wait up to 30s for the process to exit so files can be replaced }
  for I := 1 to 30 do
  begin
    Exec(ExpandConstant('{sys}\cmd.exe'), '/c tasklist /FI "IMAGENAME eq {#ServiceExe}" | find /I "{#ServiceExe}" >nul', '', SW_HIDE, ewWaitUntilTerminated, Code);
    if Code <> 0 then break;
    Sleep(1000);
  end;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#ServiceExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var BinPath: String; Code: Integer;
begin
  if CurStep = ssInstall then
  begin
    StopService();
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM {#AppExe}', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
  if CurStep = ssPostInstall then
  begin
    BinPath := ExpandConstant('{app}\Service\{#ServiceExe}');
    if ServiceExists() then
      Sc('config "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= delayed-auto obj= LocalSystem')
    else
      Sc('create "{#ServiceName}" binPath= "\"' + BinPath + '\"" start= delayed-auto obj= LocalSystem DisplayName= "{#ServiceName}"');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if DirExists(ExpandConstant(DataFolder)) and not UninstallSilent() then
      if MsgBox('Also delete CertMaster data (managed certificates, issued certificate files, ACME accounts and stored credentials) in ' +
                ExpandConstant(DataFolder) + '?' + #13#10#13#10 + 'Choose No to keep it for a future reinstall.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(ExpandConstant(DataFolder), True, True, True);
  end;
end;
