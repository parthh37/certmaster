; CertMaster Certificate Manager (agent service + desktop UI). Build after running build\publish.ps1.
#define AppVersion "1.0.0"

[Setup]
AppId=CertMasterAgent
AppName=CertMaster Certificate Manager
AppVersion={#AppVersion}
AppPublisher=CertMaster
DefaultDirName={autopf}\CertMaster
DefaultGroupName=CertMaster
OutputBaseFilename=certmaster-agent-windows-x64-{#AppVersion}
OutputDir=..\dist\installers
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "..\dist\agent\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\dist\agent\UI.Desktop\*"; DestDir: "{app}\UI.Desktop"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\CertMaster"; Filename: "{app}\UI.Desktop\CertMaster.UI.Desktop.exe"
Name: "{commondesktop}\CertMaster"; Filename: "{app}\UI.Desktop\CertMaster.UI.Desktop.exe"

[Run]
Filename: "{sys}\sc.exe"; Parameters: "create ""CertMaster Agent"" binPath= ""\""{app}\Service\CertMaster.Server.Core.exe\"""" start= auto DisplayName= ""CertMaster Agent"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "description ""CertMaster Agent"" ""Requests, renews and deploys TLS certificates"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure ""CertMaster Agent"" reset= 86400 actions= restart/60000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start ""CertMaster Agent"""; Flags: runhidden
Filename: "{app}\UI.Desktop\CertMaster.UI.Desktop.exe"; Description: "Run CertMaster"; Flags: postinstall skipifsilent nowait runascurrentuser

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop ""CertMaster Agent"""; Flags: runhidden; RunOnceId: "StopAgent"
Filename: "{sys}\sc.exe"; Parameters: "delete ""CertMaster Agent"""; Flags: runhidden; RunOnceId: "DeleteAgent"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var ResultCode: Integer;
begin
  // stop an existing service before files are replaced on upgrade
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop "CertMaster Agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2000);
  end;
end;
