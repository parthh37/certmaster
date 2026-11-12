; CertMaster Management Hub (API + Blazor UI). Build after running build\publish.ps1.
#define AppVersion "1.0.0"

[Setup]
AppId=CertMasterHub
AppName=CertMaster Management Hub
AppVersion={#AppVersion}
AppPublisher=CertMaster
DefaultDirName={autopf}\CertMasterHub
OutputBaseFilename=certmaster-hub-windows-x64-{#AppVersion}
OutputDir=..\dist\installers
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes

[Files]
Source: "..\dist\hub\Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs createallsubdirs

[Run]
Filename: "{sys}\sc.exe"; Parameters: "create ""CertMaster Management Hub"" binPath= ""\""{app}\Service\CertMaster.Server.Hub.exe\"""" start= auto DisplayName= ""CertMaster Management Hub"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure ""CertMaster Management Hub"" reset= 86400 actions= restart/60000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start ""CertMaster Management Hub"""; Flags: runhidden
Filename: "http://localhost:9697/"; Description: "Open the Management Hub"; Flags: postinstall shellexec skipifsilent nowait

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop ""CertMaster Management Hub"""; Flags: runhidden; RunOnceId: "StopHub"
Filename: "{sys}\sc.exe"; Parameters: "delete ""CertMaster Management Hub"""; Flags: runhidden; RunOnceId: "DeleteHub"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop "CertMaster Management Hub"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2000);
  end;
end;
