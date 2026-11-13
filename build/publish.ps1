# Builds release artifacts:
#   dist/agent/Service, dist/agent/UI.Desktop (desktop app + tray monitor), dist/hub/Service   (self-contained win-x64)
#   dist/installers/certmaster-windows-x64-<ver>.exe, certmaster-hub-windows-x64-<ver>.exe  (if Inno Setup is installed)
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [switch]$SkipTests,
    [switch]$SkipInstallers
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $root "dist"
[xml]$props = Get-Content (Join-Path $root "Directory.Build.props")
$version = $props.Project.PropertyGroup.Version
Write-Host "CertMaster $version" -ForegroundColor Cyan

if (-not $SkipTests) {
    dotnet test (Join-Path $root "CertMaster.sln") -c $Configuration
    if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
}

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }

function Publish($project, $out) {
    dotnet publish (Join-Path $root "src/$project") -c $Configuration -r $Runtime --self-contained true -o (Join-Path $dist $out) /p:DebugType=None /p:DebugSymbols=false
    if ($LASTEXITCODE -ne 0) { throw "publish failed: $project" }
}

Publish "CertMaster.Server.Core" "agent/Service"
Publish "CertMaster.UI.Desktop"  "agent/UI.Desktop"
# The tray monitor goes next to the desktop app and shares its self-contained runtime (one copy in the installer).
Publish "CertMaster.UI.Tray"     "agent/UI.Desktop"
Publish "CertMaster.Server.Hub"  "hub/Service"

if ($SkipInstallers) { return }
$iscc = @(
    (Get-Command iscc -ErrorAction SilentlyContinue).Source,
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { Write-Warning "Inno Setup 6 (ISCC.exe) not found; skipping installers."; return }

foreach ($iss in "certmaster-agent.iss", "certmaster-hub.iss") {
    & $iscc "/DAppVersion=$version" (Join-Path $root "installer/$iss")
    if ($LASTEXITCODE -ne 0) { throw "ISCC failed: $iss" }
}
Get-ChildItem (Join-Path $dist "installers") | ForEach-Object { Write-Host ("{0}  {1:N1} MB" -f $_.Name, ($_.Length / 1MB)) -ForegroundColor Green }
