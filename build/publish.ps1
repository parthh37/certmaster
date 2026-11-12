# Publishes self-contained win-x64 builds into ./dist, ready for the Inno Setup scripts in ./installer.
param([string]$Configuration = "Release", [string]$Runtime = "win-x64")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$dist = Join-Path $root "dist"
if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }

function Publish($project, $out) {
    dotnet publish (Join-Path $root "src/$project") -c $Configuration -r $Runtime --self-contained true -o (Join-Path $dist $out) /p:DebugType=None
    if ($LASTEXITCODE -ne 0) { throw "publish failed: $project" }
}

Publish "CertMaster.Server.Core" "agent/Service"
Publish "CertMaster.UI.Desktop"  "agent/UI.Desktop"
Publish "CertMaster.Server.Hub"  "hub/Service"
Write-Host "Published to $dist. Build installers with: iscc installer\certmaster-agent.iss ; iscc installer\certmaster-hub.iss"
