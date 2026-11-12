<#
.SYNOPSIS
    CertMaster helper: sets the Remote Desktop Gateway SSL certificate by thumbprint.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
    [switch]$RestartService
)

$ErrorActionPreference = 'Stop'

try {
    if (-not (Test-Path -LiteralPath ("Cert:\LocalMachine\My\" + $Thumbprint))) { throw "Certificate $Thumbprint was not found in LocalMachine\My." }

    if (-not (Get-Module -ListAvailable -Name RemoteDesktopServices)) { throw "The RemoteDesktopServices PowerShell module is not available. Run this task on the RD Gateway server." }
    Import-Module RemoteDesktopServices

    $setting = 'RDS:\GatewayServer\SSLCertificate\Thumbprint'
    if (-not (Test-Path -Path $setting)) { throw "RD Gateway configuration ($setting) was not found. Is the RD Gateway role installed?" }

    Write-Output "Setting RD Gateway certificate to $Thumbprint"
    Set-Item -Path $setting -Value $Thumbprint

    if ($RestartService) {
        Write-Output "Restarting TSGateway"
        Restart-Service -Name TSGateway -Force
    }
    Write-Output "RD Gateway certificate updated"
    exit 0
}
catch {
    Write-Error -Message ("RD Gateway update failed: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
}
