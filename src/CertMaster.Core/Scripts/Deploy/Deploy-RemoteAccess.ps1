<#
.SYNOPSIS
    CertMaster helper: sets the Remote Access (DirectAccess IP-HTTPS / VPN SSTP) SSL certificate.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
    [switch]$RestartService
)

$ErrorActionPreference = 'Stop'

try {
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Thumbprint } | Select-Object -First 1
    if (-not $cert) { throw "Certificate $Thumbprint was not found in LocalMachine\My." }

    if (-not (Get-Module -ListAvailable -Name RemoteAccess)) { throw "The RemoteAccess PowerShell module is not available. Install the Remote Access role management tools." }
    Import-Module RemoteAccess

    Write-Output "Setting Remote Access SSL certificate to $Thumbprint"
    Set-RemoteAccess -SslCertificate $cert

    if ($RestartService) {
        Write-Output "Restarting RemoteAccess"
        Restart-Service -Name RemoteAccess -Force
    }
    Write-Output "Remote Access certificate updated"
    exit 0
}
catch {
    Write-Error -Message ("Remote Access update failed: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
}
