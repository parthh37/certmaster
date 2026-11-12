<#
.SYNOPSIS
    CertMaster helper: applies a certificate (by thumbprint, already in LocalMachine\My) to AD FS.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
    [switch]$ServiceCommunications,
    [switch]$RestartService
)

$ErrorActionPreference = 'Stop'

try {
    $cert = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $Thumbprint) -ErrorAction SilentlyContinue
    if (-not $cert) { throw "Certificate $Thumbprint was not found in LocalMachine\My." }
    if (-not $cert.HasPrivateKey) { throw "Certificate $Thumbprint has no private key." }

    if (-not (Get-Module -ListAvailable -Name ADFS)) { throw "The ADFS PowerShell module is not available. Run this task on an AD FS server." }
    Import-Module ADFS

    Write-Output "Setting AD FS SSL certificate to $Thumbprint"
    Set-AdfsSslCertificate -Thumbprint $Thumbprint

    if ($ServiceCommunications) {
        Write-Output "Setting AD FS service-communications certificate to $Thumbprint"
        Set-AdfsCertificate -CertificateType Service-Communications -Thumbprint $Thumbprint
    }

    if ($RestartService) {
        Write-Output "Restarting adfssrv"
        Restart-Service -Name adfssrv -Force
    }
    Write-Output "AD FS certificate updated"
    exit 0
}
catch {
    Write-Error -Message ("AD FS update failed: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
}
