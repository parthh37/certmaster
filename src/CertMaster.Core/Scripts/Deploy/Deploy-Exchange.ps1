<#
.SYNOPSIS
    CertMaster helper: imports a PFX into Exchange (2013 or later) and enables it for the given services.
.NOTES
    The PFX password is read from the CERTMASTER_PFX_PASSWORD environment variable so it is never on the command line.
#>
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Thumbprint,
    [Parameter(Mandatory = $true)][string]$PfxPath,
    [ValidatePattern('^[A-Za-z,]+$')][string]$Services = 'POP,IMAP,SMTP,IIS',
    [switch]$DoNotRequireSsl
)

$ErrorActionPreference = 'Stop'

function Connect-ExchangeShell {
    if (Get-Command Get-ExchangeCertificate -ErrorAction SilentlyContinue) { return }
    $snapin = Get-PSSnapin -Registered -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Microsoft.Exchange.Management.PowerShell.SnapIn' }
    if ($snapin) {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        return
    }
    if ($env:ExchangeInstallPath) {
        $remote = Join-Path $env:ExchangeInstallPath 'bin\RemoteExchange.ps1'
        if (Test-Path -LiteralPath $remote) {
            . $remote
            Connect-ExchangeServer -auto -ClientApplication:ManagementShell | Out-Null
            return
        }
    }
    throw "Exchange Management Shell was not found on this server (no snap-in and no ExchangeInstallPath)."
}

try {
    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) { throw "PFX file not found: $PfxPath" }
    Connect-ExchangeShell

    $existing = Get-ExchangeCertificate -Thumbprint $Thumbprint -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Output "Certificate $Thumbprint is already known to Exchange"
    }
    else {
        Write-Output "Importing certificate $Thumbprint into Exchange"
        $bytes = [System.IO.File]::ReadAllBytes($PfxPath)
        $plain = [string]$env:CERTMASTER_PFX_PASSWORD
        if ($plain.Length -gt 0) {
            $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
            Import-ExchangeCertificate -FileData $bytes -Password $secure -PrivateKeyExportable $true | Out-Null
        }
        else {
            Import-ExchangeCertificate -FileData $bytes -PrivateKeyExportable $true | Out-Null
        }
    }

    $serviceList = $Services -split ',' | Where-Object { $_ } | ForEach-Object { $_.Trim() }
    Write-Output ("Enabling certificate for services: " + ($serviceList -join ','))
    $enable = @{ Thumbprint = $Thumbprint; Services = ($serviceList -join ','); Force = $true }
    if ($DoNotRequireSsl) { $enable['DoNotRequireSsl'] = $true }
    Enable-ExchangeCertificate @enable

    Write-Output "Exchange certificate updated"
    exit 0
}
catch {
    Write-Error -Message ("Exchange update failed: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
}
