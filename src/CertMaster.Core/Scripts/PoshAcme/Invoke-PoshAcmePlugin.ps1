#Requires -Version 5.1
<#
.SYNOPSIS
    CertMaster bridge to the DNS plugins of the bundled Posh-ACME module.

.DESCRIPTION
    Reads a request from a JSON file (the file is deleted as soon as it has been read), imports the bundled
    Posh-ACME module from .\Posh-ACME and calls the requested plugin's Add-DnsTxt or Remove-DnsTxt function,
    followed by Save-DnsTxt when the plugin defines it. The plugin runs inside the Posh-ACME module scope, the same
    way Posh-ACME itself calls plugins, so module-private helpers and variables are available to it.

    Secrets are only ever passed in the request file, never on the command line. SecureString parameters arrive as
    plain text in the request and are converted here; PSCredential parameters arrive as User/Password pairs.

    Request file format (UTF-8 JSON):
    {
      "Action":       "Add" | "Remove" | "Test",
      "Plugin":       "Cloudflare",
      "RecordName":   "_acme-challenge.example.com",
      "TxtValue":     "<value>",
      "PoshAcmeHome": "<folder for Posh-ACME config, optional>",
      "Verbose":      true,
      "Args": {
        "CFToken":  { "Type": "securestring", "Value": "..." },
        "AZAppCred": { "Type": "pscredential", "User": "...", "Password": "..." },
        "Name":     { "Type": "string|switch|bool|int|double|stringarray|hashtable", "Value": ... }
      }
    }

    Exit codes: 0 = success, 1 = plugin error, 2 = invalid request, 3 = module or plugin could not be loaded.

.PARAMETER ParamFile
    Path of the request JSON file.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ParamFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }

function Exit-WithError([string]$Message, [int]$Code) {
    [Console]::Error.WriteLine($Message)
    exit $Code
}

function ConvertTo-PlainObject($InputObject) {
    # ConvertFrom-Json returns PSCustomObjects; plugins expect hashtables (Windows PowerShell has no -AsHashtable).
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-PlainObject $p.Value }
        return $h
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        return , @($InputObject | ForEach-Object { ConvertTo-PlainObject $_ })
    }
    return $InputObject
}

# ---- read and immediately delete the request ----
$raw = $null
try {
    $raw = [System.IO.File]::ReadAllText($ParamFile, [System.Text.Encoding]::UTF8)
} catch {
    $readError = $_.Exception.Message
}
Remove-Item -LiteralPath $ParamFile -Force -ErrorAction SilentlyContinue
if ($null -eq $raw) { Exit-WithError "Cannot read the request file: $readError" 2 }

try { $request = $raw | ConvertFrom-Json } catch { Exit-WithError "The request file is not valid JSON." 2 }
$raw = $null

$action = "$($request.Action)"
$pluginName = "$($request.Plugin)"
if ($action -notin 'Add', 'Remove', 'Test') { Exit-WithError "Unknown action '$action'." 2 }
if ($pluginName -notmatch '^[\w-]+$') { Exit-WithError "Invalid plugin name '$pluginName'." 2 }
if ($action -ne 'Test' -and ([string]::IsNullOrWhiteSpace($request.RecordName) -or [string]::IsNullOrWhiteSpace($request.TxtValue))) {
    Exit-WithError "RecordName and TxtValue are required." 2
}

# ---- environment for the module ----
if ($request.PoshAcmeHome) {
    try {
        New-Item -ItemType Directory -Force -Path $request.PoshAcmeHome | Out-Null
        $env:POSHACME_HOME = $request.PoshAcmeHome
    } catch { }
}
# Only the bundled plugins are used.
$env:POSHACME_PLUGINS = $null

if ($PSVersionTable.PSEdition -ne 'Core') {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }
}

# ---- import the bundled module ----
$moduleDir = Join-Path $PSScriptRoot 'Posh-ACME'
$libDlls = @(Get-ChildItem -Path (Join-Path $moduleDir 'lib') -Filter '*.dll' -ErrorAction SilentlyContinue)
# The manifest requires the BouncyCastle assembly from lib\. When it is not present, import the root module
# directly; DNS plugins other than the few that need BouncyCastle work without it.
$modulePath = if ($libDlls.Count -gt 0) { Join-Path $moduleDir 'Posh-ACME.psd1' } else { Join-Path $moduleDir 'Posh-ACME.psm1' }
try {
    # Normally loaded by the manifest's RequiredAssemblies; Windows PowerShell does not load it by default.
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $module = Import-Module -Name $modulePath -Force -PassThru -DisableNameChecking -WarningAction SilentlyContinue
} catch {
    Exit-WithError "Failed to import the bundled Posh-ACME module from ${moduleDir}: $($_.Exception.Message)" 3
}
$module = @($module | Where-Object { $_.Name -eq 'Posh-ACME' })[0]
if (-not $module) { Exit-WithError "The bundled Posh-ACME module did not load." 3 }

# ---- build plugin arguments ----
$pluginArgs = @{}
if ($request.Args) {
    foreach ($prop in $request.Args.PSObject.Properties) {
        $name = $prop.Name
        $spec = $prop.Value
        $type = "$($spec.Type)".ToLowerInvariant()
        try {
            switch ($type) {
                'securestring' { $pluginArgs[$name] = ConvertTo-SecureString -String ([string]$spec.Value) -AsPlainText -Force }
                'pscredential' {
                    $secure = ConvertTo-SecureString -String ([string]$spec.Password) -AsPlainText -Force
                    $pluginArgs[$name] = New-Object System.Management.Automation.PSCredential ([string]$spec.User, $secure)
                }
                'switch'       { if ([bool]$spec.Value) { $pluginArgs[$name] = [switch]::Present } }
                'bool'         { $pluginArgs[$name] = [bool]$spec.Value }
                'int'          { $pluginArgs[$name] = [long]$spec.Value }
                'double'       { $pluginArgs[$name] = [double]$spec.Value }
                'stringarray'  { $pluginArgs[$name] = [string[]]@($spec.Value) }
                'hashtable'    { $pluginArgs[$name] = ConvertTo-PlainObject $spec.Value }
                default        { $pluginArgs[$name] = [string]$spec.Value }
            }
        } catch {
            Exit-WithError "Invalid value for plugin parameter ${name}: $($_.Exception.Message)" 2
        }
    }
}

# ---- run the plugin inside the module scope ----
$invoke = {
    param($PluginName, $Action, $RecordName, $TxtValue, $PluginArgs, $UseVerbose)

    if ($UseVerbose) { $VerbosePreference = 'Continue' }
    $detail = $script:Plugins[$PluginName]
    if (-not $detail -or -not $detail.Path) { throw "Posh-ACME plugin '$PluginName' is not available in the bundled module." }
    if ($detail.ChallengeType -ne 'dns-01') { throw "Posh-ACME plugin '$PluginName' is not a dns-01 plugin." }

    # dot source the plugin so its functions run in this (module) scope
    . $detail.Path

    $hasSave = [bool](Get-Command -Name 'Save-DnsTxt' -CommandType Function -ErrorAction SilentlyContinue)
    switch ($Action) {
        'Test' {
            foreach ($fn in 'Add-DnsTxt', 'Remove-DnsTxt') {
                if (-not (Get-Command -Name $fn -CommandType Function -ErrorAction SilentlyContinue)) { throw "Plugin $PluginName does not define $fn." }
            }
            Write-Output "Plugin $PluginName loaded."
        }
        'Add' {
            Add-DnsTxt -RecordName $RecordName -TxtValue $TxtValue @PluginArgs
            if ($hasSave) { Save-DnsTxt @PluginArgs }
        }
        'Remove' {
            Remove-DnsTxt -RecordName $RecordName -TxtValue $TxtValue @PluginArgs
            if ($hasSave) { Save-DnsTxt @PluginArgs }
        }
    }
}

try {
    & $module $invoke $pluginName $action "$($request.RecordName)" "$($request.TxtValue)" $pluginArgs ([bool]$request.Verbose) | ForEach-Object { Write-Output "$_" }
} catch {
    $message = $_.Exception.Message
    $where = $_.InvocationInfo
    if ($where -and $where.ScriptName) { $message += " (at $([System.IO.Path]::GetFileName($where.ScriptName)):$($where.ScriptLineNumber))" }
    Exit-WithError "Posh-ACME $pluginName $action failed: $message" 1
}

Write-Output 'POSHACME-RESULT: OK'
exit 0
