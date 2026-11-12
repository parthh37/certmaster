<#
.SYNOPSIS
    CertMaster helper: runs a user deployment script with named arguments and (optionally) the request result object.
.DESCRIPTION
    Arguments are read from a JSON file ({ "named": { "name": "value" }, "positional": [ "value" ] }) and splatted onto
    the target script, so argument values are never parsed as PowerShell code. When -PassResult is set, the result
    (ManagedItem, IsSuccess, Message) is passed as the first positional argument.
#>
param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [string]$ResultJsonPath,
    [string]$ArgumentsJsonPath,
    [switch]$PassResult
)

$ErrorActionPreference = 'Stop'

try {
    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "Script not found: $ScriptPath"
    }

    $named = @{}
    $positional = @()
    if ($ArgumentsJsonPath -and (Test-Path -LiteralPath $ArgumentsJsonPath)) {
        $parsed = Get-Content -LiteralPath $ArgumentsJsonPath -Raw | ConvertFrom-Json
        if ($parsed.named) {
            foreach ($p in $parsed.named.PSObject.Properties) { $named[$p.Name] = [string]$p.Value }
        }
        if ($parsed.positional) { $positional = @($parsed.positional | ForEach-Object { [string]$_ }) }
    }

    if ($PassResult) {
        if (-not $ResultJsonPath -or -not (Test-Path -LiteralPath $ResultJsonPath)) { throw "Result file not found: $ResultJsonPath" }
        $result = Get-Content -LiteralPath $ResultJsonPath -Raw | ConvertFrom-Json
        $positional = @($result) + $positional
    }

    $global:LASTEXITCODE = 0
    & $ScriptPath @positional @named
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    exit 0
}
catch {
    Write-Error -Message ("Script error: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
}
