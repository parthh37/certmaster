# Bumps <Version> in Directory.Build.props (the single source of the product version).
#   ./build/bump-version.ps1 -Bump minor        # 1.2.3 -> 1.3.0
#   ./build/bump-version.ps1 -Version 2.0.0     # explicit version
#   ./build/bump-version.ps1 -Bump patch -DryRun
# Versions are plain MAJOR.MINOR.PATCH because the installers use them as Windows file versions.
# Under GitHub Actions the result is also written to $GITHUB_OUTPUT (previous, version, tag).
param(
    [ValidateSet("patch", "minor", "major")]
    [string]$Bump = "patch",
    [string]$Version,
    [switch]$DryRun
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$propsPath = Join-Path $root "Directory.Build.props"
$text = [IO.File]::ReadAllText($propsPath)

$pattern = '<Version>\s*([^<]*?)\s*</Version>'
$match = [regex]::Match($text, $pattern)
if (-not $match.Success) { throw "No <Version> element in $propsPath" }
$current = $match.Groups[1].Value

function Parse([string]$v, [string]$what) {
    if ($v -notmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$') {
        throw "$what '$v' is not a MAJOR.MINOR.PATCH version (e.g. 1.4.0)."
    }
    [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
}

$cur = Parse $current "Current version"
if ($Version) {
    $new = Parse $Version.Trim().TrimStart("v", "V") "Requested version"
    if ($new -le $cur) { throw "Requested version $new must be greater than the current version $cur." }
} else {
    $new = switch ($Bump) {
        "major" { [version]::new($cur.Major + 1, 0, 0) }
        "minor" { [version]::new($cur.Major, $cur.Minor + 1, 0) }
        default { [version]::new($cur.Major, $cur.Minor, $cur.Build + 1) }
    }
}
$newText = "$($new.Major).$($new.Minor).$($new.Build)"
$tag = "v$newText"

& git -C $root rev-parse -q --verify "refs/tags/$tag" *> $null
if ($LASTEXITCODE -eq 0) { throw "Tag $tag already exists. Choose another version." }
$global:LASTEXITCODE = 0

if (-not $DryRun) {
    $updated = [regex]::Replace($text, $pattern, "<Version>$newText</Version>", 1)
    [IO.File]::WriteAllText($propsPath, $updated, [Text.UTF8Encoding]::new($false))
}

Write-Host "Version $current -> $newText$(if ($DryRun) { ' (dry run, nothing written)' })" -ForegroundColor Cyan
if ($env:GITHUB_OUTPUT) {
    "previous=$current", "version=$newText", "tag=$tag" | Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8
}
$newText
