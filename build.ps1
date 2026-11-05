<#
.SYNOPSIS
    Publishes keylo.exe (CLI) and keylow.exe (app) side by side into dist\Keylo.
.EXAMPLE
    ./build.ps1            # Release build into dist\Keylo
    ./build.ps1 -Install   # ...then install to %LOCALAPPDATA%\Programs\Keylo (see install.ps1)
#>
param([switch]$Install)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dist = Join-Path $root 'dist\Keylo'

if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }

# Stamp the build "1.0.0+<date>.<commit>" (shown in About and by 'keylo version').
$commit = (git -C $root rev-parse --short=7 HEAD 2>$null)
if (-not $commit) { $commit = 'nogit' }
if (git -C $root status --porcelain 2>$null) { $commit += '-dirty' }
$stamp = "-p:InformationalVersion=1.1.0+$(Get-Date -Format yyyyMMdd).$commit"

# Framework-dependent (uses the installed .NET 10 runtime); both executables share one folder of DLLs.
# keylo targets Windows and macOS; this script builds the Windows one (build.sh builds macOS).
foreach ($project in 'src\Keylo.Cli', 'src\Keylo.App') {
    dotnet publish (Join-Path $root $project) -c Release -r win-x64 -f net10.0-windows10.0.19041.0 --self-contained false -o $dist -nologo -v q $stamp
    if ($LASTEXITCODE -ne 0) { throw "publish failed for $project" }
}

Get-ChildItem $dist -Filter *.pdb | Remove-Item
Write-Host "Published Keylo 1.1.0 ($commit) to $dist" -ForegroundColor Green
Get-ChildItem $dist -Filter *.exe | ForEach-Object { "  {0,-12} {1,8:N0} KB" -f $_.Name, ($_.Length / 1KB) }

if ($Install) { & (Join-Path $root 'install.ps1') -Source $dist }
