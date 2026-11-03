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

# Framework-dependent (uses the installed .NET 10 runtime); both executables share one folder of DLLs.
foreach ($project in 'src\Keylo.Cli', 'src\Keylo.App') {
    dotnet publish (Join-Path $root $project) -c Release -r win-x64 --self-contained false -o $dist -nologo -v q
    if ($LASTEXITCODE -ne 0) { throw "publish failed for $project" }
}

Get-ChildItem $dist -Filter *.pdb | Remove-Item
Write-Host "Published to $dist" -ForegroundColor Green
Get-ChildItem $dist -Filter *.exe | ForEach-Object { "  {0,-12} {1,8:N0} KB" -f $_.Name, ($_.Length / 1KB) }

if ($Install) { & (Join-Path $root 'install.ps1') -Source $dist }
