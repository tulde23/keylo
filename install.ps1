<#
.SYNOPSIS
    Installs Keylo for the current user: copies it to %LOCALAPPDATA%\Programs\Keylo, adds that
    folder to the user PATH (so "keylo" works in any new terminal), and creates a Start menu
    shortcut to keylow.exe. No admin rights needed. Secrets are not touched.
.EXAMPLE
    ./install.ps1
    ./install.ps1 -Uninstall    # removes the program, PATH entry and shortcut; leaves your secrets
#>
param(
    [string]$Source = (Join-Path $PSScriptRoot 'dist\Keylo'),
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$target = Join-Path $env:LOCALAPPDATA 'Programs\Keylo'
$shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'Keylo.lnk'

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @($userPath -split ';' | Where-Object { $_ -and $_.TrimEnd('\') -ne $target.TrimEnd('\') })

$running = Get-Process keylow -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$target*" }
if ($running) {
    $running | Stop-Process -Force
    # Wait for the files to be released, or the copy below fails half way.
    $running | Wait-Process -Timeout 15 -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
}

if ($Uninstall) {
    Remove-Item $target -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $shortcut -Force -ErrorAction SilentlyContinue
    [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User')
    Write-Host 'Keylo uninstalled. Secrets in Credential Manager and %LOCALAPPDATA%\Keylo were left in place.'
    return
}

if (-not (Test-Path (Join-Path $Source 'keylo.exe'))) { throw "Nothing to install at $Source. Run ./build.ps1 first." }

New-Item -ItemType Directory -Force $target | Out-Null
Copy-Item (Join-Path $Source '*') $target -Recurse -Force

[Environment]::SetEnvironmentVariable('Path', (($entries + $target) -join ';'), 'User')

$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut($shortcut)
$link.TargetPath = Join-Path $target 'keylow.exe'
$link.WorkingDirectory = $target
$link.Description = 'Keylo - local secrets vault'
$link.Save()

Write-Host "Installed to $target" -ForegroundColor Green
Write-Host "  - 'keylo' is on your PATH (open a new terminal)"
Write-Host "  - Start menu: Keylo"
