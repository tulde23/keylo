$ErrorActionPreference = 'Stop'

# Runs Keylo's own uninstaller silently. It removes the program and its PATH entry; your secrets and
# settings (in %LOCALAPPDATA%\Keylo) stay.
[array]$keys = Get-UninstallRegistryKey -SoftwareName 'Keylo'
if ($keys.Count -eq 1) {
  $file = ($keys[0].UninstallString -replace '"', '').Trim()
  Uninstall-ChocolateyPackage -PackageName $env:ChocolateyPackageName -FileType 'exe' -SilentArgs '/S' -File $file -ValidExitCodes @(0)
} elseif ($keys.Count -eq 0) {
  Write-Warning "Keylo isn't installed (no uninstall entry found); nothing to remove."
} else {
  Write-Warning "Found $($keys.Count) Keylo uninstall entries; not guessing which to remove:"
  $keys | ForEach-Object { Write-Warning "- $($_.DisplayName) $($_.DisplayVersion)" }
}
