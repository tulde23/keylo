$ErrorActionPreference = 'Stop'

# Keylo's NSIS setup from the GitHub release: a per-user install to %LOCALAPPDATA%\Keylo that adds
# that folder to the user PATH.
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'exe'
  url64bit       = 'https://github.com/tulde23/keylo/releases/download/v1.7.18/Keylo_1.7.18_x64-setup.exe'
  checksum64     = '061E403BC5C445AF65D2DFC60DE30E897E87794B279912F25AEA4BB8032C2087'
  checksumType64 = 'sha256'
  silentArgs     = '/S'
  validExitCodes = @(0)
  softwareName   = 'Keylo*'
}
Install-ChocolateyPackage @packageArgs
