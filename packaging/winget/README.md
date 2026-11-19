# winget

Manifests for the Windows Package Manager, in the layout of
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs). Submit a new version by copying
`manifests/t/tulde23/Keylo/<version>` there in a pull request, or with
[wingetcreate](https://github.com/microsoft/winget-create):

```powershell
wingetcreate update tulde23.Keylo --version <version> `
  --urls https://github.com/tulde23/keylo/releases/download/v<version>/Keylo_<version>_x64-setup.exe --submit
```

Check locally first: `winget validate --manifest <folder>`, then `winget install --manifest <folder>`
in a test machine or Windows Sandbox.

The setup .exe installs the app and `keylo.exe` for your account and adds its folder to the user
PATH (from the release after 1.7; see app/src-tauri/windows/hooks.nsh).
