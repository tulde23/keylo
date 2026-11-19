; Keylo's NSIS installer hooks (bundle.windows.nsis.installerHooks in release/windows.json).
; Puts the install folder on the user PATH so `keylo` works in any new terminal, as install.ps1
; does, and takes it off again on uninstall. PowerShell's SetEnvironmentVariable broadcasts the
; change, so new terminals see it without signing out. The folder goes to PowerShell in an
; environment variable (a quote in the path can't break the command). $$ is a literal $ in NSIS.

!macro NSIS_HOOK_POSTINSTALL
  System::Call 'Kernel32::SetEnvironmentVariable(t "KEYLO_INSTDIR", t "$INSTDIR")'
  nsExec::ExecToLog `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:KEYLO_INSTDIR.TrimEnd('\'); $$p = [Environment]::GetEnvironmentVariable('Path', 'User'); $$e = @(($$p -split ';') | Where-Object { $$_ -and $$_.TrimEnd('\') -ne $$d }); [Environment]::SetEnvironmentVariable('Path', (($$e + $$d) -join ';'), 'User')"`
  Pop $0
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  System::Call 'Kernel32::SetEnvironmentVariable(t "KEYLO_INSTDIR", t "$INSTDIR")'
  nsExec::ExecToLog `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d = $$env:KEYLO_INSTDIR.TrimEnd('\'); $$p = [Environment]::GetEnvironmentVariable('Path', 'User'); $$e = @(($$p -split ';') | Where-Object { $$_ -and $$_.TrimEnd('\') -ne $$d }); [Environment]::SetEnvironmentVariable('Path', ($$e -join ';'), 'User')"`
  Pop $0
!macroend
