@echo off
setlocal EnableExtensions

REM Ensure desktop shortcuts exist for basic scan and full GUI launchers.
pushd "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $repoDir=(Resolve-Path '.').Path; $desktop=[Environment]::GetFolderPath('Desktop'); $shell=New-Object -ComObject WScript.Shell; $shortcuts=@(@{Name='AuditMatic Basic Scan'; Target='Launch_Basic_Scan.bat'}, @{Name='AuditMatic GUI'; Target='Launch_AuditMatic_GUI.bat'}); foreach ($item in $shortcuts) { $shortcutPath=Join-Path $desktop ($item.Name + '.lnk'); if (Test-Path $shortcutPath) { Write-Host ('[INFO] Shortcut exists: ' + $shortcutPath) } else { $shortcut=$shell.CreateShortcut($shortcutPath); $shortcut.TargetPath=Join-Path $repoDir $item.Target; $shortcut.WorkingDirectory=$repoDir; $shortcut.WindowStyle=1; $shortcut.Save(); Write-Host ('[OK] Created shortcut: ' + $shortcutPath) } }"

set "PS_EXIT=%ERRORLEVEL%"
if not "%PS_EXIT%"=="0" (
  echo [WARN] Could not ensure desktop shortcuts. Exit code: %PS_EXIT%.
  echo [WARN] You can still launch using Launch_Basic_Scan.bat and Launch_AuditMatic_GUI.bat.
)

popd
exit /b 0
