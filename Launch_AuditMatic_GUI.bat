@echo off
setlocal

REM Full AuditMatic GUI launcher.
pushd "%~dp0"

if exist "venv\Scripts\pythonw.exe" (
  echo [INFO] Launching AuditMatic GUI...
  start "" "venv\Scripts\pythonw.exe" "main.py"
  echo [OK] GUI launched. This window will close in 5 seconds...
  timeout /t 5 /nobreak
  popd
  goto :eof
)

if exist "venv\Scripts\python.exe" (
  echo [INFO] Launching AuditMatic GUI (console mode)...
  start "" "venv\Scripts\python.exe" "main.py"
  echo [OK] GUI launched. This window will close in 5 seconds...
  timeout /t 5 /nobreak
  popd
  goto :eof
)

echo [ERROR] Missing virtual environment at venv\Scripts\python.exe
echo [NEXT] Run setup first: setup.bat OR python bootstrap_setup.py
popd
