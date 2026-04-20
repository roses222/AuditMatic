@echo off
setlocal

REM Full AuditMatic GUI launcher.
pushd "%~dp0"

if exist "venv\Scripts\pythonw.exe" (
  start "" "venv\Scripts\pythonw.exe" "main.py"
  popd
  exit /b 0
)

if exist "venv\Scripts\python.exe" (
  start "" "venv\Scripts\python.exe" "main.py"
  popd
  exit /b 0
)

echo [ERROR] Missing virtual environment at venv\Scripts\python.exe
echo [NEXT] Run setup first: setup.bat OR python bootstrap_setup.py
popd
pause
