@echo off
setlocal

REM Headless basic local-only scan launcher (no dialogs, terminal output + logs + report).
pushd "%~dp0"

set "EXIT_CODE=0"
echo [INFO] Starting headless basic scan...
echo [INFO] This is a local-only scan using the default GEOINT SBL template.
echo.

if exist "venv\Scripts\python.exe" (
  "venv\Scripts\python.exe" "headless_basic_scan.py"
  set "EXIT_CODE=%ERRORLEVEL%"
) else (
  echo [ERROR] Missing virtual environment at venv\Scripts\python.exe
  echo [NEXT] Run setup first: setup.bat OR python bootstrap_setup.py
  set "EXIT_CODE=1"
)

echo.
if "%EXIT_CODE%"=="0" (
  echo [OK] Basic scan completed successfully.
) else (
  echo [FAIL] Basic scan ended with exit code %EXIT_CODE%.
)
echo [INFO] Logs folder: logs\
echo [INFO] Reports/workbooks: Audit Results\
echo [INFO] JSON artifacts: JSON\json_result\ and JSON\scan_jobs\
echo.
echo Press any key to close this window...

popd
pause
