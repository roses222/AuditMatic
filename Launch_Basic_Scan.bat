@echo off
setlocal

REM Standalone basic scan launcher (terminal + logs + report outputs).
pushd "%~dp0"

set "EXIT_CODE=0"
echo [INFO] Starting standalone basic scan...
echo [INFO] This flow does not use saved profiles or pipelines.

if exist "venv\Scripts\python.exe" (
  "venv\Scripts\python.exe" "quick_audit_scan.py"
  set "EXIT_CODE=%ERRORLEVEL%"
) else (
  echo [ERROR] Missing virtual environment at venv\Scripts\python.exe
  echo [NEXT] Run setup first: setup.bat OR python bootstrap_setup.py
  set "EXIT_CODE=1"
)

echo.
if "%EXIT_CODE%"=="0" (
  echo [OK] Basic scan completed.
) else (
  echo [FAIL] Basic scan ended with exit code %EXIT_CODE%.
)
echo [INFO] Logs folder: logs\
echo [INFO] Reports/workbooks: Audit Results\
echo [INFO] JSON artifacts: JSON\json_result\ and JSON\scan_jobs\

popd
pause
exit /b %EXIT_CODE%
