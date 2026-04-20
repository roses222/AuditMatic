@echo off
setlocal

REM Run the AuditMatic unit test suite from the repository root.
pushd "%~dp0"
echo [INFO] Repo root: %CD%

set "PY_EXE=venv\Scripts\python.exe"
if not exist "%PY_EXE%" (
  echo [ERROR] Virtual environment not found at %PY_EXE%
  echo Create it first: python -m venv venv
  popd
  pause
  exit /b 1
)

echo [INFO] Python interpreter: %PY_EXE%
echo [INFO] Running AuditMatic unit tests...
"%PY_EXE%" "tests\Test Scripts\run_unit_test_suite.py"
set TEST_EXIT=%ERRORLEVEL%

set "LATEST_REPORT="
for /f "delims=" %%F in ('dir /b /od "tests\reports\unit_test_report_*.json" 2^>nul') do set "LATEST_REPORT=%%F"

echo.
if "%TEST_EXIT%"=="0" (
  echo [OK] Test suite completed successfully.
) else (
  echo [FAIL] Test suite completed with failures. Exit code: %TEST_EXIT%
)

if defined LATEST_REPORT (
  echo [INFO] Latest report: tests\reports\%LATEST_REPORT%
  start "" "tests\reports"
) else (
  echo [WARN] No report file found in tests\reports.
)

popd
pause
exit /b %TEST_EXIT%
