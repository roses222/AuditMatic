@echo off
setlocal EnableExtensions

REM Bootstrap AuditMatic for first-time clones on Windows.
pushd "%~dp0"

echo [INFO] AuditMatic setup starting in %CD%

set "PYTHON_CMD="
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  set "PYTHON_CMD=py -3"
) else (
  where python >nul 2>nul
  if %ERRORLEVEL%==0 (
    set "PYTHON_CMD=python"
  )
)

if "%PYTHON_CMD%"=="" (
  echo [ERROR] Python was not found on PATH.
  echo Install Python 3.10+ and reopen terminal, then run setup.bat again.
  popd
  pause
  exit /b 1
)

echo [INFO] Using Python command: %PYTHON_CMD%
%PYTHON_CMD% --version
if not %ERRORLEVEL%==0 (
  echo [ERROR] Unable to execute Python command: %PYTHON_CMD%
  popd
  pause
  exit /b 1
)

if not exist "venv\Scripts\python.exe" (
  echo [INFO] Creating virtual environment in .\venv
  %PYTHON_CMD% -m venv venv
  if not %ERRORLEVEL%==0 (
    echo [ERROR] Failed to create virtual environment.
    popd
    pause
    exit /b 1
  )
) else (
  echo [INFO] Reusing existing virtual environment.
)

set "VENV_PY=venv\Scripts\python.exe"
set "VENV_PIP=venv\Scripts\pip.exe"

echo [INFO] Upgrading packaging tools...
"%VENV_PY%" -m pip install --upgrade pip setuptools wheel
if not %ERRORLEVEL%==0 (
  echo [ERROR] Failed to upgrade pip/setuptools/wheel.
  popd
  pause
  exit /b 1
)

echo [INFO] Installing dependencies from requirements.txt...
"%VENV_PIP%" install -r requirements.txt
if not %ERRORLEVEL%==0 (
  echo [ERROR] Dependency installation failed.
  popd
  pause
  exit /b 1
)

echo [INFO] Running dependency health check...
"%VENV_PY%" -m pip check
if not %ERRORLEVEL%==0 (
  echo [ERROR] pip check reported environment issues.
  popd
  pause
  exit /b 1
)

echo [INFO] Ensuring desktop shortcuts exist...
call ".\ensure_desktop_shortcuts.bat"

echo.
echo [OK] Setup complete.
echo [NEXT] Launch app:  .\venv\Scripts\python.exe main.py
echo [NEXT] Basic scan:  .\Launch_Basic_Scan.bat
echo [NEXT] Run tests:   .\run_tests.bat
echo.

if /I "%~1"=="--run" (
  echo [INFO] Starting AuditMatic...
  "%VENV_PY%" main.py
)

popd
pause
exit /b 0
