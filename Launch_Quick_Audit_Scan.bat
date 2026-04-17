@echo off
setlocal

pushd "%~dp0"

if exist "venv\Scripts\pythonw.exe" (
    start "" "venv\Scripts\pythonw.exe" "quick_audit_scan.py"
    exit /b 0
)

if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" "quick_audit_scan.py"
    exit /b %errorlevel%
)

py -3 "quick_audit_scan.py"
exit /b %errorlevel%
