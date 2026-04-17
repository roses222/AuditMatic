@echo off
setlocal

pushd "%~dp0"
call "scripts\Launch_Quick_Audit_Scan.bat"
set _exit=%errorlevel%
popd
exit /b %_exit%
