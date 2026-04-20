@echo off
setlocal

pushd "%~dp0"
call "Launch_Basic_Scan.bat"
set _exit=%errorlevel%
popd
exit /b %_exit%
