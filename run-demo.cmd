@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-demo.ps1" %*
set "demo_exit=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %demo_exit%
