@echo off
rem Double-click to run infra_audit now and see the report in this window.
rem Saved to history and reports\ like the daily run (it just doesn't refresh HardBounceCheck first).
cd /d "%~dp0.."
".venv\Scripts\python.exe" -m infra_audit
echo.
pause
