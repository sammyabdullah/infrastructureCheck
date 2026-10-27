@echo off
rem Scheduled run: refresh HardBounceCheck's bounce data, then run infra_audit.
rem Output is appended to data\scheduled_run.log. If infra_audit finds a FAIL
rem or a regression (exit code 2), the new report opens in Notepad.

setlocal
set "ROOT=%~dp0.."
set "HARDBOUNCE=%ROOT%\..\..\Old claude\Claude Hard Bounce Check"
set "PY=%ROOT%\.venv\Scripts\python.exe"
set "LOG=%ROOT%\data\scheduled_run.log"

if not exist "%ROOT%\data" mkdir "%ROOT%\data"
echo. >> "%LOG%"
echo ===== %DATE% %TIME% ===== >> "%LOG%"

echo --- HardBounceCheck --- >> "%LOG%"
if exist "%HARDBOUNCE%\main.py" (
    pushd "%HARDBOUNCE%"
    "%PY%" main.py >> "%LOG%" 2>&1
    popd
) else (
    echo HardBounceCheck not found at "%HARDBOUNCE%" - skipped >> "%LOG%"
)

echo --- infra_audit --- >> "%LOG%"
pushd "%ROOT%"
"%PY%" -m infra_audit --no-color >> "%LOG%" 2>&1
set RC=%ERRORLEVEL%
popd
echo infra_audit exit code %RC% >> "%LOG%"

if %RC% GEQ 2 (
    for /f "delims=" %%F in ('dir /b /o-d "%ROOT%\reports\infra_audit_*.md" 2^>nul') do (
        start "" notepad "%ROOT%\reports\%%F"
        goto :done
    )
)
:done
exit /b %RC%
