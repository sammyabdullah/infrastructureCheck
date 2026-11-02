@echo off
rem Scheduled run: refresh HardBounceCheck's bounce data, then run infra_audit.
rem Output is appended to data\scheduled_run.log, and a Command Prompt window
rem opens with the results. Its title says whether anything needs attention.

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
if exist "%ROOT%\data\last_run.txt" del "%ROOT%\data\last_run.txt"
pushd "%ROOT%"
"%PY%" -m infra_audit --no-color >> "%LOG%" 2>&1
set RC=%ERRORLEVEL%
popd
echo infra_audit exit code %RC% >> "%LOG%"

set "TITLE=infra_audit %DATE%: all good"
if %RC% EQU 1 set "TITLE=infra_audit %DATE%: warnings, nothing new"
if %RC% GEQ 2 set "TITLE=infra_audit %DATE%: ACTION NEEDED"
if exist "%ROOT%\data\last_run.txt" (
    start "%TITLE%" /d "%ROOT%" cmd /k type data\last_run.txt
) else (
    start "infra_audit %DATE%: DID NOT FINISH - see log" /d "%ROOT%" cmd /k powershell -NoProfile -Command "Get-Content data\scheduled_run.log -Tail 40"
)
exit /b %RC%
