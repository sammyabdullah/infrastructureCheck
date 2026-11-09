# Registers a daily Windows scheduled task that runs scripts\run_scheduled.bat
# (HardBounceCheck, then infra_audit) as you, at 7:43 AM. If the PC is off or
# asleep at that time, it runs as soon as possible afterwards.
#
#   Install:    powershell -ExecutionPolicy Bypass -File scripts\setup_schedule.ps1
#   Run now:    Start-ScheduledTask -TaskName "infra_audit daily"
#   Remove:     Unregister-ScheduledTask -TaskName "infra_audit daily" -Confirm:$false

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$bat = Join-Path $root "scripts\run_scheduled.bat"
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) { throw "Missing $python - create the venv first (see README Setup)." }

$action = New-ScheduledTaskAction -Execute $bat -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At 7:43am
# A start time with a UTC offset makes Windows keep the absolute time, so the run
# drifts an hour when daylight saving changes. Without an offset it stays at 7:43 local.
$trigger.StartBoundary = (Get-Date -Hour 7 -Minute 43 -Second 0).ToString("yyyy-MM-dd'T'HH:mm:ss")
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName "infra_audit daily" -Action $action -Trigger $trigger -Settings $settings `
    -Description "Read-only email infrastructure audit (HardBounceCheck + infra_audit). Log: $root\data\scheduled_run.log" `
    -Force | Out-Null

$next = (Get-ScheduledTaskInfo -TaskName "infra_audit daily").NextRunTime
Write-Host "Scheduled task 'infra_audit daily' registered. Next run: $next"
Write-Host "Log file: $root\data\scheduled_run.log"
