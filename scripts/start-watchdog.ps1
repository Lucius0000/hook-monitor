param(
    [ValidateSet("observe", "guardian", "interrupt")]
    [string]$Mode = "guardian"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"
$WatchdogPy = Join-Path $RuntimeRoot "codex_hooks_monitor\watchdog.py"
$SettingsPath = Join-Path $RuntimeRoot "settings.json"
$PidPath = Join-Path $RuntimeRoot "state\watchdog.pid"
$StdoutLog = Join-Path $RuntimeRoot "logs\watchdog.stdout.log"
$StderrLog = Join-Path $RuntimeRoot "logs\watchdog.stderr.log"

& (Join-Path $PSScriptRoot "install.ps1")

$settings = Get-Content -Raw $SettingsPath | ConvertFrom-Json
$settings.enabled = $true
switch ($Mode) {
    "observe" {
        $settings.actions.mode = "observe"
        $settings.actions.send_guardian_message = $false
        $settings.actions.show_user_popup = $true
    }
    "guardian" {
        $settings.actions.mode = "observe"
        $settings.actions.send_guardian_message = $true
        $settings.actions.show_user_popup = $true
    }
    "interrupt" {
        $settings.actions.mode = "interrupt"
        $settings.actions.send_guardian_message = $true
        $settings.actions.show_user_popup = $true
    }
}
$settings | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $SettingsPath -Encoding UTF8

& $PythonExe $AdminPy enable-hooks --runtime-root $RuntimeRoot | Out-Null

if (Test-Path $PidPath) {
    $existingPid = [int](Get-Content -Raw $PidPath).Trim()
    if ($existingPid -and (Get-Process -Id $existingPid -ErrorAction SilentlyContinue)) {
        Write-Output "watchdog already running: PID=$existingPid"
        exit 0
    }
}

$process = Start-Process -FilePath $PythonExe `
    -ArgumentList @($WatchdogPy, "--runtime-root", $RuntimeRoot) `
    -WorkingDirectory $ProjectRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -PassThru

New-Item -ItemType Directory -Force -Path (Split-Path $PidPath) | Out-Null
Set-Content -LiteralPath $PidPath -Value $process.Id -Encoding ASCII
Write-Output "watchdog started: PID=$($process.Id), mode=$Mode"
