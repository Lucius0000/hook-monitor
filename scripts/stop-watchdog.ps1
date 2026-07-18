$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"
$SettingsPath = Join-Path $RuntimeRoot "settings.json"
$PidPath = Join-Path $RuntimeRoot "state\watchdog.pid"

if (Test-Path $SettingsPath) {
    $settings = Get-Content -Raw $SettingsPath | ConvertFrom-Json
    $settings.enabled = $false
    $settings | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
}

if (Test-Path $PidPath) {
    $pidValue = [int](Get-Content -Raw $PidPath).Trim()
    $proc = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($proc) {
        Stop-Process -Id $pidValue -Force
        Write-Output "watchdog stopped: PID=$pidValue"
    }
    Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue
}

& $PythonExe $AdminPy quiesce-state --runtime-root $RuntimeRoot | Out-Null
