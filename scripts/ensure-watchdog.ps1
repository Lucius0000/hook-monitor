$ErrorActionPreference = "Stop"

$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$SettingsPath = Join-Path $RuntimeRoot "settings.json"
$PidPath = Join-Path $RuntimeRoot "state\watchdog.pid"

if (-not (Test-Path $SettingsPath)) {
    exit 0
}

$settings = Get-Content -Raw -LiteralPath $SettingsPath | ConvertFrom-Json
if (-not $settings.enabled) {
    exit 0
}

if (Test-Path $PidPath) {
    $pidText = (Get-Content -Raw -LiteralPath $PidPath).Trim()
    $pidValue = 0
    if ([int]::TryParse($pidText, [ref]$pidValue)) {
        if (Get-Process -Id $pidValue -ErrorAction SilentlyContinue) {
            exit 0
        }
    }
}

$mode = "observe"
if ($settings.actions.mode -eq "interrupt") {
    $mode = "interrupt"
} elseif ($settings.actions.send_guardian_message) {
    $mode = "guardian"
}

& (Join-Path $PSScriptRoot "start-watchdog.ps1") -Mode $mode

