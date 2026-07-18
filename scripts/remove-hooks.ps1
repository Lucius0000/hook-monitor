$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"

& (Join-Path $PSScriptRoot "stop-watchdog.ps1")
& $PythonExe $AdminPy disable-hooks --runtime-root $RuntimeRoot
