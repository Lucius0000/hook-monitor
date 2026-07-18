param(
    [string]$ThreadId = "",
    [string]$Search = "",
    [string]$TitleHint = ""
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"

if (-not $ThreadId) {
    & $PythonExe $AdminPy list-threads --search $Search --limit 20
    exit 0
}

& (Join-Path $PSScriptRoot "install.ps1")
& $PythonExe $AdminPy register-guardian --runtime-root $RuntimeRoot --thread-id $ThreadId --title-hint $TitleHint
