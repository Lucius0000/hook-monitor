param(
    [string]$Title = "Hooks Guardian",
    [string]$Model = "gpt-5.4",
    [string]$Cwd = ""
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"

if (-not $Cwd) {
    $Cwd = $ProjectRoot
}

& (Join-Path $PSScriptRoot "install.ps1")
& $PythonExe $AdminPy create-guardian-thread --runtime-root $RuntimeRoot --cwd $Cwd --title $Title --model $Model
