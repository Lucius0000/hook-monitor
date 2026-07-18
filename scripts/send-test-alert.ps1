param(
    [string]$ThreadId = "",
    [switch]$Wait
)

$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"

$argsList = @($AdminPy, "send-test-alert", "--runtime-root", $RuntimeRoot)
if ($ThreadId) {
    $argsList += @("--thread-id", $ThreadId)
}
if ($Wait.IsPresent) {
    $argsList += "--wait"
}

& $PythonExe @argsList
