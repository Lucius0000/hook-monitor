$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source
$AdminPy = Join-Path $ProjectRoot "src\codex_hooks_monitor\admin.py"
$CodexBinRoot = Join-Path $env:LOCALAPPDATA "OpenAI\Codex\bin"
$CodexExe = Get-ChildItem -Path $CodexBinRoot -Recurse -Filter "codex.exe" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $CodexExe) {
    throw "Could not locate codex.exe under $CodexBinRoot"
}

& (Join-Path $PSScriptRoot "install.ps1") | Out-Null
& $PythonExe $AdminPy enable-hooks --runtime-root $RuntimeRoot | Out-Null

Write-Output "This opens Codex CLI so you can review user-level hooks."
Write-Output "Inside the CLI session, run /hooks, trust the 4 Hooks Monitor entries, then exit."
Write-Output "The script has already ensured the current Hooks Monitor definitions are written to $RuntimeRoot\..\hooks.json."
Write-Output "This trust is persisted per hook definition hash, so you usually only need to do it once after a hook change."

& $CodexExe -C $ProjectRoot
