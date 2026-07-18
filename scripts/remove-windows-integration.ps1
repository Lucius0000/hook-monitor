$ErrorActionPreference = "Stop"

$StartMenuFolder = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Hooks Monitor"
$StartMenuMainShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Hooks Monitor.lnk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Hooks Monitor.lnk"
$ProductKey = "HKCU:\Software\HooksMonitor"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\HooksMonitor"
$AutoRecoveryTaskName = "Hooks Monitor Watchdog Auto-Recovery"

if (Get-ScheduledTask -TaskName $AutoRecoveryTaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $AutoRecoveryTaskName -Confirm:$false
}

if (Test-Path $StartMenuFolder) {
    Remove-Item -LiteralPath $StartMenuFolder -Recurse -Force
}
if (Test-Path $StartMenuMainShortcut) {
    Remove-Item -LiteralPath $StartMenuMainShortcut -Force
}
if (Test-Path $DesktopShortcut) {
    Remove-Item -LiteralPath $DesktopShortcut -Force
}
if (Test-Path $ProductKey) {
    Remove-Item -LiteralPath $ProductKey -Recurse -Force
}
if (Test-Path $UninstallKey) {
    Remove-Item -LiteralPath $UninstallKey -Recurse -Force
}

Write-Output "Hooks Monitor Windows integration removed."
Write-Output "Project files, runtime files, watchdog state, and Codex hooks were not changed."
