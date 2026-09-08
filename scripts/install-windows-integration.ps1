$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RuntimeRoot = Join-Path $env:USERPROFILE ".codex\hooks-monitor"
$PowerShellExe = (Get-Command pwsh.exe -ErrorAction Stop).Source
$StartMenuRoot = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$StartMenuFolder = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Hooks Monitor"
$StartMenuMainShortcut = Join-Path $StartMenuRoot "Hooks Monitor.lnk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "Hooks Monitor.lnk"
$ManualPath = Join-Path $ProjectRoot "README.md"
$IconPath = Join-Path $ProjectRoot "src\codex_hooks_monitor\assets\hooks-monitor.ico"
$ProductKey = "HKCU:\Software\HooksMonitor"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\HooksMonitor"
$IntegrationVersion = "2026.07.16.1"
$AutoRecoveryTaskName = "Hooks Monitor Watchdog Auto-Recovery"

function New-PowerShellShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShortcutPath,
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [string]$ScriptArguments = "",
        [switch]$KeepOpen
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $PowerShellExe
    $noExit = if ($KeepOpen) { "-NoExit " } else { "" }
    $arguments = "-NoProfile ${noExit}-ExecutionPolicy Bypass -File `"$ScriptPath`""
    if ($ScriptArguments) {
        $arguments = "$arguments $ScriptArguments"
    }
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = $ProjectRoot
    $shortcut.Description = $Description
    $shortcut.IconLocation = "$IconPath,0"
    $shortcut.Save()
}

if (Test-Path $StartMenuFolder) {
    Remove-Item -LiteralPath $StartMenuFolder -Recurse -Force
}

New-PowerShellShortcut `
    -ShortcutPath $DesktopShortcut `
    -ScriptPath (Join-Path $PSScriptRoot "manage.ps1") `
    -Description "打开 Hooks Monitor 管理控制台"

$taskAction = New-ScheduledTaskAction `
    -Execute $PowerShellExe `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'ensure-watchdog.ps1')`""
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited
$taskSettings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
Register-ScheduledTask `
    -TaskName $AutoRecoveryTaskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Principal $taskPrincipal `
    -Settings $taskSettings `
    -Description "If Hooks Monitor is enabled but its watchdog is not running, restore the last selected mode at user logon." `
    -Force | Out-Null

New-PowerShellShortcut `
    -ShortcutPath $StartMenuMainShortcut `
    -ScriptPath (Join-Path $PSScriptRoot "manage.ps1") `
    -Description "打开 Hooks Monitor 管理控制台"

$projectSizeBytes = (Get-ChildItem -LiteralPath $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
$runtimeSizeBytes = if (Test-Path $RuntimeRoot) {
    (Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
} else {
    0
}
$estimatedSizeKb = [Math]::Max(1, [Math]::Ceiling(($projectSizeBytes + $runtimeSizeBytes) / 1KB))
$uninstallCommand = "`"$PowerShellExe`" -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'remove-windows-integration.ps1')`""

New-Item -Path $ProductKey -Force | Out-Null
New-ItemProperty -Path $ProductKey -Name "ProjectRoot" -Value $ProjectRoot -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ProductKey -Name "RuntimeRoot" -Value $RuntimeRoot -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ProductKey -Name "Documentation" -Value $ManualPath -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ProductKey -Name "IconPath" -Value $IconPath -PropertyType String -Force | Out-Null
Remove-ItemProperty -Path $ProductKey -Name "StartMenuFolder" -ErrorAction SilentlyContinue
New-ItemProperty -Path $ProductKey -Name "StartMenuShortcut" -Value $StartMenuMainShortcut -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ProductKey -Name "IntegrationVersion" -Value $IntegrationVersion -PropertyType String -Force | Out-Null
New-ItemProperty -Path $ProductKey -Name "AutoRecoveryTask" -Value $AutoRecoveryTaskName -PropertyType String -Force | Out-Null

New-Item -Path $UninstallKey -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayName" -Value "Hooks Monitor Windows Integration" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayVersion" -Value $IntegrationVersion -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "Publisher" -Value "Hooks Monitor" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "InstallLocation" -Value $ProjectRoot -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayIcon" -Value "$IconPath,0" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "UninstallString" -Value $uninstallCommand -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "QuietUninstallString" -Value $uninstallCommand -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "EstimatedSize" -Value ([int]$estimatedSizeKb) -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "Comments" -Value "卸载只移除快捷方式和注册信息，不删除源码、运行时或 Codex hooks。" -PropertyType String -Force | Out-Null

Write-Output "Hooks Monitor Windows integration installed."
Write-Output "Start Menu: $StartMenuMainShortcut"
Write-Output "Desktop: $DesktopShortcut"
Write-Output "Registry: $UninstallKey"
Write-Output "Auto recovery task: $AutoRecoveryTaskName"
