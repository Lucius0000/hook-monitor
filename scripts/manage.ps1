$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ManualPath = Join-Path $ProjectRoot "hooks-monitor-使用说明书.md"

try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    & "$env:SystemRoot\System32\chcp.com" 65001 | Out-Null
} catch {
}

function Wait-ForMenu {
    Write-Host ""
    Read-Host "按 Enter 返回菜单" | Out-Null
}

function Clear-Screen {
    try {
        Clear-Host
    } catch {
    }
}

function Show-Status {
    Clear-Screen
    Write-Host "Hooks Monitor 当前状态" -ForegroundColor Cyan
    Write-Host ""
    & (Join-Path $PSScriptRoot "status.ps1")
    Wait-ForMenu
}

function Start-SelectedMode {
    while ($true) {
        Clear-Screen
        Write-Host "选择并启动模式" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Observe   仅本地提醒，不发 guardian，不自动中止"
        Write-Host "2. Guardian  本地提醒并通知固定 guardian（推荐）"
        Write-Host "3. Interrupt guardian 判定为 kill 时可中止目标进程"
        Write-Host "0. 返回"
        Write-Host ""
        $choice = Read-Host "请选择"

        switch ($choice) {
            "1" { $mode = "observe" }
            "2" { $mode = "guardian" }
            "3" {
                Write-Host ""
                Write-Host "Interrupt 可能在 guardian 明确判定后终止目标进程。" -ForegroundColor Yellow
                $confirmation = Read-Host "输入 INTERRUPT 确认启用；其他输入取消"
                if ($confirmation -cne "INTERRUPT") {
                    continue
                }
                $mode = "interrupt"
            }
            "0" { return }
            default { continue }
        }

        Clear-Screen
        & (Join-Path $PSScriptRoot "start-watchdog.ps1") -Mode $mode
        Write-Host ""
        & (Join-Path $PSScriptRoot "status.ps1")
        Wait-ForMenu
        return
    }
}

function Show-AdvancedMenu {
    while ($true) {
        Clear-Screen
        Write-Host "高级操作" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. 审核 / trust 当前 4 个用户级 hooks"
        Write-Host "2. 彻底移除当前 4 个 hooks（同时停用 watchdog）"
        Write-Host "0. 返回"
        Write-Host ""
        $choice = Read-Host "请选择"

        switch ($choice) {
            "1" {
                & (Join-Path $PSScriptRoot "review-hooks.ps1")
                return
            }
            "2" {
                Write-Host ""
                Write-Host "这会日常停用 watchdog，并从 hooks.json 移除本项目的 4 个 hooks。" -ForegroundColor Yellow
                $confirmation = Read-Host "输入 REMOVE HOOKS 确认；其他输入取消"
                if ($confirmation -ceq "REMOVE HOOKS") {
                    & (Join-Path $PSScriptRoot "remove-hooks.ps1")
                    Write-Host ""
                    & (Join-Path $PSScriptRoot "status.ps1")
                    Wait-ForMenu
                }
            }
            "0" { return }
        }
    }
}

while ($true) {
    Clear-Screen
    Write-Host "Hooks Monitor 管理控制台" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. 选择并启动模式"
    Write-Host "2. 查看当前状态"
    Write-Host "3. 日常停用 watchdog（保留 4 个 hooks 与 trust）"
    Write-Host "4. 打开使用说明书"
    Write-Host "5. 高级操作"
    Write-Host "0. 退出"
    Write-Host ""
    $choice = Read-Host "请选择"

    try {
        switch ($choice) {
            "1" { Start-SelectedMode }
            "2" { Show-Status }
            "3" {
                Clear-Screen
                & (Join-Path $PSScriptRoot "stop-watchdog.ps1")
                Write-Host "watchdog 已日常停用；4 个 hooks 与 trust 保留。"
                Write-Host ""
                & (Join-Path $PSScriptRoot "status.ps1")
                Wait-ForMenu
            }
            "4" { Start-Process -FilePath $ManualPath }
            "5" { Show-AdvancedMenu }
            "0" { exit 0 }
        }
    } catch {
        Write-Host ""
        Write-Host "操作失败：$($_.Exception.Message)" -ForegroundColor Red
        Wait-ForMenu
    }
}
