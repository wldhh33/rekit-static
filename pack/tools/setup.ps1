<#
pack\tools\setup.ps1 — 干净克隆后的资产恢复与目录联接（2026-11-17 克隆演练补件）

背景：.gitignore 排除了 m2/m3 的 samples、m2 的 tools（binutils / upx）以及 work 下的
      junction。fresh clone 直接跑 gate.ps1 会在 preflight exit 2。本脚本把这两类“仓库外
      资产”按显式来源恢复，并重建 junction；不下载、不猜来源、不伪造校验值。

用法（在克隆根执行；路径可以是任意盘符）：
  powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\setup.ps1" `
      -AssetsSource "D:\path\to\original\workspace"

参数：
  -AssetsSource  原工作区根，必须含：
                   2026-11-15\m3-task-card\work\samples
                   2026-11-15\m2-task-card\work\samples
                   2026-11-15\m2-task-card\work\tools
  -SkipJunctions 只复制资产，不建 junction（默认都做）

幂等：目标已存在且内容类型正确时跳过并报 SKIP；不会删除任何真实目录。
退出码：0 就绪 / 1 复制或联接失败 / 2 参数或来源不完整
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AssetsSource,
    [switch]$SkipJunctions
)

$ErrorActionPreference = "Stop"

$Tools = $PSScriptRoot
$Pack  = Split-Path -Parent $Tools
$Root  = Split-Path -Parent $Pack
$Src   = [System.IO.Path]::GetFullPath($AssetsSource)

$Problems = New-Object System.Collections.ArrayList

function Add-Problem([string]$msg) { [void]$Problems.Add($msg) }
function Ok([string]$msg) { Write-Host "  OK   $msg" }
function Skip([string]$msg) { Write-Host "  SKIP $msg" }

Write-Host "== rekit setup =="
Write-Host "clone: $Root"
Write-Host "assets: $Src"

if (-not (Test-Path -LiteralPath $Src)) {
    Write-Host "SETUP: FAIL exit=2 (AssetsSource not found: $Src)" -ForegroundColor Red
    exit 2
}

$required = @(
    "2026-11-15\m3-task-card\work\samples",
    "2026-11-15\m2-task-card\work\samples",
    "2026-11-15\m2-task-card\work\tools"
)
foreach ($rel in $required) {
    $p = Join-Path $Src $rel
    if (-not (Test-Path -LiteralPath $p)) {
        Add-Problem "source missing: $p"
    } else {
        Ok "source: $rel"
    }
}
if ($Problems.Count -gt 0) {
    Write-Host "SETUP: FAIL exit=2 (assets incomplete; nothing copied)" -ForegroundColor Red
    foreach ($p in $Problems) { Write-Host "  - $p" -ForegroundColor Red }
    exit 2
}

Write-Host ""
Write-Host "== assets =="
foreach ($rel in $required) {
    $from = Join-Path $Src $rel
    $to = Join-Path $Root $rel
    if (Test-Path -LiteralPath $to) {
        Skip "already present: $rel (不覆盖；要重来请手动移走)"
        continue
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force | Out-Null
    Copy-Item -LiteralPath $from -Destination $to -Recurse -Force
    $n = @(Get-ChildItem -LiteralPath $to -Recurse -File).Count
    Ok "copied: $rel ($n files)"
}

# junction 必须在资产复制之后：m3\work\tools 的目标就是 m2\work\tools
if (-not $SkipJunctions) {
    Write-Host ""
    Write-Host "== junctions =="
    $pairs = @(
        @{ Link = "2026-11-15\m2-task-card\work\rekit";  Target = "pack\04_rekit项目源码\rekit" },
        @{ Link = "2026-11-15\m2-task-card\work\tests";  Target = "pack\04_rekit项目源码\tests" },
        @{ Link = "2026-11-15\m2-task-card\work\pack03"; Target = "pack\03_路线图与章程" },
        @{ Link = "2026-11-15\m3-task-card\work\rekit";  Target = "pack\04_rekit项目源码\rekit" },
        @{ Link = "2026-11-15\m3-task-card\work\tests";  Target = "pack\04_rekit项目源码\tests" },
        @{ Link = "2026-11-15\m3-task-card\work\pack03"; Target = "pack\03_路线图与章程" },
        @{ Link = "2026-11-15\m3-task-card\work\tools";  Target = "2026-11-15\m2-task-card\work\tools" }
    )
    foreach ($pair in $pairs) {
        $link = Join-Path $Root $pair.Link
        $target = Join-Path $Root $pair.Target
        if (-not (Test-Path -LiteralPath $target)) {
            Add-Problem "junction target missing: $target"
            continue
        }
        if (Test-Path -LiteralPath $link) {
            $item = Get-Item -LiteralPath $link -Force
            if ($item.LinkType -eq "Junction") {
                $cur = @($item.Target)[0]
                if ([System.IO.Path]::GetFullPath($cur) -eq [System.IO.Path]::GetFullPath($target)) {
                    Ok "junction exists: $($pair.Link)"
                } else {
                    Add-Problem "junction points elsewhere: $($pair.Link) -> $cur (want $target)"
                }
            } else {
                Add-Problem "path exists but is not a junction: $link (remove it manually)"
            }
            continue
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $link) -Force | Out-Null
        New-Item -ItemType Junction -Path $link -Target $target | Out-Null
        Ok "junction created: $($pair.Link)"
    }
}

if ($Problems.Count -gt 0) {
    Write-Host ""
    Write-Host "SETUP: FAIL exit=1 ($($Problems.Count) item(s))" -ForegroundColor Red
    foreach ($p in $Problems) { Write-Host "  - $p" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "SETUP: OK  next: powershell -NoProfile -ExecutionPolicy Bypass -File `"pack\tools\gate.ps1`"" -ForegroundColor Green
exit 0
