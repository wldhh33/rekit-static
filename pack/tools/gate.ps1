<#
pack\tools\gate.ps1 — 单命令门禁入口（U1 收口，2026-11-17）

把“别人拿到仓库能跑”固化成一条命令：先做前置检查（fail-fast，不静默跳过），
再按固定顺序执行：
  1) ledger_check.py --check          数字总账漂移
  2) tests\evidence_index.py --check  证据索引覆盖 / 存在 / sha256
  3) verify_gate.py --run             23 套 verify + pytest + ledger 复核

本机事实（脚本会逐项检查）：
  - 样本与 binutils 被 .gitignore 排除，fresh clone 后必须先从原始副本恢复；
  - pytest 必须在 work 目录执行（fixture 路径按 cwd 解析，verify_gate 已代为切目录）；
  - .NET 运行期 oracle 需要 Windows：verify_layout 用 Windows PowerShell 的 CLR，
    verify_sigblob 用 pwsh 7 的 System.Reflection.Metadata（另需 Python 包 dnfile）。

用法（任意目录均可，脚本按自身位置定位仓库根）：
  powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1"
  powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1" -List
  powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1" -Only verify_map,verify_iat

退出码：0 PASS / 1 FAIL / 2 前置缺失（fail-closed，未执行任何验证）
#>
[CmdletBinding()]
param(
    [switch]$List,
    [string]$Only = ""
)

$ErrorActionPreference = "Stop"

$Tools = $PSScriptRoot
$Pack  = Split-Path -Parent $Tools
$Root  = Split-Path -Parent $Pack
$Work  = Join-Path $Root "2026-11-15\m3-task-card\work"
$Tests = Join-Path $Work "tests"
$Bin   = Join-Path $Root "2026-11-15\m2-task-card\work\tools\binutils-2.47\mingw64\bin"

$script:problems = New-Object System.Collections.ArrayList

function Add-Problem([string]$msg) { [void]$script:problems.Add($msg) }
function Ok([string]$msg) { Write-Host "  OK   $msg" }

Write-Host "== rekit gate: preflight =="
Write-Host "root: $Root"

# 1. 目录与目录联接（work\rekit、work\tests、work\pack03 是指向 pack 的 junction）
foreach ($p in @(
        $Work,
        $Tests,
        (Join-Path $Work "rekit"),
        (Join-Path $Work "pack03"),
        (Join-Path $Pack "04_rekit项目源码\pyproject.toml"),
        (Join-Path $Tests "evidence_index.py"),
        (Join-Path $Tools "verify_gate.py"),
        (Join-Path $Tools "ledger_check.py")
    )) {
    if (-not (Test-Path -LiteralPath $p)) {
        Add-Problem "missing: $p (work 下的 junction 见 README 安装与复现验收)"
    } else {
        Ok "exists: $p"
    }
}

# 2. Python 3.8+
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Add-Problem "python not in PATH (need Python 3.8+)"
} else {
    $pyv = & python -c "import sys;print('%d.%d' % sys.version_info[:2])" 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $pyv) {
        Add-Problem "python exists but cannot run"
    } else {
        $parts = $pyv.Trim().Split(".")
        if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 8)) {
            Add-Problem "Python $pyv < 3.8"
        } else {
            Ok "Python $pyv"
        }
    }
}

# 3. 样本（.gitignore 排除，必须先恢复）
foreach ($s in @("m9", "m17", "m18", "m20")) {
    $d = Join-Path $Work "samples\$s"
    if (-not (Test-Path -LiteralPath $d)) {
        Add-Problem "missing samples\$s (samples are .gitignored; restore before running gate)"
    } elseif (-not (Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        Add-Problem "empty samples\$s"
    } else {
        Ok "samples: $s"
    }
}

# 4. binutils（.gitignore 排除，verifies 需要 objdump）
if (-not (Test-Path -LiteralPath (Join-Path $Bin "objdump.exe"))) {
    Add-Problem "missing objdump: $Bin (binutils is .gitignored; restore before running gate)"
} else {
    Ok "objdump: $Bin"
}

# 5. .NET 运行期 oracle（Windows-only）
foreach ($t in @("powershell", "pwsh")) {
    if (-not (Get-Command $t -ErrorAction SilentlyContinue)) {
        Add-Problem "missing $t (verify_layout needs Windows PowerShell CLR; verify_sigblob needs pwsh 7 SRM)"
    } else {
        Ok "$t available"
    }
}

if ($script:problems.Count -gt 0) {
    Write-Host ""
    Write-Host "GATE: FAIL exit=2 (preflight failed: $($script:problems.Count) item(s); nothing executed)" -ForegroundColor Red
    foreach ($p in $script:problems) { Write-Host "  - $p" -ForegroundColor Red }
    exit 2
}

Write-Host ""
Write-Host "== 1/3 ledger_check --check =="
& python (Join-Path $Tools "ledger_check.py") --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "GATE: FAIL exit=1 (ledger_check)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "== 2/3 evidence_index --check =="
& python (Join-Path $Tests "evidence_index.py") --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "GATE: FAIL exit=1 (evidence_index)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "== 3/3 verify_gate =="
$gateArgs = @((Join-Path $Tools "verify_gate.py"))
if ($List) {
    $gateArgs += "--list"
} elseif ($Only) {
    $gateArgs += @("--run", "--only", $Only)
} else {
    $gateArgs += "--run"
}
Push-Location $Root
try {
    & python @gateArgs
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($rc -eq 0) {
    Write-Host ""
    Write-Host "GATE: PASS exit=0" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "GATE: FAIL exit=$rc (verify_gate)" -ForegroundColor Red
}
exit $rc
