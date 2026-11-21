# 2026-11-15：为 rekit 测试注入 binutils(objdump/readelf) 的 PATH 后跑全量
# 背景：binutils 装在 work/tools，不在 pack 内，也不希望污染机器级 PATH；
#       用户级 PATH 已追加该目录，但已打开的终端/IDE 需重启才继承，故提供本脚本。
# 用法： .\run_pytest.ps1  [-Repo <rekit 仓库根>] [-Args <额外的 pytest 参数>]
param(
    [string]$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..\pack\04_rekit项目源码')).Path,
    [string[]]$Args = @()
)
$bin = Join-Path $PSScriptRoot 'tools\binutils-2.47\mingw64\bin'
if (-not (Test-Path (Join-Path $bin 'objdump.exe'))) {
    throw "objdump 不存在：$bin（请先确认 work/tools/binutils-2.47 完整）"
}
$env:PATH = "$bin;$env:PATH"
$env:REKIT_TOOL_BIN = $bin
& objdump --version | Select-Object -First 1
Push-Location $Repo
try {
    python -m pytest tests -q @Args
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
