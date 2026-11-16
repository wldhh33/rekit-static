<#
outputs/m19_sigblob/gen.ps1 — M19 签名层补证样本重建（2026-11-17 补证批次）

做两件事（全部在 work 内，路径按 $PSScriptRoot 定位，可换盘符）：
  1. ilasm 汇编 SigSample.il / DeepSig63.il / DeepSig.il
     -> samples\m19_sigblob\_gen\{SigSample,DeepSig63,DeepSig}.dll
  2. python make_negatives.py 生成 _neg\BadCompressed.dll /
     TruncatedSig.dll / UnknownCodedTag.dll
最后写 work\m19_sample_manifest.json（sha256 + 构造方式），供 R95 口径登记。

注意：ilasm 会写入随机 MVID 与时间戳，重跑后 sha256 会变 —— 这不是逐字节可复现，
可复现的是源码与签名结构；重跑后需同步 manifest 并重跑 verify_sigblob。
#>
[CmdletBinding()]
param(
    [string]$Ilasm = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$Here  = $PSScriptRoot
$Work  = Split-Path -Parent (Split-Path -Parent $Here)
$Out   = Join-Path $Work "samples\m19_sigblob"
$Gen   = Join-Path $Out "_gen"
$Neg   = Join-Path $Out "_neg"

if (-not (Test-Path -LiteralPath $Ilasm)) {
    Write-Host "gen: FAIL 缺 ilasm: $Ilasm" -ForegroundColor Red
    exit 2
}
New-Item -ItemType Directory -Path $Gen, $Neg -Force | Out-Null

$Map = @(
    @{ Src = Join-Path $Here "SigSample.il"; Dll = Join-Path $Gen "SigSample.dll"; Name = "SigSample.dll" },
    @{ Src = Join-Path $Here "DeepSig63.il"; Dll = Join-Path $Gen "DeepSig63.dll"; Name = "DeepSig63.dll" },
    @{ Src = Join-Path $Here "DeepSig.il";   Dll = Join-Path $Gen "DeepSig.dll";   Name = "DeepSig.dll" }
)
foreach ($m in $Map) {
    & $Ilasm /dll /nologo /output:$($m.Dll) $($m.Src) | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $m.Dll)) {
        Write-Host "gen: FAIL ilasm exit=$LASTEXITCODE $($m.Name)" -ForegroundColor Red
        exit 1
    }
}

$rows = @()
foreach ($m in $Map) {
    $rows += [pscustomobject]@{
        file      = $m.Name
        role      = "受控样本"
        sha256    = (Get-FileHash -LiteralPath $m.Dll -Algorithm SHA256).Hash.ToLower()
        size      = (Get-Item -LiteralPath $m.Dll).Length
        build     = "ilasm v4.0.30319 汇编 outputs\m19_sigblob\$(Split-Path -Leaf $m.Src)"
        license   = "self-authored IL（本项目自写，无第三方内容）"
        redistributable = $false
    }
}
# 负样本清单以 make_negatives.py 的输出为准（reason / patch 不在两处各写一份）
$negOut = & $Python (Join-Path $Here "make_negatives.py") (Join-Path $Gen "SigSample.dll") $Neg
if ($LASTEXITCODE -ne 0) {
    Write-Host "gen: FAIL make_negatives exit=$LASTEXITCODE" -ForegroundColor Red
    exit 1
}
$negData = (@($negOut)[-1]) | ConvertFrom-Json
foreach ($n in $negData.negatives) {
    $rows += [pscustomobject]@{
        file      = $n.file
        role      = "负样本"
        sha256    = $n.sha256
        size      = $n.size
        build     = "make_negatives.py 原位改 1 字节（$($n.patch)，长度不变）→ $($n.expect)"
        license   = "self-authored IL（本项目自写，无第三方内容）"
        redistributable = $false
    }
}

$manifest = [ordered]@{
    schema = 1
    batch  = "2026-11-17 M19 签名层补证"
    note   = "ilasm 写入随机 MVID/时间戳：重跑后 sha256 会变，需重跑 gen.ps1 重新登记；可复现的是源码与签名结构。"
    samples = $rows
}
$manifestPath = Join-Path $Work "m19_sample_manifest.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "gen: OK  manifest=$manifestPath"
foreach ($r in $rows) { Write-Host ("  {0,-20} {1}" -f $r.file, $r.sha256) }
exit 0
