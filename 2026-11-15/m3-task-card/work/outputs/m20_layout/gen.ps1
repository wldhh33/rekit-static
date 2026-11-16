# M20 sample generation (Windows, .NET Framework csc/ilasm).
# Regenerate the controlled samples into work/samples/m20/_gen.
# The binaries are ignored by git; the sources above are the truth.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$work = Resolve-Path (Join-Path $here '..\..')          # ...\m3-task-card\work
$gen = Join-Path $work 'samples\m20\_gen'
New-Item -ItemType Directory -Force $gen | Out-Null
$fw = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'

& (Join-Path $fw 'ilasm.exe') /nologo /dll `
    "/output:$gen\LayoutSample.dll" (Join-Path $here 'LayoutSample.il')
if ($LASTEXITCODE -ne 0) { throw "ilasm failed: $LASTEXITCODE" }

& (Join-Path $fw 'csc.exe') /nologo /target:library /optimize+ `
    "/out:$gen\LayoutCSharp.dll" (Join-Path $here 'LayoutCSharp.cs')
if ($LASTEXITCODE -ne 0) { throw "csc failed: $LASTEXITCODE" }

Get-ChildItem $gen | Select-Object Name, Length
