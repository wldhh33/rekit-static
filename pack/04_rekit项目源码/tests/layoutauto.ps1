# tests/layoutauto.ps1 - M20 runtime layout oracle for sequential/auto structs.
#
# layoutref.ps1 uses Marshal.OffsetOf/SizeOf, which refuses auto-layout types
# ("cannot be marshaled as an unmanaged structure"). This script gives
# sequential/auto types an independent runtime reading instead:
#   * compile-time reference to the controlled sample assembly,
#   * C# probe compiled with /unsafe,
#   * zero the struct, assign exactly one field, scan for the first non-zero
#     byte -> that field's offset (one field at a time, so no pattern
#     collisions between fields of the same or overlapping width),
#   * sizeof(T) inside the same unsafe context -> CLR actual size.
#
# Output: one JSON line on stdout
#   {types:{<name>:{size, offsets:{<field>:<int>}, errors:{}}},
#    unsupported:{<name>:<reason>}, source:"unsafe-fixed-sentinel"}
# A -1 offset means the field left no non-zero byte; callers must treat it as
# a failure, never as offset 0.
#
# This is a RUNTIME DERIVATION, not a static metadata claim. Results must not
# be folded into static conclusions (see rekit/layout.py static_conclusion).
#
# Runtime: Windows PowerShell 5.1 + .NET Framework CSharpCodeProvider.
param(
    [Parameter(Mandatory = $true)][string]$Assembly,
    [Parameter(Mandatory = $true)][string]$Types
)

$ErrorActionPreference = 'Stop'
$path = (Resolve-Path $Assembly).Path
$dir = Split-Path -Parent $path
$asm = [Reflection.Assembly]::LoadFrom($path)
$flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,DeclaredOnly'

# Field types we can assign and then see as non-zero bytes. Everything else is
# reported in "errors"/"unsupported" rather than silently skipped.
$kinds = @{
    'System.Byte'    = 'unchecked((byte)0x7A)'
    'System.SByte'   = 'unchecked((sbyte)0x7A)'
    'System.Boolean' = 'true'
    'System.Char'    = 'unchecked((char)0x7A3B)'
    'System.Int16'   = 'unchecked((short)0x7A3B)'
    'System.UInt16'  = 'unchecked((ushort)0x7A3B)'
    'System.Int32'   = 'unchecked((int)0x7A3B5C4D)'
    'System.UInt32'  = 'unchecked((uint)0x7A3B5C4Du)'
    'System.Single'  = 'BitConverter.ToSingle(BitConverter.GetBytes(unchecked((int)0x4F5E6D7C)), 0)'
    'System.Int64'   = 'unchecked((long)0x1122334455667788)'
    'System.UInt64'  = 'unchecked((ulong)0x1122334455667788u)'
    'System.Double'  = 'BitConverter.Int64BitsToDouble(unchecked((long)0x1122334455667788))'
}

$body = New-Object System.Text.StringBuilder
$unsupported = @{}
$firstType = $true
foreach ($name in ($Types -split ',')) {
    $name = $name.Trim()
    if (-not $name) { continue }
    $t = $asm.GetType($name)
    if ($null -eq $t) {
        $unsupported[$name] = 'type_not_found'
        continue
    }
    $fields = @($t.GetFields($flags) | Where-Object { -not $_.IsStatic })
    $ok = @()
    $errs = @()
    foreach ($f in $fields) {
        if ($kinds.ContainsKey($f.FieldType.FullName)) { $ok += $f }
        else { $errs += ('"{0}":"field_type_unsupported:{1}"' -f $f.Name, $f.FieldType.FullName) }
    }
    if ($ok.Count -eq 0) {
        $unsupported[$name] = 'no_probeable_instance_fields'
        continue
    }
    if (-not $firstType) { [void]$body.Append('sb.Append(",");') }
    $firstType = $false
    [void]$body.Append('{')
    [void]$body.Append('sb.Append("\"' + $name + '\":{");')
    [void]$body.Append('int size = sizeof(').Append($name).Append(');')
    [void]$body.Append('var arr = new ').Append($name).Append('[1];')
    [void]$body.Append('fixed (').Append($name).Append('* p = arr) {')
    [void]$body.Append('byte* b = (byte*)p;')
    $idx = 0
    foreach ($f in $ok) {
        [void]$body.Append('for (int i = 0; i < size; i++) b[i] = 0;')
        [void]$body.Append('p[0].').Append($f.Name).Append(' = ')
        [void]$body.Append($kinds[$f.FieldType.FullName]).Append(';')
        [void]$body.Append('int o').Append($idx).Append(' = First(b, size);')
        $idx++
    }
    [void]$body.Append('sb.Append("\"size\":").Append(size);')
    [void]$body.Append('sb.Append(",\"offsets\":{");')
    $appends = @()
    for ($i = 0; $i -lt $ok.Count; $i++) {
        $sep = if ($i -gt 0) { ',' } else { '' }
        $appends += ('sb.Append("{0}\"{1}\":").Append(o{2});' -f $sep, $ok[$i].Name, $i)
    }
    [void]$body.Append(($appends -join ' '))
    [void]$body.Append('sb.Append("}");')
    if ($errs.Count -gt 0) {
        [void]$body.Append('sb.Append(",\"errors\":{").Append(')
        [void]$body.Append(($errs -join ', '))
        [void]$body.Append(').Append("}");')
    } else {
        [void]$body.Append('sb.Append(",\"errors\":{}");')
    }
    [void]$body.Append('sb.Append("}");')   # close this type's JSON object
    [void]$body.Append('}')                  # close fixed
    [void]$body.Append('}')                  # close C# block
}

if ($body.Length -eq 0) {
    Write-Error "layoutauto: no probeable types ($($Types))"
    exit 3
}

$src = @"
using System;
public static class RekitAutoProbe
{
    static unsafe int First(byte* b, int n)
    {
        for (int i = 0; i < n; i++) { if (b[i] != 0) return i; }
        return -1;
    }
    public static unsafe string Run()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("{\"types\":{");
        $body
        sb.Append("},\"source\":\"unsafe-fixed-sentinel\"}");
        return sb.ToString();
    }
}
"@

# resolve sample dependencies from the sample directory when the probe runs
$handler = [ResolveEventHandler] {
    param($s, $e)
    $an = New-Object Reflection.AssemblyName($e.Name)
    $cand = Join-Path $dir ($an.Name + '.dll')
    if (Test-Path -LiteralPath $cand) { return [Reflection.Assembly]::LoadFrom($cand) }
    return $null
}
[AppDomain]::CurrentDomain.add_AssemblyResolve($handler)

$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$cp = New-Object System.CodeDom.Compiler.CompilerParameters
$cp.GenerateInMemory = $true
$cp.CompilerOptions = '/unsafe'
[void]$cp.ReferencedAssemblies.Add('System.dll')
[void]$cp.ReferencedAssemblies.Add($path)
$res = $provider.CompileAssemblyFromSource($cp, $src)
if ($env:REKIT_PROBE_DUMP) {
    Set-Content -LiteralPath $env:REKIT_PROBE_DUMP -Value $src -Encoding UTF8
}
if ($res.Errors.HasErrors) {
    foreach ($e in $res.Errors) { Write-Error ("probe compile: " + $e.ToString()) }
    exit 3
}
$probe = $res.CompiledAssembly.GetType('RekitAutoProbe')
$json = $probe.GetMethod('Run').Invoke($null, $null)
# Do not emit the assembly path: PS 5.1 stdout encoding mangles non-ASCII
# paths, and the caller already knows it. Unsupported types are reported
# explicitly instead of being dropped.
$json = $json.TrimEnd('}')
if ($unsupported.Count -gt 0) {
    $names = ($unsupported.Keys | ForEach-Object { '"' + $_ + '":"' + $unsupported[$_] + '"' }) -join ','
    $json = $json + ',"unsupported":{' + $names + '}'
}
Write-Output ($json + '}')
exit 0
