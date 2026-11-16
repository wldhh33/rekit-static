# tests/layoutref.ps1 - M20 runtime-layout oracle.
#
# Independent of rekit: loads a controlled .NET assembly into the CLR and asks
# the runtime for type size and field offsets.
#   size   : Marshal.SizeOf(Type)   (reflection-bound overload; PowerShell
#            would otherwise bind SizeOf(object) and fail)
#   offset : Marshal.OffsetOf(Type, fieldName)
#
# sequential/auto offsets are runtime-derived by definition: they are NOT a
# static metadata claim and must not be folded into static conclusions.
# Static fields (and fields the marshaller refuses) land in field_errors.
#
# Must run under Windows PowerShell 5.1 (the .NET Framework CLR that can load
# the controlled samples).
param(
    [Parameter(Mandatory = $true)][string]$Assembly,
    [Parameter(Mandatory = $true)][string]$Types
)

$ErrorActionPreference = 'Stop'
$path = (Resolve-Path $Assembly).Path
$asm = [Reflection.Assembly]::LoadFrom($path)
$sizeOf = [Runtime.InteropServices.Marshal].GetMethod(
    'SizeOf', [type[]]@([type]))
$flags = [Reflection.BindingFlags]'Public,NonPublic,Instance,Static,DeclaredOnly'

$out = @{}
foreach ($name in ($Types -split ',')) {
    $name = $name.Trim()
    if (-not $name) { continue }
    $t = $asm.GetType($name)
    if ($null -eq $t) {
        $out[$name] = @{ missing = 'type_not_found' }
        continue
    }
    $entry = @{ size = $null; size_error = $null; fields = @{}; field_errors = @{} }
    try {
        $entry.size = [int]$sizeOf.Invoke($null, @($t))
    }
    catch {
        $entry.size_error = $_.Exception.InnerException.Message
    }
    foreach ($f in $t.GetFields($flags)) {
        try {
            $entry.fields[$f.Name] = [int][Runtime.InteropServices.Marshal]::OffsetOf($t, $f.Name)
        }
        catch {
            $entry.field_errors[$f.Name] = $_.Exception.InnerException.Message
        }
    }
    $out[$name] = $entry
}

ConvertTo-Json -Compress -Depth 8 @{
    types = $out
    source = 'Marshal.OffsetOf / Marshal.SizeOf(Type)'
    assembly = $path
}
