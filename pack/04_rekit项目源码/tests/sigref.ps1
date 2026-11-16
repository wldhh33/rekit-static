# tests/sigref.ps1 — M19 独立语义参考（微软 SRM DecodeSignature）
#
# 目的：给 verify_sigblob.py 提供与被测实现（rekit/sigblob.py）无关的期望值。
# 做法：用 System.Reflection.Metadata（ECMA-335 的官方实现）的 DecodeSignature
#       解码 MethodDef / MemberRef / StandAloneSig 的方法签名，并按 spec.md §3
#       的 canonical 文法输出整串；字段/局部变量签名只报 kind，不解类型。
#
# 输出：stdout 一行 JSON：{"rows":[{table,row,token,blob_index,status,canonical|error}]}
#   status = none | method | field | local | empty | error
# 依赖：pwsh 7 + .NET 的 System.Reflection.Metadata / System.Collections.Immutable
#       / System.Text.Json（随 pwsh 自带）。缺依赖 -> stderr + exit 3。
param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference = 'Stop'
try {
    $src = @'
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;

namespace RekitSig
{
    public struct GCtx { }

    public sealed class Prov : ISignatureTypeProvider<string, GCtx>
    {
        private readonly MetadataReader r;
        public Prov(MetadataReader reader) { r = reader; }

        public string GetPrimitiveType(PrimitiveTypeCode t) { return t.ToString(); }

        public string GetTypeFromDefinition(MetadataReader mr, TypeDefinitionHandle h,
                                            byte raw)
        {
            return (raw == 0x11 ? "valuetype" : "class") + " [TD]" + DefName(mr, h);
        }

        public string GetTypeFromReference(MetadataReader mr, TypeReferenceHandle h,
                                           byte raw)
        {
            return (raw == 0x11 ? "valuetype" : "class") + " [TR]" + RefName(mr, h);
        }

        public string GetTypeFromSpecification(MetadataReader mr, GCtx c,
                                               TypeSpecificationHandle h, byte raw)
        {
            return "spec@0x1B" + MetadataTokens.GetRowNumber(h).ToString("x6");
        }

        public string GetSZArrayType(string e) { return e + "[]"; }

        public string GetArrayType(string e, ArrayShape s)
        {
            var sb = new StringBuilder(e);
            sb.Append("[r=").Append(s.Rank);
            if (s.Sizes.Length > 0)
            {
                sb.Append(";s=");
                for (int i = 0; i < s.Sizes.Length; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append(s.Sizes[i]);
                }
            }
            if (s.LowerBounds.Length > 0)
            {
                sb.Append(";lb=");
                for (int i = 0; i < s.LowerBounds.Length; i++)
                {
                    if (i > 0) sb.Append(",");
                    sb.Append(s.LowerBounds[i]);
                }
            }
            sb.Append("]");
            return sb.ToString();
        }

        public string GetByReferenceType(string e) { return e + "&"; }
        public string GetPointerType(string e) { return e + "*"; }

        public string GetGenericInstantiation(string g, ImmutableArray<string> a)
        {
            var sb = new StringBuilder(g);
            sb.Append("<");
            for (int i = 0; i < a.Length; i++)
            {
                if (i > 0) sb.Append(",");
                sb.Append(a[i]);
            }
            sb.Append(">");
            return sb.ToString();
        }

        public string GetGenericMethodParameter(GCtx c, int i) { return "!!" + i; }
        public string GetGenericTypeParameter(GCtx c, int i) { return "!" + i; }
        public string GetFunctionPointerType(MethodSignature<string> s)
        {
            return "fnptr(" + Fmt.Sig(s) + ")";
        }
        public string GetModifiedType(string mod, string un, bool req)
        {
            // spec.md §3：modreq([TR]Ns.X)T —— 修饰类型不带 class/valuetype 前缀
            string m = mod;
            if (m.StartsWith("class ")) m = m.Substring(6);
            else if (m.StartsWith("valuetype ")) m = m.Substring(10);
            return (req ? "modreq(" : "modopt(") + m + ")" + un;
        }
        public string GetPinnedType(string e) { return "pinned(" + e + ")"; }

        internal static string DefName(MetadataReader mr, TypeDefinitionHandle h)
        {
            var td = mr.GetTypeDefinition(h);
            string name = mr.GetString(td.Name);
            var decl = td.GetDeclaringType();
            if (!decl.IsNil) return DefName(mr, decl) + "+" + name;
            string ns = mr.GetString(td.Namespace);
            return ns.Length > 0 ? ns + "." + name : name;
        }

        internal static string RefName(MetadataReader mr, TypeReferenceHandle h)
        {
            var tr = mr.GetTypeReference(h);
            string name = mr.GetString(tr.Name);
            if (tr.ResolutionScope.Kind == HandleKind.TypeReference)
                return RefName(mr, (TypeReferenceHandle)tr.ResolutionScope) + "+" + name;
            string ns = mr.GetString(tr.Namespace);
            return ns.Length > 0 ? ns + "." + name : name;
        }
    }

    public static class Fmt
    {
        public static string Sig(MethodSignature<string> s)
        {
            var sb = new StringBuilder();
            sb.Append("sig cc=").Append(s.Header.CallingConvention)
              .Append(" hasthis=").Append(s.Header.IsInstance ? 1 : 0)
              .Append(" explicit=").Append(s.Header.HasExplicitThis ? 1 : 0)
              .Append(" generic=").Append(s.Header.IsGeneric ? 1 : 0)
              .Append(" gpc=").Append(s.GenericParameterCount)
              .Append(" req=").Append(s.RequiredParameterCount)
              .Append(" ret=").Append(s.ReturnType)
              .Append(" params=[");
            for (int i = 0; i < s.ParameterTypes.Length; i++)
            {
                if (i > 0) sb.Append(",");
                sb.Append(s.ParameterTypes[i]);
            }
            sb.Append("]");
            return sb.ToString();
        }
    }

    public static class SigRef
    {
        public static string Scan(string path)
        {
            var rows = new List<Dictionary<string, object>>();
            using (var fs = System.IO.File.OpenRead(path))
            using (var pe = new PEReader(fs))
            {
                if (!pe.HasMetadata)
                    throw new InvalidOperationException("no CLI metadata");
                var mr = pe.GetMetadataReader();
                var p = new Prov(mr);

                int n = mr.GetTableRowCount(TableIndex.MethodDef);
                for (int i = 1; i <= n; i++)
                {
                    var h = MetadataTokens.MethodDefinitionHandle(i);
                    var d = mr.GetMethodDefinition(h);
                    Add(rows, mr, "MethodDef", 0x06, i, d.Signature,
                        () => Fmt.Sig(d.DecodeSignature(p, default(GCtx))));
                }

                n = mr.GetTableRowCount(TableIndex.MemberRef);
                for (int i = 1; i <= n; i++)
                {
                    var h = MetadataTokens.MemberReferenceHandle(i);
                    var d = mr.GetMemberReference(h);
                    Add(rows, mr, "MemberRef", 0x0A, i, d.Signature,
                        () => Fmt.Sig(d.DecodeMethodSignature(p, default(GCtx))));
                }

                n = mr.GetTableRowCount(TableIndex.StandAloneSig);
                for (int i = 1; i <= n; i++)
                {
                    var h = MetadataTokens.StandaloneSignatureHandle(i);
                    var d = mr.GetStandaloneSignature(h);
                    Add(rows, mr, "StandAloneSig", 0x11, i, d.Signature,
                        () => Fmt.Sig(d.DecodeMethodSignature(p, default(GCtx))));
                }
            }
            return System.Text.Json.JsonSerializer.Serialize(
                new Dictionary<string, object> { { "rows", rows } });
        }

        private static void Add(List<Dictionary<string, object>> rows,
                                MetadataReader mr, string table, int tid, int i,
                                BlobHandle bh, Func<string> dec)
        {
            var row = new Dictionary<string, object>();
            row["table"] = table;
            row["row"] = i;
            row["token"] = "0x" + ((tid << 24) | i).ToString("x8");
            int idx = bh.IsNil ? 0 : MetadataTokens.GetHeapOffset(bh);
            row["blob_index"] = idx;
            if (idx == 0)
            {
                row["status"] = "none";
                rows.Add(row);
                return;
            }
            int first = -1;
            try
            {
                var br = mr.GetBlobReader(bh);
                if (br.Length > 0) first = br.ReadByte();
            }
            catch (Exception ex)
            {
                row["status"] = "error";
                row["error"] = "blob:" + ex.GetType().Name + ": " + ex.Message;
                rows.Add(row);
                return;
            }
            string kind = first < 0 ? "empty"
                : (first & 0x3F) == 0x06 ? "field"
                : (first & 0x3F) == 0x07 ? "local" : "method";
            if (kind != "method")
            {
                row["status"] = kind;
                rows.Add(row);
                return;
            }
            try
            {
                row["status"] = "method";
                row["canonical"] = dec();
            }
            catch (Exception ex)
            {
                row["status"] = "error";
                row["error"] = ex.GetType().Name + ": " + ex.Message;
            }
            rows.Add(row);
        }
    }
}
'@
    $dir = Join-Path (Split-Path ([System.Reflection.Metadata.MetadataReader].Assembly.Location)) "ref"
    $refs = @(
        "$dir\System.Runtime.dll",
        "$dir\System.Collections.dll",
        "$dir\System.Collections.Immutable.dll",
        "$dir\System.Reflection.Metadata.dll",
        "$dir\System.Text.Json.dll",
        "$dir\System.Text.Encodings.Web.dll",
        "$dir\System.Memory.dll",
        "$dir\System.Runtime.InteropServices.dll",
        "$dir\netstandard.dll"
    )
    Add-Type -TypeDefinition $src -ReferencedAssemblies $refs
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    [RekitSig.SigRef]::Scan($Path)
}
catch {
    [Console]::Error.WriteLine("sigref_error: " + $_.Exception.Message)
    exit 3
}
