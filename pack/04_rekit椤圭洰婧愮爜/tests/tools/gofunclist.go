// gofunclist: 用 Go 标准库 debug/gosym 从 .gopclntab 提取函数清单（外部独立参照）。
// M10 起用于对拍；M11 提升为仓库内验证工具（tests/verify_gopclntab.py 调用）。
//
// 独立性：只使用 Go 官方解析器与 debug/elf、debug/pe 的节信息，
// 不读取 rekit 的任何解析结果，也不使用被测实现的偏移推断。
//
// 用法: go run gofunclist.go <binary> <out.tsv>
// 输出: entry_hex\tend_hex\tname
package main

import (
	"bufio"
	"debug/elf"
	"debug/gosym"
	"debug/pe"
	"fmt"
	"os"
	"sort"
)

type fn struct {
	Entry, End uint64
	Name       string
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gofunclist <binary> <out.tsv>")
		os.Exit(2)
	}
	path, out := os.Args[1], os.Args[2]
	var pcln []byte
	var textAddr uint64
	imgBase := uint64(0)

	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		s := f.Section(".gopclntab")
		if s == nil {
			fmt.Fprintln(os.Stderr, "no .gopclntab")
			os.Exit(1)
		}
		pcln, _ = s.Data()
		textAddr = f.Section(".text").Addr
	} else {
		p, err := pe.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open:", err)
			os.Exit(1)
		}
		defer p.Close()
		imgBase = uint64(p.OptionalHeader.(*pe.OptionalHeader64).ImageBase)
		for _, s := range p.Sections {
			if s.Name == ".gopclntab" {
				pcln, _ = s.Data()
			}
			if s.Name == ".text" {
				textAddr = imgBase + uint64(s.VirtualAddress)
			}
		}
		if pcln == nil {
			// Go PE 把 pclntab 放在 .rdata 里（符号 runtime.pclntab），无独立节名；
			// 扫全文件找 pcHeader magic（f1 ff ff ff 00 00 01 08）作为独立定位。
			raw, _ := os.ReadFile(path)
			magic := []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00, 0x01, 0x08}
			idx := -1
			for i := 0; i+8 <= len(raw); i++ {
				if string(raw[i:i+8]) == string(magic) {
					idx = i
					break
				}
			}
			if idx < 0 {
				fmt.Fprintln(os.Stderr, "no .gopclntab and no pcHeader magic")
				os.Exit(1)
			}
			pcln = raw[idx:]
			fmt.Fprintf(os.Stderr, "found pclntab magic at file offset 0x%x\n", idx)
		}
	}

	lt := gosym.NewLineTable(pcln, textAddr)
	tab, err := gosym.NewTable(nil, lt)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gosym:", err)
		os.Exit(1)
	}
	var fns []fn
	for _, f := range tab.Funcs {
		if f.Entry == 0 {
			continue
		}
		fns = append(fns, fn{f.Entry, f.End, f.Name})
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Entry < fns[j].Entry })
	w, _ := os.Create(out)
	bw := bufio.NewWriter(w)
	defer w.Close()
	defer bw.Flush()
	fmt.Fprintf(bw, "# text=0x%x image_base=0x%x nfunc=%d\n",
		textAddr, imgBase, len(fns))
	for _, f := range fns {
		fmt.Fprintf(bw, "0x%x\t0x%x\t%s\n", f.Entry, f.End, f.Name)
	}
	fmt.Printf("wrote %d funcs to %s (text=0x%x)\n", len(fns), out, textAddr)
}
