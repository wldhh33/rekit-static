
simd_O2.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <add8>:
   0:	85 c9                	test   %ecx,%ecx
   2:	7e 2e                	jle    32 <add8+0x32>
   4:	48 63 c9             	movslq %ecx,%rcx
   7:	31 c0                	xor    %eax,%eax
   9:	4c 8d 04 8d 00 00 00 	lea    0x0(,%rcx,4),%r8
  10:	00 
  11:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  18:	00 00 00 00 
  1c:	0f 1f 40 00          	nopl   0x0(%rax)
  20:	8b 0c 06             	mov    (%rsi,%rax,1),%ecx
  23:	03 0c 07             	add    (%rdi,%rax,1),%ecx
  26:	89 0c 02             	mov    %ecx,(%rdx,%rax,1)
  29:	48 83 c0 04          	add    $0x4,%rax
  2d:	49 39 c0             	cmp    %rax,%r8
  30:	75 ee                	jne    20 <add8+0x20>
  32:	c3                   	ret
  33:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  3a:	00 00 00 00 
  3e:	66 90                	xchg   %ax,%ax

0000000000000040 <sum16>:
  40:	85 f6                	test   %esi,%esi
  42:	7e 1c                	jle    60 <sum16+0x20>
  44:	48 63 f6             	movslq %esi,%rsi
  47:	31 c0                	xor    %eax,%eax
  49:	48 8d 0c 77          	lea    (%rdi,%rsi,2),%rcx
  4d:	0f 1f 00             	nopl   (%rax)
  50:	0f bf 17             	movswl (%rdi),%edx
  53:	48 83 c7 02          	add    $0x2,%rdi
  57:	01 d0                	add    %edx,%eax
  59:	48 39 cf             	cmp    %rcx,%rdi
  5c:	75 f2                	jne    50 <sum16+0x10>
  5e:	c3                   	ret
  5f:	90                   	nop
  60:	31 c0                	xor    %eax,%eax
  62:	c3                   	ret
  63:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  6a:	00 00 00 00 
  6e:	66 90                	xchg   %ax,%ax

0000000000000070 <zero128>:
  70:	c5 f9 ef c0          	vpxor  %xmm0,%xmm0,%xmm0
  74:	62 f1 7f 28 7f 07    	vmovdqu8 %ymm0,(%rdi)
  7a:	62 f1 7f 28 7f 47 01 	vmovdqu8 %ymm0,0x20(%rdi)
  81:	62 f1 7f 28 7f 47 02 	vmovdqu8 %ymm0,0x40(%rdi)
  88:	62 f1 7f 28 7f 47 03 	vmovdqu8 %ymm0,0x60(%rdi)
  8f:	c5 f8 77             	vzeroupper
  92:	c3                   	ret
