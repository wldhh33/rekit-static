
simd_fixed.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <add_fixed>:
   0:	31 c0                	xor    %eax,%eax
   2:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
   9:	00 00 00 00 
   d:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
  14:	00 00 00 00 
  18:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
  1f:	00 
  20:	8b 0c 06             	mov    (%rsi,%rax,1),%ecx
  23:	03 0c 07             	add    (%rdi,%rax,1),%ecx
  26:	89 0c 02             	mov    %ecx,(%rdx,%rax,1)
  29:	48 83 c0 04          	add    $0x4,%rax
  2d:	48 3d 00 02 00 00    	cmp    $0x200,%rax
  33:	75 eb                	jne    20 <add_fixed+0x20>
  35:	c3                   	ret
