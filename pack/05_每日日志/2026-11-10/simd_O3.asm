
simd_O3.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <add_fixed>:
   0:	48 8d 4f 04          	lea    0x4(%rdi),%rcx
   4:	48 89 d0             	mov    %rdx,%rax
   7:	48 29 c8             	sub    %rcx,%rax
   a:	48 83 f8 18          	cmp    $0x18,%rax
   e:	0f 86 71 01 00 00    	jbe    185 <add_fixed+0x185>
  14:	48 8d 4e 04          	lea    0x4(%rsi),%rcx
  18:	48 89 d0             	mov    %rdx,%rax
  1b:	48 29 c8             	sub    %rcx,%rax
  1e:	48 83 f8 18          	cmp    $0x18,%rax
  22:	0f 86 5d 01 00 00    	jbe    185 <add_fixed+0x185>
  28:	c5 fe 6f 06          	vmovdqu (%rsi),%ymm0
  2c:	c5 fd fe 07          	vpaddd (%rdi),%ymm0,%ymm0
  30:	c5 fe 7f 02          	vmovdqu %ymm0,(%rdx)
  34:	c5 fe 6f 46 20       	vmovdqu 0x20(%rsi),%ymm0
  39:	c5 fd fe 47 20       	vpaddd 0x20(%rdi),%ymm0,%ymm0
  3e:	c5 fe 7f 42 20       	vmovdqu %ymm0,0x20(%rdx)
  43:	c5 fe 6f 46 40       	vmovdqu 0x40(%rsi),%ymm0
  48:	c5 fd fe 47 40       	vpaddd 0x40(%rdi),%ymm0,%ymm0
  4d:	c5 fe 7f 42 40       	vmovdqu %ymm0,0x40(%rdx)
  52:	c5 fe 6f 46 60       	vmovdqu 0x60(%rsi),%ymm0
  57:	c5 fd fe 47 60       	vpaddd 0x60(%rdi),%ymm0,%ymm0
  5c:	c5 fe 7f 42 60       	vmovdqu %ymm0,0x60(%rdx)
  61:	c5 fe 6f 86 80 00 00 	vmovdqu 0x80(%rsi),%ymm0
  68:	00 
  69:	c5 fd fe 87 80 00 00 	vpaddd 0x80(%rdi),%ymm0,%ymm0
  70:	00 
  71:	c5 fe 7f 82 80 00 00 	vmovdqu %ymm0,0x80(%rdx)
  78:	00 
  79:	c5 fe 6f 86 a0 00 00 	vmovdqu 0xa0(%rsi),%ymm0
  80:	00 
  81:	c5 fd fe 87 a0 00 00 	vpaddd 0xa0(%rdi),%ymm0,%ymm0
  88:	00 
  89:	c5 fe 7f 82 a0 00 00 	vmovdqu %ymm0,0xa0(%rdx)
  90:	00 
  91:	c5 fe 6f 86 c0 00 00 	vmovdqu 0xc0(%rsi),%ymm0
  98:	00 
  99:	c5 fd fe 87 c0 00 00 	vpaddd 0xc0(%rdi),%ymm0,%ymm0
  a0:	00 
  a1:	c5 fe 7f 82 c0 00 00 	vmovdqu %ymm0,0xc0(%rdx)
  a8:	00 
  a9:	c5 fe 6f 86 e0 00 00 	vmovdqu 0xe0(%rsi),%ymm0
  b0:	00 
  b1:	c5 fd fe 87 e0 00 00 	vpaddd 0xe0(%rdi),%ymm0,%ymm0
  b8:	00 
  b9:	c5 fe 7f 82 e0 00 00 	vmovdqu %ymm0,0xe0(%rdx)
  c0:	00 
  c1:	c5 fe 6f 86 00 01 00 	vmovdqu 0x100(%rsi),%ymm0
  c8:	00 
  c9:	c5 fd fe 87 00 01 00 	vpaddd 0x100(%rdi),%ymm0,%ymm0
  d0:	00 
  d1:	c5 fe 7f 82 00 01 00 	vmovdqu %ymm0,0x100(%rdx)
  d8:	00 
  d9:	c5 fe 6f 86 20 01 00 	vmovdqu 0x120(%rsi),%ymm0
  e0:	00 
  e1:	c5 fd fe 87 20 01 00 	vpaddd 0x120(%rdi),%ymm0,%ymm0
  e8:	00 
  e9:	c5 fe 7f 82 20 01 00 	vmovdqu %ymm0,0x120(%rdx)
  f0:	00 
  f1:	c5 fe 6f 86 40 01 00 	vmovdqu 0x140(%rsi),%ymm0
  f8:	00 
  f9:	c5 fd fe 87 40 01 00 	vpaddd 0x140(%rdi),%ymm0,%ymm0
 100:	00 
 101:	c5 fe 7f 82 40 01 00 	vmovdqu %ymm0,0x140(%rdx)
 108:	00 
 109:	c5 fe 6f 86 60 01 00 	vmovdqu 0x160(%rsi),%ymm0
 110:	00 
 111:	c5 fd fe 87 60 01 00 	vpaddd 0x160(%rdi),%ymm0,%ymm0
 118:	00 
 119:	c5 fe 7f 82 60 01 00 	vmovdqu %ymm0,0x160(%rdx)
 120:	00 
 121:	c5 fe 6f 86 80 01 00 	vmovdqu 0x180(%rsi),%ymm0
 128:	00 
 129:	c5 fd fe 87 80 01 00 	vpaddd 0x180(%rdi),%ymm0,%ymm0
 130:	00 
 131:	c5 fe 7f 82 80 01 00 	vmovdqu %ymm0,0x180(%rdx)
 138:	00 
 139:	c5 fe 6f 86 a0 01 00 	vmovdqu 0x1a0(%rsi),%ymm0
 140:	00 
 141:	c5 fd fe 87 a0 01 00 	vpaddd 0x1a0(%rdi),%ymm0,%ymm0
 148:	00 
 149:	c5 fe 7f 82 a0 01 00 	vmovdqu %ymm0,0x1a0(%rdx)
 150:	00 
 151:	c5 fe 6f 86 c0 01 00 	vmovdqu 0x1c0(%rsi),%ymm0
 158:	00 
 159:	c5 fd fe 87 c0 01 00 	vpaddd 0x1c0(%rdi),%ymm0,%ymm0
 160:	00 
 161:	c5 fe 7f 82 c0 01 00 	vmovdqu %ymm0,0x1c0(%rdx)
 168:	00 
 169:	c5 fe 6f 86 e0 01 00 	vmovdqu 0x1e0(%rsi),%ymm0
 170:	00 
 171:	c5 fd fe 87 e0 01 00 	vpaddd 0x1e0(%rdi),%ymm0,%ymm0
 178:	00 
 179:	c5 fe 7f 82 e0 01 00 	vmovdqu %ymm0,0x1e0(%rdx)
 180:	00 
 181:	c5 f8 77             	vzeroupper
 184:	c3                   	ret
 185:	31 c0                	xor    %eax,%eax
 187:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
 18e:	00 00 00 00 
 192:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
 199:	00 00 00 00 
 19d:	0f 1f 00             	nopl   (%rax)
 1a0:	8b 0c 06             	mov    (%rsi,%rax,1),%ecx
 1a3:	03 0c 07             	add    (%rdi,%rax,1),%ecx
 1a6:	89 0c 02             	mov    %ecx,(%rdx,%rax,1)
 1a9:	48 83 c0 04          	add    $0x4,%rax
 1ad:	48 3d 00 02 00 00    	cmp    $0x200,%rax
 1b3:	75 eb                	jne    1a0 <add_fixed+0x1a0>
 1b5:	c3                   	ret
