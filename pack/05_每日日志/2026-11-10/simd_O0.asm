
simd_O0.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <add8>:
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
   8:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
   c:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  10:	89 4d d4             	mov    %ecx,-0x2c(%rbp)
  13:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  1a:	eb 48                	jmp    64 <add8+0x64>
  1c:	8b 45 fc             	mov    -0x4(%rbp),%eax
  1f:	48 98                	cltq
  21:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  28:	00 
  29:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  2d:	48 01 d0             	add    %rdx,%rax
  30:	8b 08                	mov    (%rax),%ecx
  32:	8b 45 fc             	mov    -0x4(%rbp),%eax
  35:	48 98                	cltq
  37:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  3e:	00 
  3f:	48 8b 45 e0          	mov    -0x20(%rbp),%rax
  43:	48 01 d0             	add    %rdx,%rax
  46:	8b 10                	mov    (%rax),%edx
  48:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4b:	48 98                	cltq
  4d:	48 8d 34 85 00 00 00 	lea    0x0(,%rax,4),%rsi
  54:	00 
  55:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  59:	48 01 f0             	add    %rsi,%rax
  5c:	01 ca                	add    %ecx,%edx
  5e:	89 10                	mov    %edx,(%rax)
  60:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  64:	8b 45 fc             	mov    -0x4(%rbp),%eax
  67:	3b 45 d4             	cmp    -0x2c(%rbp),%eax
  6a:	7c b0                	jl     1c <add8+0x1c>
  6c:	90                   	nop
  6d:	90                   	nop
  6e:	5d                   	pop    %rbp
  6f:	c3                   	ret

0000000000000070 <sum16>:
  70:	55                   	push   %rbp
  71:	48 89 e5             	mov    %rsp,%rbp
  74:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  78:	89 75 e4             	mov    %esi,-0x1c(%rbp)
  7b:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  82:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  89:	eb 1b                	jmp    a6 <sum16+0x36>
  8b:	8b 45 f8             	mov    -0x8(%rbp),%eax
  8e:	48 98                	cltq
  90:	48 8d 14 00          	lea    (%rax,%rax,1),%rdx
  94:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  98:	48 01 d0             	add    %rdx,%rax
  9b:	0f b7 00             	movzwl (%rax),%eax
  9e:	98                   	cwtl
  9f:	01 45 fc             	add    %eax,-0x4(%rbp)
  a2:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  a6:	8b 45 f8             	mov    -0x8(%rbp),%eax
  a9:	3b 45 e4             	cmp    -0x1c(%rbp),%eax
  ac:	7c dd                	jl     8b <sum16+0x1b>
  ae:	8b 45 fc             	mov    -0x4(%rbp),%eax
  b1:	5d                   	pop    %rbp
  b2:	c3                   	ret

00000000000000b3 <zero128>:
  b3:	55                   	push   %rbp
  b4:	48 89 e5             	mov    %rsp,%rbp
  b7:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  bb:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  c2:	eb 1e                	jmp    e2 <zero128+0x2f>
  c4:	8b 45 fc             	mov    -0x4(%rbp),%eax
  c7:	48 98                	cltq
  c9:	48 8d 14 85 00 00 00 	lea    0x0(,%rax,4),%rdx
  d0:	00 
  d1:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  d5:	48 01 d0             	add    %rdx,%rax
  d8:	c7 00 00 00 00 00    	movl   $0x0,(%rax)
  de:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  e2:	83 7d fc 1f          	cmpl   $0x1f,-0x4(%rbp)
  e6:	7e dc                	jle    c4 <zero128+0x11>
  e8:	90                   	nop
  e9:	90                   	nop
  ea:	5d                   	pop    %rbp
  eb:	c3                   	ret
