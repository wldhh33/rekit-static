# tests/samples/avx/avx_dense.s — 自建 AVX/VEX 密集样本（M4 第二单元）
#
# 目的：量化 disasm/recdesc 对 VEX（AVX）abstain 的实际代价。
# 布局特意做成：start(纯整数) → avx_add(VEX) → plain_loop(纯整数) → avx_mul(VEX)。
# 线性扫描会在 avx_add 的第一条 VEX 处停止，扫不到后面的 plain_loop；
# 递归下降按函数种子各自下降，plain_loop 仍可完整解出——两者差异可直接对照。
#
# 构建（本项目 binutils 2.47 是 mingw 目标，产物为 PE32+，不是 ELF）：
#   as --64 -o avx_dense.o avx_dense.s
#   ld -e _start --export-all-symbols -o avx_dense.exe avx_dense.o
# 种子来源：PE 入口点 + --export-all-symbols 生成的导出表（均为权威种子）。
# 说明：本机无 ELF 目标的汇编器；ELF 侧的 VEX 代价用真实样本 dyn_static 量化。
    .section .rdata,"dr"
    .align 32
.Lc0:
    .float 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0
.Lc1:
    .float 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0

    .text
    .globl _start
_start:
    call plain_loop
    call avx_add
    call plain_loop
    call avx_mul
    call avx_mix
    mov $60, %eax
    xor %edi, %edi
    syscall

    .globl avx_add
avx_add:
    vmovaps .Lc0(%rip), %ymm0
    vaddps %ymm1, %ymm0, %ymm0
    vmovaps .Lc1(%rip), %ymm2
    vaddps %ymm2, %ymm0, %ymm0
    vmovaps %ymm0, -32(%rsp)
    vzeroupper
    ret

    .globl plain_loop
plain_loop:
    xor %eax, %eax
    mov $10, %ecx
.Lloop:
    add $3, %eax
    imul %ecx, %eax
    dec %ecx
    jnz .Lloop
    ret

    .globl avx_mul
avx_mul:
    vmovaps .Lc0(%rip), %ymm0
    vmovaps .Lc1(%rip), %ymm1
    vmulps %ymm1, %ymm0, %ymm2
    vaddps %ymm2, %ymm0, %ymm3
    vsubps %ymm1, %ymm3, %ymm4
    vxorpd %ymm5, %ymm5, %ymm5
    vmovaps %ymm4, -32(%rsp)
    vzeroupper
    ret

    .globl avx_mix
avx_mix:
    vmovaps .Lc0(%rip), %ymm0
    vmovaps .Lc1(%rip), %ymm1
    vaddps %ymm1, %ymm0, %ymm2
    vmulps %ymm2, %ymm1, %ymm3
    vsubps %ymm0, %ymm3, %ymm4
    vdivps %ymm1, %ymm4, %ymm5
    vxorpd %ymm6, %ymm6, %ymm6
    vandps %ymm5, %ymm6, %ymm7
    vorps %ymm7, %ymm4, %ymm8
    vmovaps %ymm8, -32(%rsp)
    vzeroupper
    ret
