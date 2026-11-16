# x86-64 调用约定速查卡（阶段一 #2，2026-11-07 实证版）

## 一图流对照

| 维度 | System V AMD64（Linux/macOS） | MS x64（Windows） |
|---|---|---|
| 整数参数 1–6 | rdi, rsi, rdx, rcx, r8, r9 | rcx, rdx, r8, r9（仅 4 个） |
| 第 7+ 参数 | caller 从右到左压栈 | caller 从右到左压栈 |
| 前置栈空间 | 无 | **shadow space 32B**（caller 必须预留，callee 可存回 4 个寄存器参数） |
| 返回值 | rax（>16B 经 rdi 隐藏指针返回） | rax（同理） |
| 浮点参数 | xmm0–xmm7 | 仅前 4 个浮点用 xmm0–3 |
| callee-saved | rbx, rbp, r12–r15 | rbx, rbp, rdi, rsi, r12–r15（注意 rdi/rsi 方向相反！） |
| caller 清栈 | caller `add $0xN,%rsp` | caller `add $0xN,%rsp`（N 含 shadow space） |
| 栈对齐 | call 前 rsp ≡ 8 (mod 16) | 同左 |

## 今日实证（gcc -O0, Ubuntu x64，System V）

```asm
main:                                   add8:                      ; callee 视角
  push $0x8        ; 第8参,先进栈(高址)   push %rbp
  push $0x7        ; 第7参,后进栈(低址)   mov  %rsp,%rbp
  mov $0x6,%r9d    ; ← 第6参              mov  %edi,-0x4(%rbp)   ; 参数1 spill
  mov $0x5,%r8d    ; ← 第5参              mov  %esi,-0x8(%rbp)   ; 参数2
  mov $0x4,%ecx    ; ← 第4参              ...
  mov $0x3,%edx    ; ← 第3参              mov  0x10(%rbp),%eax   ; ← 第7参（栈上）
  mov $0x2,%esi    ; ← 第2参              mov  0x18(%rbp),%eax   ; ← 第8参（栈上）
  mov $0x1,%edi    ; ← 第1参              pop  %rbp
  call add8                              ret
  add $0x10,%rsp   ; caller 清栈(2参×8B)
```

**callee 取栈参公式（System V）**：第 n≥7 个参数位于 `rbp + 16 + (n−7)×8`（rbp+0=旧rbp, rbp+8=返回地址）。

## 逆向应用三招

1. **认函数签名**：见 `mov edi,esi` 成对装载 → 准备 2 参数调用；见 `rcx` 在 Windows 样本中装载 → 大概率第 1 参。
2. **找调用点**：grep `lea rdi,[xxx]` + `call` → 该函数接收 xxx 指针为参数 1。
3. **栈参陷阱**：函数读 `rsp+0x10`/`rbp+0x10` 却不见参数装载 → 参数在栈上，去 caller 处找 push 序列（**从右到左**，故最后 push 的是最左栈参）。

## 今日实证踩到的坑（记入规则库）

- **R6 vaddr ≠ file offset**：ELF 动态段 DT_STRTAB/DT_SYMTAB 等值是**虚拟地址**，PIE（差 0x1000）与非 PIE（差 ImageBase）都必须经 PT_LOAD 映射换算 `off = vaddr − p_vaddr + p_offset`。直用会越界（今日反证：0x400418 直用即 ValueError）。
- **R7 glibc 2.34+ 无独立 libm 依赖**：`gcc -lm` 不再产生 `DT_NEEDED libm.so.6`，libm 已并入 libc——验证解析器时别拿 libm 当"多依赖"样本。

## 练习建议（次日可选青铜热身）

- 用 `objdump -d` 看 `printf` 调用点（变参：整数仍走 rdi..r9，浮点走 xmm0..），数一数 gcc 怎么摆 `al`（变参 SSE 计数）。
- 手算：`f(a,b,c,d,e,f,g,h,i,j)` 第 j 参在 callee 的 rbp 偏移 = `16 + (10−7)×8 = 40 = 0x28`，再用反汇编验证。
