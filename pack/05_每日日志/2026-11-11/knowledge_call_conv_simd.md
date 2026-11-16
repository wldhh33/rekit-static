# 知识卡：System V AMD64 调用约定 × AVX 混合现场（阶段一 #2 收尾小测，2026-11-11）

> 样本：`mix.c`（10 参数：8 整型 + 2 double + AVX256 运算），gcc -O2 -mavx2。
> 反汇编全文：`mix_disasm.txt`。运行自证：ret=28002 = 4×(2.5+4.5)×1000 + popcount(36)。

## 调用全程（main → mix）

### main 侧（调用方义务）
1. **栈对齐**：`sub rsp,0x8`——进入 main 时 rsp≡8 (mod 16)，call 前必须归零对齐。
2. **整型传参**（顺序无关）：`edi=1, esi=2, edx=3, ecx=4, r8d=5, r9d=6` → a–f 六参数按 System V 整型寄存器序装载。
3. **浮点传参**：`vmovsd xmm0,[rip+0xfa4]`(=2.5)、`vmovsd xmm1,[rip+0xfb1]`(=4.5) → double 走 xmm0/xmm1，与整型寄存器**并行编号、互不占位**。
4. **栈传参**：`push 0x8; push 0x7`——第 8 参 h 先压、第 7 参 g 后压（右→左）；call 后布局：[rsp]=ret_addr，[rsp+8]=g，[rsp+0x10]=h。
5. `call mix`：隐式压入返回地址 0x108d。
6. 返回后 `pop rdx; pop rcx` 调用方清理栈参数（System V 无 callee-cleanup）。

### mix 侧（被调方义务）
1. **prologue**：`push rbp; mov rbp,rsp`（帧基：rbp+8=返回地址，rbp+0x10/0x18=g/h——正是 `add eax,[rbp+0x10]` 的取参点）；`push rbx` 保存 callee-saved。
2. **重对齐**：`and rsp,0xffffffffffffffe0`——vmovapd YMM 要求 32B 对齐，rbx 存对齐后栈顶作循环哨兵。
3. **SIMD 优化识别**：源码 set1(x)+set1(y)+add_pd 三个向量运算，被编译器**合并为标量 vaddsd 后一次 vbroadcastsd**——等值广播提升，读反汇编时别指望指令与源码一一对应。
4. **混合运算落栈**：`vmovapd [rsp-0x20],ymm0` → buf[4]；随后浮点循环 `vmulsd×1000.0 + vcvttsd2si + add` 是**标量循环**（acc 依赖链 + 浮点→整型转换，-O2 不向量化——编译器不做数学魔法）。
5. **对比**：整型位计数循环（8×`>>i &1` 求和）却被向量化成 `vpsravd+vpand` + 水平归约树（`vextracti128/vpmovsxdq/vpaddq/vpsrldq`）——**可结合、无精度歧义的整型归约才是自动向量化甜区**。
6. **epilogue**：`vzeroupper`（ret 前清 ymm 上半 128 位，免 AVX→SSE 转换惩罚，ABI 义务）→ `mov rbx,[rbp-0x8]` 恢复 → `leave` → `ret`（返回值在 rax）。

## 今日规则沉淀

- **R19 内联吞噬调用链**：-O2 下小函数默认内联，`call` 会从调用方消失（首次编译实测 main 无 call mix）；**验证调用约定的样本必须 `__attribute__((noinline))`**。反向用途：call 消失本身就是"该函数被内联"的判定证据。
- **R20 栈参数右→左**：push 序 = 参数序的逆序；帧内定位锚 rbp 而非 rsp（被调方可能 `and rsp` 重对齐，rsp 锚会失真——本例 mix 用 [rbp+0x10] 取 g 而非 [rsp]）。
- **R21 传参双轨**：整型与浮点寄存器编号独立（rdi..r9 与 xmm0..xmm7 各自计数），混参函数读反汇编时两轨并行追踪。

## 练习建议（留给下次自测）

1. 把第 9/10 参数也改成整型（g,h,i,j → 4 个栈参数），验证 [rsp+8..0x20] 布局与 R20。
2. 去掉 noinline 用 `-O0` 对比：寄存器装载顺序、canary（Ubuntu 默认 -fstack-protector-strong 在 -O0 下显形）差异。
3. 把 buf 循环改写为无依赖形式（acc 数组再归约），观察是否触发 vaddpd/vmulpd 向量化。
