// 阶段一收尾小测样本：main→mix 调用链 + AVX SIMD
// 10 参数设计：6 整型走 rdi/rsi/rdx/rcx/r8/r9，2 整型走栈，2 double 走 xmm0/xmm1
#include <immintrin.h>
#include <stdio.h>

__attribute__((noinline)) long mix(int a, int b, int c, int d, int e, int f, int g, int h,
         double x, double y) {
    __m256d va = _mm256_set1_pd(x);      // ymm 广播 x
    __m256d vb = _mm256_set1_pd(y);      // ymm 广播 y
    __m256d vs = _mm256_add_pd(va, vb);  // 4 lane 齐加
    double buf[4] __attribute__((aligned(32)));
    _mm256_store_pd(buf, vs);            // 存回栈上 32B 对齐数组
    long acc = 0;
    for (int i = 0; i < 4; i++) acc += (long)(buf[i] * 1000.0);
    for (int i = 0; i < 8; i++) acc += ((a+b+c+d+e+f+g+h) >> i) & 1;
    return acc;
}

int main(void) {
    long r = mix(1, 2, 3, 4, 5, 6, 7, 8, 2.5, 4.5);
    printf("ret=%ld\n", r);
    return 0;
}
